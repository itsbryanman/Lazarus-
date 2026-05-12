//! Streaming AEAD chunk encryption with deterministic nonce derivation.
//!
//! `StreamingEncryptor` wraps AES-256-GCM and derives the 12-byte nonce
//! deterministically from `BLAKE3(chunk_hash || key_epoch)`. This means the
//! same plaintext encrypted with the same key produces the same ciphertext,
//! preserving deduplication across snapshots.
//!
//! `key_epoch` is bumped whenever the repository's chunk-encryption key
//! material rotates, so post-rotation chunks never collide nonces with
//! pre-rotation chunks under the (old) key — even though, after rotation,
//! they're encrypted under the new key.
//!
//! ### Wire format
//! ```text
//! +------+--------+------------------+
//! | ver  | epoch  |  ciphertext+tag  |
//! +------+--------+------------------+
//!   1B    4B(LE)        N bytes
//! ```
//! The nonce itself is **not** stored — it is recomputed at decrypt time from
//! the chunk hash plus the epoch byte. The chunk hash is supplied externally
//! by the caller (it is the catalog key for the chunk).
//!
//! Backwards compatibility: the legacy backup path stored `nonce(12) ||
//! ciphertext`. The decoder for that format remains in `key_manager.rs`. New
//! callers should use `StreamingEncryptor` and the `EncryptedChunk` framing
//! defined here. `decrypt_legacy` is provided to migrate older repos.

#![allow(deprecated)]

use crate::error::{LazarusError, Result};
use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};

/// Magic version byte that marks the streaming-AEAD chunk framing. Allows the
/// decoder to recognize new vs legacy chunks without ambiguity (legacy chunks
/// always start with a 12-byte random nonce, so a fixed leading byte is a
/// perfectly fine discriminator).
pub const STREAMING_VERSION: u8 = 0x02;

/// Length of the deterministic nonce (AES-GCM standard).
pub const NONCE_LEN: usize = 12;

/// Streaming AEAD wrapper for chunk-sized payloads. Cheap to clone; holds only
/// 32 bytes of key material and a 4-byte epoch.
#[derive(Clone)]
pub struct StreamingEncryptor {
    key: [u8; 32],
    epoch: u32,
}

impl StreamingEncryptor {
    /// Build a new encryptor with the given chunk-encryption key. The default
    /// `key_epoch` is 0 — call [`with_epoch`] after a rotation.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            key: *key,
            epoch: 0,
        }
    }

    /// Set the key epoch. Increment this any time the underlying key material
    /// is rotated so the deterministic nonce derivation diverges.
    pub fn with_epoch(mut self, epoch: u32) -> Self {
        self.epoch = epoch;
        self
    }

    /// Current epoch this encryptor uses for nonce derivation.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Encrypt a chunk under the streaming framing. The output prepends a
    /// 1-byte version and the 4-byte epoch so the decoder can route correctly
    /// across repo upgrades.
    pub fn encrypt_chunk(&self, chunk_hash: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = derive_nonce(chunk_hash, self.epoch);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        let ct = cipher
            .encrypt(GenericArray::from_slice(&nonce), plaintext)
            .map_err(|_| LazarusError::EncryptionError("AEAD encrypt failed".into()))?;

        let mut out = Vec::with_capacity(1 + 4 + ct.len());
        out.push(STREAMING_VERSION);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a chunk that was produced by [`encrypt_chunk`]. Returns an
    /// error if the framing does not match (caller should fall back to
    /// [`decrypt_legacy`] for older repositories).
    pub fn decrypt_chunk(&self, chunk_hash: &[u8; 32], framed: &[u8]) -> Result<Vec<u8>> {
        if framed.len() < 1 + 4 {
            return Err(LazarusError::EncryptionError(
                "Streaming chunk too short".into(),
            ));
        }
        if framed[0] != STREAMING_VERSION {
            return Err(LazarusError::EncryptionError(
                "Unrecognized chunk framing version".into(),
            ));
        }
        let mut epoch_bytes = [0u8; 4];
        epoch_bytes.copy_from_slice(&framed[1..5]);
        let epoch = u32::from_le_bytes(epoch_bytes);
        let ct = &framed[5..];

        let nonce = derive_nonce(chunk_hash, epoch);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        cipher
            .decrypt(GenericArray::from_slice(&nonce), ct)
            .map_err(|_| LazarusError::EncryptionError("AEAD decrypt failed".into()))
    }

    /// Decode a legacy (pre-streaming) chunk: `nonce(12) || ciphertext`.
    /// Used during the one-shot upgrade path so existing repositories can be
    /// read after upgrading the binary.
    pub fn decrypt_legacy(&self, framed: &[u8]) -> Result<Vec<u8>> {
        if framed.len() < NONCE_LEN {
            return Err(LazarusError::EncryptionError(
                "Legacy chunk too short".into(),
            ));
        }
        let (nonce, ct) = framed.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        cipher
            .decrypt(GenericArray::from_slice(nonce), ct)
            .map_err(|_| LazarusError::EncryptionError("Legacy AEAD decrypt failed".into()))
    }

    /// Read the framing version byte without performing any crypto. Useful for
    /// migration tooling.
    pub fn detect_framing(framed: &[u8]) -> ChunkFraming {
        match framed.first().copied() {
            Some(STREAMING_VERSION) => ChunkFraming::Streaming,
            _ => ChunkFraming::Legacy,
        }
    }
}

/// Discriminator returned by [`StreamingEncryptor::detect_framing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkFraming {
    /// `nonce(12) || ciphertext` — legacy `key_manager::encrypt_data` output.
    Legacy,
    /// `0x02 || epoch(4) || ciphertext` — modern streaming AEAD.
    Streaming,
}

/// Derive the deterministic 12-byte nonce for a `(chunk_hash, key_epoch)`
/// pair. Documented exactly as in `lazarus_resurrection_prompt.md` §1.5: first
/// 12 bytes of `BLAKE3(chunk_hash || key_epoch)`. The epoch byte is encoded
/// little-endian.
fn derive_nonce(chunk_hash: &[u8; 32], key_epoch: u32) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(chunk_hash);
    hasher.update(&key_epoch.to_le_bytes());
    let digest = hasher.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn round_trip() {
        let enc = StreamingEncryptor::new(&key());
        let chunk_hash = blake3::hash(b"plaintext").into();
        let ct = enc.encrypt_chunk(&chunk_hash, b"plaintext").unwrap();
        let pt = enc.decrypt_chunk(&chunk_hash, &ct).unwrap();
        assert_eq!(pt, b"plaintext");
    }

    #[test]
    fn deterministic_ciphertext_preserves_dedup() {
        let enc = StreamingEncryptor::new(&key());
        let chunk_hash = blake3::hash(b"the same").into();
        let a = enc.encrypt_chunk(&chunk_hash, b"the same").unwrap();
        let b = enc.encrypt_chunk(&chunk_hash, b"the same").unwrap();
        assert_eq!(a, b, "deterministic encryption must yield identical output");
    }

    #[test]
    fn different_epoch_yields_different_ciphertext() {
        let enc1 = StreamingEncryptor::new(&key()).with_epoch(0);
        let enc2 = StreamingEncryptor::new(&key()).with_epoch(1);
        let chunk_hash = blake3::hash(b"data").into();
        let a = enc1.encrypt_chunk(&chunk_hash, b"data").unwrap();
        let b = enc2.encrypt_chunk(&chunk_hash, b"data").unwrap();
        assert_ne!(a, b);

        // Each should still round-trip under its own epoch.
        assert_eq!(enc1.decrypt_chunk(&chunk_hash, &a).unwrap(), b"data");
        assert_eq!(enc2.decrypt_chunk(&chunk_hash, &b).unwrap(), b"data");
    }

    #[test]
    fn cross_epoch_decrypt_works_via_embedded_epoch() {
        // The framing carries the epoch the chunk was written under, so even a
        // "current epoch = 5" encryptor should be able to decrypt an older
        // epoch-0 chunk transparently.
        let writer = StreamingEncryptor::new(&key()).with_epoch(0);
        let reader = StreamingEncryptor::new(&key()).with_epoch(5);
        let chunk_hash = blake3::hash(b"old chunk").into();
        let ct = writer.encrypt_chunk(&chunk_hash, b"old chunk").unwrap();
        assert_eq!(
            reader.decrypt_chunk(&chunk_hash, &ct).unwrap(),
            b"old chunk"
        );
    }

    #[test]
    fn rejects_corrupted_ciphertext() {
        let enc = StreamingEncryptor::new(&key());
        let chunk_hash = blake3::hash(b"x").into();
        let mut ct = enc.encrypt_chunk(&chunk_hash, b"x").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(enc.decrypt_chunk(&chunk_hash, &ct).is_err());
    }

    #[test]
    fn rejects_wrong_chunk_hash() {
        let enc = StreamingEncryptor::new(&key());
        let real = blake3::hash(b"x").into();
        let other: [u8; 32] = blake3::hash(b"y").into();
        let ct = enc.encrypt_chunk(&real, b"x").unwrap();
        // Decrypting with a different chunk-hash derives a different nonce.
        assert!(enc.decrypt_chunk(&other, &ct).is_err());
    }

    #[test]
    fn detect_framing_distinguishes_versions() {
        let enc = StreamingEncryptor::new(&key());
        let ch = blake3::hash(b"x").into();
        let ct = enc.encrypt_chunk(&ch, b"x").unwrap();
        assert_eq!(StreamingEncryptor::detect_framing(&ct), ChunkFraming::Streaming);

        // A 12-byte nonce-led blob is treated as legacy.
        let legacy = vec![0u8; 32];
        assert_eq!(
            StreamingEncryptor::detect_framing(&legacy),
            ChunkFraming::Legacy
        );
    }
}
