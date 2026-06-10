//! Glue between captured fingerprints and the catalog/storage stack.
//!
//! Two storage tracks share this code:
//!
//! * Non-sensitive payloads (the fingerprint itself, ESP archive bytes,
//!   kernel images) are encrypted with the *data* key like any other
//!   chunk and keyed by hex BLAKE3 of their plaintext.
//! * Sensitive payloads (`/etc/shadow`, ssh host keys) are encrypted
//!   with the *metadata* key. Same on-disk layout (`nonce || ciphertext`)
//!   so storage backends can't tell them apart at rest.
//!
//! Both tracks register every chunk with the `DedupTable` so pruning
//! respects them, and both prefix the AEAD plaintext with an 8-byte
//! magic+version header so a future format bump is detectable.

use crate::catalog::index::CatalogIndex;
use crate::encryption::key_manager::KeyManager;
use crate::error::{LazarusError, Result};
use crate::snapshot::dedup::DedupTable;
use crate::storage::backend::StorageBackend;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

use super::system::{FINGERPRINT_VERSION, SystemFingerprint};

/// Plaintext magic for an encrypted SystemFingerprint blob.
pub const MAGIC_FINGERPRINT: &[u8; 4] = b"LZFP";
/// Plaintext magic for an encrypted sensitive blob.
pub const MAGIC_SENSITIVE_BLOB: &[u8; 4] = b"LZBP";

/// Persistence helper that writes capture artefacts into the existing
/// repository (chunk storage, dedup table) under the right encryption
/// key. `dry_run` buffers writes so callers can do `--dry-run` flows
/// without touching the backend.
pub struct FingerprintPersister<'a> {
    pub backend: &'a dyn StorageBackend,
    pub keys: &'a KeyManager,
    pub catalog: &'a CatalogIndex,
    pub dedup: &'a DedupTable,
    pub snapshot_id: &'a str,
    pub dry_run: bool,
    pub(crate) buffered: Mutex<Vec<BufferedWrite>>,
}

pub(crate) struct BufferedWrite {
    pub hex: String,
    pub kind: BufferedKind,
}

pub(crate) enum BufferedKind {
    DataKey,
    MetadataKey,
}

impl<'a> FingerprintPersister<'a> {
    pub fn new(
        backend: &'a dyn StorageBackend,
        keys: &'a KeyManager,
        catalog: &'a CatalogIndex,
        dedup: &'a DedupTable,
        snapshot_id: &'a str,
        dry_run: bool,
    ) -> Self {
        Self {
            backend,
            keys,
            catalog,
            dedup,
            snapshot_id,
            dry_run,
            buffered: Mutex::new(Vec::new()),
        }
    }

    /// Persist the top-level fingerprint under the data key.
    /// Returns the hex BLAKE3 hash of the plaintext (the chunk key).
    pub async fn persist_fingerprint(&self, fp: &SystemFingerprint) -> Result<String> {
        let mut plaintext = Vec::with_capacity(2048);
        plaintext.extend_from_slice(MAGIC_FINGERPRINT);
        plaintext.extend_from_slice(&FINGERPRINT_VERSION.to_le_bytes());
        let body = bincode::serialize(fp)
            .map_err(|e| LazarusError::SerializationError(format!("bincode: {e}")))?;
        plaintext.extend_from_slice(&body);
        self.put_data_key_bytes(&plaintext).await
    }

    /// Persist arbitrary bytes (e.g. an ESP tar archive, a kernel
    /// image) under the data key. No framing — the caller is responsible
    /// for any internal structure.
    pub async fn persist_blob_data_key(&self, plaintext: &[u8]) -> Result<String> {
        self.put_data_key_bytes(plaintext).await
    }

    /// Persist a sensitive value (`/etc/shadow`, ssh host keys) under
    /// the metadata key. The plaintext gets the `LZBP` magic + version
    /// header so the reader can sanity-check that it's pointed at the
    /// right kind of blob.
    pub async fn persist_blob_metadata_key<T: Serialize>(&self, blob: &T) -> Result<String> {
        let mut plaintext = Vec::with_capacity(1024);
        plaintext.extend_from_slice(MAGIC_SENSITIVE_BLOB);
        plaintext.extend_from_slice(&FINGERPRINT_VERSION.to_le_bytes());
        let body = bincode::serialize(blob)
            .map_err(|e| LazarusError::SerializationError(format!("bincode: {e}")))?;
        plaintext.extend_from_slice(&body);
        self.put_metadata_key_bytes(&plaintext).await
    }

    /// Inverse of `persist_fingerprint`. Verifies magic + version
    /// before decoding so a tampered/wrong chunk fails with a typed
    /// error rather than a confusing bincode panic.
    pub async fn load_fingerprint(&self, hex_hash: &str) -> Result<SystemFingerprint> {
        let plaintext = self.get_data_key_bytes(hex_hash).await?;
        let body = strip_header(&plaintext, MAGIC_FINGERPRINT, "fingerprint")?;
        bincode::deserialize(body).map_err(|e| {
            LazarusError::SerializationError(format!("fingerprint bincode decode: {e}"))
        })
    }

    /// Inverse of `persist_blob_metadata_key`.
    pub async fn load_blob_metadata_key<T: DeserializeOwned>(&self, hex_hash: &str) -> Result<T> {
        let plaintext = self.get_metadata_key_bytes(hex_hash).await?;
        let body = strip_header(&plaintext, MAGIC_SENSITIVE_BLOB, "sensitive_blob")?;
        bincode::deserialize(body).map_err(|e| {
            LazarusError::SerializationError(format!("blob bincode decode: {e}"))
        })
    }

    // --- internals -------------------------------------------------------

    async fn put_data_key_bytes(&self, plaintext: &[u8]) -> Result<String> {
        let hex = hex::encode(blake3::hash(plaintext).as_bytes());
        // Register the dedup reference even on dry-run-into-existing-snapshot
        // would be premature; only do it when we actually write.
        if self.dry_run {
            self.buffered.lock().await.push(BufferedWrite {
                hex: hex.clone(),
                kind: BufferedKind::DataKey,
            });
            return Ok(hex);
        }
        let (ct, nonce) = self.keys.encrypt_data(plaintext)?;
        let mut on_disk = Vec::with_capacity(nonce.len() + ct.len());
        on_disk.extend_from_slice(&nonce);
        on_disk.extend_from_slice(&ct);
        let storage_key = sharded_key(&hex);
        self.backend.put(&storage_key, &on_disk).await?;
        self.register_ref(&hex)?;
        Ok(hex)
    }

    async fn put_metadata_key_bytes(&self, plaintext: &[u8]) -> Result<String> {
        let hex = hex::encode(blake3::hash(plaintext).as_bytes());
        if self.dry_run {
            self.buffered.lock().await.push(BufferedWrite {
                hex: hex.clone(),
                kind: BufferedKind::MetadataKey,
            });
            return Ok(hex);
        }
        let (ct, nonce) = self.keys.encrypt_metadata_bytes(plaintext)?;
        let mut on_disk = Vec::with_capacity(nonce.len() + ct.len());
        on_disk.extend_from_slice(&nonce);
        on_disk.extend_from_slice(&ct);
        let storage_key = sharded_key(&hex);
        self.backend.put(&storage_key, &on_disk).await?;
        self.register_ref(&hex)?;
        Ok(hex)
    }

    async fn get_data_key_bytes(&self, hex_hash: &str) -> Result<Vec<u8>> {
        let storage_key = sharded_key(hex_hash);
        let on_disk = self.backend.get(&storage_key).await?;
        if on_disk.len() < 12 {
            return Err(LazarusError::Storage(
                "fingerprint chunk too short to contain nonce".into(),
            ));
        }
        let (nonce, ct) = on_disk.split_at(12);
        self.keys.decrypt_data(ct, nonce)
    }

    async fn get_metadata_key_bytes(&self, hex_hash: &str) -> Result<Vec<u8>> {
        let storage_key = sharded_key(hex_hash);
        let on_disk = self.backend.get(&storage_key).await?;
        if on_disk.len() < 12 {
            return Err(LazarusError::Storage(
                "sensitive blob chunk too short to contain nonce".into(),
            ));
        }
        let (nonce, ct) = on_disk.split_at(12);
        self.keys.decrypt_metadata_bytes(ct, nonce)
    }

    fn register_ref(&self, hex_hash: &str) -> Result<()> {
        let bytes = hex::decode(hex_hash).map_err(|e| {
            LazarusError::Storage(format!("invalid chunk hash hex: {e}"))
        })?;
        if bytes.len() != 32 {
            return Err(LazarusError::Storage(format!(
                "expected 32-byte BLAKE3 hash, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        self.dedup.add_reference(&arr, self.snapshot_id)?;
        Ok(())
    }
}

/// Build a sharded storage key from a bare hex hash.
///
/// Matches the convention used by `backup.rs` and `prune.rs`:
/// `format!("{}/{}", &hex[..2], hex)`.
pub fn sharded_key(hex_hash: &str) -> String {
    format!("{}/{}", &hex_hash[..2], hex_hash)
}

/// Strip the 8-byte magic+version header. Returns the body slice on
/// success, or a typed error if magic is wrong or the version is newer
/// than this build knows how to decode.
fn strip_header<'a>(buf: &'a [u8], expected_magic: &[u8; 4], label: &str) -> Result<&'a [u8]> {
    if buf.len() < 8 {
        return Err(LazarusError::VerificationFailed(format!(
            "{label} blob shorter than header"
        )));
    }
    if &buf[..4] != expected_magic {
        return Err(LazarusError::VerificationFailed(format!(
            "{label} magic mismatch: got {:?}, expected {:?}",
            &buf[..4],
            expected_magic
        )));
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if version > FINGERPRINT_VERSION {
        return Err(LazarusError::VerificationFailed(format!(
            "{label} version {version} newer than supported {FINGERPRINT_VERSION}"
        )));
    }
    Ok(&buf[8..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::local::LocalStorage;
    use tempfile::tempdir;

    fn dummy_fingerprint() -> SystemFingerprint {
        SystemFingerprint {
            version: FINGERPRINT_VERSION,
            captured_at_epoch_s: 1234,
            captured_by: "test".into(),
            hostname: "host".into(),
            fqdn: None,
            machine_id: Some("abc123".into()),
            kernel: Default::default(),
            cpu: Default::default(),
            memory_bytes: 0,
            disks: vec![],
            lvm: None,
            mdadm: None,
            filesystems: vec![],
            fstab: String::new(),
            crypttab: None,
            network: crate::capture::network::NetworkConfig::default(),
            bootloader: crate::capture::bootloader::BootloaderConfig::default(),
            packages: crate::capture::packages::PackageManifest::default(),
            services: vec![],
            users: crate::capture::users::UserDatabaseRef::empty(),
            ssh_host_keys: crate::capture::secrets::SshHostKeysRef::empty(),
            firmware: Default::default(),
            warnings: vec![],
        }
    }

    #[tokio::test]
    async fn fingerprint_roundtrip() {
        let dir = tempdir().unwrap();
        let (keys, _cfg) = KeyManager::init_repository("pw").unwrap();
        let catalog = CatalogIndex::new(dir.path().join("catalog.db")).unwrap();
        let storage = LocalStorage::new(dir.path().join("data"));
        let dedup = DedupTable::open(dir.path().join("catalog.db")).unwrap();
        let persister = FingerprintPersister::new(&storage, &keys, &catalog, &dedup, "snap-1", false);
        let fp = dummy_fingerprint();
        let hash = persister.persist_fingerprint(&fp).await.unwrap();
        let got = persister.load_fingerprint(&hash).await.unwrap();
        assert_eq!(got.hostname, fp.hostname);
        assert_eq!(got.machine_id, fp.machine_id);
    }

    #[tokio::test]
    async fn dry_run_does_not_touch_backend() {
        let dir = tempdir().unwrap();
        let (keys, _cfg) = KeyManager::init_repository("pw").unwrap();
        let catalog = CatalogIndex::new(dir.path().join("catalog.db")).unwrap();
        let storage = LocalStorage::new(dir.path().join("data"));
        let dedup = DedupTable::open(dir.path().join("catalog.db")).unwrap();
        let persister = FingerprintPersister::new(&storage, &keys, &catalog, &dedup, "snap-1", true);
        let fp = dummy_fingerprint();
        let hash = persister.persist_fingerprint(&fp).await.unwrap();
        assert_eq!(hash.len(), 64);
        // Loading should fail because nothing was written.
        assert!(persister.load_fingerprint(&hash).await.is_err());
    }

    #[tokio::test]
    async fn tamper_detection() {
        let dir = tempdir().unwrap();
        let (keys, _cfg) = KeyManager::init_repository("pw").unwrap();
        let catalog = CatalogIndex::new(dir.path().join("catalog.db")).unwrap();
        let storage = LocalStorage::new(dir.path().join("data"));
        let dedup = DedupTable::open(dir.path().join("catalog.db")).unwrap();
        let persister = FingerprintPersister::new(&storage, &keys, &catalog, &dedup, "snap-1", false);
        let fp = dummy_fingerprint();
        let hash = persister.persist_fingerprint(&fp).await.unwrap();

        // Tamper with the stored ciphertext using the sharded key.
        let key = sharded_key(&hash);
        let on_disk = storage.get(&key).await.unwrap();
        let mut bad = on_disk.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        storage.put(&key, &bad).await.unwrap();
        assert!(persister.load_fingerprint(&hash).await.is_err());
    }

    #[tokio::test]
    async fn storage_uses_sharded_key() {
        let dir = tempdir().unwrap();
        let (keys, _cfg) = KeyManager::init_repository("pw").unwrap();
        let catalog = CatalogIndex::new(dir.path().join("catalog.db")).unwrap();
        let storage = LocalStorage::new(dir.path().join("data"));
        let dedup = DedupTable::open(dir.path().join("catalog.db")).unwrap();
        let persister = FingerprintPersister::new(&storage, &keys, &catalog, &dedup, "snap-1", false);
        let fp = dummy_fingerprint();
        let hash = persister.persist_fingerprint(&fp).await.unwrap();

        // The bare key must not exist; the sharded key must.
        assert!(storage.get(&hash).await.is_err());
        let sharded = sharded_key(&hash);
        assert!(storage.get(&sharded).await.is_ok());
        // Verify the shard prefix matches the first two hex chars.
        assert!(sharded.starts_with(&format!("{}/", &hash[..2])));
    }
}
