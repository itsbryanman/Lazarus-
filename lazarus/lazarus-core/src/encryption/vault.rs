//! Encrypted credential vault for storage-backend secrets.
//!
//! Operators routinely need to give Lazarus an S3 access key, an SSH
//! passphrase, or similar. Storing those in plaintext config is a footgun, so
//! this module stores them in a small JSON file encrypted with the metadata
//! key. The vault file lives at `<repo>/vault.json` and uses AES-256-GCM with
//! a per-secret random nonce.

#![allow(deprecated)]

use crate::error::{LazarusError, Result};
use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const VAULT_FILE: &str = "vault.json";
const VAULT_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct VaultFile {
    version: u32,
    /// Map of `name -> (nonce, ciphertext)` (both base64-free; raw bytes
    /// because serde_json handles `Vec<u8>` as a JSON array).
    entries: BTreeMap<String, VaultEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct VaultEntry {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// In-memory handle for the vault. Holds the metadata key and lazily reads
/// the file when needed. The on-disk layout is stable and may be inspected
/// without the key (entry names are visible — they're chosen by the operator
/// and need to be human-readable so config can reference them).
pub struct Vault {
    path: PathBuf,
    key: [u8; 32],
}

impl Vault {
    /// Bind a vault to a repository directory. The metadata key from
    /// `KeyManager::get_metadata_key()` should be passed here.
    pub fn open<P: AsRef<Path>>(repo_path: P, metadata_key: [u8; 32]) -> Self {
        Self {
            path: repo_path.as_ref().join(VAULT_FILE),
            key: metadata_key,
        }
    }

    fn load(&self) -> Result<VaultFile> {
        if !self.path.exists() {
            return Ok(VaultFile {
                version: VAULT_VERSION,
                entries: BTreeMap::new(),
            });
        }
        let raw = fs::read_to_string(&self.path)?;
        let vf: VaultFile = serde_json::from_str(&raw)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        if vf.version != VAULT_VERSION {
            return Err(LazarusError::Storage(format!(
                "Unsupported vault version: {}",
                vf.version
            )));
        }
        Ok(vf)
    }

    fn save(&self, vf: &VaultFile) -> Result<()> {
        let json = serde_json::to_string_pretty(vf)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        // Atomic write: temp + rename.
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, json)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Insert or replace `name -> secret`.
    pub fn put_secret(&self, name: &str, secret: &[u8]) -> Result<()> {
        let mut vf = self.load()?;
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(GenericArray::from_slice(&nonce), secret)
            .map_err(|_| LazarusError::EncryptionError("Vault encrypt failed".into()))?;
        vf.entries.insert(
            name.to_string(),
            VaultEntry {
                nonce: nonce.to_vec(),
                ciphertext,
            },
        );
        self.save(&vf)
    }

    /// Retrieve a secret by name, returning `None` if absent.
    pub fn get_secret(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let vf = self.load()?;
        let Some(entry) = vf.entries.get(name) else {
            return Ok(None);
        };
        if entry.nonce.len() != 12 {
            return Err(LazarusError::EncryptionError(
                "Vault entry has invalid nonce length".into(),
            ));
        }
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        let pt = cipher
            .decrypt(
                GenericArray::from_slice(&entry.nonce),
                entry.ciphertext.as_ref(),
            )
            .map_err(|_| LazarusError::EncryptionError("Vault decrypt failed".into()))?;
        Ok(Some(pt))
    }

    /// Delete a secret. No-op if it doesn't exist.
    pub fn delete_secret(&self, name: &str) -> Result<()> {
        let mut vf = self.load()?;
        vf.entries.remove(name);
        self.save(&vf)
    }

    /// List all secret names. Names themselves are stored in plaintext.
    pub fn list_names(&self) -> Result<Vec<String>> {
        let vf = self.load()?;
        Ok(vf.entries.keys().cloned().collect())
    }

    /// Convenience: store/retrieve UTF-8 strings.
    pub fn put_secret_str(&self, name: &str, secret: &str) -> Result<()> {
        self.put_secret(name, secret.as_bytes())
    }
    pub fn get_secret_str(&self, name: &str) -> Result<Option<String>> {
        match self.get_secret(name)? {
            None => Ok(None),
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| LazarusError::EncryptionError("Vault entry not valid UTF-8".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn put_get_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open(dir.path(), key());
        v.put_secret_str("aws_access_key_id", "AKIA...").unwrap();
        assert_eq!(
            v.get_secret_str("aws_access_key_id").unwrap().unwrap(),
            "AKIA..."
        );
    }

    #[test]
    fn missing_secret_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open(dir.path(), key());
        assert!(v.get_secret_str("nope").unwrap().is_none());
    }

    #[test]
    fn delete_works() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open(dir.path(), key());
        v.put_secret_str("x", "1").unwrap();
        v.delete_secret("x").unwrap();
        assert!(v.get_secret("x").unwrap().is_none());
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open(dir.path(), key());
        v.put_secret_str("x", "secret").unwrap();
        let attacker = Vault::open(dir.path(), [0u8; 32]);
        assert!(attacker.get_secret("x").is_err());
    }

    #[test]
    fn list_names_visible() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open(dir.path(), key());
        v.put_secret_str("a", "1").unwrap();
        v.put_secret_str("b", "2").unwrap();
        let names = v.list_names().unwrap();
        assert!(names.contains(&"a".to_string()));
        assert!(names.contains(&"b".to_string()));
    }
}
