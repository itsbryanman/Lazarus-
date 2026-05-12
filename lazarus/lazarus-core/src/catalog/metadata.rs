//! Encrypted, lightweight snapshot metadata sidecar.
//!
//! `CatalogIndex` already stores small encrypted blobs alongside each
//! snapshot, but those are tightly coupled to the catalog DB and require
//! reading the snapshot table to access. The TUI / `lazarus list` paths often
//! want to display a snapshot summary (tags, description, custom retention)
//! quickly, ideally without holding open a SQLite connection or scanning the
//! chunk catalog.
//!
//! `MetadataStore` provides that: a single JSON file per repository, keyed by
//! snapshot id, with each value encrypted under the metadata key. The whole
//! file is small (one entry per snapshot) and can be reloaded in milliseconds.

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

const METADATA_FILE: &str = "snapshot_metadata.json";
const METADATA_VERSION: u32 = 1;

/// Operator-supplied metadata for a snapshot. Free-form fields are kept
/// optional so older clients reading newer files behave well.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// Tags such as `["weekly", "production", "db1"]`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional retention override in days; falls back to the repo policy if
    /// `None`.
    #[serde(default)]
    pub retention_days: Option<u32>,
    /// Source path the snapshot was taken from. Convenient for the list TUI.
    #[serde(default)]
    pub source: Option<String>,
    /// Hostname that took the snapshot.
    #[serde(default)]
    pub hostname: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct StoreFile {
    version: u32,
    entries: BTreeMap<String, MetadataEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MetadataEntry {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Lightweight handle around the encrypted snapshot-metadata file.
pub struct MetadataStore {
    path: PathBuf,
    key: [u8; 32],
}

impl MetadataStore {
    /// Bind to `<repo>/snapshot_metadata.json`. The metadata key from
    /// `KeyManager::get_metadata_key()` should be passed here.
    pub fn open<P: AsRef<Path>>(repo_path: P, metadata_key: [u8; 32]) -> Self {
        Self {
            path: repo_path.as_ref().join(METADATA_FILE),
            key: metadata_key,
        }
    }

    fn load(&self) -> Result<StoreFile> {
        if !self.path.exists() {
            return Ok(StoreFile {
                version: METADATA_VERSION,
                entries: BTreeMap::new(),
            });
        }
        let raw = fs::read_to_string(&self.path)?;
        let sf: StoreFile = serde_json::from_str(&raw)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        if sf.version != METADATA_VERSION {
            return Err(LazarusError::Storage(format!(
                "Unsupported metadata file version: {}",
                sf.version
            )));
        }
        Ok(sf)
    }

    fn save(&self, sf: &StoreFile) -> Result<()> {
        let json = serde_json::to_string_pretty(sf)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, json)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Insert or replace metadata for the given snapshot id.
    pub fn put(&self, snapshot_id: &str, meta: &SnapshotMetadata) -> Result<()> {
        let mut sf = self.load()?;
        let plaintext = serde_json::to_vec(meta)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(GenericArray::from_slice(&nonce), plaintext.as_ref())
            .map_err(|_| LazarusError::EncryptionError("Metadata encrypt failed".into()))?;
        sf.entries.insert(
            snapshot_id.to_string(),
            MetadataEntry {
                nonce: nonce.to_vec(),
                ciphertext: ct,
            },
        );
        self.save(&sf)
    }

    /// Retrieve metadata for the given snapshot id, or `None` if absent.
    pub fn get(&self, snapshot_id: &str) -> Result<Option<SnapshotMetadata>> {
        let sf = self.load()?;
        let Some(entry) = sf.entries.get(snapshot_id) else {
            return Ok(None);
        };
        if entry.nonce.len() != 12 {
            return Err(LazarusError::EncryptionError(
                "Metadata entry has invalid nonce length".into(),
            ));
        }
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        let pt = cipher
            .decrypt(
                GenericArray::from_slice(&entry.nonce),
                entry.ciphertext.as_ref(),
            )
            .map_err(|_| LazarusError::EncryptionError("Metadata decrypt failed".into()))?;
        let meta: SnapshotMetadata = serde_json::from_slice(&pt)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        Ok(Some(meta))
    }

    /// Remove the metadata entry for a snapshot id.
    pub fn delete(&self, snapshot_id: &str) -> Result<()> {
        let mut sf = self.load()?;
        sf.entries.remove(snapshot_id);
        self.save(&sf)
    }

    /// All snapshot ids currently tracked. Decrypts nothing.
    pub fn ids(&self) -> Result<Vec<String>> {
        let sf = self.load()?;
        Ok(sf.entries.keys().cloned().collect())
    }

    /// Bulk-load all entries (one decrypt per entry). Suitable for the TUI
    /// list path; do not call from hot loops over millions of snapshots.
    pub fn load_all(&self) -> Result<BTreeMap<String, SnapshotMetadata>> {
        let sf = self.load()?;
        let mut out = BTreeMap::new();
        for id in sf.entries.keys() {
            if let Some(meta) = self.get(id)? {
                out.insert(id.clone(), meta);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> [u8; 32] {
        [3u8; 32]
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = MetadataStore::open(dir.path(), k());
        let meta = SnapshotMetadata {
            tags: vec!["nightly".into(), "db".into()],
            description: Some("Tuesday backup".into()),
            retention_days: Some(60),
            source: Some("/var/lib/postgresql".into()),
            hostname: Some("db-1".into()),
        };
        store.put("snap-1", &meta).unwrap();
        let got = store.get("snap-1").unwrap().unwrap();
        assert_eq!(got, meta);
    }

    #[test]
    fn missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = MetadataStore::open(dir.path(), k());
        assert!(store.get("nope").unwrap().is_none());
    }

    #[test]
    fn delete_removes_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = MetadataStore::open(dir.path(), k());
        store.put("s", &SnapshotMetadata::default()).unwrap();
        store.delete("s").unwrap();
        assert!(store.get("s").unwrap().is_none());
    }

    #[test]
    fn wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = MetadataStore::open(dir.path(), k());
        store.put("s", &SnapshotMetadata::default()).unwrap();
        let attacker = MetadataStore::open(dir.path(), [0u8; 32]);
        assert!(attacker.get("s").is_err());
    }

    #[test]
    fn load_all_returns_every_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = MetadataStore::open(dir.path(), k());
        for i in 0..3 {
            let mut m = SnapshotMetadata::default();
            m.tags.push(format!("t{}", i));
            store.put(&format!("snap-{}", i), &m).unwrap();
        }
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.contains_key("snap-0"));
        assert!(all.contains_key("snap-1"));
        assert!(all.contains_key("snap-2"));
    }
}
