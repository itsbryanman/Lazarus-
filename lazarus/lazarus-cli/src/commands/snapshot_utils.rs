use lazarus_core::catalog::index::{CatalogIndex, ObjectMetadata, ObjectType};
use lazarus_core::encryption::key_manager::KeyManager;
use lazarus_core::error::{LazarusError, Result};
use serde::Deserialize;
use serde_json;
use std::collections::HashSet;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct SnapshotMetadataRecord {
    pub source: Option<String>,
    pub hostname: Option<String>,
}

/// Encrypt snapshot metadata so the nonce is stored alongside the ciphertext.
pub fn encrypt_snapshot_metadata(key_manager: &KeyManager, metadata_json: &str) -> Result<Vec<u8>> {
    let (encrypted, nonce) = key_manager.encrypt_metadata(metadata_json)?;
    let mut blob = nonce;
    blob.extend_from_slice(&encrypted);
    Ok(blob)
}

/// Attempt to parse snapshot metadata back into a strongly typed record.
pub fn parse_snapshot_metadata(
    key_manager: &KeyManager,
    blob: &[u8],
) -> Option<SnapshotMetadataRecord> {
    if blob.is_empty() {
        return None;
    }

    if blob.len() < 12 {
        return serde_json::from_slice(blob).ok();
    }

    let (nonce, encrypted) = blob.split_at(12);
    let json = key_manager.decrypt_metadata(encrypted, nonce).ok()?;
    serde_json::from_str(&json).ok()
}

pub fn decrypt_object_metadata(key_manager: &KeyManager, blob: &[u8]) -> Result<ObjectMetadata> {
    if blob.len() < 12 {
        let fallback = String::from_utf8(blob.to_vec())
            .map_err(|_| LazarusError::EncryptionError("Invalid metadata encoding".into()))?;
        return serde_json::from_str(&fallback)
            .map_err(|e| LazarusError::SerializationError(e.to_string()));
    }

    let (nonce, encrypted_metadata) = blob.split_at(12);
    let metadata_json = key_manager.decrypt_metadata(encrypted_metadata, nonce)?;
    serde_json::from_str(&metadata_json)
        .map_err(|e| LazarusError::SerializationError(e.to_string()))
}

pub fn calculate_snapshot_size(
    catalog: &CatalogIndex,
    key_manager: &KeyManager,
    root_id: i64,
) -> Result<u64> {
    let mut visited = HashSet::new();
    accumulate_snapshot_size(catalog, key_manager, root_id, &mut visited)
}

fn accumulate_snapshot_size(
    catalog: &CatalogIndex,
    key_manager: &KeyManager,
    object_id: i64,
    visited: &mut HashSet<i64>,
) -> Result<u64> {
    if !visited.insert(object_id) {
        return Ok(0);
    }

    let (obj_type, metadata_blob) = match catalog.get_object(object_id)? {
        Some(value) => value,
        None => return Ok(0),
    };
    let metadata = decrypt_object_metadata(key_manager, &metadata_blob)?;

    match obj_type {
        ObjectType::File => Ok(metadata.size),
        ObjectType::Directory => {
            let mut total = 0;
            for (child_id, _) in catalog.get_tree_children(object_id)? {
                total += accumulate_snapshot_size(catalog, key_manager, child_id, visited)?;
            }
            Ok(total)
        }
    }
}
