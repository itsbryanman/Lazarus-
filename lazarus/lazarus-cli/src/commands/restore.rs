use clap::Args;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
use lazarus_core::error::Result;
use lazarus_core::config::ConfigManager;
use lazarus_core::catalog::index::{CatalogIndex, ObjectType, ObjectMetadata};
use std::path::Path;

#[derive(Args)]
pub struct RestoreArgs {
    #[arg(short, long, help = "Snapshot ID to restore")]
    pub snapshot: String,

    #[arg(short, long, help = "Destination path for restore")]
    pub destination: String,

    #[arg(short, long, help = "Repository path")]
    pub repository: String,

    #[arg(short, long, help = "Master password for decryption")]
    pub password: String,
}

pub async fn restore(args: &RestoreArgs) -> Result<()> {
    println!("Starting restore...");

    // Open repository and unlock with password
    let config_mgr = ConfigManager::new(&args.repository);
    let key_manager = config_mgr.open_repository(&args.password).await?;

    // Open catalog database
    let catalog = CatalogIndex::new(config_mgr.database_path())?;

    // Initialize storage backend
    let storage = LocalStorage::new(config_mgr.data_path());

    // Get snapshot details
    let snapshot_data = catalog.get_snapshot(&args.snapshot)?
        .ok_or_else(|| lazarus_core::error::LazarusError::Storage(
            format!("Snapshot '{}' not found", args.snapshot)
        ))?;

    let (root_object_id, _encrypted_metadata) = snapshot_data;

    // Get root object
    let (obj_type, encrypted_obj_metadata) = catalog.get_object(root_object_id)?
        .ok_or_else(|| lazarus_core::error::LazarusError::Storage(
            "Root object not found".to_string()
        ))?;

    // Restore from root
    let dest_path = Path::new(&args.destination);
    match obj_type {
        ObjectType::File => {
            restore_file(&key_manager, &catalog, &storage, root_object_id, dest_path).await?;
        }
        ObjectType::Directory => {
            restore_directory(&key_manager, &catalog, &storage, root_object_id, dest_path).await?;
        }
    }

    println!("✓ Restore completed successfully!");

    Ok(())
}

async fn restore_file(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    file_object_id: i64,
    dest_path: &Path,
) -> Result<()> {
    // Get file chunks in order
    let chunk_hashes = catalog.get_file_chunks(file_object_id)?;

    let mut file_data = Vec::new();

    for hash in chunk_hashes {
        // Read chunk from storage
        let shard_dir = &hash[..2];
        let stored_data = storage.get(&format!("{}/{}", shard_dir, hash)).await?;

        // Extract nonce (first 12 bytes) and encrypted data
        if stored_data.len() < 12 {
            return Err(lazarus_core::error::LazarusError::EncryptionError(
                "Stored chunk too small".to_string()
            ));
        }

        let nonce = &stored_data[..12];
        let encrypted_chunk = &stored_data[12..];

        // Decrypt chunk
        let compressed_chunk = key_manager.decrypt_data(encrypted_chunk, nonce)?;

        // Decompress chunk
        let chunk = zstd::decode_all(&compressed_chunk[..])?;

        file_data.extend_from_slice(&chunk);
    }

    // Write to destination
    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(dest_path, &file_data).await?;

    println!("  ✓ Restored file: {}", dest_path.display());

    Ok(())
}

async fn restore_directory(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    dir_object_id: i64,
    dest_path: &Path,
) -> Result<()> {
    // Create destination directory
    tokio::fs::create_dir_all(dest_path).await?;

    println!("  ✓ Restored directory: {}/", dest_path.display());

    // Get children
    let children = catalog.get_tree_children(dir_object_id)?;

    for (child_id, encrypted_name) in children {
        // Decrypt child name
        // The encrypted_name contains both nonce and encrypted data
        // We need to split them similar to how we handle chunks
        if encrypted_name.len() < 12 {
            continue; // Skip invalid entries
        }

        let nonce = &encrypted_name[..12];
        let encrypted = &encrypted_name[12..];

        let child_name = key_manager.decrypt_metadata(encrypted, nonce)?;

        // Get child object
        let (child_type, _) = catalog.get_object(child_id)?
            .ok_or_else(|| lazarus_core::error::LazarusError::Storage(
                "Child object not found".to_string()
            ))?;

        // Build child path
        let child_path = dest_path.join(&child_name);

        // Recursively restore child
        match child_type {
            ObjectType::File => {
                restore_file(key_manager, catalog, storage, child_id, &child_path).await?;
            }
            ObjectType::Directory => {
                Box::pin(restore_directory(key_manager, catalog, storage, child_id, &child_path)).await?;
            }
        }
    }

    Ok(())
}
