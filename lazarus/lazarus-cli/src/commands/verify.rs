use super::snapshot_utils::decrypt_object_metadata;
use clap::Args;
use lazarus_core::catalog::index::CatalogIndex;
use lazarus_core::catalog::index::ObjectType;
use lazarus_core::compression::adaptive;
use lazarus_core::config::ConfigManager;
use lazarus_core::error::Result;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
use std::path::Path;

#[derive(Args)]
pub struct VerifyArgs {
    #[arg(short, long, help = "Repository path")]
    pub repository: String,

    #[arg(short, long, help = "Master password for decryption")]
    pub password: String,
}

pub async fn verify(args: &VerifyArgs) -> Result<()> {
    println!("Starting repository verification...\n");

    // Open repository
    let config_mgr = ConfigManager::new(&args.repository);
    let key_manager = config_mgr.open_repository(&args.password).await?;

    // Open catalog
    let catalog = CatalogIndex::new(config_mgr.database_path())?;

    // Initialize storage backend
    let storage = LocalStorage::new(Path::new(&args.repository).join("data"));

    // Get all chunk hashes from catalog
    let chunk_hashes = catalog.list_all_chunk_hashes()?;
    let total_chunks = chunk_hashes.len();

    println!("Found {} chunks in catalog", total_chunks);
    println!("Verifying integrity...\n");

    let mut missing_chunks = 0;
    let mut corrupted_chunks = 0;
    let mut verified_chunks = 0;
    let mut manifest_errors = 0;

    for (idx, hash) in chunk_hashes.iter().enumerate() {
        if (idx + 1) % 100 == 0 || idx == 0 {
            print!("\rProgress: {}/{} chunks verified", idx + 1, total_chunks);
            use std::io::Write;
            std::io::stdout().flush().unwrap();
        }

        // Build the storage key
        let shard_dir = &hash[..2];
        let key = format!("{}/{}", shard_dir, hash);

        // Try to retrieve the chunk
        let encrypted_data = match storage.get(&key).await {
            Ok(data) => data,
            Err(_) => {
                println!("\n  ERROR: Missing chunk: {}", hash);
                missing_chunks += 1;
                continue;
            }
        };

        // Verify the chunk integrity
        if encrypted_data.len() < 12 {
            println!("\n  ERROR: Corrupted chunk (too small): {}", hash);
            corrupted_chunks += 1;
            continue;
        }

        // Extract nonce (first 12 bytes)
        let nonce = &encrypted_data[..12];
        let ciphertext = &encrypted_data[12..];

        // Decrypt the chunk
        let encoded_data = match key_manager.decrypt_data(ciphertext, nonce) {
            Ok(data) => data,
            Err(e) => {
                println!("\n  ERROR: Failed to decrypt chunk {}: {}", hash, e);
                corrupted_chunks += 1;
                continue;
            }
        };

        // Decode the data (adaptive compression aware)
        let data = match adaptive::decode_chunk(&encoded_data) {
            Ok(data) => data,
            Err(e) => {
                println!("\n  ERROR: Failed to decompress chunk {}: {}", hash, e);
                corrupted_chunks += 1;
                continue;
            }
        };

        // Calculate hash and verify
        let calculated_hash = blake3::hash(&data);
        let calculated_hash_hex = calculated_hash.to_hex().to_string();

        if calculated_hash_hex != *hash {
            println!(
                "\n  ERROR: Hash mismatch for chunk {}:\n    Expected: {}\n    Got: {}",
                hash, hash, calculated_hash_hex
            );
            corrupted_chunks += 1;
            continue;
        }

        verified_chunks += 1;
    }

    for (snapshot_id, _) in catalog.list_snapshots()? {
        if let Some((root_object_id, _)) = catalog.get_snapshot(&snapshot_id)? {
            let mut visited = std::collections::HashSet::new();
            manifest_errors += verify_block_manifests(
                &catalog,
                &key_manager,
                root_object_id,
                &mut visited,
                &snapshot_id,
            )?;
        }
    }

    println!("\n\nVerification complete:");
    println!("  Total chunks:     {}", total_chunks);
    println!("  Verified:         {}", verified_chunks);
    println!("  Missing:          {}", missing_chunks);
    println!("  Corrupted:        {}", corrupted_chunks);
    println!("  Manifest errors:  {}", manifest_errors);

    if missing_chunks > 0 || corrupted_chunks > 0 || manifest_errors > 0 {
        println!("\n❌ Repository has integrity issues!");
        return Err(lazarus_core::error::LazarusError::VerificationFailed(
            format!(
                "{} missing, {} corrupted, {} manifest errors",
                missing_chunks, corrupted_chunks, manifest_errors
            ),
        ));
    } else {
        println!("\n✓ Repository integrity verified successfully!");
    }

    Ok(())
}

fn verify_block_manifests(
    catalog: &CatalogIndex,
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    object_id: i64,
    visited: &mut std::collections::HashSet<i64>,
    snapshot_id: &str,
) -> Result<usize> {
    if !visited.insert(object_id) {
        return Ok(0);
    }

    let Some((obj_type, metadata_blob)) = catalog.get_object(object_id)? else {
        return Ok(0);
    };

    match obj_type {
        ObjectType::File => Ok(0),
        ObjectType::Directory => {
            let mut errors = 0;
            for (child_id, _) in catalog.get_tree_children(object_id)? {
                errors +=
                    verify_block_manifests(catalog, key_manager, child_id, visited, snapshot_id)?;
            }
            Ok(errors)
        }
        ObjectType::BlockDevice => {
            let metadata = decrypt_object_metadata(key_manager, &metadata_blob)?;
            let layout = catalog.get_block_layout(object_id)?;
            let mut errors = 0;
            let mut allocated_total = 0u64;
            let mut last_extent_end = 0u64;
            for extent in &layout.extents {
                if extent.offset < last_extent_end {
                    println!(
                        "\n  ERROR: Snapshot {} block object {} has out-of-order extents",
                        snapshot_id, object_id
                    );
                    errors += 1;
                }
                let extent_end = extent.offset.saturating_add(extent.length);
                if extent_end > metadata.size {
                    println!(
                        "\n  ERROR: Snapshot {} block object {} extent {} exceeds device size",
                        snapshot_id, object_id, extent.extent_idx
                    );
                    errors += 1;
                }
                let chunk_total: u64 = extent.chunks.iter().map(|chunk| chunk.length).sum();
                if chunk_total != extent.length {
                    println!(
                        "\n  ERROR: Snapshot {} block object {} extent {} length mismatch",
                        snapshot_id, object_id, extent.extent_idx
                    );
                    errors += 1;
                }
                allocated_total = allocated_total.saturating_add(extent.length);
                last_extent_end = extent_end;
            }
            if allocated_total > metadata.size {
                println!(
                    "\n  ERROR: Snapshot {} block object {} allocated bytes exceed device size",
                    snapshot_id, object_id
                );
                errors += 1;
            }
            Ok(errors)
        }
    }
}
