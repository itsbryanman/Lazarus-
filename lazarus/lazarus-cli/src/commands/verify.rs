use clap::Args;
use lazarus_core::config::ConfigManager;
use lazarus_core::catalog::index::CatalogIndex;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
use lazarus_core::error::Result;
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
        let compressed_data = match key_manager.decrypt_data(ciphertext, nonce) {
            Ok(data) => data,
            Err(e) => {
                println!("\n  ERROR: Failed to decrypt chunk {}: {}", hash, e);
                corrupted_chunks += 1;
                continue;
            }
        };

        // Decompress the data
        let data = match zstd::decode_all(&compressed_data[..]) {
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

    println!("\n\nVerification complete:");
    println!("  Total chunks:     {}", total_chunks);
    println!("  Verified:         {}", verified_chunks);
    println!("  Missing:          {}", missing_chunks);
    println!("  Corrupted:        {}", corrupted_chunks);

    if missing_chunks > 0 || corrupted_chunks > 0 {
        println!("\n❌ Repository has integrity issues!");
        return Err(lazarus_core::error::LazarusError::VerificationFailed(
            format!("{} missing, {} corrupted", missing_chunks, corrupted_chunks)
        ));
    } else {
        println!("\n✓ Repository integrity verified successfully!");
    }

    Ok(())
}
