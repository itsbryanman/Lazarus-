use clap::Args;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
use lazarus_core::error::Result;
use lazarus_core::chunking::fixed_size::FixedSizeChunker;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use aes_gcm::aead::{Aead, generic_array::GenericArray};

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB

#[derive(Args)]
pub struct BackupArgs {
    #[arg(short, long)]
    pub source: String,

    #[arg(short, long)]
    pub destination: String,
}

pub async fn backup(args: &BackupArgs) -> Result<()> {
    let storage = LocalStorage::new(&args.destination);
    let data = tokio::fs::read(&args.source).await?;

    let chunker = FixedSizeChunker::new(&data, CHUNK_SIZE);
    let mut chunk_hashes = Vec::new();

    let key = GenericArray::from_slice(&[0u8; 32]);
    let cipher = Aes256Gcm::new(key);

    for chunk in chunker {
        let compressed_chunk = zstd::encode_all(chunk, 3)?;
        let nonce = GenericArray::from_slice(&[0u8; 12]); // NOT SECURE! 
        let encrypted_chunk = cipher.encrypt(nonce, compressed_chunk.as_ref()).unwrap();

        let hash = blake3::hash(&encrypted_chunk);
        let hash_hex = hash.to_hex();
        storage.put(&hash_hex, &encrypted_chunk).await?;
        chunk_hashes.push(hash_hex.to_string());
    }

    let manifest = chunk_hashes.join("\n");
    let manifest_key = format!("{}.manifest", args.source);
    storage.put(&manifest_key, manifest.as_bytes()).await?;

    println!("Backup successful!");
    Ok(())
}
