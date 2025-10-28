use clap::Args;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
use lazarus_core::error::Result;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use aes_gcm::aead::{Aead, generic_array::GenericArray};

#[derive(Args)]
pub struct RestoreArgs {
    #[arg(short, long)]
    pub source: String,

    #[arg(short, long)]
    pub destination: String,

    #[arg(short, long)]
    pub repository: String,
}

pub async fn restore(args: &RestoreArgs) -> Result<()> {
    let storage = LocalStorage::new(&args.repository);
    let manifest_key = format!("{}.manifest", args.source);
    let manifest_data = storage.get(&manifest_key).await?;
    let manifest = String::from_utf8(manifest_data).unwrap();

    let key = GenericArray::from_slice(&[0u8; 32]);
    let cipher = Aes256Gcm::new(key);

    let mut data = Vec::new();
    for hash in manifest.lines() {
        let encrypted_chunk = storage.get(hash).await?;
        let nonce = GenericArray::from_slice(&[0u8; 12]); // NOT SECURE! 
        let compressed_chunk = cipher.decrypt(nonce, encrypted_chunk.as_ref()).unwrap();
        let chunk = zstd::decode_all(&compressed_chunk[..])?;
        data.extend_from_slice(&chunk);
    }

    tokio::fs::write(&args.destination, &data).await?;
    println!("Restore successful!");
    Ok(())
}
