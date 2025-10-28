use clap::Args;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
use lazarus_core::error::Result;
use lazarus_core::chunking::fixed_size::FixedSizeChunker;
use lazarus_core::config::ConfigManager;
use lazarus_core::catalog::index::{CatalogIndex, ObjectType, ObjectMetadata};
use std::path::Path;
use std::time::SystemTime;

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB

#[derive(Args)]
pub struct BackupArgs {
    #[arg(short, long, help = "Source file or directory to backup")]
    pub source: String,

    #[arg(short, long, help = "Repository path")]
    pub repository: String,

    #[arg(short, long, help = "Master password for encryption")]
    pub password: String,
}

pub async fn backup(args: &BackupArgs) -> Result<()> {
    println!("Starting backup...");

    // Open repository and unlock with password
    let config_mgr = ConfigManager::new(&args.repository);
    let key_manager = config_mgr.open_repository(&args.password).await?;

    // Open catalog database
    let catalog = CatalogIndex::new(config_mgr.database_path())?;

    // Initialize storage backend
    let storage = LocalStorage::new(config_mgr.data_path());

    // Get source path
    let source_path = Path::new(&args.source);

    // Create snapshot ID (timestamp-based)
    let snapshot_id = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Backup the source (file or directory)
    let root_object_id = if source_path.is_file() {
        backup_file(&key_manager, &catalog, &storage, source_path).await?
    } else if source_path.is_dir() {
        backup_directory(&key_manager, &catalog, &storage, source_path).await?
    } else {
        return Err(lazarus_core::error::LazarusError::Storage(
            "Source is neither a file nor a directory".to_string()
        ));
    };

    // Create snapshot metadata
    let snapshot_metadata = serde_json::json!({
        "source": args.source,
        "hostname": hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
    });
    let (encrypted_snapshot_metadata, _) = key_manager
        .encrypt_metadata(&snapshot_metadata.to_string())?;

    // Save snapshot to catalog
    catalog.create_snapshot(&snapshot_id, timestamp, root_object_id, &encrypted_snapshot_metadata)?;

    println!("✓ Backup completed successfully!");
    println!("  Snapshot ID: {}", snapshot_id);

    let (chunks, objects, snapshots) = catalog.get_stats()?;
    println!("  Repository stats:");
    println!("    Chunks: {}", chunks);
    println!("    Objects: {}", objects);
    println!("    Snapshots: {}", snapshots);

    Ok(())
}

async fn backup_file(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    file_path: &Path,
) -> Result<i64> {
    println!("Backing up file: {}", file_path.display());

    // Read file data
    let data = tokio::fs::read(file_path).await?;

    // Get file metadata
    let metadata = tokio::fs::metadata(file_path).await?;
    let file_metadata = ObjectMetadata {
        name: file_path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        mode: 0o644, // Default permissions
        size: metadata.len(),
        modified: metadata.modified()
            .unwrap_or(SystemTime::now())
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Encrypt metadata
    let metadata_json = serde_json::to_string(&file_metadata)
        .map_err(|e| lazarus_core::error::LazarusError::SerializationError(e.to_string()))?;
    let (encrypted_metadata, _) = key_manager.encrypt_metadata(&metadata_json)?;

    // Create object for file
    let file_object_id = catalog.create_object(ObjectType::File, &encrypted_metadata)?;

    // Chunk the file
    let chunker = FixedSizeChunker::new(&data, CHUNK_SIZE);
    let mut chunk_order = 0;

    for chunk in chunker {
        // Hash the uncompressed chunk
        let chunk_hash = blake3::hash(chunk);
        let hash_hex = chunk_hash.to_hex().to_string();

        // Check if chunk already exists (deduplication)
        if !catalog.chunk_exists(&hash_hex)? {
            // Compress the chunk
            let compressed_chunk = zstd::encode_all(chunk, 3)?;

            // Encrypt with unique nonce
            let (encrypted_chunk, nonce) = key_manager.encrypt_data(&compressed_chunk)?;

            // Store chunk with nonce prepended (first 12 bytes are nonce)
            let mut stored_data = nonce;
            stored_data.extend_from_slice(&encrypted_chunk);

            // Store to backend using hash-based sharding
            let shard_dir = &hash_hex[..2];
            storage.put(&format!("{}/{}", shard_dir, hash_hex), &stored_data).await?;

            // Record in catalog
            catalog.upsert_chunk(&hash_hex, stored_data.len(), chunk.len())?;
        }

        // Add chunk to file mapping
        catalog.add_file_chunk(file_object_id, &hash_hex, chunk_order)?;
        chunk_order += 1;
    }

    println!("  ✓ {} ({} chunks)", file_path.display(), chunk_order);

    Ok(file_object_id)
}

async fn backup_directory(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    dir_path: &Path,
) -> Result<i64> {
    println!("Backing up directory: {}", dir_path.display());

    // Create object for directory
    let metadata = tokio::fs::metadata(dir_path).await?;
    let dir_metadata = ObjectMetadata {
        name: dir_path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        mode: 0o755, // Default directory permissions
        size: 0,
        modified: metadata.modified()
            .unwrap_or(SystemTime::now())
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let metadata_json = serde_json::to_string(&dir_metadata)
        .map_err(|e| lazarus_core::error::LazarusError::SerializationError(e.to_string()))?;
    let (encrypted_metadata, _) = key_manager.encrypt_metadata(&metadata_json)?;

    let dir_object_id = catalog.create_object(ObjectType::Directory, &encrypted_metadata)?;

    // Walk directory entries
    let mut entries = tokio::fs::read_dir(dir_path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let entry_path = entry.path();
        let entry_name = entry.file_name().to_string_lossy().to_string();

        // Recursively backup child
        let child_object_id = if entry_path.is_file() {
            backup_file(key_manager, catalog, storage, &entry_path).await?
        } else if entry_path.is_dir() {
            Box::pin(backup_directory(key_manager, catalog, storage, &entry_path)).await?
        } else {
            continue; // Skip symlinks and other special files
        };

        // Encrypt the child name
        let (encrypted_name, nonce) = key_manager.encrypt_metadata(&entry_name)?;

        // Prepend nonce to encrypted name for storage
        let mut stored_name = nonce;
        stored_name.extend_from_slice(&encrypted_name);

        // Add to tree
        catalog.add_tree_entry(dir_object_id, child_object_id, &stored_name)?;
    }

    println!("  ✓ {}/", dir_path.display());

    Ok(dir_object_id)
}
