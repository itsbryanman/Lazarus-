use clap::Args;
use lazarus_core::catalog::index::{CatalogIndex, ObjectMetadata, ObjectType};
use lazarus_core::chunking::fixed_size::FixedSizeChunker;
use lazarus_core::compression::adaptive;
use lazarus_core::config::ConfigManager;
use lazarus_core::error::{LazarusError, Result};
use lazarus_core::security::ransomware::{DetectionEngine, DetectionVerdict};
use lazarus_core::storage::backend::{RetentionLock, StorageBackend};
use lazarus_core::storage::local::LocalStorage;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
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

    let retention_policy = config_mgr.load_retention_policy().await?;
    let retention_lock = retention_policy.as_lock();
    if retention_lock.is_some() {
        println!(
            "Immutable retention policy active (mode: {:?}, minimum {} days)",
            retention_policy.mode, retention_policy.min_retention_days
        );
    }

    // Get source path
    let source_path = Path::new(&args.source);

    let detection_engine = DetectionEngine::new(config_mgr.repo_path());
    let detection_report = detection_engine
        .analyze_paths(&[source_path.to_path_buf()])
        .await?;

    match detection_report.verdict {
        DetectionVerdict::Clean => {
            println!(
                "Ransomware pre-check passed. Trust score: {:.0}%",
                detection_report.trust.score * 100.0
            );
            if let Some(rec) = detection_report.trust.recommendation {
                println!("  Advisory: {}", rec);
            }
        }
        DetectionVerdict::Suspicious => {
            println!("⚠️  Suspicious activity detected prior to backup!");
            for anomaly in &detection_report.anomalies {
                println!("  - {:?}", anomaly);
            }
            return Err(LazarusError::VerificationFailed(
                "Backup aborted due to ransomware indicators".into(),
            ));
        }
    }

    // Create snapshot ID (timestamp-based)
    let snapshot_id = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Backup the source (file or directory)
    let lock_ref = retention_lock.as_ref();
    let root_object_id = if source_path.is_file() {
        backup_file(&key_manager, &catalog, &storage, source_path, lock_ref).await?
    } else if source_path.is_dir() {
        backup_directory(&key_manager, &catalog, &storage, source_path, lock_ref).await?
    } else {
        return Err(lazarus_core::error::LazarusError::Storage(
            "Source is neither a file nor a directory".to_string(),
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
    let (encrypted_snapshot_metadata, _) =
        key_manager.encrypt_metadata(&snapshot_metadata.to_string())?;

    // Save snapshot to catalog
    catalog.create_snapshot(
        &snapshot_id,
        timestamp,
        root_object_id,
        &encrypted_snapshot_metadata,
    )?;

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
    retention: Option<&RetentionLock>,
) -> Result<i64> {
    println!("Backing up file: {}", file_path.display());

    // Read file data
    let data = tokio::fs::read(file_path).await?;

    // Get file metadata
    let metadata = tokio::fs::metadata(file_path).await?;
    let file_metadata = build_object_metadata(
        file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        &metadata,
        false,
    );

    // Encrypt metadata (nonce prepended)
    let metadata_blob = serialize_and_encrypt_metadata(key_manager, &file_metadata)?;

    // Create object for file
    let file_object_id = catalog.create_object(ObjectType::File, &metadata_blob)?;

    // Chunk the file
    let chunker = FixedSizeChunker::new(&data, CHUNK_SIZE);
    let mut chunk_order = 0;

    for chunk in chunker {
        // Hash the uncompressed chunk
        let chunk_hash = blake3::hash(chunk);
        let hash_hex = chunk_hash.to_hex().to_string();

        // Check if chunk already exists (deduplication)
        if !catalog.chunk_exists(&hash_hex)? {
            // Encode chunk with adaptive compression + header
            let encoded_chunk = adaptive::encode_chunk(chunk)?;

            // Encrypt with unique nonce
            let (encrypted_chunk, nonce) = key_manager.encrypt_data(&encoded_chunk)?;

            // Store chunk with nonce prepended (first 12 bytes are nonce)
            let mut stored_data = nonce;
            stored_data.extend_from_slice(&encrypted_chunk);

            // Store to backend using hash-based sharding
            let shard_dir = &hash_hex[..2];
            storage
                .write_once(
                    &format!("{}/{}", shard_dir, hash_hex),
                    &stored_data,
                    retention,
                )
                .await?;

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
    retention: Option<&RetentionLock>,
) -> Result<i64> {
    println!("Backing up directory: {}", dir_path.display());

    // Create object for directory
    let metadata = tokio::fs::metadata(dir_path).await?;
    let dir_metadata = build_object_metadata(
        dir_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        &metadata,
        true,
    );

    let metadata_blob = serialize_and_encrypt_metadata(key_manager, &dir_metadata)?;

    let dir_object_id = catalog.create_object(ObjectType::Directory, &metadata_blob)?;

    // Walk directory entries
    let mut entries = tokio::fs::read_dir(dir_path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let entry_path = entry.path();
        let entry_name = entry.file_name().to_string_lossy().to_string();

        // Recursively backup child
        let child_object_id = if entry_path.is_file() {
            backup_file(key_manager, catalog, storage, &entry_path, retention).await?
        } else if entry_path.is_dir() {
            Box::pin(backup_directory(
                key_manager,
                catalog,
                storage,
                &entry_path,
                retention,
            ))
            .await?
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

fn build_object_metadata(
    name: String,
    metadata: &std::fs::Metadata,
    is_dir: bool,
) -> ObjectMetadata {
    let (uid, gid, mode) = capture_platform_metadata(metadata, is_dir);
    ObjectMetadata {
        name,
        mode,
        size: if is_dir { 0 } else { metadata.len() },
        modified: system_time_to_unix(metadata.modified().unwrap_or_else(|_| SystemTime::now())),
        uid,
        gid,
    }
}

fn serialize_and_encrypt_metadata(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    metadata: &ObjectMetadata,
) -> Result<Vec<u8>> {
    let metadata_json = serde_json::to_string(metadata)
        .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
    let (encrypted_metadata, nonce) = key_manager.encrypt_metadata(&metadata_json)?;
    let mut stored_metadata = nonce;
    stored_metadata.extend_from_slice(&encrypted_metadata);
    Ok(stored_metadata)
}

fn system_time_to_unix(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}

#[cfg(unix)]
fn capture_platform_metadata(metadata: &std::fs::Metadata, _is_dir: bool) -> (u32, u32, u32) {
    (metadata.uid(), metadata.gid(), metadata.mode())
}

#[cfg(not(unix))]
fn capture_platform_metadata(_metadata: &std::fs::Metadata, is_dir: bool) -> (u32, u32, u32) {
    (0, 0, if is_dir { 0o755 } else { 0o644 })
}
