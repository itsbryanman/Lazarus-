use super::snapshot_utils::encrypt_snapshot_metadata;
use clap::{ArgAction, Args};
use futures::{stream::FuturesUnordered, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use lazarus_core::catalog::index::{CatalogIndex, ObjectMetadata, ObjectType};
use lazarus_core::chunking::streaming::StreamingChunker;
use lazarus_core::compression::adaptive;
use lazarus_core::config::ConfigManager;
use lazarus_core::error::{LazarusError, Result};
use lazarus_core::security::ransomware::{DetectionEngine, DetectionVerdict};
use lazarus_core::snapshot::dedup::DedupTable;
use lazarus_core::storage::backend::{RetentionLock, StorageBackend};
use lazarus_core::storage::local::LocalStorage;
use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{fs, path::Path, time::SystemTime};
use tokio::io::BufReader;
use tokio::task;

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB

#[derive(Args)]
pub struct BackupArgs {
    #[arg(short, long, help = "Source file or directory to backup")]
    pub source: String,

    #[arg(short, long, help = "Repository path")]
    pub repository: String,

    #[arg(short, long, help = "Master password for encryption")]
    pub password: String,

    #[arg(
        long,
        help = "Ignore ransomware detection warnings and proceed anyway",
        action = ArgAction::SetTrue
    )]
    pub force: bool,
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
            if args.force {
                println!("Proceeding with backup due to --force override. Expect potential risk.");
            } else {
                return Err(LazarusError::VerificationFailed(
                    "Backup aborted due to ransomware indicators".into(),
                ));
            }
        }
    }

    let total_bytes = estimate_total_bytes(source_path)?;
    let progress = create_progress_bar(total_bytes, "Backing up");
    progress.println(format!("Source: {}", source_path.display()));

    // Create snapshot ID (timestamp-based)
    let snapshot_id = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Backup the source (file or directory)
    let lock_ref = retention_lock.as_ref();
    let mut chunk_set: HashSet<[u8; 32]> = HashSet::new();
    let root_object_id = if source_path.is_file() {
        backup_file(
            &key_manager,
            &catalog,
            &storage,
            source_path,
            lock_ref,
            &progress,
            &mut chunk_set,
        )
        .await?
    } else if source_path.is_dir() {
        backup_directory(
            &key_manager,
            &catalog,
            &storage,
            source_path,
            lock_ref,
            &progress,
            &mut chunk_set,
        )
        .await?
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
    let snapshot_metadata_blob =
        encrypt_snapshot_metadata(&key_manager, &snapshot_metadata.to_string())?;

    // Save snapshot to catalog
    catalog.create_snapshot(
        &snapshot_id,
        timestamp,
        root_object_id,
        &snapshot_metadata_blob,
    )?;

    // Record dedup references for every chunk this snapshot uses. The
    // DedupTable lives in the same SQLite DB as the catalog, so this is just
    // an extra batch insert per snapshot.
    let chunks: Vec<[u8; 32]> = chunk_set.into_iter().collect();
    let mut dedup = DedupTable::open(config_mgr.database_path())?;
    dedup.add_references_batch(&snapshot_id, &chunks)?;

    progress.finish_with_message("Backup completed successfully");
    println!("✓ Backup completed successfully!");
    println!("  Snapshot ID: {}", snapshot_id);

    let (chunks, objects, snapshots) = catalog.get_stats()?;
    println!("  Repository stats:");
    println!("    Chunks: {}", chunks);
    println!("    Objects: {}", objects);
    println!("    Snapshots: {}", snapshots);

    Ok(())
}

struct ChunkProcessingResult {
    order: usize,
    hash_hex: String,
    chunk_len: usize,
    stored_data: Vec<u8>,
}

fn spawn_chunk_processing(
    order: usize,
    chunk: Vec<u8>,
    key_manager: lazarus_core::encryption::key_manager::KeyManager,
) -> task::JoinHandle<Result<ChunkProcessingResult>> {
    task::spawn_blocking(move || {
        let chunk_hash = blake3::hash(&chunk);
        let hash_hex = chunk_hash.to_hex().to_string();

        let encoded_chunk = adaptive::encode_chunk(&chunk)?;
        let (encrypted_chunk, nonce) = key_manager.encrypt_data(&encoded_chunk)?;

        let mut stored_data = nonce;
        stored_data.extend_from_slice(&encrypted_chunk);

        Ok(ChunkProcessingResult {
            order,
            hash_hex,
            chunk_len: chunk.len(),
            stored_data,
        })
    })
}

async fn backup_file(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    file_path: &Path,
    retention: Option<&RetentionLock>,
    progress: &ProgressBar,
    chunk_set: &mut HashSet<[u8; 32]>,
) -> Result<i64> {
    progress.set_message(format!("Backing up {}", file_path.display()));
    progress.println(format!("Backing up file: {}", file_path.display()));

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

    let file = tokio::fs::File::open(file_path).await?;
    let reader = BufReader::new(file);
    let mut chunker = StreamingChunker::new(reader, CHUNK_SIZE);

    let pipeline_depth = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .max(2);

    let mut inflight: FuturesUnordered<_> = FuturesUnordered::new();
    let mut scheduled_chunks = 0usize;
    let mut eof = false;

    loop {
        while inflight.len() < pipeline_depth && !eof {
            match chunker.next_chunk().await? {
                Some(chunk) => {
                    let handle =
                        spawn_chunk_processing(scheduled_chunks, chunk, key_manager.clone());
                    inflight.push(handle);
                    scheduled_chunks += 1;
                }
                None => {
                    eof = true;
                }
            }
        }

        if inflight.is_empty() {
            break;
        }

        if let Some(result) = inflight.next().await {
            let processed = result
                .map_err(|e| LazarusError::Storage(format!("Chunk worker failed: {}", e)))??;
            handle_processed_chunk(
                processed,
                catalog,
                storage,
                file_object_id,
                retention,
                progress,
                chunk_set,
            )
            .await?;
        }
    }

    progress.println(format!(
        "  ✓ {} ({} chunks)",
        file_path.display(),
        scheduled_chunks
    ));

    Ok(file_object_id)
}

async fn handle_processed_chunk(
    chunk: ChunkProcessingResult,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    file_object_id: i64,
    retention: Option<&RetentionLock>,
    progress: &ProgressBar,
    chunk_set: &mut HashSet<[u8; 32]>,
) -> Result<()> {
    let ChunkProcessingResult {
        order,
        hash_hex,
        chunk_len,
        stored_data,
    } = chunk;

    if !catalog.chunk_exists(&hash_hex)? {
        let shard_dir = &hash_hex[..hash_hex.len().min(2)];
        storage
            .write_once(
                &format!("{}/{}", shard_dir, hash_hex),
                &stored_data,
                retention,
            )
            .await?;
        catalog.upsert_chunk(&hash_hex, stored_data.len(), chunk_len)?;
    }

    catalog.add_file_chunk(file_object_id, &hash_hex, order)?;
    if let Some(bytes) = hex_to_array(&hash_hex) {
        chunk_set.insert(bytes);
    }
    progress.inc(chunk_len as u64);

    Ok(())
}

fn hex_to_array(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

async fn backup_directory(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    dir_path: &Path,
    retention: Option<&RetentionLock>,
    progress: &ProgressBar,
    chunk_set: &mut HashSet<[u8; 32]>,
) -> Result<i64> {
    progress.set_message(format!("Scanning {}", dir_path.display()));
    progress.println(format!("Backing up directory: {}", dir_path.display()));

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
            backup_file(
                key_manager,
                catalog,
                storage,
                &entry_path,
                retention,
                progress,
                chunk_set,
            )
            .await?
        } else if entry_path.is_dir() {
            Box::pin(backup_directory(
                key_manager,
                catalog,
                storage,
                &entry_path,
                retention,
                progress,
                chunk_set,
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

    progress.println(format!("  ✓ {}/", dir_path.display()));

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
        mtime: system_time_to_unix(metadata.modified().unwrap_or_else(|_| SystemTime::now())),
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

fn estimate_total_bytes(path: &Path) -> Result<u64> {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        Ok(metadata.len())
    } else if metadata.is_dir() {
        let mut total = 0;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            total += estimate_total_bytes(&entry.path())?;
        }
        Ok(total)
    } else {
        Ok(0)
    }
}

fn create_progress_bar(total_bytes: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes.max(1));
    let style = ProgressStyle::with_template(
        "{spinner} {msg:<20} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
    )
    .unwrap()
    .progress_chars("=>-");
    pb.set_style(style);
    pb.set_message(message.to_string());
    pb
}
