use clap::Parser;
use filetime::{set_file_times, FileTime};
use lazarus_common::lazarus::agent::{
    agent_service_client::AgentServiceClient, chunk_service_client::ChunkServiceClient,
    ChunkDownloadRequest, ChunkHash, ChunkUpload, GetJobsRequest, HeartbeatRequest,
    JobCompletionRequest, JobStatistics, JobType, ProgressUpdate, RegisterRequest,
};
use lazarus_core::catalog::index::{CatalogIndex, ObjectMetadata, ObjectType};
use lazarus_core::chunking::cdc::CdcChunker;
use lazarus_core::compression::adaptive;
use lazarus_core::config::ConfigManager;
use lazarus_core::error::LazarusError;
use lazarus_core::security::ransomware::{DetectionEngine, DetectionVerdict};
use lazarus_core::snapshot::dedup::DedupTable;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
use std::convert::TryFrom;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::SystemTime,
};
#[cfg(unix)]
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::PermissionsExt},
};
use tokio::time::{interval, sleep, Duration};
use tonic::Request;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(author, version, about = "Lazarus Backup Agent", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "http://localhost:50051")]
    server: String,

    #[arg(short, long)]
    repository: String,

    #[arg(short, long)]
    password: String,

    #[arg(long, default_value = "30")]
    heartbeat_interval: u64,

    #[arg(long, default_value = "10")]
    poll_interval: u64,
}

struct Agent {
    agent_id: String,
    server_address: String,
    repository: String,
    password: String,
    heartbeat_interval: Duration,
    poll_interval: Duration,
}

impl Agent {
    fn new(cli: Cli) -> Self {
        let agent_id = format!("agent-{}", uuid::Uuid::new_v4());

        Self {
            agent_id,
            server_address: cli.server,
            repository: cli.repository,
            password: cli.password,
            heartbeat_interval: Duration::from_secs(cli.heartbeat_interval),
            poll_interval: Duration::from_secs(cli.poll_interval),
        }
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting Lazarus Agent");
        info!("Agent ID: {}", self.agent_id);
        info!("Server: {}", self.server_address);

        // Connect to server
        let mut agent_client = AgentServiceClient::connect(self.server_address.clone()).await?;
        let chunk_client = ChunkServiceClient::connect(self.server_address.clone()).await?;

        // Register with server
        self.register(&mut agent_client).await?;

        // Spawn heartbeat task
        let heartbeat_agent_id = self.agent_id.clone();
        let heartbeat_server = self.server_address.clone();
        let heartbeat_interval = self.heartbeat_interval;
        tokio::spawn(async move {
            if let Err(e) =
                run_heartbeat_loop(heartbeat_agent_id, heartbeat_server, heartbeat_interval).await
            {
                error!("Heartbeat loop failed: {}", e);
            }
        });

        // Main job polling loop
        self.job_loop(agent_client, chunk_client).await?;

        Ok(())
    }

    async fn register(
        &self,
        client: &mut AgentServiceClient<tonic::transport::Channel>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Registering with server...");

        let request = Request::new(RegisterRequest {
            agent_id: self.agent_id.clone(),
            hostname: hostname::get()?.to_string_lossy().to_string(),
            os_type: std::env::consts::OS.to_string(),
            os_version: "unknown".to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            metadata: HashMap::new(),
        });

        let response = client.register_agent(request).await?;
        let register_response = response.into_inner();

        if register_response.success {
            info!("Successfully registered with server");
            info!("Server version: {}", register_response.server_version);
        } else {
            error!("Failed to register: {}", register_response.message);
        }

        Ok(())
    }

    async fn job_loop(
        &self,
        mut agent_client: AgentServiceClient<tonic::transport::Channel>,
        chunk_client: ChunkServiceClient<tonic::transport::Channel>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut poll_timer = interval(self.poll_interval);

        loop {
            poll_timer.tick().await;

            // Poll for jobs
            let request = Request::new(GetJobsRequest {
                agent_id: self.agent_id.clone(),
            });

            match agent_client.get_jobs(request).await {
                Ok(response) => {
                    let jobs_response = response.into_inner();

                    for job in jobs_response.jobs {
                        info!("Received job: {} (type: {:?})", job.job_id, job.job_type);

                        // Execute the job
                        if let Err(e) = self
                            .execute_job(
                                &job.job_id,
                                job.job_type,
                                &job.parameters,
                                &mut agent_client,
                                &chunk_client,
                            )
                            .await
                        {
                            error!("Job {} failed: {}", job.job_id, e);
                            // Report failure
                            let _ = agent_client
                                .complete_job(Request::new(JobCompletionRequest {
                                    agent_id: self.agent_id.clone(),
                                    job_id: job.job_id.clone(),
                                    success: false,
                                    error_message: format!("Job failed: {}", e),
                                    completion_time: chrono::Utc::now().timestamp(),
                                    statistics: None,
                                }))
                                .await;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to poll for jobs: {}", e);
                }
            }
        }
    }

    async fn execute_job(
        &self,
        job_id: &str,
        job_type_code: i32,
        parameters: &HashMap<String, String>,
        agent_client: &mut AgentServiceClient<tonic::transport::Channel>,
        chunk_client: &ChunkServiceClient<tonic::transport::Channel>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Start the job
        let start_request = Request::new(tokio_stream::once(ProgressUpdate {
            agent_id: self.agent_id.clone(),
            job_id: job_id.to_string(),
            progress_percent: 0,
            status_message: "Starting job".to_string(),
            bytes_processed: 0,
            total_bytes: 0,
        }));
        agent_client.report_progress(start_request).await?;

        let job_type = JobType::try_from(job_type_code)
            .map_err(|_| format!("Unknown job type: {}", job_type_code))?;

        match job_type {
            JobType::Backup => {
                let source = parameters
                    .get("source")
                    .ok_or("Missing 'source' parameter")?;
                self.perform_backup(job_id, source, agent_client, chunk_client)
                    .await?;
            }
            JobType::Restore => {
                self.perform_restore(job_id, parameters, agent_client, chunk_client)
                    .await?;
            }
            JobType::Prune => {
                self.perform_prune(job_id, parameters, agent_client).await?;
            }
            JobType::Verify => {
                self.perform_verify(job_id, agent_client).await?;
            }
        }

        // Complete the job
        let stats = JobStatistics {
            bytes_processed: 0,
            files_processed: 0,
            chunks_created: 0,
            chunks_deduplicated: 0,
            duration_seconds: 0,
        };

        let complete_request = Request::new(JobCompletionRequest {
            agent_id: self.agent_id.clone(),
            job_id: job_id.to_string(),
            success: true,
            error_message: String::new(),
            completion_time: chrono::Utc::now().timestamp(),
            statistics: Some(stats),
        });
        agent_client.complete_job(complete_request).await?;

        Ok(())
    }

    async fn perform_backup(
        &self,
        job_id: &str,
        source_path: &str,
        agent_client: &mut AgentServiceClient<tonic::transport::Channel>,
        chunk_client: &ChunkServiceClient<tonic::transport::Channel>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Performing backup of: {}", source_path);

        // Open repository
        let config_mgr = ConfigManager::new(&self.repository);
        let key_manager = config_mgr.open_repository(&self.password).await?;
        let catalog = CatalogIndex::new(config_mgr.database_path())?;

        // Run ransomware detection before touching data
        let detection_engine = DetectionEngine::new(config_mgr.repo_path());
        let report = detection_engine
            .analyze_paths(&[Path::new(source_path).to_path_buf()])
            .await?;
        if matches!(report.verdict, DetectionVerdict::Suspicious) {
            warn!("Ransomware indicators detected. Aborting backup.");
            for anomaly in report.anomalies {
                warn!("  {:?}", anomaly);
            }
            return Err("Security Alert: Ransomware detected".into());
        }

        // Process the file/directory
        let source = Path::new(source_path);
        if !source.exists() {
            return Err(format!("Source path does not exist: {}", source_path).into());
        }

        if source.is_file() {
            self.backup_file(
                source,
                job_id,
                &key_manager,
                &catalog,
                agent_client,
                chunk_client,
            )
            .await?;
        } else {
            // For simplicity, we'll just backup files in the directory (non-recursive)
            // A full implementation would handle directories recursively
            for entry in std::fs::read_dir(source)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    self.backup_file(
                        &path,
                        job_id,
                        &key_manager,
                        &catalog,
                        agent_client,
                        chunk_client,
                    )
                    .await?;
                }
            }
        }

        info!("Backup completed successfully");
        Ok(())
    }

    async fn perform_restore(
        &self,
        job_id: &str,
        parameters: &HashMap<String, String>,
        agent_client: &mut AgentServiceClient<tonic::transport::Channel>,
        chunk_client: &ChunkServiceClient<tonic::transport::Channel>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot_id = parameters
            .get("snapshot_id")
            .ok_or("Missing 'snapshot_id' parameter")?;
        let destination = parameters
            .get("destination")
            .ok_or("Missing 'destination' parameter")?;
        let dest_path = PathBuf::from(destination);

        let config_mgr = ConfigManager::new(&self.repository);
        let key_manager = config_mgr.open_repository(&self.password).await?;
        let catalog = CatalogIndex::new(config_mgr.database_path())?;

        let (root_object_id, _) = catalog
            .get_snapshot(snapshot_id)?
            .ok_or_else(|| format!("Snapshot '{}' not found", snapshot_id))?;

        let (total_files, total_bytes) =
            estimate_restore_metrics(&catalog, &key_manager, root_object_id)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let mut progress_tracker = RestoreProgress::new(total_files, total_bytes);

        let progress_request = Request::new(tokio_stream::once(ProgressUpdate {
            agent_id: self.agent_id.clone(),
            job_id: job_id.to_string(),
            progress_percent: 0,
            status_message: format!(
                "Restoring snapshot {} to {}",
                snapshot_id,
                dest_path.display()
            ),
            bytes_processed: 0,
            total_bytes: (total_bytes.min(i64::MAX as u64)) as i64,
        }));
        agent_client.report_progress(progress_request).await?;

        let (root_type, root_metadata_blob) = catalog
            .get_object(root_object_id)?
            .ok_or_else(|| "Root object not found".to_string())?;
        let root_metadata = decrypt_object_metadata(&key_manager, &root_metadata_blob)?;

        match root_type {
            ObjectType::File | ObjectType::BlockDevice => {
                restore_file(
                    &key_manager,
                    &catalog,
                    chunk_client,
                    agent_client,
                    &self.agent_id,
                    job_id,
                    root_object_id,
                    root_metadata,
                    &dest_path,
                    &mut progress_tracker,
                )
                .await?;
            }
            ObjectType::Directory => {
                restore_directory(
                    &key_manager,
                    &catalog,
                    chunk_client,
                    agent_client,
                    &self.agent_id,
                    job_id,
                    root_object_id,
                    root_metadata,
                    &dest_path,
                    &mut progress_tracker,
                )
                .await?;
            }
            ObjectType::SystemFingerprint => {
                return Err("this snapshot's root object is a SystemFingerprint; restore it from the recovery environment, not the agent".into());
            }
        }

        let (percent, processed_bytes, total_bytes) = progress_tracker.finalize();
        let final_request = Request::new(tokio_stream::once(ProgressUpdate {
            agent_id: self.agent_id.clone(),
            job_id: job_id.to_string(),
            progress_percent: percent,
            status_message: format!(
                "Snapshot {} restored successfully at {}",
                snapshot_id,
                dest_path.display()
            ),
            bytes_processed: processed_bytes.min(i64::MAX as u64) as i64,
            total_bytes: total_bytes.min(i64::MAX as u64) as i64,
        }));
        agent_client.report_progress(final_request).await?;

        info!(
            "Snapshot {} restored successfully at {}",
            snapshot_id,
            dest_path.display()
        );
        Ok(())
    }

    async fn perform_verify(
        &self,
        job_id: &str,
        agent_client: &mut AgentServiceClient<tonic::transport::Channel>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config_mgr = ConfigManager::new(&self.repository);
        let key_manager = config_mgr.open_repository(&self.password).await?;
        let catalog = CatalogIndex::new(config_mgr.database_path())?;
        let storage = LocalStorage::new(config_mgr.data_path());

        let progress_request = Request::new(tokio_stream::once(ProgressUpdate {
            agent_id: self.agent_id.clone(),
            job_id: job_id.to_string(),
            progress_percent: 0,
            status_message: "Verifying repository chunks".to_string(),
            bytes_processed: 0,
            total_bytes: 0,
        }));
        agent_client.report_progress(progress_request).await?;

        let chunk_hashes = catalog.list_all_chunk_hashes()?;
        let total_chunks = chunk_hashes.len();
        info!("Verifying {} chunks", total_chunks);

        let mut missing_chunks = 0usize;
        let mut corrupted_chunks = 0usize;

        for (idx, hash) in chunk_hashes.iter().enumerate() {
            let shard_dir = &hash[..2];
            let key = format!("{}/{}", shard_dir, hash);

            let encrypted_data = match storage.get(&key).await {
                Ok(data) => data,
                Err(_) => {
                    missing_chunks += 1;
                    warn!("Missing chunk {}", hash);
                    continue;
                }
            };

            if encrypted_data.len() < 12 {
                corrupted_chunks += 1;
                warn!("Chunk {} is truncated", hash);
                continue;
            }

            let nonce = &encrypted_data[..12];
            let encrypted_chunk = &encrypted_data[12..];

            let encoded_chunk = match key_manager.decrypt_data(encrypted_chunk, nonce) {
                Ok(data) => data,
                Err(e) => {
                    corrupted_chunks += 1;
                    warn!("Failed to decrypt chunk {}: {}", hash, e);
                    continue;
                }
            };

            let chunk = match adaptive::decode_chunk(&encoded_chunk) {
                Ok(data) => data,
                Err(e) => {
                    corrupted_chunks += 1;
                    warn!("Failed to decode chunk {}: {}", hash, e);
                    continue;
                }
            };

            let calculated_hash = blake3::hash(&chunk).to_hex().to_string();
            if calculated_hash != *hash {
                corrupted_chunks += 1;
                warn!(
                    "Hash mismatch for chunk {} (expected {}, got {})",
                    hash, hash, calculated_hash
                );
            }

            if (idx + 1) % 250 == 0 {
                info!("Verified {}/{} chunks", idx + 1, total_chunks);
            }
        }

        if missing_chunks > 0 || corrupted_chunks > 0 {
            return Err(LazarusError::VerificationFailed(format!(
                "{} missing, {} corrupted",
                missing_chunks, corrupted_chunks
            ))
            .into());
        }

        info!("Repository verification completed successfully");
        Ok(())
    }

    async fn perform_prune(
        &self,
        job_id: &str,
        parameters: &HashMap<String, String>,
        agent_client: &mut AgentServiceClient<tonic::transport::Channel>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let keep_last = parameters
            .get("keep_last")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(5);
        let keep_days = parameters
            .get("keep_days")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);
        let dry_run = parameters
            .get("dry_run")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let config_mgr = ConfigManager::new(&self.repository);
        let catalog = CatalogIndex::new(config_mgr.database_path())?;
        let storage = LocalStorage::new(config_mgr.data_path());
        // Open the DedupTable to protect fingerprint chunks that still
        // have live references. Full ref-removal parity with the CLI
        // prune can be a follow-up; for now we only protect.
        // TODO(phase-4): full dedup ref removal in agent prune
        let dedup = DedupTable::open(config_mgr.database_path())?;

        let progress_request = Request::new(tokio_stream::once(ProgressUpdate {
            agent_id: self.agent_id.clone(),
            job_id: job_id.to_string(),
            progress_percent: 0,
            status_message: "Pruning unreferenced chunks".to_string(),
            bytes_processed: 0,
            total_bytes: 0,
        }));
        agent_client.report_progress(progress_request).await?;

        let snapshots = catalog.list_snapshots()?;
        if snapshots.is_empty() {
            info!("No snapshots found; nothing to prune");
            return Ok(());
        }

        let keep_snapshots = select_snapshots_to_keep(&snapshots, keep_last, keep_days);
        info!(
            "Retention will keep {}/{} snapshots",
            keep_snapshots.len(),
            snapshots.len()
        );

        let mut active_chunks = HashSet::new();
        let mut visited_objects = HashSet::new();
        for snapshot_id in &keep_snapshots {
            if let Some((root_object_id, _)) = catalog.get_snapshot(snapshot_id)? {
                mark_object_chunks(
                    &catalog,
                    root_object_id,
                    &mut visited_objects,
                    &mut active_chunks,
                )?;
            }
        }

        let all_chunks = catalog.list_all_chunk_hashes()?;
        let reclaimable: Vec<String> = all_chunks
            .into_iter()
            .filter(|hash| {
                if active_chunks.contains(hash) {
                    return false;
                }
                // Protect chunks that still have dedup references
                // (e.g. fingerprint chunks from --capture-system).
                if hash.len() == 64 {
                    let mut bytes = [0u8; 32];
                    let mut valid = true;
                    for i in 0..32 {
                        match u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16) {
                            Ok(b) => bytes[i] = b,
                            Err(_) => {
                                valid = false;
                                break;
                            }
                        }
                    }
                    if valid && dedup.refcount(&bytes).unwrap_or(0) > 0 {
                        return false;
                    }
                }
                true
            })
            .collect();

        if reclaimable.is_empty() {
            info!("All chunks are still referenced; nothing to prune");
            return Ok(());
        }

        if dry_run {
            for hash in &reclaimable {
                info!("Dry run: would delete chunk {}", hash);
            }
            return Ok(());
        }

        let mut removed = 0usize;
        for hash in reclaimable {
            let shard = &hash[..2];
            let key = format!("{}/{}", shard, hash);

            match storage.delete(&key).await {
                Ok(_) => {
                    catalog.delete_file_chunks_by_hash(&hash)?;
                    catalog.delete_chunk(&hash)?;
                    removed += 1;
                    info!("Deleted chunk {}", hash);
                }
                Err(err) => {
                    warn!("Failed to delete chunk {} from storage: {}", hash, err);
                }
            }
        }

        info!("Prune complete. Removed {} chunk(s)", removed);
        Ok(())
    }

    async fn backup_file(
        &self,
        file_path: &Path,
        job_id: &str,
        key_manager: &lazarus_core::encryption::key_manager::KeyManager,
        catalog: &CatalogIndex,
        agent_client: &mut AgentServiceClient<tonic::transport::Channel>,
        chunk_client: &ChunkServiceClient<tonic::transport::Channel>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Backing up file: {}", file_path.display());

        // Report progress
        let progress_request = Request::new(tokio_stream::once(ProgressUpdate {
            agent_id: self.agent_id.clone(),
            job_id: job_id.to_string(),
            progress_percent: 0,
            status_message: format!("Processing file: {}", file_path.display()),
            bytes_processed: 0,
            total_bytes: 0,
        }));
        agent_client.report_progress(progress_request).await?;

        // Read file
        let data = std::fs::read(file_path)?;

        // Capture metadata so permissions/time survive round-trips
        let fs_metadata = std::fs::metadata(file_path)?;
        let file_metadata = build_object_metadata(
            file_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            &fs_metadata,
            false,
        );
        let metadata_blob = serialize_and_encrypt_metadata(key_manager, &file_metadata)?;
        let file_object_id = catalog.create_object(ObjectType::File, &metadata_blob)?;

        // Chunk the file using CDC
        let chunker = CdcChunker::new(&data);
        let chunks: Vec<_> = chunker.collect();

        info!("File chunked into {} pieces", chunks.len());

        // Check which chunks already exist on server
        let chunk_hashes: Vec<String> = chunks
            .iter()
            .map(|chunk| {
                let hash = blake3::hash(chunk);
                hash.to_hex().to_string()
            })
            .collect();

        // Create stream of chunk hashes to check
        let hash_check_data: Vec<ChunkHash> = chunk_hashes
            .iter()
            .map(|h| ChunkHash { hash: h.clone() })
            .collect();
        let hash_stream = tokio_stream::iter(hash_check_data);

        let mut chunk_client_clone = chunk_client.clone();
        let request = Request::new(hash_stream);
        let mut response_stream = chunk_client_clone
            .check_chunks_exist(request)
            .await?
            .into_inner();

        let mut missing_chunks = std::collections::HashSet::new();
        while let Some(response) = response_stream.message().await? {
            if !response.exists {
                missing_chunks.insert(response.hash);
            }
        }

        info!("Need to upload {} chunks", missing_chunks.len());

        // Upload missing chunks
        for (i, chunk_data) in chunks.iter().enumerate() {
            let hash = chunk_hashes[i].clone();

            if missing_chunks.contains(&hash) {
                // Encode chunk with adaptive compression header
                let encoded = adaptive::encode_chunk(chunk_data)?;

                // Encrypt the chunk
                let (encrypted, nonce) = key_manager.encrypt_data(&encoded)?;
                let stored_size = encrypted.len();

                // Combine nonce and encrypted data
                let mut full_data = nonce;
                full_data.extend_from_slice(&encrypted);

                // Upload to server
                let payload = ChunkUpload {
                    hash: hash.clone(),
                    data: full_data,
                    uncompressed_size: chunk_data.len() as i32,
                };

                upload_chunk_with_retry(chunk_client, payload, &hash).await?;

                // Record in catalog
                catalog.upsert_chunk(&hash, stored_size, chunk_data.len())?;
            }

            catalog.add_file_chunk(file_object_id, &hash, i)?;
        }

        info!("File backup completed: {}", file_path.display());
        Ok(())
    }
}

async fn run_heartbeat_loop(
    agent_id: String,
    server_address: String,
    interval_duration: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = AgentServiceClient::connect(server_address).await?;
    let mut timer = interval(interval_duration);

    loop {
        timer.tick().await;

        let request = Request::new(HeartbeatRequest {
            agent_id: agent_id.clone(),
            timestamp: chrono::Utc::now().timestamp(),
        });

        match client.heartbeat(request).await {
            Ok(_) => {
                info!("Heartbeat sent successfully");
            }
            Err(e) => {
                warn!("Failed to send heartbeat: {}", e);
            }
        }
    }
}

async fn upload_chunk_with_retry(
    chunk_client: &ChunkServiceClient<tonic::transport::Channel>,
    payload: ChunkUpload,
    hash: &str,
) -> Result<(), tonic::Status> {
    const MAX_ATTEMPTS: u32 = 3;
    let mut attempt = 0;

    loop {
        let stream = tokio_stream::iter(vec![payload.clone()]);
        let request = Request::new(stream);
        let mut client = chunk_client.clone();

        match client.upload_chunk(request).await {
            Ok(_) => return Ok(()),
            Err(err) => {
                attempt += 1;
                if attempt >= MAX_ATTEMPTS {
                    return Err(err);
                }

                let backoff = Duration::from_millis(500 * (1 << (attempt - 1)));
                warn!(
                    "Chunk {} upload failed (attempt {}/{}). Retrying in {:?}: {}",
                    hash, attempt, MAX_ATTEMPTS, backoff, err
                );
                sleep(backoff).await;
            }
        }
    }
}

async fn download_chunk_from_server(
    chunk_client: &ChunkServiceClient<tonic::transport::Channel>,
    hash: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const MAX_ATTEMPTS: u32 = 3;

    for attempt in 1..=MAX_ATTEMPTS {
        match download_chunk_once(chunk_client, hash).await {
            Ok(data) => return Ok(data),
            Err(err) => {
                if attempt == MAX_ATTEMPTS {
                    return Err(Box::new(err));
                }

                let backoff = Duration::from_millis(500 * (1 << (attempt - 1)));
                warn!(
                    "Chunk {} download failed (attempt {}/{}). Retrying in {:?}: {}",
                    hash, attempt, MAX_ATTEMPTS, backoff, err
                );
                sleep(backoff).await;
            }
        }
    }

    Err("Exceeded download retry budget".into())
}

async fn download_chunk_once(
    chunk_client: &ChunkServiceClient<tonic::transport::Channel>,
    hash: &str,
) -> Result<Vec<u8>, tonic::Status> {
    let request = Request::new(ChunkDownloadRequest {
        hash: hash.to_string(),
    });
    let mut client = chunk_client.clone();
    let mut stream = client.download_chunk(request).await?.into_inner();
    let mut data = Vec::new();

    while let Some(chunk) = stream.message().await? {
        data.extend_from_slice(&chunk.data);
    }

    if data.is_empty() {
        Err(tonic::Status::not_found(format!(
            "Chunk {} not found on server",
            hash
        )))
    } else {
        Ok(data)
    }
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

fn serialize_and_encrypt_metadata(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    metadata: &ObjectMetadata,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata_json = serde_json::to_string(metadata)?;
    let (encrypted_metadata, nonce) = key_manager.encrypt_metadata(&metadata_json)?;
    let mut stored_metadata = nonce;
    stored_metadata.extend_from_slice(&encrypted_metadata);
    Ok(stored_metadata)
}

fn estimate_restore_metrics(
    catalog: &CatalogIndex,
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    object_id: i64,
) -> Result<(u64, u64), LazarusError> {
    let mut visited = HashSet::new();
    estimate_restore_metrics_inner(catalog, key_manager, object_id, &mut visited)
}

fn estimate_restore_metrics_inner(
    catalog: &CatalogIndex,
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    object_id: i64,
    visited: &mut HashSet<i64>,
) -> Result<(u64, u64), LazarusError> {
    if !visited.insert(object_id) {
        return Ok((0, 0));
    }

    let (obj_type, metadata_blob) = match catalog.get_object(object_id)? {
        Some(value) => value,
        None => return Ok((0, 0)),
    };
    let metadata = decrypt_object_metadata(key_manager, &metadata_blob)?;

    match obj_type {
        ObjectType::File | ObjectType::BlockDevice => Ok((1, metadata.size)),
        // SystemFingerprint objects are not file-tree children; they
        // contribute zero files/bytes to restore metrics.
        ObjectType::SystemFingerprint => Ok((0, 0)),
        ObjectType::Directory => {
            let mut files = 0;
            let mut bytes = 0;
            for (child_id, _) in catalog.get_tree_children(object_id)? {
                let (child_files, child_bytes) =
                    estimate_restore_metrics_inner(catalog, key_manager, child_id, visited)?;
                files += child_files;
                bytes += child_bytes;
            }
            Ok((files, bytes))
        }
    }
}

struct RestoreProgress {
    total_files: u64,
    total_bytes: u64,
    processed_files: u64,
    processed_bytes: u64,
}

impl RestoreProgress {
    fn new(total_files: u64, total_bytes: u64) -> Self {
        Self {
            total_files,
            total_bytes,
            processed_files: 0,
            processed_bytes: 0,
        }
    }

    fn record_file(&mut self, file_size: u64) -> (i32, u64, u64) {
        self.processed_files = self.processed_files.saturating_add(1);
        self.processed_bytes = self.processed_bytes.saturating_add(file_size);
        (
            self.percent_complete(),
            self.processed_bytes,
            self.total_bytes,
        )
    }

    fn finalize(&mut self) -> (i32, u64, u64) {
        self.processed_files = self.total_files;
        self.processed_bytes = self.total_bytes;
        (100, self.processed_bytes, self.total_bytes)
    }

    fn percent_complete(&self) -> i32 {
        if self.total_bytes > 0 {
            ((self.processed_bytes.min(self.total_bytes) * 100) / self.total_bytes) as i32
        } else if self.total_files > 0 {
            ((self.processed_files.min(self.total_files) * 100) / self.total_files) as i32
        } else {
            100
        }
        .clamp(0, 100)
    }
}

#[allow(clippy::too_many_arguments)]
async fn restore_file(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    chunk_client: &ChunkServiceClient<tonic::transport::Channel>,
    agent_client: &mut AgentServiceClient<tonic::transport::Channel>,
    agent_id: &str,
    job_id: &str,
    file_object_id: i64,
    metadata: ObjectMetadata,
    dest_path: &Path,
    progress: &mut RestoreProgress,
) -> Result<(), Box<dyn std::error::Error>> {
    let chunk_hashes = catalog.get_file_chunks(file_object_id)?;
    let mut file_data = Vec::new();

    for hash in chunk_hashes {
        let stored_data = download_chunk_from_server(chunk_client, &hash).await?;

        if stored_data.len() < 12 {
            return Err(LazarusError::EncryptionError("Stored chunk too small".into()).into());
        }

        let nonce = &stored_data[..12];
        let encrypted_chunk = &stored_data[12..];
        let encoded_chunk = key_manager.decrypt_data(encrypted_chunk, nonce)?;
        let chunk = adaptive::decode_chunk(&encoded_chunk)?;
        file_data.extend_from_slice(&chunk);
    }

    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(dest_path, &file_data).await?;
    apply_metadata(dest_path, &metadata).await?;

    let (percent, processed_bytes, total_bytes) = progress.record_file(metadata.size);
    let progress_request = Request::new(tokio_stream::once(ProgressUpdate {
        agent_id: agent_id.to_string(),
        job_id: job_id.to_string(),
        progress_percent: percent,
        status_message: format!("Restored file: {}", dest_path.display()),
        bytes_processed: processed_bytes.min(i64::MAX as u64) as i64,
        total_bytes: total_bytes.min(i64::MAX as u64) as i64,
    }));
    agent_client.report_progress(progress_request).await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn restore_directory(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    chunk_client: &ChunkServiceClient<tonic::transport::Channel>,
    agent_client: &mut AgentServiceClient<tonic::transport::Channel>,
    agent_id: &str,
    job_id: &str,
    dir_object_id: i64,
    metadata: ObjectMetadata,
    dest_path: &Path,
    progress: &mut RestoreProgress,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::fs::create_dir_all(dest_path).await?;
    apply_metadata(dest_path, &metadata).await?;

    let children = catalog.get_tree_children(dir_object_id)?;
    for (child_id, encrypted_name) in children {
        if encrypted_name.len() < 12 {
            continue;
        }

        let nonce = &encrypted_name[..12];
        let encrypted = &encrypted_name[12..];
        let child_name = key_manager.decrypt_metadata(encrypted, nonce)?;

        let (child_type, child_metadata_blob) = catalog
            .get_object(child_id)?
            .ok_or_else(|| LazarusError::Storage("Child object not found".to_string()))?;
        let child_metadata = decrypt_object_metadata(key_manager, &child_metadata_blob)?;
        let child_path = dest_path.join(child_name);

        match child_type {
            ObjectType::File | ObjectType::BlockDevice => {
                restore_file(
                    key_manager,
                    catalog,
                    chunk_client,
                    agent_client,
                    agent_id,
                    job_id,
                    child_id,
                    child_metadata,
                    &child_path,
                    progress,
                )
                .await?;
            }
            ObjectType::Directory => {
                Box::pin(restore_directory(
                    key_manager,
                    catalog,
                    chunk_client,
                    agent_client,
                    agent_id,
                    job_id,
                    child_id,
                    child_metadata,
                    &child_path,
                    progress,
                ))
                .await?;
            }
            ObjectType::SystemFingerprint => {
                return Err(
                    "nested SystemFingerprint objects are not supported in file-tree restore"
                        .into(),
                );
            }
        }
    }

    Ok(())
}

fn decrypt_object_metadata(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    blob: &[u8],
) -> Result<ObjectMetadata, LazarusError> {
    if blob.len() < 12 {
        let fallback = String::from_utf8(blob.to_vec())
            .map_err(|_| LazarusError::EncryptionError("Invalid metadata encoding".into()))?;
        return serde_json::from_str(&fallback)
            .map_err(|e| LazarusError::SerializationError(e.to_string()));
    }

    let nonce = &blob[..12];
    let encrypted_metadata = &blob[12..];
    let metadata_json = key_manager.decrypt_metadata(encrypted_metadata, nonce)?;
    serde_json::from_str(&metadata_json)
        .map_err(|e| LazarusError::SerializationError(e.to_string()))
}

async fn apply_metadata(
    path: &Path,
    metadata: &ObjectMetadata,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::fs::Permissions;

        if metadata.mode != 0 {
            if let Err(err) =
                tokio::fs::set_permissions(path, Permissions::from_mode(metadata.mode)).await
            {
                warn!("Failed to set permissions on {}: {}", path.display(), err);
            }
        }

        if let Err(err) = chown_path(path, metadata.uid, metadata.gid) {
            warn!("Failed to set ownership on {}: {}", path.display(), err);
        }
    }

    let mtime = metadata.mtime.min(i64::MAX as u64) as i64;
    let file_time = FileTime::from_unix_time(mtime, 0);
    if let Err(err) = set_file_times(path, file_time, file_time) {
        warn!("Failed to apply timestamps on {}: {}", path.display(), err);
    }

    Ok(())
}

#[cfg(unix)]
fn chown_path(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains null byte")
    })?;
    let res = unsafe { libc::chown(c_path.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) };
    if res == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn select_snapshots_to_keep(
    snapshots: &[(String, u64)],
    keep_last: usize,
    keep_days: u64,
) -> HashSet<String> {
    let mut keep = HashSet::new();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs();
    let cutoff = if keep_days == 0 {
        0
    } else {
        now.saturating_sub(keep_days * 86_400)
    };

    for (idx, (snapshot_id, timestamp)) in snapshots.iter().enumerate() {
        if idx < keep_last {
            keep.insert(snapshot_id.clone());
            continue;
        }
        if keep_days > 0 && *timestamp >= cutoff {
            keep.insert(snapshot_id.clone());
        }
    }

    keep
}

fn mark_object_chunks(
    catalog: &CatalogIndex,
    object_id: i64,
    visited_objects: &mut HashSet<i64>,
    active_chunks: &mut HashSet<String>,
) -> lazarus_core::error::Result<()> {
    if !visited_objects.insert(object_id) {
        return Ok(());
    }

    let (obj_type, _) = match catalog.get_object(object_id)? {
        Some(data) => data,
        None => return Ok(()),
    };

    match obj_type {
        ObjectType::File => {
            for chunk_hash in catalog.get_file_chunks(object_id)? {
                active_chunks.insert(chunk_hash);
            }
        }
        ObjectType::BlockDevice => {
            for extent in catalog.get_block_layout(object_id)?.extents {
                for chunk in extent.chunks {
                    active_chunks.insert(chunk.hash);
                }
            }
        }
        ObjectType::Directory => {
            for (child_id, _) in catalog.get_tree_children(object_id)? {
                mark_object_chunks(catalog, child_id, visited_objects, active_chunks)?;
            }
        }
        ObjectType::SystemFingerprint => {
            // SystemFingerprint chunks are referenced via the
            // DedupTable directly at capture time (see
            // FingerprintPersister); there are no per-object chunk
            // rows to mark from the catalog side.
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let agent = Agent::new(cli);

    if let Err(e) = agent.run().await {
        error!("Agent failed: {}", e);
        std::process::exit(1);
    }
}
