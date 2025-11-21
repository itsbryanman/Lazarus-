use clap::Parser;
use lazarus_common::lazarus::agent::{
    agent_service_client::AgentServiceClient, chunk_service_client::ChunkServiceClient, ChunkHash,
    ChunkUpload, GetJobsRequest, HeartbeatRequest, JobCompletionRequest, JobStatistics,
    ProgressUpdate, RegisterRequest,
};
use lazarus_core::catalog::index::CatalogIndex;
use lazarus_core::chunking::cdc::CdcChunker;
use lazarus_core::compression::adaptive;
use lazarus_core::config::ConfigManager;
use lazarus_core::security::ransomware::{DetectionEngine, DetectionVerdict};
use std::collections::HashMap;
use std::path::Path;
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
        job_type: i32,
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

        // JobType::BACKUP = 0
        match job_type {
            0 => {
                let source = parameters
                    .get("source")
                    .ok_or("Missing 'source' parameter")?;
                self.perform_backup(job_id, source, agent_client, chunk_client)
                    .await?;
            }
            _ => {
                return Err(format!("Unknown job type: {}", job_type).into());
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

        let mut missing_chunks = Vec::new();
        while let Some(response) = response_stream.message().await? {
            if !response.exists {
                missing_chunks.push(response.hash);
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
