use clap::{Parser, Subcommand};
use lazarus_common::lazarus::agent::{agent_service_server, chunk_service_server};
use lazarus_core::config::ConfigManager;
use lazarus_server::{
    agent_manager::AgentManager,
    grpc::{AgentServiceImpl, ChunkServiceImpl},
    job_scheduler::JobScheduler,
};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tonic::transport::Server;
use tracing::info;

#[derive(Parser)]
#[command(author, version, about = "Lazarus Backup Server", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Lazarus server
    Start {
        #[arg(short, long, default_value = "0.0.0.0:50051")]
        address: String,

        #[arg(short, long, default_value = "/var/lib/lazarus/server")]
        data_dir: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { address, data_dir } => {
            start_server(&address, &data_dir).await?;
        }
    }

    Ok(())
}

async fn start_server(address: &str, data_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting Lazarus Server...");
    info!("Data directory: {}", data_dir);

    fs::create_dir_all(data_dir)?;
    let db_path = Path::new(data_dir).join("server.db");

    // Create shared state
    let agent_manager = AgentManager::new();
    let job_scheduler = JobScheduler::new(&db_path)?;

    // Parse address
    let addr: SocketAddr = address.parse()?;

    info!("Starting gRPC server on {}", addr);

    // Create gRPC services
    let agent_service = AgentServiceImpl::new(agent_manager.clone(), job_scheduler.clone());

    let config_mgr = ConfigManager::new(&data_dir);
    let retention_policy = config_mgr.load_retention_policy().await?;
    let retention_lock = retention_policy.as_lock();
    if retention_lock.is_some() {
        info!(
            "Immutable retention enforcement enabled (mode: {:?}, {} days)",
            retention_policy.mode, retention_policy.min_retention_days
        );
    }
    let chunk_service = ChunkServiceImpl::new(&data_dir, retention_lock);

    // Start scheduler in background
    let scheduler_handle = {
        let scheduler = job_scheduler.clone();
        tokio::spawn(async move {
            scheduler.run().await;
        })
    };

    // Start gRPC server
    Server::builder()
        .add_service(agent_service_server::AgentServiceServer::new(agent_service))
        .add_service(chunk_service_server::ChunkServiceServer::new(chunk_service))
        .serve(addr)
        .await?;

    // Wait for scheduler
    scheduler_handle.await?;

    Ok(())
}
