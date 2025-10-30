use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::info;

mod agent_manager;
mod grpc;
mod job_scheduler;

use agent_manager::AgentManager;
use grpc::{AgentServiceImpl, ChunkServiceImpl};
use job_scheduler::JobScheduler;
use lazarus_common::lazarus::agent::{agent_service_server, chunk_service_server};

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

    // Create shared state
    let agent_manager = AgentManager::new();
    let job_scheduler = JobScheduler::new();

    // Parse address
    let addr: SocketAddr = address.parse()?;

    info!("Starting gRPC server on {}", addr);

    // Create gRPC services
    let agent_service = AgentServiceImpl::new(agent_manager.clone(), job_scheduler.clone());
    let chunk_service = ChunkServiceImpl::new(data_dir.to_string());

    // Start scheduler in background
    let scheduler_handle = tokio::spawn(async move {
        job_scheduler.run().await;
    });

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
