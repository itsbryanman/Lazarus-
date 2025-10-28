use clap::{Parser, Subcommand};

pub mod commands;
pub mod interactive;
pub mod output;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new repository
    Init(commands::init::InitArgs),
    /// Backup data
    Backup(commands::backup::BackupArgs),
    /// Restore data
    Restore(commands::restore::RestoreArgs),
    /// List snapshots
    List(commands::list::ListArgs),
    /// Verify backups
    Verify(commands::verify::VerifyArgs),
    /// Configure Lazarus
    Config(commands::config::ConfigArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Init(args) => commands::init::init(args).await,
        Commands::Backup(args) => commands::backup::backup(args).await,
        Commands::Restore(args) => commands::restore::restore(args).await,
        Commands::List(args) => commands::list::list(args).await,
        Commands::Verify(_args) => {
            println!("Verify command not yet implemented");
            Ok(())
        }
        Commands::Config(_args) => {
            println!("Config command not yet implemented");
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }
}