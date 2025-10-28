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
    /// Backup data
    Backup(commands::backup::BackupArgs),
    /// Restore data
    Restore(commands::restore::RestoreArgs),
    /// Verify backups
    Verify(commands::verify::VerifyArgs),
    /// List backups
    List(commands::list::ListArgs),
    /// Configure Lazarus
    Config(commands::config::ConfigArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Backup(args) => commands::backup::backup(args).await,
        Commands::Restore(args) => commands::restore::restore(args).await,
        Commands::Verify(args) => {
            println!("Verify command");
            Ok(())
        }
        Commands::List(args) => {
            println!("List command");
            Ok(())
        }
        Commands::Config(args) => {
            println!("Config command");
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }
}