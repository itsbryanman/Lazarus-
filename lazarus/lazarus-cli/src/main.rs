use clap::{Parser, Subcommand};
use lazarus_cli::commands;

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
    /// Manage immutable retention policies
    Retention(commands::retention::RetentionArgs),
    /// Remove unreferenced data using a retention policy
    Prune(commands::prune::PruneArgs),
    /// Security operations (key rotation, etc.)
    Security(commands::security::SecurityArgs),
    /// Recovery utilities (ISO builder, etc.)
    Recover(commands::recover::RecoverArgs),
    /// Capture a bare-metal system fingerprint
    SystemSnapshot(commands::system_snapshot::SystemSnapshotArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Init(args) => commands::init::init(args).await,
        Commands::Backup(args) => commands::backup::backup(args).await,
        Commands::Restore(args) => commands::restore::restore(args).await,
        Commands::List(args) => commands::list::list(args).await,
        Commands::Verify(args) => commands::verify::verify(args).await,
        Commands::Config(args) => commands::config::config(args).await,
        Commands::Retention(args) => commands::retention::retention(args).await,
        Commands::Prune(args) => commands::prune::prune(args).await,
        Commands::Security(args) => commands::security::security(args).await,
        Commands::Recover(args) => commands::recover::recover(args).await,
        Commands::SystemSnapshot(args) => commands::system_snapshot::run(args).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }
}
