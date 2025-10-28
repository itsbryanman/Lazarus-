use clap::Args;
use lazarus_core::config::ConfigManager;
use lazarus_core::catalog::index::CatalogIndex;
use lazarus_core::error::Result;

#[derive(Args)]
pub struct ListArgs {
    #[arg(short, long, help = "Repository path")]
    pub repository: String,

    #[arg(short, long, help = "Master password for decryption")]
    pub password: String,
}

pub async fn list(args: &ListArgs) -> Result<()> {
    // Open repository
    let config_mgr = ConfigManager::new(&args.repository);
    let _key_manager = config_mgr.open_repository(&args.password).await?;

    // Open catalog
    let catalog = CatalogIndex::new(config_mgr.database_path())?;

    // List snapshots
    let snapshots = catalog.list_snapshots()?;

    if snapshots.is_empty() {
        println!("No snapshots found in repository.");
        return Ok(());
    }

    println!("Available snapshots:\n");
    println!("{:<25} {}", "Snapshot ID", "Timestamp");
    println!("{}", "-".repeat(60));

    for (snapshot_id, timestamp) in snapshots {
        let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        println!("{:<25} {}", snapshot_id, datetime);
    }

    // Show stats
    let (chunks, objects, snapshot_count) = catalog.get_stats()?;
    println!("\nRepository statistics:");
    println!("  Total chunks: {}", chunks);
    println!("  Total objects: {}", objects);
    println!("  Total snapshots: {}", snapshot_count);

    Ok(())
}
