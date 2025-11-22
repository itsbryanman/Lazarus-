use super::snapshot_utils::{calculate_snapshot_size, parse_snapshot_metadata};
use clap::Args;
use comfy_table::{presets::UTF8_FULL, Table};
use indicatif::HumanBytes;
use lazarus_core::catalog::index::CatalogIndex;
use lazarus_core::config::ConfigManager;
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
    let key_manager = config_mgr.open_repository(&args.password).await?;

    // Open catalog
    let catalog = CatalogIndex::new(config_mgr.database_path())?;

    // List snapshots
    let snapshots = catalog.list_snapshots()?;

    if snapshots.is_empty() {
        println!("No snapshots found in repository.");
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Snapshot ID", "Date", "Size", "Hostname"]);

    for (snapshot_id, timestamp) in snapshots {
        let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let (root_object_id, metadata_blob) = match catalog.get_snapshot(&snapshot_id)? {
            Some(data) => data,
            None => continue,
        };

        let size_bytes = calculate_snapshot_size(&catalog, &key_manager, root_object_id)?;
        let metadata = parse_snapshot_metadata(&key_manager, &metadata_blob);
        let hostname = metadata
            .and_then(|meta| meta.hostname)
            .unwrap_or_else(|| "Unknown".to_string());

        table.add_row(vec![
            snapshot_id,
            datetime,
            HumanBytes(size_bytes).to_string(),
            hostname,
        ]);
    }

    println!("\nAvailable snapshots:\n");
    println!("{}", table);

    // Show stats
    let (chunks, objects, snapshot_count) = catalog.get_stats()?;
    println!("\nRepository statistics:");
    println!("  Total chunks: {}", chunks);
    println!("  Total objects: {}", objects);
    println!("  Total snapshots: {}", snapshot_count);

    Ok(())
}
