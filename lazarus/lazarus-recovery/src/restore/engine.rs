use lazarus_cli::commands::restore::{RestoreArgs, restore};
use lazarus_core::catalog::index::CatalogIndex;
use lazarus_core::config::ConfigManager;
use lazarus_core::error::LazarusError;
use tokio::runtime::Runtime;

#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub id: String,
    pub timestamp: u64,
}

pub fn list_snapshots(repo_path: &str, password: &str) -> Result<Vec<SnapshotInfo>, String> {
    let runtime = Runtime::new().map_err(|e| e.to_string())?;
    let repo = repo_path.to_string();
    let password = password.to_string();

    runtime
        .block_on(async move {
            let config = ConfigManager::new(&repo);
            // Unlock repository to validate credentials
            let _key_manager = config.open_repository(&password).await?;
            let catalog = CatalogIndex::new(config.database_path())?;
            let snapshots = catalog.list_snapshots()?;
            Ok::<_, LazarusError>(
                snapshots
                    .into_iter()
                    .map(|(id, timestamp)| SnapshotInfo { id, timestamp })
                    .collect(),
            )
        })
        .map_err(|e| e.to_string())
}

pub fn restore_snapshot(
    repo_path: &str,
    password: &str,
    snapshot_id: &str,
    destination: &str,
) -> Result<(), String> {
    let runtime = Runtime::new().map_err(|e| e.to_string())?;
    let args = RestoreArgs {
        snapshot: snapshot_id.to_string(),
        destination: destination.to_string(),
        repository: repo_path.to_string(),
        password: password.to_string(),
    };

    runtime.block_on(restore(&args)).map_err(|e| e.to_string())
}
