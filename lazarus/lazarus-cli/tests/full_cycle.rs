use lazarus_cli::commands::{
    backup::{backup, BackupArgs},
    restore::{restore, RestoreArgs},
};
use lazarus_core::catalog::index::CatalogIndex;
use lazarus_core::config::ConfigManager;
use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::time::{sleep, Duration};
use walkdir::WalkDir;

const PASSWORD: &str = "test-password";

#[tokio::test]
async fn full_cycle_backup_and_restore_matches_hashes() {
    let temp = TempDir::new().expect("temp dir");
    let repo_path = temp.path().join("repo");
    let source_path = temp.path().join("source");
    let restore_path = temp.path().join("restored");

    fs::create_dir_all(&repo_path).unwrap();
    fs::create_dir_all(&source_path).unwrap();

    create_random_tree(&source_path, 100, 512 * 1024).expect("random tree");

    let config = ConfigManager::new(&repo_path);
    config
        .init_repository(PASSWORD)
        .await
        .expect("init repository");

    let backup_args = BackupArgs {
        source: Some(source_path.to_string_lossy().to_string()),
        repository: repo_path.to_string_lossy().to_string(),
        password: PASSWORD.to_string(),
        force: false,
        consistent: false,
        snapshotter: lazarus_cli::commands::backup::SnapshotterChoice::Auto,
        block_mode: false,
        device: None,
        no_hooks: false,
        hook_templates: Vec::new(),
    };
    backup(&backup_args).await.expect("backup succeeds");

    sleep(Duration::from_millis(50)).await;

    let catalog = CatalogIndex::new(config.database_path()).expect("catalog open");
    let snapshots = catalog.list_snapshots().expect("list snapshots");
    assert!(
        !snapshots.is_empty(),
        "backup must create at least one snapshot"
    );
    let latest_snapshot = &snapshots[0].0;

    let restore_args = RestoreArgs {
        snapshot: Some(latest_snapshot.clone()),
        destination: Some(restore_path.to_string_lossy().to_string()),
        repository: repo_path.to_string_lossy().to_string(),
        password: PASSWORD.to_string(),
    };
    restore(&restore_args).await.expect("restore succeeds");

    let original_hashes = hash_directory(&source_path).expect("hash source");
    let restored_hashes = hash_directory(&restore_path).expect("hash restored");

    assert_eq!(original_hashes, restored_hashes);
}

fn create_random_tree(root: &Path, file_count: usize, bytes_per_file: usize) -> io::Result<()> {
    let mut rng = StdRng::seed_from_u64(42);
    for i in 0..file_count {
        let subdir = root.join(format!("dir_{}", i % 5));
        fs::create_dir_all(&subdir)?;
        let file_path = subdir.join(format!("file_{i}.bin"));
        let mut file = File::create(file_path)?;
        let mut remaining = bytes_per_file;
        while remaining > 0 {
            let chunk = remaining.min(64 * 1024);
            let letter = b'A' + (rng.gen::<u8>() % 26);
            let buffer = vec![letter; chunk];
            file.write_all(&buffer)?;
            remaining -= chunk;
        }
    }
    Ok(())
}

fn hash_directory(root: &Path) -> io::Result<BTreeMap<PathBuf, String>> {
    let mut hashes = BTreeMap::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
            let data = fs::read(entry.path())?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            hashes.insert(relative, format!("{:x}", hasher.finalize()));
        }
    }
    Ok(hashes)
}
