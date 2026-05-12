use lazarus_cli::commands::{
    backup::{backup, BackupArgs, SnapshotterChoice},
    restore::{restore, RestoreArgs},
};
use lazarus_core::catalog::index::{CatalogIndex, ObjectType};
use lazarus_core::config::ConfigManager;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use tempfile::TempDir;

const PASSWORD: &str = "test-password";

#[tokio::test]
async fn block_mode_backup_restores_sparse_image() {
    let temp = TempDir::new().expect("temp dir");
    let repo_path = temp.path().join("repo");
    let source_path = temp.path().join("source.img");
    let restore_path = temp.path().join("restored.img");

    fs::create_dir_all(&repo_path).unwrap();
    create_sparse_source(&source_path).unwrap();

    let config = ConfigManager::new(&repo_path);
    config
        .init_repository(PASSWORD)
        .await
        .expect("init repository");

    let backup_args = BackupArgs {
        source: None,
        repository: repo_path.to_string_lossy().to_string(),
        password: PASSWORD.to_string(),
        force: false,
        consistent: false,
        snapshotter: SnapshotterChoice::Auto,
        block_mode: true,
        device: Some(source_path.to_string_lossy().to_string()),
        no_hooks: true,
        hook_templates: Vec::new(),
    };
    backup(&backup_args).await.expect("block backup succeeds");

    let catalog = CatalogIndex::new(config.database_path()).expect("catalog open");
    let snapshots = catalog.list_snapshots().expect("list snapshots");
    let (root_object_id, _) = catalog
        .get_snapshot(&snapshots[0].0)
        .expect("snapshot lookup")
        .expect("snapshot exists");
    let (object_type, _) = catalog
        .get_object(root_object_id)
        .expect("object lookup")
        .expect("root object exists");
    assert_eq!(object_type, ObjectType::BlockDevice);
    assert!(!catalog
        .get_block_layout(root_object_id)
        .unwrap()
        .extents
        .is_empty());

    let restore_args = RestoreArgs {
        snapshot: Some(snapshots[0].0.clone()),
        destination: Some(restore_path.to_string_lossy().to_string()),
        device: None,
        allow_overwrite: false,
        verify: true,
        repository: repo_path.to_string_lossy().to_string(),
        password: PASSWORD.to_string(),
    };
    restore(&restore_args)
        .await
        .expect("block restore succeeds");

    assert_eq!(fs::metadata(&restore_path).unwrap().len(), 4 * 1024 * 1024);
    assert_eq!(
        read_all(&source_path).unwrap(),
        read_all(&restore_path).unwrap()
    );
}

fn create_sparse_source(path: &std::path::Path) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.set_len(4 * 1024 * 1024)?;
    file.seek(SeekFrom::Start(4096))?;
    file.write_all(b"lazarus-block-a")?;
    file.seek(SeekFrom::Start(3 * 1024 * 1024))?;
    file.write_all(b"lazarus-block-b")?;
    file.flush()
}

fn read_all(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}
