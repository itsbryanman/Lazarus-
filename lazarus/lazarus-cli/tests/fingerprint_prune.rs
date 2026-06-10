use lazarus_cli::commands::prune::{prune, PruneArgs};
use lazarus_cli::commands::snapshot_utils::encrypt_snapshot_metadata;
use lazarus_core::capture::persist::{sharded_key, FingerprintPersister};
use lazarus_core::capture::system::{SystemFingerprint, FINGERPRINT_VERSION};
use lazarus_core::capture::{
    bootloader::BootloaderConfig, network::NetworkConfig, packages::PackageManifest,
    secrets::SshHostKeysRef, users::UserDatabaseRef,
};
use lazarus_core::catalog::index::{CatalogIndex, ObjectType};
use lazarus_core::catalog::metadata::{MetadataStore, SnapshotMetadata};
use lazarus_core::config::ConfigManager;
use lazarus_core::encryption::key_manager::KeyManager;
use lazarus_core::snapshot::dedup::DedupTable;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;

const PASSWORD: &str = "test-password";

#[tokio::test]
async fn prune_reclaims_fingerprint_chunk_after_last_reference() {
    let temp = tempfile::tempdir().expect("temp dir");
    let repo_path = temp.path().join("repo");
    std::fs::create_dir_all(&repo_path).expect("repo dir");

    let config = ConfigManager::new(&repo_path);
    config
        .init_repository(PASSWORD)
        .await
        .expect("init repository");

    let key_manager = config
        .open_repository(PASSWORD)
        .await
        .expect("open repository");
    let catalog = CatalogIndex::new(config.database_path()).expect("catalog");
    let dedup = DedupTable::open(config.database_path()).expect("dedup");
    let storage = LocalStorage::new(config.data_path());
    let meta_store = MetadataStore::open(config.repo_path(), *key_manager.get_metadata_key());

    let fingerprint = dummy_fingerprint();

    let persister1 =
        FingerprintPersister::new(&storage, &key_manager, &catalog, &dedup, "snap-1", false);
    let fp_hash = persister1
        .persist_fingerprint(&fingerprint)
        .await
        .expect("persist fingerprint");

    let root_blob = encrypt_snapshot_metadata(
        &key_manager,
        &serde_json::json!({
            "fingerprint_chunk": fp_hash,
            "format_version": 1,
        })
        .to_string(),
    )
    .expect("encrypt fingerprint metadata");
    let root_object_id = catalog
        .create_object(ObjectType::SystemFingerprint, &root_blob)
        .expect("create fingerprint object");

    create_snapshot(
        &catalog,
        &meta_store,
        &key_manager,
        "snap-1",
        100,
        root_object_id,
        &fp_hash,
    )
    .expect("create first snapshot");

    let persister2 =
        FingerprintPersister::new(&storage, &key_manager, &catalog, &dedup, "snap-2", false);
    let fp_hash_2 = persister2
        .persist_fingerprint(&fingerprint)
        .await
        .expect("persist fingerprint again");
    assert_eq!(fp_hash, fp_hash_2);

    create_snapshot(
        &catalog,
        &meta_store,
        &key_manager,
        "snap-2",
        200,
        root_object_id,
        &fp_hash,
    )
    .expect("create second snapshot");

    let key = sharded_key(&fp_hash);
    assert!(storage.get(&key).await.is_ok(), "fingerprint chunk exists");

    prune(&PruneArgs {
        repository: repo_path.to_string_lossy().to_string(),
        password: PASSWORD.to_string(),
        keep_last: 1,
        keep_days: 0,
        dry_run: false,
    })
    .await
    .expect("first prune");

    assert!(
        storage.get(&key).await.is_ok(),
        "fingerprint chunk should survive while one snapshot still references it"
    );

    prune(&PruneArgs {
        repository: repo_path.to_string_lossy().to_string(),
        password: PASSWORD.to_string(),
        keep_last: 0,
        keep_days: 0,
        dry_run: false,
    })
    .await
    .expect("second prune");

    assert!(
        storage.get(&key).await.is_err(),
        "fingerprint chunk should be deleted after the last referencing snapshot is pruned"
    );
}

fn create_snapshot(
    catalog: &CatalogIndex,
    meta_store: &MetadataStore,
    key_manager: &KeyManager,
    snapshot_id: &str,
    timestamp: u64,
    root_object_id: i64,
    fp_hash: &str,
) -> lazarus_core::error::Result<()> {
    let snapshot_metadata_blob = encrypt_snapshot_metadata(
        key_manager,
        &serde_json::json!({
            "source": "system",
            "hostname": "test-host",
        })
        .to_string(),
    )?;
    catalog.create_snapshot(
        snapshot_id,
        timestamp,
        root_object_id,
        &snapshot_metadata_blob,
    )?;
    meta_store.put(
        snapshot_id,
        &SnapshotMetadata {
            hostname: Some("test-host".into()),
            source: Some("system".into()),
            system_fingerprint_chunk: Some(fp_hash.to_string()),
            system_fingerprint_format_version: Some(1),
            tags: vec![],
            description: None,
            retention_days: None,
        },
    )?;
    Ok(())
}

fn dummy_fingerprint() -> SystemFingerprint {
    SystemFingerprint {
        version: FINGERPRINT_VERSION,
        captured_at_epoch_s: 1234,
        captured_by: "test".into(),
        hostname: "host".into(),
        fqdn: None,
        machine_id: Some("abc123".into()),
        kernel: Default::default(),
        cpu: Default::default(),
        memory_bytes: 0,
        disks: vec![],
        lvm: None,
        mdadm: None,
        filesystems: vec![],
        fstab: String::new(),
        crypttab: None,
        network: NetworkConfig::default(),
        bootloader: BootloaderConfig::default(),
        packages: PackageManifest::default(),
        services: vec![],
        users: UserDatabaseRef::empty(),
        ssh_host_keys: SshHostKeysRef::empty(),
        firmware: Default::default(),
        warnings: vec![],
    }
}
