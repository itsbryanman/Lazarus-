//! Integration test: fingerprint chunks are protected during prune when
//! references exist, and reclaimed once all references are gone.

use lazarus_core::capture::persist::{FingerprintPersister, sharded_key};
use lazarus_core::catalog::index::CatalogIndex;
use lazarus_core::encryption::key_manager::KeyManager;
use lazarus_core::snapshot::dedup::DedupTable;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;

#[tokio::test]
async fn fingerprint_chunk_survives_partial_prune() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();

    let (keys, _cfg) = KeyManager::init_repository("pw").unwrap();
    let catalog = CatalogIndex::new(repo.join("catalog.db")).unwrap();
    let dedup = DedupTable::open(repo.join("catalog.db")).unwrap();
    let storage = LocalStorage::new(repo.join("data"));

    // Build a dummy fingerprint.
    let fp = lazarus_core::capture::system::SystemFingerprint {
        version: 1,
        captured_at_epoch_s: 100,
        captured_by: "test".into(),
        hostname: "host".into(),
        fqdn: None,
        machine_id: Some("m1".into()),
        kernel: Default::default(),
        cpu: Default::default(),
        memory_bytes: 0,
        disks: vec![],
        lvm: None,
        mdadm: None,
        filesystems: vec![],
        fstab: String::new(),
        crypttab: None,
        network: Default::default(),
        bootloader: Default::default(),
        packages: Default::default(),
        services: vec![],
        users: lazarus_core::capture::users::UserDatabaseRef::empty(),
        ssh_host_keys: lazarus_core::capture::secrets::SshHostKeysRef::empty(),
        firmware: Default::default(),
        warnings: vec![],
    };

    // Persist under snap-1.
    let p1 = FingerprintPersister::new(&storage, &keys, &catalog, &dedup, "snap-1", false);
    let hash = p1.persist_fingerprint(&fp).await.unwrap();

    // Register the same chunk under snap-2 by persisting again.
    let p2 = FingerprintPersister::new(&storage, &keys, &catalog, &dedup, "snap-2", false);
    let hash2 = p2.persist_fingerprint(&fp).await.unwrap();
    assert_eq!(hash, hash2, "same fingerprint should produce the same hash");

    // Both snapshots reference the chunk.
    assert_eq!(dedup.refcount(&hash_to_bytes(&hash)).unwrap(), 2);

    // Prune snap-1: chunk should survive (still referenced by snap-2).
    let freed = dedup.remove_snapshot_references("snap-1").unwrap();
    assert!(
        freed.is_empty(),
        "chunk should not be freed while snap-2 still references it"
    );
    let key = sharded_key(&hash);
    assert!(
        storage.get(&key).await.is_ok(),
        "chunk should still exist on disk"
    );

    // Prune snap-2: chunk should become reclaimable.
    let freed = dedup.remove_snapshot_references("snap-2").unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0], hash_to_bytes(&hash));

    // Delete the chunk from storage (what prune would do).
    storage.delete(&key).await.unwrap();
    assert!(
        storage.get(&key).await.is_err(),
        "chunk should be gone from disk"
    );
}

fn hash_to_bytes(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
