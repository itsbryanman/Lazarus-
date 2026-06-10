use clap::Args;
use lazarus_core::capture::persist::sharded_key;
use lazarus_core::catalog::index::{CatalogIndex, ObjectType};
use lazarus_core::catalog::metadata::MetadataStore;
use lazarus_core::config::ConfigManager;
use lazarus_core::error::Result;
use lazarus_core::snapshot::dedup::DedupTable;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Args)]
pub struct PruneArgs {
    #[arg(short, long, help = "Repository path")]
    pub repository: String,

    #[arg(short, long, help = "Master password for decryption")]
    pub password: String,

    #[arg(long, default_value_t = 5, help = "Keep the newest N snapshots")]
    pub keep_last: usize,

    #[arg(
        long,
        default_value_t = 30,
        help = "Keep snapshots newer than this many days"
    )]
    pub keep_days: u64,

    #[arg(long, action = clap::ArgAction::SetTrue, help = "Simulate deletions without removing data")]
    pub dry_run: bool,
}

pub async fn prune(args: &PruneArgs) -> Result<()> {
    println!("Starting prune operation");

    let config_mgr = ConfigManager::new(&args.repository);
    let key_manager = config_mgr.open_repository(&args.password).await?;
    let catalog = CatalogIndex::new(config_mgr.database_path())?;
    let storage = LocalStorage::new(config_mgr.data_path());
    let dedup = DedupTable::open(config_mgr.database_path())?;
    let meta_store = MetadataStore::open(config_mgr.repo_path(), *key_manager.get_metadata_key());

    let snapshots = catalog.list_snapshots()?;
    if snapshots.is_empty() {
        println!("No snapshots found; nothing to prune.");
        return Ok(());
    }

    let keep_snapshots = select_snapshots_to_keep(&snapshots, args.keep_last, args.keep_days);
    println!(
        "Retention policy will keep {}/{} snapshots",
        keep_snapshots.len(),
        snapshots.len()
    );

    if keep_snapshots.is_empty() {
        println!("Warning: retention policy matched zero snapshots; all chunks may be pruned");
    }

    // Derive the set of dropped snapshots.
    let kept: HashSet<&String> = keep_snapshots.iter().collect();
    let dropped_snapshots: Vec<&String> = snapshots
        .iter()
        .map(|(id, _)| id)
        .filter(|id| !kept.contains(id))
        .collect();

    let mut active_chunks = HashSet::new();
    let mut visited_objects = HashSet::new();
    for snapshot_id in &keep_snapshots {
        if let Some((root_object_id, _)) = catalog.get_snapshot(snapshot_id)? {
            mark_object_chunks(
                &catalog,
                root_object_id,
                &mut visited_objects,
                &mut active_chunks,
            )?;
        }
    }

    // --- Catalog-tracked chunk pruning ---
    let all_chunks = catalog.list_all_chunk_hashes()?;
    let reclaimable: Vec<String> = all_chunks
        .into_iter()
        .filter(|hash| !active_chunks.contains(hash))
        .collect();

    // --- DedupTable-only chunk pruning (fingerprint chunks) ---
    let dedup_reclaimable: Vec<String> = if args.dry_run {
        let mut dropped_refs_by_hash: HashMap<String, usize> = HashMap::new();
        for id in &dropped_snapshots {
            for hex in dedup.chunks_for_snapshot(id)? {
                *dropped_refs_by_hash.entry(hex).or_insert(0) += 1;
            }
        }

        let mut would_free = Vec::new();
        for (hex, dropped_refs) in dropped_refs_by_hash {
            if let Some(bytes) = hex_to_array(&hex) {
                let current_refs = dedup.refcount(&bytes)? as usize;
                if current_refs == dropped_refs && !reclaimable.iter().any(|r| r == &hex) {
                    would_free.push(hex);
                }
            }
        }
        would_free
    } else {
        let mut freed = Vec::new();
        for id in &dropped_snapshots {
            let newly_free = dedup.remove_snapshot_references(id)?;
            for hash in newly_free {
                let hex = hash
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                if !reclaimable.iter().any(|r| r == &hex) {
                    freed.push(hex);
                }
            }
        }
        freed
    };

    let total_reclaimable = reclaimable.len() + dedup_reclaimable.len();

    println!(
        "Identified {} orphan chunk(s) ({} catalog, {} fingerprint/dedup-only)",
        total_reclaimable,
        reclaimable.len(),
        dedup_reclaimable.len()
    );

    if args.dry_run {
        for hash in &reclaimable {
            println!("  would delete chunk {}", hash);
        }
        for hash in &dedup_reclaimable {
            println!("  would delete fingerprint chunk {}", hash);
        }
        for id in &dropped_snapshots {
            println!("  would drop snapshot {}", id);
        }
        return Ok(());
    }

    if total_reclaimable == 0 {
        // Still need to clean up dropped snapshot rows and metadata.
        for id in &dropped_snapshots {
            catalog.delete_snapshot(id)?;
            let _ = meta_store.delete(id);
        }
        println!("No orphan chunks found; dropped snapshot rows cleaned up.");
        return Ok(());
    }

    let mut removed = 0usize;

    // Delete catalog-tracked orphan chunks.
    for hash in reclaimable {
        let key = sharded_key(&hash);
        match storage.delete(&key).await {
            Ok(_) => {
                catalog.delete_file_chunks_by_hash(&hash)?;
                catalog.delete_chunk(&hash)?;
                removed += 1;
                println!("  deleted chunk {}", hash);
            }
            Err(err) => {
                eprintln!(
                    "Warning: failed to delete chunk {} from storage: {}",
                    hash, err
                );
            }
        }
    }

    // Delete dedup-only (fingerprint/sensitive blob) orphan chunks.
    for hash in dedup_reclaimable {
        let key = sharded_key(&hash);
        match storage.delete(&key).await {
            Ok(_) => {
                removed += 1;
                println!("  deleted fingerprint chunk {}", hash);
            }
            Err(err) => {
                eprintln!(
                    "Warning: failed to delete fingerprint chunk {} from storage: {}",
                    hash, err
                );
            }
        }
    }

    // Clean up dropped snapshot catalog rows and metadata sidecar entries.
    for id in &dropped_snapshots {
        catalog.delete_snapshot(id)?;
        let _ = meta_store.delete(id);
    }

    println!("Prune complete. Removed {} chunk(s)", removed);
    Ok(())
}

fn hex_to_array(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn select_snapshots_to_keep(
    snapshots: &[(String, u64)],
    keep_last: usize,
    keep_days: u64,
) -> HashSet<String> {
    let mut keep = HashSet::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();
    let cutoff = if keep_days == 0 {
        0
    } else {
        now.saturating_sub(keep_days * 86_400)
    };

    for (idx, (snapshot_id, timestamp)) in snapshots.iter().enumerate() {
        if idx < keep_last {
            keep.insert(snapshot_id.clone());
            continue;
        }
        if keep_days > 0 && *timestamp >= cutoff {
            keep.insert(snapshot_id.clone());
        }
    }

    keep
}

fn mark_object_chunks(
    catalog: &CatalogIndex,
    object_id: i64,
    visited_objects: &mut HashSet<i64>,
    active_chunks: &mut HashSet<String>,
) -> Result<()> {
    if !visited_objects.insert(object_id) {
        return Ok(());
    }

    let (obj_type, _) = match catalog.get_object(object_id)? {
        Some(data) => data,
        None => return Ok(()),
    };

    match obj_type {
        ObjectType::File => {
            for chunk_hash in catalog.get_file_chunks(object_id)? {
                active_chunks.insert(chunk_hash);
            }
        }
        ObjectType::BlockDevice => {
            for extent in catalog.get_block_layout(object_id)?.extents {
                for chunk in extent.chunks {
                    active_chunks.insert(chunk.hash);
                }
            }
        }
        ObjectType::Directory => {
            for (child_id, _) in catalog.get_tree_children(object_id)? {
                mark_object_chunks(catalog, child_id, visited_objects, active_chunks)?;
            }
        }
        ObjectType::SystemFingerprint => {
            // SystemFingerprint chunks are referenced via the
            // DedupTable directly at capture time (see
            // FingerprintPersister); there are no per-object chunk
            // rows to mark from the catalog side.
        }
    }

    Ok(())
}
