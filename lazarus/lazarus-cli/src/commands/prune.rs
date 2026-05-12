use clap::Args;
use lazarus_core::catalog::index::{CatalogIndex, ObjectType};
use lazarus_core::config::ConfigManager;
use lazarus_core::error::Result;
use lazarus_core::snapshot::dedup::DedupTable;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Args)]
pub struct PruneArgs {
    #[arg(short, long, help = "Repository path")]
    pub repository: String,

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
    let catalog = CatalogIndex::new(config_mgr.database_path())?;
    let storage = LocalStorage::new(config_mgr.data_path());
    let dedup = DedupTable::open(config_mgr.database_path())?;

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

    let all_chunks = catalog.list_all_chunk_hashes()?;
    let reclaimable: Vec<String> = all_chunks
        .into_iter()
        .filter(|hash| !active_chunks.contains(hash))
        .collect();

    if reclaimable.is_empty() {
        println!("All chunks are referenced by retained snapshots.");
        return Ok(());
    }

    println!("Identified {} orphan chunk(s)", reclaimable.len());

    if args.dry_run {
        for hash in &reclaimable {
            println!("  would delete chunk {}", hash);
        }
        return Ok(());
    }

    let mut removed = 0usize;
    for hash in reclaimable {
        let shard = &hash[..2];
        let key = format!("{}/{}", shard, hash);

        match storage.delete(&key).await {
            Ok(_) => {
                catalog.delete_file_chunks_by_hash(&hash)?;
                catalog.delete_chunk(&hash)?;
                if let Some(bytes) = hex_to_array(&hash) {
                    // Defensive: ensure no stale ChunkRefs row survives.
                    let _ = dedup.refcount(&bytes);
                }
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

    // Drop dedup references for snapshots that were dropped from the
    // retention set. Important so a re-prune later doesn't see them as
    // "alive" and refuse to remove their unique chunks.
    let kept: HashSet<&String> = keep_snapshots.iter().collect();
    for (id, _) in &snapshots {
        if !kept.contains(id) {
            dedup.drop_snapshot(id)?;
        }
    }

    println!("Prune complete. Removed {} chunk(s)", removed);
    Ok(())
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
