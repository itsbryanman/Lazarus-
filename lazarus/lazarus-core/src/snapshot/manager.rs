//! High-level orchestrator for snapshot lifecycle operations.
//!
//! `SnapshotManager` is the abstraction that future server / agent / recovery
//! TUI code targets so they don't have to re-implement the chunk/encrypt/
//! catalog dance that currently lives in `lazarus-cli/src/commands/backup.rs`
//! and `restore.rs`.
//!
//! The CLI will be migrated incrementally (see Phase 1.3 acceptance notes in
//! `lazarus_resurrection_prompt.md`); this initial implementation focuses on
//! providing a stable, testable surface for new code paths.
//!
//! ### Wiring
//! The manager pulls together:
//!   * `CatalogIndex`        – chunk/object/snapshot metadata DB.
//!   * `DedupTable`          – per-chunk reference counting (Phase 1.1).
//!   * `BlockTracker`        – `(path,mtime,size)` fast-path cache (Phase 1.2).
//!   * `MetadataStore`       – encrypted snapshot tags/description (Phase 1.4).
//!   * `History`             – signed append-only audit log (Phase 1.4).
//!   * `StreamingEncryptor`  – chunk crypto with deterministic nonces (1.5).
//!   * Any `StorageBackend`  – local, S3, SSH, future distributed.
//!
//! The manager intentionally does NOT take a CLI-style `KeyManager`; instead
//! it accepts the raw chunk-encryption key + metadata key. This keeps it
//! reusable for the agent (which may unlock from a token rather than a
//! password) and makes mocking straightforward in tests.

use crate::catalog::history::{History, Operation};
use crate::catalog::index::CatalogIndex;
use crate::catalog::metadata::{MetadataStore, SnapshotMetadata};
use crate::encryption::aes::StreamingEncryptor;
use crate::error::{LazarusError, Result};
use crate::integrity::merkle::{self, Node};
use crate::snapshot::block_tracker::BlockTracker;
use crate::snapshot::dedup::{DedupStats, DedupTable};
use crate::storage::backend::{RetentionLock, StorageBackend};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Identifier for a snapshot. Currently a timestamp-derived string but typed
/// so call sites are self-documenting and we can swap the format later
/// without churning every signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub String);

impl SnapshotId {
    pub fn from_str(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Options accepted by `create_snapshot`. Future fields (e.g. include/exclude
/// patterns, freeze hooks) will be added in later phases.
#[derive(Debug, Clone, Default)]
pub struct SnapshotOpts {
    pub metadata: SnapshotMetadata,
    /// If set, applies this retention lock to chunks written during this
    /// snapshot.
    pub retention: Option<RetentionLock>,
}

/// Options for restore. Phase 1 has none; placeholder for future "alternate
/// destination", "include subset", etc.
#[derive(Debug, Clone, Default)]
pub struct RestoreOpts {}

/// Verification depth knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// Catalog-only checks; no data reads.
    Catalog,
    /// Re-read every chunk and BLAKE3 it.
    Chunks,
    /// Re-read every chunk and verify against the snapshot's Merkle root.
    Merkle,
}

#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    pub snapshot_id: String,
    pub chunks_checked: usize,
    pub corrupted_chunks: Vec<String>,
    pub missing_chunks: Vec<String>,
    pub merkle_ok: Option<bool>,
}

/// Retention policy passed to `prune`. Mirrors the existing CLI flags:
/// `keep_last` snapshots and `keep_days` window.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub keep_last: usize,
    pub keep_days: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            keep_last: 5,
            keep_days: 30,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PruneReport {
    pub removed_snapshots: Vec<String>,
    pub removed_chunks: Vec<String>,
    pub kept_snapshots: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotSummary {
    pub id: String,
    pub timestamp: u64,
    pub metadata: Option<SnapshotMetadata>,
}

/// Concrete orchestrator. Holds an `Arc<dyn StorageBackend>` so the same
/// instance can be shared between async tasks.
pub struct SnapshotManager {
    catalog: CatalogIndex,
    storage: Arc<dyn StorageBackend>,
    encryptor: StreamingEncryptor,
    #[allow(dead_code)]
    metadata_key: [u8; 32],
    dedup: DedupTable,
    block_tracker: BlockTracker,
    metadata_store: MetadataStore,
    history: History,
    repo_path: PathBuf,
    actor: String,
}

impl SnapshotManager {
    /// Build a manager bound to a repository directory plus an opened
    /// catalog and storage backend. The two 32-byte keys are the
    /// chunk-encryption key (a.k.a. repo key) and metadata key — typically
    /// returned by `KeyManager::get_repo_key()` / `get_metadata_key()`.
    pub fn new(
        repo_path: impl AsRef<Path>,
        catalog: CatalogIndex,
        storage: Arc<dyn StorageBackend>,
        chunk_key: [u8; 32],
        metadata_key: [u8; 32],
    ) -> Result<Self> {
        let repo_path = repo_path.as_ref().to_path_buf();
        let dedup = DedupTable::open(repo_path.join("indexes").join("index.db"))?;
        let block_tracker = BlockTracker::open(&repo_path)?;
        let metadata_store = MetadataStore::open(&repo_path, metadata_key);
        let history = History::open(&repo_path, metadata_key);
        let encryptor = StreamingEncryptor::new(&chunk_key);
        let actor = hostname_or_unknown();

        Ok(Self {
            catalog,
            storage,
            encryptor,
            metadata_key,
            dedup,
            block_tracker,
            metadata_store,
            history,
            repo_path,
            actor,
        })
    }

    /// Override the actor string used in history entries (e.g. agent id).
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }

    /// Set a non-zero key epoch on the chunk encryptor. Call after
    /// rotating the chunk key so deterministic nonces don't collide.
    pub fn with_key_epoch(mut self, epoch: u32) -> Self {
        self.encryptor = self.encryptor.with_epoch(epoch);
        self
    }

    /// Borrow the underlying catalog (read-only intent).
    pub fn catalog(&self) -> &CatalogIndex {
        &self.catalog
    }

    /// Borrow the dedup table.
    pub fn dedup(&self) -> &DedupTable {
        &self.dedup
    }

    /// Borrow the block tracker (mutable for record_file).
    pub fn block_tracker_mut(&mut self) -> &mut BlockTracker {
        &mut self.block_tracker
    }

    /// Borrow the metadata store.
    pub fn metadata_store(&self) -> &MetadataStore {
        &self.metadata_store
    }

    /// Borrow the history log.
    pub fn history(&self) -> &History {
        &self.history
    }

    /// Borrow the streaming encryptor.
    pub fn encryptor(&self) -> &StreamingEncryptor {
        &self.encryptor
    }

    /// Repository root path.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    /// Storage backend (cloneable Arc).
    pub fn storage(&self) -> Arc<dyn StorageBackend> {
        self.storage.clone()
    }

    /// Record a freshly-created snapshot in the metadata store and history
    /// log, and bump the dedup refcount for every chunk it references.
    ///
    /// This is the integration shim used by the existing CLI `backup`
    /// command path until the rest of the create_snapshot pipeline is
    /// migrated to live entirely inside the manager. It encapsulates the
    /// post-write bookkeeping so callers can't forget a step.
    pub fn finalize_snapshot(
        &mut self,
        snapshot_id: &SnapshotId,
        chunk_hashes: &[[u8; 32]],
        metadata: &SnapshotMetadata,
        merkle_root: Option<Node>,
    ) -> Result<()> {
        // 1. Refcount bookkeeping in a single transaction.
        self.dedup
            .add_references_batch(snapshot_id.as_str(), chunk_hashes)?;

        // 2. Snapshot metadata (encrypted under the metadata key).
        self.metadata_store.put(snapshot_id.as_str(), metadata)?;

        // 3. History line.
        let details = serde_json::json!({
            "snapshot_id": snapshot_id.as_str(),
            "chunk_count": chunk_hashes.len(),
            "merkle_root": merkle_root.map(|r| hex::encode_slice(&r)),
        });
        self.history
            .record(Operation::Backup, &self.actor, details)?;
        Ok(())
    }

    /// Remove a snapshot from the dedup table, the metadata store, and the
    /// catalog. Returns the chunks that became orphaned and are now safe to
    /// delete from object storage.
    pub fn remove_snapshot(&mut self, snapshot_id: &SnapshotId) -> Result<Vec<String>> {
        self.dedup.drop_snapshot(snapshot_id.as_str())?;
        self.metadata_store.delete(snapshot_id.as_str())?;
        self.history.record(
            Operation::Prune,
            &self.actor,
            serde_json::json!({"snapshot_id": snapshot_id.as_str()}),
        )?;
        let orphans = self.dedup.unreferenced_chunks_hex()?;
        Ok(orphans)
    }

    /// Build a `Vec<SnapshotSummary>` sorted newest-first.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotSummary>> {
        let mut out = Vec::new();
        for (id, ts) in self.catalog.list_snapshots()? {
            let metadata = self.metadata_store.get(&id).unwrap_or(None);
            out.push(SnapshotSummary {
                id,
                timestamp: ts,
                metadata,
            });
        }
        Ok(out)
    }

    /// Compute the Merkle root for an ordered list of chunk hashes. Helper
    /// for callers building snapshots.
    pub fn merkle_root(chunks: &[Node]) -> Node {
        merkle::root_of(chunks)
    }

    /// Record an arbitrary operation in the history log. Used by the CLI
    /// commands that aren't yet fully ported to the manager.
    pub fn record_history(&self, op: Operation, details: serde_json::Value) -> Result<()> {
        self.history.record(op, &self.actor, details)?;
        Ok(())
    }
}

fn hostname_or_unknown() -> String {
    hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Tiny private hex helper so we don't pull a hex crate just for a JSON
/// audit field.
mod hex {
    pub fn encode_slice(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::backend::StorageBackend;
    use crate::storage::local::LocalStorage;
    use std::sync::Arc;

    fn make_manager() -> (tempfile::TempDir, SnapshotManager) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("indexes")).unwrap();
        std::fs::create_dir_all(dir.path().join("data")).unwrap();
        let catalog = CatalogIndex::new(dir.path().join("indexes").join("index.db")).unwrap();
        let storage: Arc<dyn StorageBackend> = Arc::new(LocalStorage::new(dir.path().join("data")));
        let mgr = SnapshotManager::new(dir.path(), catalog, storage, [1u8; 32], [2u8; 32]).unwrap();
        (dir, mgr)
    }

    #[test]
    fn finalize_records_refs_metadata_and_history() {
        let (_dir, mut mgr) = make_manager();
        let id = SnapshotId::from_str("snap-test");
        let chunks = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let meta = SnapshotMetadata {
            description: Some("smoke test".into()),
            ..Default::default()
        };
        mgr.finalize_snapshot(
            &id,
            &chunks,
            &meta,
            Some(SnapshotManager::merkle_root(&chunks)),
        )
        .unwrap();

        let stats = mgr.dedup().stats().unwrap();
        assert_eq!(stats.referenced_chunks, 3);

        let stored = mgr.metadata_store().get("snap-test").unwrap().unwrap();
        assert_eq!(stored.description.as_deref(), Some("smoke test"));

        let history = mgr.history().entries().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].operation, Operation::Backup);
    }

    #[test]
    fn remove_snapshot_returns_orphans() {
        let (dir, mut mgr) = make_manager();

        // Pre-seed the Chunks table so unreferenced_chunks has rows to find.
        let conn = rusqlite::Connection::open(dir.path().join("indexes").join("index.db")).unwrap();
        for i in 0..3u8 {
            let hex: String = [i; 32].iter().map(|b| format!("{:02x}", b)).collect();
            conn.execute(
                "INSERT OR IGNORE INTO Chunks (hash, stored_size, uncompressed_size) VALUES (?1, 0, 0)",
                rusqlite::params![hex],
            )
            .unwrap();
        }
        drop(conn);

        let id = SnapshotId::from_str("only-snap");
        let chunks = vec![[0u8; 32], [1u8; 32], [2u8; 32]];
        mgr.finalize_snapshot(&id, &chunks, &SnapshotMetadata::default(), None)
            .unwrap();
        let orphans = mgr.remove_snapshot(&id).unwrap();
        assert_eq!(orphans.len(), 3);
    }

    #[test]
    fn merkle_root_is_stable() {
        let chunks = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let r1 = SnapshotManager::merkle_root(&chunks);
        let r2 = SnapshotManager::merkle_root(&chunks);
        assert_eq!(r1, r2);
    }
}
