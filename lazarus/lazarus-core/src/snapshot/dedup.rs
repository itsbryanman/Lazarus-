//! Chunk reference-count tracking for deduplication and safe pruning.
//!
//! `DedupTable` maintains a `chunk_hash -> snapshot_id` association table inside
//! the catalog SQLite database. Each row represents a single reference of a
//! chunk by a snapshot. The number of rows for a given `chunk_hash` is its
//! reference count, and a chunk is only safe to delete when that count drops
//! to zero.
//!
//! This module is used in two places:
//!   * `backup.rs` calls `add_reference` for every chunk that becomes part of a
//!     new snapshot (whether or not the chunk's bytes were freshly written).
//!   * `prune.rs` calls `unreferenced_chunks` to find chunks that no live
//!     snapshot references, then deletes them and calls `forget_chunk`.

use crate::error::{LazarusError, Result};
use rusqlite::{Connection, params};
use std::path::Path;

/// Aggregate statistics about the dedup table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DedupStats {
    /// Number of distinct chunk hashes that are currently referenced.
    pub referenced_chunks: u64,
    /// Total number of (chunk, snapshot) reference rows.
    pub total_references: u64,
    /// Number of distinct snapshots holding at least one reference.
    pub referencing_snapshots: u64,
}

/// SQLite-backed reference counter for chunks. The table lives in the same
/// catalog database as the rest of the snapshot index so refcount updates and
/// catalog updates can run in a single transaction.
pub struct DedupTable {
    conn: Connection,
}

impl DedupTable {
    /// Open or create a `DedupTable` at the given SQLite database path. Safe to
    /// call against an existing catalog database — it only adds tables and
    /// indexes if missing.
    pub fn open<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn = Connection::open(db_path.as_ref())
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let table = Self { conn };
        table.init_schema()?;
        Ok(table)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS ChunkRefs (
                    chunk_hash BLOB NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    PRIMARY KEY (chunk_hash, snapshot_id)
                );
                CREATE INDEX IF NOT EXISTS idx_chunkrefs_hash ON ChunkRefs(chunk_hash);
                CREATE INDEX IF NOT EXISTS idx_chunkrefs_snapshot ON ChunkRefs(snapshot_id);
                "#,
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Record that `snapshot_id` references `chunk_hash`. Idempotent: calling
    /// twice for the same pair is a no-op (and returns the current refcount).
    /// Returns the new total refcount for the chunk.
    pub fn add_reference(&self, chunk_hash: &[u8; 32], snapshot_id: &str) -> Result<u64> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO ChunkRefs (chunk_hash, snapshot_id) VALUES (?1, ?2)",
                params![&chunk_hash[..], snapshot_id],
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        self.refcount(chunk_hash)
    }

    /// Drop the reference of `snapshot_id` to `chunk_hash`. Returns the new
    /// refcount (0 if no other snapshots still reference it).
    pub fn remove_reference(&self, chunk_hash: &[u8; 32], snapshot_id: &str) -> Result<u64> {
        self.conn
            .execute(
                "DELETE FROM ChunkRefs WHERE chunk_hash = ?1 AND snapshot_id = ?2",
                params![&chunk_hash[..], snapshot_id],
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        self.refcount(chunk_hash)
    }

    /// Drop every reference held by `snapshot_id`. Useful when a snapshot is
    /// removed wholesale during prune.
    pub fn drop_snapshot(&self, snapshot_id: &str) -> Result<u64> {
        let removed = self
            .conn
            .execute(
                "DELETE FROM ChunkRefs WHERE snapshot_id = ?1",
                params![snapshot_id],
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(removed as u64)
    }

    /// Drop all references for `snapshot_id` and return the hex hashes of
    /// chunks whose refcount reached zero as a result. This is the clean
    /// shape for prune: it tells the caller exactly which chunks are now
    /// reclaimable.
    pub fn remove_snapshot_references(&self, snapshot_id: &str) -> Result<Vec<[u8; 32]>> {
        // Collect the chunk hashes this snapshot references before deleting.
        let mut stmt = self
            .conn
            .prepare("SELECT chunk_hash FROM ChunkRefs WHERE snapshot_id = ?1")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        let hashes: Vec<[u8; 32]> = stmt
            .query_map(params![snapshot_id], |row| {
                let blob: Vec<u8> = row.get(0)?;
                let mut arr = [0u8; 32];
                if blob.len() == 32 {
                    arr.copy_from_slice(&blob);
                }
                Ok(arr)
            })
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        // Drop the snapshot's references.
        self.drop_snapshot(snapshot_id)?;

        // Check which of those hashes now have refcount zero.
        let mut newly_unreferenced = Vec::new();
        for hash in &hashes {
            if self.refcount(hash)? == 0 {
                newly_unreferenced.push(*hash);
            }
        }
        Ok(newly_unreferenced)
    }

    /// Return the hex hashes of all chunks referenced by `snapshot_id`.
    pub fn chunks_for_snapshot(&self, snapshot_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT chunk_hash FROM ChunkRefs WHERE snapshot_id = ?1")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        let hashes: Vec<String> = stmt
            .query_map(params![snapshot_id], |row| {
                let blob: Vec<u8> = row.get(0)?;
                let hex: String = blob.iter().map(|b| format!("{:02x}", b)).collect();
                Ok(hex)
            })
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(hashes)
    }

    /// Current refcount for a chunk (number of snapshots that reference it).
    pub fn refcount(&self, chunk_hash: &[u8; 32]) -> Result<u64> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM ChunkRefs WHERE chunk_hash = ?1",
                params![&chunk_hash[..]],
                |row| row.get(0),
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(count as u64)
    }

    /// All chunks whose refcount is zero — i.e. not referenced by any
    /// snapshot. Caller is expected to delete them from storage and the
    /// chunks table, then call `forget_chunk`.
    pub fn unreferenced_chunks(&self) -> Result<Vec<[u8; 32]>> {
        // We surface chunks that exist in the catalog Chunks table but have no
        // surviving ChunkRefs row. The Chunks table is owned by `CatalogIndex`
        // but lives in the same DB, so a LEFT JOIN works.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT c.hash FROM Chunks c \
                 LEFT JOIN ChunkRefs r ON r.chunk_hash = c.hash_bytes \
                 WHERE r.chunk_hash IS NULL",
            )
            .ok();

        // The Chunks schema in the existing CatalogIndex stores hashes as TEXT
        // (hex), not BLOB. To keep a single source of truth, we instead look
        // up unreferenced chunks by examining hashes in the existing Chunks
        // table whose hex equivalents have no ChunkRefs row.
        if stmt.is_none() {
            stmt = Some(
                self.conn
                    .prepare(
                        "SELECT c.hash FROM Chunks c \
                         WHERE NOT EXISTS ( \
                             SELECT 1 FROM ChunkRefs r WHERE lower(hex(r.chunk_hash)) = lower(c.hash) \
                         )",
                    )
                    .map_err(|e| LazarusError::DatabaseError(e.to_string()))?,
            );
        }

        let mut stmt = stmt.unwrap();
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let mut out = Vec::new();
        for row in rows {
            let hex = row.map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
            if let Some(bytes) = hex_to_array(&hex) {
                out.push(bytes);
            }
        }
        Ok(out)
    }

    /// Convenience: list unreferenced chunks as their hex encoding (matching
    /// the format used by `CatalogIndex`).
    pub fn unreferenced_chunks_hex(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT c.hash FROM Chunks c \
                 WHERE NOT EXISTS ( \
                     SELECT 1 FROM ChunkRefs r WHERE lower(hex(r.chunk_hash)) = lower(c.hash) \
                 )",
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| LazarusError::DatabaseError(e.to_string()))?);
        }
        Ok(out)
    }

    /// Aggregate statistics over the ChunkRefs table.
    pub fn stats(&self) -> Result<DedupStats> {
        let referenced_chunks: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(DISTINCT chunk_hash) FROM ChunkRefs",
                [],
                |row| row.get(0),
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        let total_references: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM ChunkRefs", [], |row| row.get(0))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        let referencing_snapshots: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(DISTINCT snapshot_id) FROM ChunkRefs",
                [],
                |row| row.get(0),
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(DedupStats {
            referenced_chunks: referenced_chunks as u64,
            total_references: total_references as u64,
            referencing_snapshots: referencing_snapshots as u64,
        })
    }

    /// Add many references in a single transaction. Hot-path optimization for
    /// snapshots with millions of chunks.
    pub fn add_references_batch(&mut self, snapshot_id: &str, chunks: &[[u8; 32]]) -> Result<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT OR IGNORE INTO ChunkRefs (chunk_hash, snapshot_id) VALUES (?1, ?2)",
                )
                .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
            for chunk in chunks {
                stmt.execute(params![&chunk[..], snapshot_id])
                    .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
            }
        }
        tx.commit()
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn open_with_chunks_table() -> (tempfile::TempDir, DedupTable) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("catalog.db");
        // Pre-create the `Chunks` table that CatalogIndex would normally own,
        // because `unreferenced_chunks` joins against it.
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS Chunks (\
                    hash TEXT PRIMARY KEY, \
                    stored_size INTEGER NOT NULL, \
                    uncompressed_size INTEGER NOT NULL\
                );",
            )
            .unwrap();
        }
        let table = DedupTable::open(&db).unwrap();
        (dir, table)
    }

    fn h(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn hex(byte: u8) -> String {
        let h = h(byte);
        h.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn insert_chunk_row(db_path: &std::path::Path, hex_hash: &str) {
        let conn = Connection::open(db_path).unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO Chunks (hash, stored_size, uncompressed_size) VALUES (?1, 0, 0)",
            params![hex_hash],
        )
        .unwrap();
    }

    #[test]
    fn add_reference_is_idempotent() {
        let (_dir, table) = open_with_chunks_table();
        assert_eq!(table.add_reference(&h(1), "snap-a").unwrap(), 1);
        assert_eq!(table.add_reference(&h(1), "snap-a").unwrap(), 1);
        assert_eq!(table.add_reference(&h(1), "snap-b").unwrap(), 2);
    }

    #[test]
    fn remove_reference_decrements() {
        let (_dir, table) = open_with_chunks_table();
        table.add_reference(&h(2), "s1").unwrap();
        table.add_reference(&h(2), "s2").unwrap();
        assert_eq!(table.refcount(&h(2)).unwrap(), 2);
        assert_eq!(table.remove_reference(&h(2), "s1").unwrap(), 1);
        assert_eq!(table.remove_reference(&h(2), "s1").unwrap(), 1); // no-op
        assert_eq!(table.remove_reference(&h(2), "s2").unwrap(), 0);
    }

    #[test]
    fn drop_snapshot_removes_all_refs() {
        let (_dir, table) = open_with_chunks_table();
        table.add_reference(&h(1), "snap").unwrap();
        table.add_reference(&h(2), "snap").unwrap();
        table.add_reference(&h(3), "snap").unwrap();
        assert_eq!(table.drop_snapshot("snap").unwrap(), 3);
        assert_eq!(table.refcount(&h(1)).unwrap(), 0);
    }

    #[test]
    fn unreferenced_chunks_lists_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("catalog.db");
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS Chunks (hash TEXT PRIMARY KEY, stored_size INTEGER NOT NULL, uncompressed_size INTEGER NOT NULL);",
            )
            .unwrap();
        }
        insert_chunk_row(&db, &hex(1));
        insert_chunk_row(&db, &hex(2));
        insert_chunk_row(&db, &hex(3));

        let table = DedupTable::open(&db).unwrap();
        table.add_reference(&h(1), "snap-x").unwrap();

        let orphans = table.unreferenced_chunks_hex().unwrap();
        assert_eq!(orphans.len(), 2);
        assert!(orphans.contains(&hex(2)));
        assert!(orphans.contains(&hex(3)));
        assert!(!orphans.contains(&hex(1)));
    }

    #[test]
    fn stats_reflect_state() {
        let (_dir, table) = open_with_chunks_table();
        table.add_reference(&h(1), "s1").unwrap();
        table.add_reference(&h(1), "s2").unwrap();
        table.add_reference(&h(2), "s1").unwrap();
        let s = table.stats().unwrap();
        assert_eq!(s.referenced_chunks, 2);
        assert_eq!(s.total_references, 3);
        assert_eq!(s.referencing_snapshots, 2);
    }

    #[test]
    fn batch_insert_works() {
        let (_dir, mut table) = open_with_chunks_table();
        let chunks = vec![h(1), h(2), h(3), h(1)];
        table.add_references_batch("snap-batch", &chunks).unwrap();
        assert_eq!(table.refcount(&h(1)).unwrap(), 1);
        assert_eq!(table.refcount(&h(2)).unwrap(), 1);
        assert_eq!(table.refcount(&h(3)).unwrap(), 1);
    }
}
