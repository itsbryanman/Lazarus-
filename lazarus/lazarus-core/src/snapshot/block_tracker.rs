//! Per-file change-detection cache used to skip re-reading files whose
//! `(path, mtime, size)` triple has not changed since the previous backup.
//!
//! When the previous snapshot's chunk list for a file is reused, the backup
//! pipeline can avoid the cost of opening, hashing and re-chunking that file —
//! the standard "fast path" in mature backup tools. Crucially, **bytes are
//! never re-hashed from this cache**; the chunk references it returns must
//! still resolve to chunks that exist in the repository for the snapshot to
//! be readable. Callers verify this when materializing the snapshot.

use crate::error::{LazarusError, Result};
use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One chunk's identity inside a tracked file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    /// BLAKE3 hash of the chunk plaintext (32 bytes).
    pub hash: [u8; 32],
    /// Position of the chunk inside the file (0-based).
    pub order: u64,
    /// Plaintext length of the chunk.
    pub length: u64,
}

/// SQLite-backed file-state cache. The DB lives at
/// `<repo_path>/indexes/block_tracker.db` so it does not contend on the main
/// catalog connection during the backup.
pub struct BlockTracker {
    conn: Connection,
}

impl BlockTracker {
    /// Open or create the block-tracker database. `repo_path` is the path to
    /// the repository root; the actual sqlite file lives in
    /// `<repo_path>/indexes/block_tracker.db`.
    pub fn open<P: AsRef<Path>>(repo_path: P) -> Result<Self> {
        let dir = repo_path.as_ref().join("indexes");
        std::fs::create_dir_all(&dir)?;
        let db_path = dir.join("block_tracker.db");
        Self::open_at(&db_path)
    }

    /// Open or create at an explicit path. Useful for tests and for the
    /// recovery TUI which may pass a non-standard layout.
    pub fn open_at<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn = Connection::open(db_path.as_ref())
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", &"WAL")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        conn.pragma_update(None, "synchronous", &"NORMAL")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        let tracker = Self { conn };
        tracker.init_schema()?;
        Ok(tracker)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS FileStates (
                    path TEXT PRIMARY KEY,
                    mtime INTEGER NOT NULL,
                    size INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
                );
                CREATE TABLE IF NOT EXISTS FileChunks (
                    path TEXT NOT NULL,
                    chunk_order INTEGER NOT NULL,
                    chunk_hash BLOB NOT NULL,
                    chunk_length INTEGER NOT NULL,
                    PRIMARY KEY (path, chunk_order),
                    FOREIGN KEY (path) REFERENCES FileStates(path) ON DELETE CASCADE
                );
                "#,
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Record the current state of a file plus its chunk list. Replaces any
    /// previous state for the same path.
    pub fn record_file(
        &mut self,
        path: &Path,
        mtime: u64,
        size: u64,
        chunks: &[ChunkRef],
    ) -> Result<()> {
        let key = path_key(path);
        let tx = self
            .conn
            .transaction()
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        tx.execute(
            "INSERT OR REPLACE INTO FileStates (path, mtime, size) VALUES (?1, ?2, ?3)",
            params![key, mtime as i64, size as i64],
        )
        .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        tx.execute("DELETE FROM FileChunks WHERE path = ?1", params![key])
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO FileChunks (path, chunk_order, chunk_hash, chunk_length) \
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
            for chunk in chunks {
                stmt.execute(params![
                    key,
                    chunk.order as i64,
                    &chunk.hash[..],
                    chunk.length as i64,
                ])
                .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
            }
        }
        tx.commit()
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// If `(path, mtime, size)` matches the recorded state, return the
    /// previous chunk list verbatim. Otherwise return `None`. The caller MUST
    /// fall back to reading and chunking the file if `None` is returned.
    pub fn lookup_unchanged(
        &self,
        path: &Path,
        mtime: u64,
        size: u64,
    ) -> Result<Option<Vec<ChunkRef>>> {
        let key = path_key(path);
        let row = self.conn.query_row(
            "SELECT mtime, size FROM FileStates WHERE path = ?1",
            params![key],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        );
        let (rec_mtime, rec_size) = match row {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(LazarusError::DatabaseError(e.to_string())),
        };
        if rec_mtime as u64 != mtime || rec_size as u64 != size {
            return Ok(None);
        }

        let mut stmt = self
            .conn
            .prepare(
                "SELECT chunk_order, chunk_hash, chunk_length FROM FileChunks \
                 WHERE path = ?1 ORDER BY chunk_order",
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        let rows = stmt
            .query_map(params![key], |row| {
                let order: i64 = row.get(0)?;
                let hash_blob: Vec<u8> = row.get(1)?;
                let length: i64 = row.get(2)?;
                Ok((order, hash_blob, length))
            })
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let mut chunks = Vec::new();
        for r in rows {
            let (order, hash_blob, length) =
                r.map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
            if hash_blob.len() != 32 {
                return Ok(None); // corrupted state — fall back to re-read
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_blob);
            chunks.push(ChunkRef {
                hash,
                order: order as u64,
                length: length as u64,
            });
        }
        Ok(Some(chunks))
    }

    /// Forget any cached state for `path`.
    pub fn forget(&self, path: &Path) -> Result<()> {
        let key = path_key(path);
        self.conn
            .execute("DELETE FROM FileStates WHERE path = ?1", params![key])
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        self.conn
            .execute("DELETE FROM FileChunks WHERE path = ?1", params![key])
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Wipe the entire cache. Used by `lazarus repo upgrade` and tests.
    pub fn clear(&self) -> Result<()> {
        self.conn
            .execute_batch("DELETE FROM FileChunks; DELETE FROM FileStates;")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Number of tracked files.
    pub fn len(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM FileStates", [], |row| row.get(0))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(n as u64)
    }
}

fn path_key(path: &Path) -> String {
    // Canonicalize when possible; fall back to the raw path otherwise.
    let canon: PathBuf = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    canon.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_tracker() -> (tempfile::TempDir, BlockTracker) {
        let dir = tempfile::tempdir().unwrap();
        let tracker = BlockTracker::open(dir.path()).unwrap();
        (dir, tracker)
    }

    fn make_chunk(order: u64, byte: u8, len: u64) -> ChunkRef {
        ChunkRef {
            hash: [byte; 32],
            order,
            length: len,
        }
    }

    #[test]
    fn record_and_lookup_match() {
        let (dir, mut tracker) = tmp_tracker();
        let f = dir.path().join("a.bin");
        std::fs::write(&f, b"hello").unwrap();
        let chunks = vec![make_chunk(0, 1, 5)];
        tracker.record_file(&f, 1234, 5, &chunks).unwrap();

        let hit = tracker.lookup_unchanged(&f, 1234, 5).unwrap();
        assert_eq!(hit, Some(chunks));
    }

    #[test]
    fn mtime_change_invalidates() {
        let (dir, mut tracker) = tmp_tracker();
        let f = dir.path().join("a.bin");
        std::fs::write(&f, b"hello").unwrap();
        tracker
            .record_file(&f, 1, 5, &[make_chunk(0, 1, 5)])
            .unwrap();
        assert!(tracker.lookup_unchanged(&f, 2, 5).unwrap().is_none());
        assert!(tracker.lookup_unchanged(&f, 1, 99).unwrap().is_none());
    }

    #[test]
    fn record_replaces_previous_chunks() {
        let (dir, mut tracker) = tmp_tracker();
        let f = dir.path().join("a.bin");
        std::fs::write(&f, b"hello world").unwrap();
        tracker
            .record_file(&f, 10, 11, &[make_chunk(0, 1, 11)])
            .unwrap();
        let new = vec![make_chunk(0, 2, 5), make_chunk(1, 3, 6)];
        tracker.record_file(&f, 11, 11, &new).unwrap();
        let hit = tracker.lookup_unchanged(&f, 11, 11).unwrap().unwrap();
        assert_eq!(hit.len(), 2);
        assert_eq!(hit[0].hash, [2u8; 32]);
        assert_eq!(hit[1].hash, [3u8; 32]);
    }

    #[test]
    fn forget_removes_state() {
        let (dir, mut tracker) = tmp_tracker();
        let f = dir.path().join("a.bin");
        std::fs::write(&f, b"x").unwrap();
        tracker
            .record_file(&f, 1, 1, &[make_chunk(0, 1, 1)])
            .unwrap();
        tracker.forget(&f).unwrap();
        assert!(tracker.lookup_unchanged(&f, 1, 1).unwrap().is_none());
    }

    #[test]
    fn unknown_file_misses() {
        let (dir, tracker) = tmp_tracker();
        let f = dir.path().join("nope.bin");
        assert!(tracker.lookup_unchanged(&f, 0, 0).unwrap().is_none());
    }
}
