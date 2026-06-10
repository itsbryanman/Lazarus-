use crate::error::{LazarusError, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Type of object in the catalog
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    File = 0,
    Directory = 1,
    BlockDevice = 2,
    SystemFingerprint = 3,
}

/// Metadata for a file or directory object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    pub name: String,
    #[serde(default)]
    pub mode: u32,
    pub size: u64,
    #[serde(default, alias = "modified")]
    pub mtime: u64,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
}

/// Catalog database for managing backups
pub struct CatalogIndex {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExtentChunk {
    pub chunk_idx: u64,
    pub hash: String,
    pub rel_offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExtent {
    pub extent_idx: u64,
    pub offset: u64,
    pub length: u64,
    pub chunks: Vec<BlockExtentChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockLayout {
    pub object_id: i64,
    pub extents: Vec<BlockExtent>,
}

impl CatalogIndex {
    /// Create a new catalog or open an existing one
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn =
            Connection::open(db_path).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        conn.pragma_update(None, "journal_mode", &"WAL")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        conn.pragma_update(None, "synchronous", &"NORMAL")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        conn.pragma_update(None, "foreign_keys", &"ON")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let catalog = Self { conn };
        catalog.init_schema()?;
        Ok(catalog)
    }

    /// Initialize the database schema
    fn init_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(
                r#"
            CREATE TABLE IF NOT EXISTS Chunks (
                hash TEXT PRIMARY KEY,
                stored_size INTEGER NOT NULL,
                uncompressed_size INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS Objects (
                object_id INTEGER PRIMARY KEY AUTOINCREMENT,
                type INTEGER NOT NULL,
                metadata BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS Tree (
                parent_object_id INTEGER NOT NULL,
                child_object_id INTEGER NOT NULL,
                encrypted_name BLOB NOT NULL,
                PRIMARY KEY (parent_object_id, encrypted_name),
                FOREIGN KEY (parent_object_id) REFERENCES Objects(object_id),
                FOREIGN KEY (child_object_id) REFERENCES Objects(object_id)
            );

            CREATE TABLE IF NOT EXISTS FileChunks (
                file_object_id INTEGER NOT NULL,
                chunk_hash TEXT NOT NULL,
                chunk_order INTEGER NOT NULL,
                PRIMARY KEY (file_object_id, chunk_order),
                FOREIGN KEY (file_object_id) REFERENCES Objects(object_id),
                FOREIGN KEY (chunk_hash) REFERENCES Chunks(hash)
            );

            CREATE TABLE IF NOT EXISTS BlockExtents (
                object_id INTEGER NOT NULL,
                extent_idx INTEGER NOT NULL,
                extent_offset INTEGER NOT NULL,
                extent_len INTEGER NOT NULL,
                PRIMARY KEY (object_id, extent_idx),
                FOREIGN KEY (object_id) REFERENCES Objects(object_id)
            );

            CREATE TABLE IF NOT EXISTS BlockExtentChunks (
                object_id INTEGER NOT NULL,
                extent_idx INTEGER NOT NULL,
                chunk_idx INTEGER NOT NULL,
                chunk_hash TEXT NOT NULL,
                rel_offset INTEGER NOT NULL,
                chunk_len INTEGER NOT NULL,
                PRIMARY KEY (object_id, extent_idx, chunk_idx),
                FOREIGN KEY (object_id, extent_idx) REFERENCES BlockExtents(object_id, extent_idx),
                FOREIGN KEY (chunk_hash) REFERENCES Chunks(hash)
            );

            CREATE TABLE IF NOT EXISTS Snapshots (
                snapshot_id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                root_object_id INTEGER NOT NULL,
                metadata BLOB NOT NULL,
                FOREIGN KEY (root_object_id) REFERENCES Objects(object_id)
            );

            CREATE INDEX IF NOT EXISTS idx_chunks_hash ON Chunks(hash);
            CREATE INDEX IF NOT EXISTS idx_filechunks_file ON FileChunks(file_object_id);
            CREATE INDEX IF NOT EXISTS idx_block_extents_object ON BlockExtents(object_id);
            CREATE INDEX IF NOT EXISTS idx_block_extent_chunks_object ON BlockExtentChunks(object_id);
            CREATE INDEX IF NOT EXISTS idx_block_extent_chunks_hash ON BlockExtentChunks(chunk_hash);
            CREATE INDEX IF NOT EXISTS idx_tree_parent ON Tree(parent_object_id);
            CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON Snapshots(timestamp);

            CREATE TABLE IF NOT EXISTS CatalogSchemaVersion (
                version INTEGER PRIMARY KEY
            );
            INSERT OR IGNORE INTO CatalogSchemaVersion(version) VALUES (2);
            "#,
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Insert or get a chunk by hash
    pub fn upsert_chunk(
        &self,
        hash: &str,
        stored_size: usize,
        uncompressed_size: usize,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO Chunks (hash, stored_size, uncompressed_size) VALUES (?1, ?2, ?3)",
            params![hash, stored_size as i64, uncompressed_size as i64],
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Check if a chunk exists
    pub fn chunk_exists(&self, hash: &str) -> Result<bool> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM Chunks WHERE hash = ?1",
                params![hash],
                |row| row.get(0),
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(count > 0)
    }

    /// Create a new object (file or directory)
    pub fn create_object(&self, obj_type: ObjectType, encrypted_metadata: &[u8]) -> Result<i64> {
        self.conn
            .execute(
                "INSERT INTO Objects (type, metadata) VALUES (?1, ?2)",
                params![obj_type as i32, encrypted_metadata],
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Add a tree entry (link parent directory to child)
    pub fn add_tree_entry(
        &self,
        parent_id: i64,
        child_id: i64,
        encrypted_name: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO Tree (parent_object_id, child_object_id, encrypted_name) VALUES (?1, ?2, ?3)",
            params![parent_id, child_id, encrypted_name],
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Add a file chunk mapping
    pub fn add_file_chunk(&self, file_id: i64, chunk_hash: &str, order: usize) -> Result<()> {
        self.conn.execute(
            "INSERT INTO FileChunks (file_object_id, chunk_hash, chunk_order) VALUES (?1, ?2, ?3)",
            params![file_id, chunk_hash, order as i64],
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    pub fn add_block_extent(
        &self,
        object_id: i64,
        extent_idx: u64,
        offset: u64,
        length: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO BlockExtents (object_id, extent_idx, extent_offset, extent_len) VALUES (?1, ?2, ?3, ?4)",
            params![object_id, extent_idx as i64, offset as i64, length as i64],
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    pub fn add_block_extent_chunk(
        &self,
        object_id: i64,
        extent_idx: u64,
        chunk_idx: u64,
        chunk_hash: &str,
        rel_offset: u64,
        length: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO BlockExtentChunks (object_id, extent_idx, chunk_idx, chunk_hash, rel_offset, chunk_len) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                object_id,
                extent_idx as i64,
                chunk_idx as i64,
                chunk_hash,
                rel_offset as i64,
                length as i64
            ],
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Create a new snapshot
    pub fn create_snapshot(
        &self,
        snapshot_id: &str,
        timestamp: u64,
        root_object_id: i64,
        encrypted_metadata: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO Snapshots (snapshot_id, timestamp, root_object_id, metadata) VALUES (?1, ?2, ?3, ?4)",
            params![snapshot_id, timestamp as i64, root_object_id, encrypted_metadata],
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// List all snapshots
    pub fn list_snapshots(&self) -> Result<Vec<(String, u64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT snapshot_id, timestamp FROM Snapshots ORDER BY timestamp DESC")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let snapshots = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for snapshot in snapshots {
            result.push(snapshot.map_err(|e| LazarusError::DatabaseError(e.to_string()))?);
        }

        Ok(result)
    }

    /// Get snapshot details
    pub fn get_snapshot(&self, snapshot_id: &str) -> Result<Option<(i64, Vec<u8>)>> {
        let result = self.conn.query_row(
            "SELECT root_object_id, metadata FROM Snapshots WHERE snapshot_id = ?1",
            params![snapshot_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        );

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LazarusError::DatabaseError(e.to_string())),
        }
    }

    /// Get object metadata
    pub fn get_object(&self, object_id: i64) -> Result<Option<(ObjectType, Vec<u8>)>> {
        let result = self.conn.query_row(
            "SELECT type, metadata FROM Objects WHERE object_id = ?1",
            params![object_id],
            |row| {
                let obj_type = match row.get::<_, i32>(0)? {
                    0 => ObjectType::File,
                    1 => ObjectType::Directory,
                    2 => ObjectType::BlockDevice,
                    3 => ObjectType::SystemFingerprint,
                    other => {
                        eprintln!(
                            "warning: unknown ObjectType integer {}; defaulting to File",
                            other
                        );
                        ObjectType::File
                    }
                };
                Ok((obj_type, row.get::<_, Vec<u8>>(1)?))
            },
        );

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LazarusError::DatabaseError(e.to_string())),
        }
    }

    /// Get children of a directory object
    pub fn get_tree_children(&self, parent_id: i64) -> Result<Vec<(i64, Vec<u8>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT child_object_id, encrypted_name FROM Tree WHERE parent_object_id = ?1")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let children = stmt
            .query_map(params![parent_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for child in children {
            result.push(child.map_err(|e| LazarusError::DatabaseError(e.to_string()))?);
        }

        Ok(result)
    }

    /// Get file chunks in order
    pub fn get_file_chunks(&self, file_id: i64) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT chunk_hash FROM FileChunks WHERE file_object_id = ?1 ORDER BY chunk_order",
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let chunks = stmt
            .query_map(params![file_id], |row| row.get::<_, String>(0))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for chunk in chunks {
            result.push(chunk.map_err(|e| LazarusError::DatabaseError(e.to_string()))?);
        }

        Ok(result)
    }

    pub fn get_block_extents(&self, object_id: i64) -> Result<Vec<(u64, u64, u64)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT extent_idx, extent_offset, extent_len FROM BlockExtents WHERE object_id = ?1 ORDER BY extent_idx",
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let extents = stmt
            .query_map(params![object_id], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for extent in extents {
            result.push(extent.map_err(|e| LazarusError::DatabaseError(e.to_string()))?);
        }

        Ok(result)
    }

    pub fn get_block_extent_chunks(
        &self,
        object_id: i64,
        extent_idx: u64,
    ) -> Result<Vec<(u64, String, u64, u64)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT chunk_idx, chunk_hash, rel_offset, chunk_len FROM BlockExtentChunks WHERE object_id = ?1 AND extent_idx = ?2 ORDER BY chunk_idx",
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let chunks = stmt
            .query_map(params![object_id, extent_idx as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, i64>(3)? as u64,
                ))
            })
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for chunk in chunks {
            result.push(chunk.map_err(|e| LazarusError::DatabaseError(e.to_string()))?);
        }

        Ok(result)
    }

    pub fn get_block_layout(&self, object_id: i64) -> Result<BlockLayout> {
        let mut extents = Vec::new();
        for (extent_idx, offset, length) in self.get_block_extents(object_id)? {
            let chunks = self
                .get_block_extent_chunks(object_id, extent_idx)?
                .into_iter()
                .map(|(chunk_idx, hash, rel_offset, length)| BlockExtentChunk {
                    chunk_idx,
                    hash,
                    rel_offset,
                    length,
                })
                .collect();
            extents.push(BlockExtent {
                extent_idx,
                offset,
                length,
                chunks,
            });
        }

        Ok(BlockLayout { object_id, extents })
    }

    /// Get total storage statistics
    pub fn get_stats(&self) -> Result<(usize, usize, usize)> {
        let chunk_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM Chunks", [], |row| row.get(0))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let object_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM Objects", [], |row| row.get(0))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let snapshot_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM Snapshots", [], |row| row.get(0))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        Ok((
            chunk_count as usize,
            object_count as usize,
            snapshot_count as usize,
        ))
    }

    /// List all chunk hashes in the catalog
    pub fn list_all_chunk_hashes(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT hash FROM Chunks")
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        let chunks = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for chunk in chunks {
            result.push(chunk.map_err(|e| LazarusError::DatabaseError(e.to_string()))?);
        }
        Ok(result)
    }

    /// Remove all file chunk references to a specific chunk hash
    pub fn delete_file_chunks_by_hash(&self, hash: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM FileChunks WHERE chunk_hash = ?1",
                params![hash],
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        self.conn
            .execute(
                "DELETE FROM BlockExtentChunks WHERE chunk_hash = ?1",
                params![hash],
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Remove a chunk record from the catalog
    pub fn delete_chunk(&self, hash: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM Chunks WHERE hash = ?1", params![hash])
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Remove a snapshot and its associated objects from the catalog.
    pub fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM Snapshots WHERE snapshot_id = ?1",
                params![snapshot_id],
            )
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_catalog() -> (tempfile::TempDir, CatalogIndex) {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("catalog.db");
        let catalog = CatalogIndex::new(&db_path).unwrap();
        (temp_dir, catalog)
    }

    #[test]
    fn test_chunk_operations() {
        let (_dir, catalog) = create_test_catalog();

        // Insert a chunk
        let hash = "abc123";
        catalog.upsert_chunk(hash, 100, 200).unwrap();

        // Check if chunk exists
        assert!(catalog.chunk_exists(hash).unwrap());

        // Check non-existent chunk
        assert!(!catalog.chunk_exists("nonexistent").unwrap());

        // Upsert same chunk again (should not error)
        catalog.upsert_chunk(hash, 100, 200).unwrap();
    }

    #[test]
    fn test_object_operations() {
        let (_dir, catalog) = create_test_catalog();

        // Create a file object
        let metadata = b"encrypted metadata";
        let file_id = catalog.create_object(ObjectType::File, metadata).unwrap();
        assert!(file_id > 0);

        // Create a directory object
        let dir_id = catalog
            .create_object(ObjectType::Directory, metadata)
            .unwrap();
        assert!(dir_id > 0);
        assert_ne!(file_id, dir_id);

        // Retrieve file object
        let (obj_type, obj_metadata) = catalog.get_object(file_id).unwrap().unwrap();
        assert_eq!(obj_type, ObjectType::File);
        assert_eq!(obj_metadata, metadata);

        // Retrieve directory object
        let (obj_type, _) = catalog.get_object(dir_id).unwrap().unwrap();
        assert_eq!(obj_type, ObjectType::Directory);

        // Non-existent object
        assert!(catalog.get_object(9999).unwrap().is_none());
    }

    #[test]
    fn test_tree_operations() {
        let (_dir, catalog) = create_test_catalog();

        // Create parent and child objects
        let parent_id = catalog
            .create_object(ObjectType::Directory, b"parent")
            .unwrap();
        let child_id = catalog.create_object(ObjectType::File, b"child").unwrap();

        // Add tree entry
        let encrypted_name = b"encrypted_filename";
        catalog
            .add_tree_entry(parent_id, child_id, encrypted_name)
            .unwrap();

        // Get children
        let children = catalog.get_tree_children(parent_id).unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].0, child_id);
        assert_eq!(children[0].1, encrypted_name);
    }

    #[test]
    fn test_file_chunks() {
        let (_dir, catalog) = create_test_catalog();

        // Create chunks
        catalog.upsert_chunk("chunk1", 100, 200).unwrap();
        catalog.upsert_chunk("chunk2", 150, 250).unwrap();
        catalog.upsert_chunk("chunk3", 120, 220).unwrap();

        // Create file object
        let file_id = catalog.create_object(ObjectType::File, b"file").unwrap();

        // Add file chunks in specific order
        catalog.add_file_chunk(file_id, "chunk1", 0).unwrap();
        catalog.add_file_chunk(file_id, "chunk2", 1).unwrap();
        catalog.add_file_chunk(file_id, "chunk3", 2).unwrap();

        // Retrieve file chunks
        let chunks = catalog.get_file_chunks(file_id).unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], "chunk1");
        assert_eq!(chunks[1], "chunk2");
        assert_eq!(chunks[2], "chunk3");
    }

    #[test]
    fn test_block_extent_manifest_round_trip() {
        let (_dir, catalog) = create_test_catalog();
        catalog.upsert_chunk("chunk1", 100, 200).unwrap();
        catalog.upsert_chunk("chunk2", 150, 250).unwrap();

        let object_id = catalog
            .create_object(ObjectType::BlockDevice, b"block")
            .unwrap();
        catalog.add_block_extent(object_id, 0, 4096, 450).unwrap();
        catalog
            .add_block_extent_chunk(object_id, 0, 0, "chunk1", 0, 200)
            .unwrap();
        catalog
            .add_block_extent_chunk(object_id, 0, 1, "chunk2", 200, 250)
            .unwrap();

        let extents = catalog.get_block_extents(object_id).unwrap();
        assert_eq!(extents, vec![(0, 4096, 450)]);

        let chunks = catalog.get_block_extent_chunks(object_id, 0).unwrap();
        assert_eq!(
            chunks,
            vec![
                (0, "chunk1".to_string(), 0, 200),
                (1, "chunk2".to_string(), 200, 250)
            ]
        );

        let layout = catalog.get_block_layout(object_id).unwrap();
        assert_eq!(layout.extents.len(), 1);
        assert_eq!(layout.extents[0].offset, 4096);
        assert_eq!(layout.extents[0].chunks.len(), 2);
    }

    #[test]
    fn test_snapshot_operations() {
        let (_dir, catalog) = create_test_catalog();

        // Create root object
        let root_id = catalog
            .create_object(ObjectType::Directory, b"root")
            .unwrap();

        // Create snapshot
        let snapshot_id = "snapshot-123";
        let timestamp = 1234567890u64;
        let metadata = b"snapshot metadata";
        catalog
            .create_snapshot(snapshot_id, timestamp, root_id, metadata)
            .unwrap();

        // List snapshots
        let snapshots = catalog.list_snapshots().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].0, snapshot_id);
        assert_eq!(snapshots[0].1, timestamp);

        // Get snapshot details
        let (retrieved_root_id, retrieved_metadata) =
            catalog.get_snapshot(snapshot_id).unwrap().unwrap();
        assert_eq!(retrieved_root_id, root_id);
        assert_eq!(retrieved_metadata, metadata);

        // Non-existent snapshot
        assert!(catalog.get_snapshot("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_stats() {
        let (_dir, catalog) = create_test_catalog();

        // Initially empty
        let (chunks, objects, snapshots) = catalog.get_stats().unwrap();
        assert_eq!(chunks, 0);
        assert_eq!(objects, 0);
        assert_eq!(snapshots, 0);

        // Add some data
        catalog.upsert_chunk("chunk1", 100, 200).unwrap();
        catalog.upsert_chunk("chunk2", 150, 250).unwrap();
        let obj_id = catalog.create_object(ObjectType::File, b"file").unwrap();
        catalog
            .create_snapshot("snap1", 123, obj_id, b"meta")
            .unwrap();

        // Check stats
        let (chunks, objects, snapshots) = catalog.get_stats().unwrap();
        assert_eq!(chunks, 2);
        assert_eq!(objects, 1);
        assert_eq!(snapshots, 1);
    }

    #[test]
    fn test_list_all_chunk_hashes() {
        let (_dir, catalog) = create_test_catalog();

        // Add multiple chunks
        catalog.upsert_chunk("hash1", 100, 200).unwrap();
        catalog.upsert_chunk("hash2", 150, 250).unwrap();
        catalog.upsert_chunk("hash3", 120, 220).unwrap();

        // List all hashes
        let hashes = catalog.list_all_chunk_hashes().unwrap();
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains(&"hash1".to_string()));
        assert!(hashes.contains(&"hash2".to_string()));
        assert!(hashes.contains(&"hash3".to_string()));
    }

    #[test]
    fn test_multiple_snapshots_ordering() {
        let (_dir, catalog) = create_test_catalog();

        // Create multiple snapshots with different timestamps
        let root_id = catalog
            .create_object(ObjectType::Directory, b"root")
            .unwrap();

        catalog
            .create_snapshot("snap1", 1000, root_id, b"meta1")
            .unwrap();
        catalog
            .create_snapshot("snap2", 3000, root_id, b"meta2")
            .unwrap();
        catalog
            .create_snapshot("snap3", 2000, root_id, b"meta3")
            .unwrap();

        // List should be ordered by timestamp (descending)
        let snapshots = catalog.list_snapshots().unwrap();
        assert_eq!(snapshots.len(), 3);
        assert_eq!(snapshots[0].0, "snap2"); // timestamp 3000
        assert_eq!(snapshots[1].0, "snap3"); // timestamp 2000
        assert_eq!(snapshots[2].0, "snap1"); // timestamp 1000
    }
}
