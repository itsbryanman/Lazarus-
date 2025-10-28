use crate::error::{Result, LazarusError};
use rusqlite::{Connection, params};
use std::path::Path;
use serde::{Deserialize, Serialize};

/// Type of object in the catalog
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    File = 0,
    Directory = 1,
}

/// Metadata for a file or directory object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    pub name: String,
    pub mode: u32,
    pub size: u64,
    pub modified: u64,
}

/// Catalog database for managing backups
pub struct CatalogIndex {
    conn: Connection,
}

impl CatalogIndex {
    /// Create a new catalog or open an existing one
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn = Connection::open(db_path)
            .map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let catalog = Self { conn };
        catalog.init_schema()?;
        Ok(catalog)
    }

    /// Initialize the database schema
    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
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

            CREATE TABLE IF NOT EXISTS Snapshots (
                snapshot_id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                root_object_id INTEGER NOT NULL,
                metadata BLOB NOT NULL,
                FOREIGN KEY (root_object_id) REFERENCES Objects(object_id)
            );

            CREATE INDEX IF NOT EXISTS idx_chunks_hash ON Chunks(hash);
            CREATE INDEX IF NOT EXISTS idx_filechunks_file ON FileChunks(file_object_id);
            CREATE INDEX IF NOT EXISTS idx_tree_parent ON Tree(parent_object_id);
            CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON Snapshots(timestamp);
            "#
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Insert or get a chunk by hash
    pub fn upsert_chunk(&self, hash: &str, stored_size: usize, uncompressed_size: usize) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO Chunks (hash, stored_size, uncompressed_size) VALUES (?1, ?2, ?3)",
            params![hash, stored_size as i64, uncompressed_size as i64],
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Check if a chunk exists
    pub fn chunk_exists(&self, hash: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM Chunks WHERE hash = ?1",
            params![hash],
            |row| row.get(0)
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(count > 0)
    }

    /// Create a new object (file or directory)
    pub fn create_object(&self, obj_type: ObjectType, encrypted_metadata: &[u8]) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO Objects (type, metadata) VALUES (?1, ?2)",
            params![obj_type as i32, encrypted_metadata],
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Add a tree entry (link parent directory to child)
    pub fn add_tree_entry(&self, parent_id: i64, child_id: i64, encrypted_name: &[u8]) -> Result<()> {
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

    /// Create a new snapshot
    pub fn create_snapshot(&self, snapshot_id: &str, timestamp: u64, root_object_id: i64, encrypted_metadata: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO Snapshots (snapshot_id, timestamp, root_object_id, metadata) VALUES (?1, ?2, ?3, ?4)",
            params![snapshot_id, timestamp as i64, root_object_id, encrypted_metadata],
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// List all snapshots
    pub fn list_snapshots(&self) -> Result<Vec<(String, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT snapshot_id, timestamp FROM Snapshots ORDER BY timestamp DESC"
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let snapshots = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
            ))
        }).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

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
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
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
                    _ => ObjectType::File, // Default
                };
                Ok((obj_type, row.get::<_, Vec<u8>>(1)?))
            }
        );

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LazarusError::DatabaseError(e.to_string())),
        }
    }

    /// Get children of a directory object
    pub fn get_tree_children(&self, parent_id: i64) -> Result<Vec<(i64, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT child_object_id, encrypted_name FROM Tree WHERE parent_object_id = ?1"
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let children = stmt.query_map(params![parent_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
            ))
        }).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for child in children {
            result.push(child.map_err(|e| LazarusError::DatabaseError(e.to_string()))?);
        }

        Ok(result)
    }

    /// Get file chunks in order
    pub fn get_file_chunks(&self, file_id: i64) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT chunk_hash FROM FileChunks WHERE file_object_id = ?1 ORDER BY chunk_order"
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let chunks = stmt.query_map(params![file_id], |row| {
            row.get::<_, String>(0)
        }).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for chunk in chunks {
            result.push(chunk.map_err(|e| LazarusError::DatabaseError(e.to_string()))?);
        }

        Ok(result)
    }

    /// Get total storage statistics
    pub fn get_stats(&self) -> Result<(usize, usize, usize)> {
        let chunk_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM Chunks",
            [],
            |row| row.get(0)
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let object_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM Objects",
            [],
            |row| row.get(0)
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        let snapshot_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM Snapshots",
            [],
            |row| row.get(0)
        ).map_err(|e| LazarusError::DatabaseError(e.to_string()))?;

        Ok((chunk_count as usize, object_count as usize, snapshot_count as usize))
    }
}
