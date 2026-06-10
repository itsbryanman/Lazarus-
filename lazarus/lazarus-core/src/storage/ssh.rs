use crate::error::{LazarusError, Result};
use crate::storage::backend::StorageBackend;
use async_trait::async_trait;
use ssh2::Session;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// SSH/SFTP storage backend
pub struct SshStorage {
    host: String,
    port: u16,
    username: String,
    key_path: Option<PathBuf>,
    password: Option<String>,
    remote_path: PathBuf,
    // Connection is wrapped in Arc<Mutex<>> for thread-safe shared access
    session: Arc<Mutex<Option<Session>>>,
}

impl SshStorage {
    /// Create a new SSH storage backend with password authentication
    pub async fn new(
        host: String,
        port: u16,
        username: String,
        password: String,
        remote_path: PathBuf,
    ) -> Result<Self> {
        let storage = Self {
            host,
            port,
            username,
            key_path: None,
            password: Some(password),
            remote_path,
            session: Arc::new(Mutex::new(None)),
        };

        // Test connection
        storage.connect()?;

        Ok(storage)
    }

    /// Create a new SSH storage backend with key authentication
    pub async fn new_with_key(
        host: String,
        port: u16,
        username: String,
        key_path: PathBuf,
        remote_path: PathBuf,
    ) -> Result<Self> {
        let storage = Self {
            host,
            port,
            username,
            key_path: Some(key_path),
            password: None,
            remote_path,
            session: Arc::new(Mutex::new(None)),
        };

        // Test connection
        storage.connect()?;

        Ok(storage)
    }

    /// Establish SSH connection
    fn connect(&self) -> Result<()> {
        let tcp = TcpStream::connect(format!("{}:{}", self.host, self.port)).map_err(|e| {
            LazarusError::Storage(format!("Failed to connect to SSH server: {}", e))
        })?;

        let mut sess = Session::new()
            .map_err(|e| LazarusError::Storage(format!("Failed to create SSH session: {}", e)))?;

        sess.set_tcp_stream(tcp);
        sess.handshake()
            .map_err(|e| LazarusError::Storage(format!("SSH handshake failed: {}", e)))?;

        // Authenticate
        if let Some(ref key_path) = self.key_path {
            sess.userauth_pubkey_file(&self.username, None, key_path, None)
                .map_err(|e| {
                    LazarusError::Storage(format!("SSH key authentication failed: {}", e))
                })?;
        } else if let Some(ref password) = self.password {
            sess.userauth_password(&self.username, password)
                .map_err(|e| {
                    LazarusError::Storage(format!("SSH password authentication failed: {}", e))
                })?;
        } else {
            return Err(LazarusError::Storage(
                "No authentication method provided".to_string(),
            ));
        }

        if !sess.authenticated() {
            return Err(LazarusError::Storage(
                "SSH authentication failed".to_string(),
            ));
        }

        // Store session
        let mut session_guard = self.session.lock().unwrap();
        *session_guard = Some(sess);

        Ok(())
    }

    /// Get or create a valid SFTP session
    /// Note: Since ssh2::Session doesn't implement Clone, we create a new connection each time.
    /// For production use, implement a connection pool.
    fn get_session(&self) -> Result<Session> {
        let tcp = TcpStream::connect(format!("{}:{}", self.host, self.port))
            .map_err(|e| LazarusError::Storage(format!("Failed to connect: {}", e)))?;
        let mut sess = Session::new()
            .map_err(|e| LazarusError::Storage(format!("Failed to create session: {}", e)))?;
        sess.set_tcp_stream(tcp);
        sess.handshake()
            .map_err(|e| LazarusError::Storage(format!("Handshake failed: {}", e)))?;

        if let Some(ref key_path) = self.key_path {
            sess.userauth_pubkey_file(&self.username, None, key_path, None)
                .map_err(|e| LazarusError::Storage(format!("Auth failed: {}", e)))?;
        } else if let Some(ref password) = self.password {
            sess.userauth_password(&self.username, password)
                .map_err(|e| LazarusError::Storage(format!("Auth failed: {}", e)))?;
        }

        Ok(sess)
    }

    fn get_remote_path(&self, key: &str) -> PathBuf {
        self.remote_path.join(key.trim_start_matches('/'))
    }
}

#[async_trait]
impl StorageBackend for SshStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let sess = self.get_session()?;
        let sftp = sess
            .sftp()
            .map_err(|e| LazarusError::Storage(format!("Failed to open SFTP session: {}", e)))?;

        let remote_path = self.get_remote_path(key);

        // Create parent directories if needed
        if let Some(parent) = remote_path.parent() {
            let _ = sftp.mkdir(parent, 0o755); // Ignore error if directory exists
        }

        let mut file = sftp
            .create(&remote_path)
            .map_err(|e| LazarusError::Storage(format!("Failed to create remote file: {}", e)))?;

        file.write_all(data)
            .map_err(|e| LazarusError::Storage(format!("Failed to write data: {}", e)))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let sess = self.get_session()?;
        let sftp = sess
            .sftp()
            .map_err(|e| LazarusError::Storage(format!("Failed to open SFTP session: {}", e)))?;

        let remote_path = self.get_remote_path(key);

        let mut file = sftp
            .open(&remote_path)
            .map_err(|e| LazarusError::Storage(format!("Failed to open remote file: {}", e)))?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| LazarusError::Storage(format!("Failed to read data: {}", e)))?;

        Ok(data)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let sess = self.get_session()?;
        let sftp = sess
            .sftp()
            .map_err(|e| LazarusError::Storage(format!("Failed to open SFTP session: {}", e)))?;

        let remote_path = self.get_remote_path(key);

        sftp.unlink(&remote_path)
            .map_err(|e| LazarusError::Storage(format!("Failed to delete file: {}", e)))?;

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let sess = self.get_session()?;
        let sftp = sess
            .sftp()
            .map_err(|e| LazarusError::Storage(format!("Failed to open SFTP session: {}", e)))?;

        let remote_prefix = self.get_remote_path(prefix);

        let entries = sftp
            .readdir(&remote_prefix)
            .map_err(|e| LazarusError::Storage(format!("Failed to list directory: {}", e)))?;

        let mut result = Vec::new();
        for (path, stat) in entries {
            if stat.is_file() && let Some(path_str) = path.to_str() {
                result.push(path_str.to_string());
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires network access to a test SSH server"]
    async fn test_ssh_storage_creation() {
        // This test requires a real SSH server, so we just test the structure
        // In a real environment, you'd use a test SSH server or mock
        let result = SshStorage::new(
            "example.com".to_string(),
            22,
            "user".to_string(),
            "password".to_string(),
            PathBuf::from("/backups"),
        )
        .await;

        // Should fail to connect to non-existent server
        assert!(result.is_err());
    }
}
