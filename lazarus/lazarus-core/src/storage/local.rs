use std::path::{Path, PathBuf};
use async_trait::async_trait;
use tokio::fs;
use crate::error::{Error, Result};
use super::backend::StorageBackend;

#[derive(Clone)]
pub struct LocalStorage {
    path: PathBuf,
}

impl LocalStorage {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        LocalStorage {
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[async_trait]
impl StorageBackend for LocalStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.path.join(key.strip_prefix("/").unwrap_or(key));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&path, data).await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let path = self.path.join(key.strip_prefix("/").unwrap_or(key));
        fs::read(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Storage(format!("Key '{}' not found", key))
            } else {
                Error::Io(e)
            }
        })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.path.join(key.strip_prefix("/").unwrap_or(key));
        fs::remove_file(&path).await?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut entries = Vec::new();
        let mut dir = fs::read_dir(self.path.join(prefix)).await?;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                if let Some(path_str) = path.to_str() {
                    entries.push(path_str.to_string());
                }
            }
        }
        Ok(entries)
    }
}