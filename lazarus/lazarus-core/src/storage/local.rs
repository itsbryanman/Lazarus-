use super::backend::{RetentionLock, StorageBackend};
use crate::error::{Error, Result};
use async_trait::async_trait;
use rand::{Rng, distributions::Alphanumeric};
use std::path::{Path, PathBuf};
use tokio::{fs, io::AsyncWriteExt, task};

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

    fn resolve_key(&self, key: &str) -> PathBuf {
        self.path.join(key.trim_start_matches('/'))
    }

    async fn apply_local_policy(&self, key: &str, lock: &RetentionLock) -> Result<()> {
        if !lock.local_immutability {
            return Ok(());
        }

        let target = self.resolve_key(key);
        Self::toggle_local_immutable(target, true).await
    }

    async fn release_local_policy(&self, key: &str) -> Result<()> {
        let target = self.resolve_key(key);
        Self::toggle_local_immutable(target, false).await
    }

    async fn toggle_local_immutable(target: PathBuf, enable: bool) -> Result<()> {
        task::spawn_blocking(move || Self::toggle_local_immutable_blocking(&target, enable))
            .await
            .map_err(|e| Error::Storage(format!("Immutable flag task failed: {}", e)))??;
        Ok(())
    }

    fn toggle_local_immutable_blocking(target: &Path, enable: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;

            let flag = if enable { "+i" } else { "-i" };
            let status = Command::new("chattr").arg(flag).arg(target).status()?;
            if !status.success() {
                return Err(Error::Storage(format!(
                    "Failed to toggle immutable flag for {}",
                    target.display()
                )));
            }
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_READONLY, GetFileAttributesW, SetFileAttributesW,
            };

            let wide: Vec<u16> = target
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                let mut attrs = GetFileAttributesW(wide.as_ptr());
                if attrs == u32::MAX {
                    return Err(Error::Storage(format!(
                        "Failed to query attributes for {}",
                        target.display()
                    )));
                }

                if enable {
                    attrs |= FILE_ATTRIBUTE_READONLY;
                } else {
                    attrs &= !FILE_ATTRIBUTE_READONLY;
                }

                if SetFileAttributesW(wide.as_ptr(), attrs) == 0 {
                    return Err(Error::Storage(format!(
                        "Failed to update attributes for {}",
                        target.display()
                    )));
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl StorageBackend for LocalStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.resolve_key(key);
        let parent = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.path.clone());
        fs::create_dir_all(&parent).await?;

        let suffix: String = {
            let mut rng = rand::thread_rng();
            (0..16).map(|_| rng.sample(Alphanumeric) as char).collect()
        };
        let tmp_name = format!(
            ".tmp.{}.{}",
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "chunk".to_string()),
            suffix
        );
        let tmp_path = parent.join(tmp_name);

        let mut temp_file = fs::File::create(&tmp_path).await?;
        temp_file.write_all(data).await?;
        temp_file.sync_all().await?;
        drop(temp_file);

        let tmp_for_task = tmp_path.clone();
        let final_for_task = path.clone();
        let rename_result =
            task::spawn_blocking(move || std::fs::rename(tmp_for_task, final_for_task))
                .await
                .map_err(|e| Error::Storage(format!("Atomic rename task failed: {}", e)))?;

        if let Err(err) = rename_result {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(Error::Io(err));
        }

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let path = self.resolve_key(key);
        fs::read(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Storage(format!("Key '{}' not found", key))
            } else {
                Error::Io(e)
            }
        })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.resolve_key(key);
        fs::remove_file(&path).await?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut entries = Vec::new();
        let mut dir = fs::read_dir(self.path.join(prefix)).await?;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path.is_file() && let Some(path_str) = path.to_str() {
                entries.push(path_str.to_string());
            }
        }
        Ok(entries)
    }

    async fn write_once(&self, key: &str, data: &[u8], lock: Option<&RetentionLock>) -> Result<()> {
        self.put(key, data).await?;
        if let Some(lock) = lock {
            self.apply_local_policy(key, lock).await?;
        }
        Ok(())
    }

    async fn set_retention_lock(&self, key: &str, lock: &RetentionLock) -> Result<()> {
        if lock.local_immutability {
            self.apply_local_policy(key, lock).await
        } else {
            self.release_local_policy(key).await
        }
    }
}
