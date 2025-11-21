use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::backend::{RetentionLock, StorageBackend};
use crate::error::{LazarusError, Result};

/// Storage backend powered by the `rclone` binary. Authentication and
/// cloud-specific behavior are delegated to the user's rclone configuration,
/// allowing Lazarus to treat every provider as a generic remote.
pub struct RcloneStorage {
    binary: PathBuf,
    remote: String,
    prefix: String,
}

impl RcloneStorage {
    /// Create a new backend that targets the given rclone remote path (e.g. "gdrive:backups").
    pub fn new(remote: impl Into<String>) -> Self {
        Self::with_binary_path("rclone", remote, "")
    }

    /// Create a backend with an explicit prefix nested under the remote.
    pub fn with_prefix(remote: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self::with_binary_path("rclone", remote, prefix)
    }

    /// Create a backend specifying the binary path (helpful for portable installations).
    pub fn with_binary_path(
        binary: impl Into<PathBuf>,
        remote: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Self {
        Self {
            binary: binary.into(),
            remote: remote.into(),
            prefix: prefix.into(),
        }
    }

    fn remote_root(&self) -> String {
        if self.prefix.is_empty() {
            self.remote.clone()
        } else {
            join_remote_path(&self.remote, self.prefix.trim_matches('/'))
        }
    }

    fn remote_path(&self, key: &str) -> String {
        let normalized = key.trim_matches('/');
        if normalized.is_empty() {
            return self.remote_root();
        }
        join_remote_path(&self.remote_root(), normalized)
    }

    async fn run_command(&self, args: Vec<String>, input: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut command = Command::new(&self.binary);
        command.args(&args);
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|e| LazarusError::Storage(format!("Failed to spawn rclone: {e}")))?;

        if let Some(data) = input {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(data).await.map_err(|e| {
                    LazarusError::Storage(format!("Failed to stream data to rclone: {e}"))
                })?;
            }
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| LazarusError::Storage(format!("rclone failed: {e}")))?;

        if !output.status.success() {
            return Err(LazarusError::Storage(format!(
                "rclone command {:?} exited with {}: {}",
                args,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(output.stdout)
    }

    async fn push_data(&self, key: &str, data: &[u8]) -> Result<()> {
        let target = self.remote_path(key);
        let args = vec!["rcat".to_string(), target];
        self.run_command(args, Some(data)).await?;
        Ok(())
    }

    async fn read_data(&self, key: &str) -> Result<Vec<u8>> {
        let target = self.remote_path(key);
        let args = vec!["cat".to_string(), target];
        self.run_command(args, None).await
    }

    async fn delete_object(&self, key: &str) -> Result<()> {
        let target = self.remote_path(key);
        let args = vec!["deletefile".to_string(), target];
        self.run_command(args, None).await?;
        Ok(())
    }

    async fn list_objects(&self, prefix: &str) -> Result<Vec<String>> {
        let target = self.remote_path(prefix);
        let args = vec![
            "lsf".to_string(),
            target,
            "--files-only".to_string(),
            "--recursive".to_string(),
        ];
        let raw = self.run_command(args, None).await?;
        let normalized_prefix = prefix.trim_matches('/').to_string();
        let mut items = Vec::new();
        for line in raw.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let entry = String::from_utf8_lossy(line)
                .trim()
                .trim_end_matches('/')
                .to_string();
            if entry.is_empty() {
                continue;
            }
            let key = if normalized_prefix.is_empty() {
                entry
            } else {
                format!("{}/{}", normalized_prefix, entry)
            };
            items.push(key);
        }
        Ok(items)
    }
}

fn join_remote_path(base: &str, segment: &str) -> String {
    if segment.is_empty() {
        return base.to_string();
    }

    let trimmed_segment = segment.trim_matches('/');
    if trimmed_segment.is_empty() {
        return base.to_string();
    }

    if base.is_empty() {
        trimmed_segment.to_string()
    } else if base.ends_with(':') {
        format!("{}{}", base, trimmed_segment)
    } else {
        format!("{}/{}", base.trim_end_matches('/'), trimmed_segment)
    }
}

#[async_trait]
impl StorageBackend for RcloneStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        self.push_data(key, data).await
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.read_data(key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.delete_object(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_objects(prefix).await
    }

    async fn write_once(&self, key: &str, data: &[u8], lock: Option<&RetentionLock>) -> Result<()> {
        if lock.is_some() {
            return Err(LazarusError::Storage(
                "Immutable writes are not supported by the rclone backend".into(),
            ));
        }
        self.put(key, data).await
    }

    async fn set_retention_lock(&self, _key: &str, _lock: &RetentionLock) -> Result<()> {
        Err(LazarusError::Storage(
            "Retention locking is not available for the rclone backend".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::join_remote_path;

    #[test]
    fn join_remote_handles_colon() {
        assert_eq!(join_remote_path("gdrive:", "backups"), "gdrive:backups");
        assert_eq!(
            join_remote_path("gdrive:tenant", "daily"),
            "gdrive:tenant/daily"
        );
        assert_eq!(join_remote_path("/data", "vault"), "/data/vault");
    }
}
