use crate::error::{LazarusError, Result};
use crate::storage::backend::{RetentionLock, RetentionMode, StorageBackend};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    ObjectLockLegalHold, ObjectLockLegalHoldStatus, ObjectLockRetention, ObjectLockRetentionMode,
};
use aws_smithy_types::DateTime;
use std::time::{SystemTime, UNIX_EPOCH};

/// S3-compatible storage backend
pub struct S3Storage {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3Storage {
    /// Create a new S3 storage backend
    pub async fn new(bucket: String, prefix: String) -> Result<Self> {
        // Load AWS configuration from environment
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        let client = Client::new(&config);

        Ok(Self {
            client,
            bucket,
            prefix,
        })
    }

    /// Create a new S3 storage backend with custom endpoint (for S3-compatible services)
    pub async fn new_with_endpoint(
        bucket: String,
        prefix: String,
        endpoint: String,
    ) -> Result<Self> {
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        let s3_config = aws_sdk_s3::config::Builder::from(&config)
            .endpoint_url(endpoint)
            .build();
        let client = Client::from_conf(s3_config);

        Ok(Self {
            client,
            bucket,
            prefix,
        })
    }

    /// Get the full S3 key for a given path
    fn get_key(&self, key: &str) -> String {
        format_key(&self.prefix, key)
    }
}

fn format_key(prefix: &str, key: &str) -> String {
    let normalized_key = key.trim_start_matches('/');
    if prefix.is_empty() {
        normalized_key.to_string()
    } else {
        format!("{}/{}", prefix.trim_end_matches('/'), normalized_key)
    }
}

fn convert_mode(mode: RetentionMode) -> ObjectLockRetentionMode {
    match mode {
        RetentionMode::Governance => ObjectLockRetentionMode::Governance,
        RetentionMode::Compliance => ObjectLockRetentionMode::Compliance,
    }
}

fn convert_datetime(time: SystemTime) -> Result<DateTime> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LazarusError::Storage("Invalid retention timestamp".into()))?;
    Ok(DateTime::from_secs(duration.as_secs() as i64))
}

impl S3Storage {
    async fn apply_legal_hold(&self, key: &str, lock: &RetentionLock) -> Result<()> {
        let status = if lock.legal_hold {
            ObjectLockLegalHoldStatus::On
        } else {
            ObjectLockLegalHoldStatus::Off
        };

        let request = ObjectLockLegalHold::builder().status(status).build();

        self.client
            .put_object_legal_hold()
            .bucket(&self.bucket)
            .key(key)
            .legal_hold(request)
            .send()
            .await
            .map_err(|e| LazarusError::Storage(format!("S3 legal hold error: {e}")))?;

        Ok(())
    }

    async fn apply_retention(&self, key: &str, lock: &RetentionLock) -> Result<()> {
        let retain_until = match lock.retain_until {
            Some(time) => time,
            None => return Ok(()),
        };

        let retention = ObjectLockRetention::builder()
            .mode(convert_mode(lock.mode))
            .retain_until_date(convert_datetime(retain_until)?)
            .build();

        self.client
            .put_object_retention()
            .bucket(&self.bucket)
            .key(key)
            .retention(retention)
            .send()
            .await
            .map_err(|e| LazarusError::Storage(format!("S3 retention error: {e}")))?;

        Ok(())
    }
}

#[async_trait]
impl StorageBackend for S3Storage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let s3_key = self.get_key(key);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .body(ByteStream::from(data.to_vec()))
            .send()
            .await
            .map_err(|e| LazarusError::Storage(format!("S3 put error: {}", e)))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let s3_key = self.get_key(key);

        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
            .map_err(|e| LazarusError::Storage(format!("S3 get error: {}", e)))?;

        let data = response
            .body
            .collect()
            .await
            .map_err(|e| LazarusError::Storage(format!("S3 body read error: {}", e)))?
            .into_bytes()
            .to_vec();

        Ok(data)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let s3_key = self.get_key(key);

        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
            .map_err(|e| LazarusError::Storage(format!("S3 delete error: {}", e)))?;

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let s3_prefix = self.get_key(prefix);

        let mut results = Vec::new();
        let mut continuation_token = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&s3_prefix);

            if let Some(token) = continuation_token {
                request = request.continuation_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| LazarusError::Storage(format!("S3 list error: {}", e)))?;

            if let Some(contents) = response.contents {
                for object in contents {
                    if let Some(key) = object.key {
                        // Remove the prefix from the key
                        let stripped_key = if !self.prefix.is_empty() {
                            key.strip_prefix(&format!("{}/", self.prefix.trim_end_matches('/')))
                                .unwrap_or(&key)
                                .to_string()
                        } else {
                            key
                        };
                        results.push(stripped_key);
                    }
                }
            }

            if response.is_truncated.unwrap_or(false) {
                continuation_token = response.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(results)
    }

    async fn write_once(&self, key: &str, data: &[u8], lock: Option<&RetentionLock>) -> Result<()> {
        self.put(key, data).await?;
        if let Some(lock) = lock {
            self.set_retention_lock(key, lock).await?;
        }
        Ok(())
    }

    async fn set_retention_lock(&self, key: &str, lock: &RetentionLock) -> Result<()> {
        let s3_key = self.get_key(key);
        self.apply_legal_hold(&s3_key, lock).await?;
        self.apply_retention(&s3_key, lock).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_key() {
        assert_eq!(format_key("backups", "file.txt"), "backups/file.txt");
        assert_eq!(
            format_key("backups/", "dir/file.txt"),
            "backups/dir/file.txt"
        );
        assert_eq!(format_key("", "file.txt"), "file.txt");
        assert_eq!(
            format_key("nested/prefix", "/leading/slash.txt"),
            "nested/prefix/leading/slash.txt"
        );
    }
}
