use crate::error::{Result, LazarusError};
use crate::storage::backend::StorageBackend;
use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use std::path::Path;

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
        let config = aws_config::load_from_env().await;
        let client = Client::new(&config);

        Ok(Self {
            client,
            bucket,
            prefix,
        })
    }

    /// Create a new S3 storage backend with custom endpoint (for S3-compatible services)
    pub async fn new_with_endpoint(bucket: String, prefix: String, endpoint: String) -> Result<Self> {
        let config = aws_config::load_from_env().await;
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
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", self.prefix.trim_end_matches('/'), key)
        }
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

        let response = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
            .map_err(|e| LazarusError::Storage(format!("S3 get error: {}", e)))?;

        let data = response.body.collect().await
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
            let mut request = self.client
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_key() {
        let storage = S3Storage {
            client: Client::new(&aws_config::SdkConfig::builder().build()),
            bucket: "test-bucket".to_string(),
            prefix: "backups".to_string(),
        };

        assert_eq!(storage.get_key("file.txt"), "backups/file.txt");
        assert_eq!(storage.get_key("dir/file.txt"), "backups/dir/file.txt");

        let storage_no_prefix = S3Storage {
            client: Client::new(&aws_config::SdkConfig::builder().build()),
            bucket: "test-bucket".to_string(),
            prefix: String::new(),
        };

        assert_eq!(storage_no_prefix.get_key("file.txt"), "file.txt");
    }
}
