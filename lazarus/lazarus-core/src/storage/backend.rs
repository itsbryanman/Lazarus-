use crate::error::{LazarusError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Object lock protection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RetentionMode {
    #[default]
    Governance,
    Compliance,
}

/// Retention configuration used when applying immutability to an object
#[derive(Debug, Clone)]
pub struct RetentionLock {
    pub mode: RetentionMode,
    pub retain_until: Option<SystemTime>,
    pub legal_hold: bool,
    pub local_immutability: bool,
}

impl RetentionLock {
    pub fn new(mode: RetentionMode) -> Self {
        Self {
            mode,
            retain_until: None,
            legal_hold: false,
            local_immutability: false,
        }
    }

    pub fn with_retain_duration(mut self, duration: Duration) -> Self {
        self.retain_until = Some(SystemTime::now() + duration);
        self
    }
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;

    /// Store data in an immutable fashion. Implementations that do not support
    /// immutability fall back to a regular put.
    async fn write_once(&self, key: &str, data: &[u8], lock: Option<&RetentionLock>) -> Result<()> {
        if lock.is_some() {
            return Err(LazarusError::Storage(
                "Immutable writes are not supported for this backend".into(),
            ));
        }
        self.put(key, data).await
    }

    /// Apply or update retention metadata for an existing object
    async fn set_retention_lock(&self, _key: &str, _lock: &RetentionLock) -> Result<()> {
        Err(LazarusError::Storage(
            "Retention locking is not supported for this backend".into(),
        ))
    }
}
