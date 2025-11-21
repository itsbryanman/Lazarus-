use crate::encryption::key_manager::{KeyManager, RepositoryConfig};
use crate::error::{LazarusError, Result};
use crate::storage::backend::{RetentionLock, RetentionMode};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const CONFIG_FILE: &str = "config.json";
const RETENTION_POLICY_FILE: &str = "retention_policy.json";

/// Immutable retention policy persisted alongside the repository configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub enabled: bool,
    pub mode: RetentionMode,
    pub min_retention_days: u32,
    pub legal_hold: bool,
    pub local_immutability: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: RetentionMode::Governance,
            min_retention_days: 30,
            legal_hold: false,
            local_immutability: cfg!(target_os = "linux") || cfg!(target_os = "windows"),
        }
    }
}

impl RetentionPolicy {
    fn retention_duration(&self) -> Option<Duration> {
        if self.min_retention_days == 0 {
            None
        } else {
            Some(Duration::from_secs(self.min_retention_days as u64 * 86_400))
        }
    }

    pub fn as_lock(&self) -> Option<RetentionLock> {
        if !self.enabled {
            return None;
        }

        let mut lock = RetentionLock::new(self.mode);
        lock.legal_hold = self.legal_hold;
        lock.local_immutability = self.local_immutability;
        if let Some(duration) = self.retention_duration() {
            lock.retain_until = Some(SystemTime::now() + duration);
        }
        Some(lock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn retention_policy_disabled() {
        let policy = RetentionPolicy::default();
        assert!(policy.as_lock().is_none());
    }

    #[test]
    fn retention_policy_enabled_generates_lock() {
        let mut policy = RetentionPolicy::default();
        policy.enabled = true;
        policy.min_retention_days = 1;
        policy.legal_hold = true;
        policy.local_immutability = true;

        let lock = policy.as_lock().expect("lock expected");
        assert!(lock.retain_until.is_some());
        assert!(lock.legal_hold);
        assert!(lock.local_immutability);
    }

    #[tokio::test]
    async fn retention_policy_persistence_roundtrip() {
        let dir = tempdir().expect("temp dir");
        let manager = ConfigManager::new(dir.path());

        let mut policy = RetentionPolicy::default();
        policy.enabled = true;
        policy.min_retention_days = 120;
        policy.legal_hold = true;
        policy.local_immutability = false;

        manager
            .save_retention_policy(&policy)
            .await
            .expect("save retention policy");

        let loaded = manager
            .load_retention_policy()
            .await
            .expect("load retention policy");

        assert!(loaded.enabled);
        assert_eq!(loaded.min_retention_days, 120);
        assert!(loaded.legal_hold);
        assert!(!loaded.local_immutability);
    }
}

/// Repository configuration manager
pub struct ConfigManager {
    repo_path: PathBuf,
}

impl ConfigManager {
    /// Create a new config manager for a repository path
    pub fn new<P: AsRef<Path>>(repo_path: P) -> Self {
        Self {
            repo_path: repo_path.as_ref().to_path_buf(),
        }
    }

    /// Load immutable retention policy (defaults if missing)
    pub async fn load_retention_policy(&self) -> Result<RetentionPolicy> {
        let path = self.repo_path.join(RETENTION_POLICY_FILE);
        if !path.exists() {
            return Ok(RetentionPolicy::default());
        }

        let json = tokio::fs::read_to_string(&path).await?;
        serde_json::from_str(&json).map_err(|e| LazarusError::SerializationError(e.to_string()))
    }

    /// Persist immutable retention policy
    pub async fn save_retention_policy(&self, policy: &RetentionPolicy) -> Result<()> {
        let path = self.repo_path.join(RETENTION_POLICY_FILE);
        let json = serde_json::to_string_pretty(policy)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        tokio::fs::write(&path, json).await?;
        Ok(())
    }

    /// Helper: generate in-memory retention lock ready for storage backends
    pub async fn default_retention_lock(&self) -> Result<Option<RetentionLock>> {
        let policy = self.load_retention_policy().await?;
        Ok(policy.as_lock())
    }

    /// Initialize a new repository
    pub async fn init_repository(&self, master_password: &str) -> Result<KeyManager> {
        // Check if repository already exists
        let config_path = self.repo_path.join(CONFIG_FILE);
        if config_path.exists() {
            return Err(LazarusError::Storage(
                "Repository already exists".to_string(),
            ));
        }

        // Create repository directory structure
        tokio::fs::create_dir_all(&self.repo_path).await?;
        tokio::fs::create_dir_all(self.repo_path.join("data")).await?;
        tokio::fs::create_dir_all(self.repo_path.join("indexes")).await?;
        tokio::fs::create_dir_all(self.repo_path.join("snapshots")).await?;

        // Persist default retention policy so operators can tune immutability immediately
        self.save_retention_policy(&RetentionPolicy::default())
            .await?;

        // Initialize key manager and config
        let (key_manager, config) = KeyManager::init_repository(master_password)?;

        // Save config
        self.save_config(&config).await?;

        println!("Repository initialized at: {}", self.repo_path.display());
        println!(
            "IMPORTANT: Keep your master password safe! Without it, your data cannot be recovered."
        );

        Ok(key_manager)
    }

    /// Open an existing repository
    pub async fn open_repository(&self, master_password: &str) -> Result<KeyManager> {
        let config = self.load_config().await?;
        KeyManager::unlock_repository(master_password, &config)
    }

    /// Save repository configuration
    async fn save_config(&self, config: &RepositoryConfig) -> Result<()> {
        let config_path = self.repo_path.join(CONFIG_FILE);
        let json = serde_json::to_string_pretty(config)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        tokio::fs::write(&config_path, json).await?;
        Ok(())
    }

    /// Load repository configuration
    async fn load_config(&self) -> Result<RepositoryConfig> {
        let config_path = self.repo_path.join(CONFIG_FILE);
        if !config_path.exists() {
            return Err(LazarusError::Storage(
                "Repository not found. Run 'init' first.".to_string(),
            ));
        }

        let json = tokio::fs::read_to_string(&config_path).await?;
        serde_json::from_str(&json).map_err(|e| LazarusError::SerializationError(e.to_string()))
    }

    /// Get the repository path
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    /// Get the data directory path
    pub fn data_path(&self) -> PathBuf {
        self.repo_path.join("data")
    }

    /// Get the indexes directory path
    pub fn indexes_path(&self) -> PathBuf {
        self.repo_path.join("indexes")
    }

    /// Get the snapshots directory path
    pub fn snapshots_path(&self) -> PathBuf {
        self.repo_path.join("snapshots")
    }

    /// Get the database path
    pub fn database_path(&self) -> PathBuf {
        self.indexes_path().join("index.db")
    }
}
