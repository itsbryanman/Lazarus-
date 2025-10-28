use crate::encryption::key_manager::{KeyManager, RepositoryConfig};
use crate::error::{Result, LazarusError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = "config.json";

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

    /// Initialize a new repository
    pub async fn init_repository(&self, master_password: &str) -> Result<KeyManager> {
        // Check if repository already exists
        let config_path = self.repo_path.join(CONFIG_FILE);
        if config_path.exists() {
            return Err(LazarusError::Storage(
                "Repository already exists".to_string()
            ));
        }

        // Create repository directory structure
        tokio::fs::create_dir_all(&self.repo_path).await?;
        tokio::fs::create_dir_all(self.repo_path.join("data")).await?;
        tokio::fs::create_dir_all(self.repo_path.join("indexes")).await?;
        tokio::fs::create_dir_all(self.repo_path.join("snapshots")).await?;

        // Initialize key manager and config
        let (key_manager, config) = KeyManager::init_repository(master_password)?;

        // Save config
        self.save_config(&config).await?;

        println!("Repository initialized at: {}", self.repo_path.display());
        println!("IMPORTANT: Keep your master password safe! Without it, your data cannot be recovered.");

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
                "Repository not found. Run 'init' first.".to_string()
            ));
        }

        let json = tokio::fs::read_to_string(&config_path).await?;
        serde_json::from_str(&json)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))
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
