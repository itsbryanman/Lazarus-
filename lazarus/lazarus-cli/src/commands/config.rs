use clap::Args;
use lazarus_core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Args)]
pub struct ConfigArgs {
    #[arg(short, long, help = "Configuration key to get/set")]
    pub key: Option<String>,

    #[arg(short, long, help = "Value to set (omit to get)")]
    pub value: Option<String>,

    #[arg(long, help = "List all configuration values")]
    pub list: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct ClientConfig {
    settings: HashMap<String, String>,
}

impl ClientConfig {
    fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir().ok_or_else(|| {
            lazarus_core::error::LazarusError::Storage(
                "Unable to determine config directory".to_string(),
            )
        })?;

        let lazarus_config = config_dir.join("lazarus");
        std::fs::create_dir_all(&lazarus_config)?;

        Ok(lazarus_config.join("client.toml"))
    }

    fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(&path)?;
        let config: ClientConfig = toml::from_str(&contents)
            .map_err(|e| lazarus_core::error::LazarusError::SerializationError(e.to_string()))?;

        Ok(config)
    }

    fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        let contents = toml::to_string_pretty(self)
            .map_err(|e| lazarus_core::error::LazarusError::SerializationError(e.to_string()))?;

        std::fs::write(&path, contents)?;
        Ok(())
    }

    fn get(&self, key: &str) -> Option<&String> {
        self.settings.get(key)
    }

    fn set(&mut self, key: String, value: String) {
        self.settings.insert(key, value);
    }

    fn list(&self) -> &HashMap<String, String> {
        &self.settings
    }
}

pub async fn config(args: &ConfigArgs) -> Result<()> {
    let mut config = ClientConfig::load()?;

    if args.list {
        // List all configuration
        if config.list().is_empty() {
            println!("No configuration values set.");
        } else {
            println!("Configuration:");
            for (key, value) in config.list() {
                println!("  {} = {}", key, value);
            }
        }
        return Ok(());
    }

    match (&args.key, &args.value) {
        (Some(key), Some(value)) => {
            // Set configuration
            config.set(key.clone(), value.clone());
            config.save()?;
            println!("Set {} = {}", key, value);
        }
        (Some(key), None) => {
            // Get configuration
            match config.get(key) {
                Some(value) => println!("{} = {}", key, value),
                None => println!("Configuration key '{}' not found", key),
            }
        }
        (None, _) => {
            println!("Error: --key is required (or use --list to show all configuration)");
        }
    }

    Ok(())
}
