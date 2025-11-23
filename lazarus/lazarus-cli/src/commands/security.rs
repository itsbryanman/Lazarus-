use clap::{Args, Subcommand};
use dialoguer::Password;
use lazarus_core::config::ConfigManager;
use lazarus_core::error::{LazarusError, Result};

#[derive(Args)]
pub struct SecurityArgs {
    #[arg(short, long, help = "Repository path to manage security for")]
    pub repository: String,

    #[command(subcommand)]
    pub command: SecurityCommand,
}

#[derive(Subcommand)]
pub enum SecurityCommand {
    #[command(name = "rotate-key", about = "Rotate the repository master key")]
    RotateKey,
}

pub async fn security(args: &SecurityArgs) -> Result<()> {
    match args.command {
        SecurityCommand::RotateKey => rotate_master_key(&args.repository).await,
    }
}

async fn rotate_master_key(repository: &str) -> Result<()> {
    let config_mgr = ConfigManager::new(repository);

    let current_password = Password::new()
        .with_prompt("Enter current master password")
        .allow_empty_password(false)
        .interact()
        .map_err(dialoguer_error)?;

    let new_password = Password::new()
        .with_prompt("Enter new master password")
        .with_confirmation(
            "Confirm new master password",
            "Passwords do not match. Please try again.",
        )
        .allow_empty_password(false)
        .interact()
        .map_err(dialoguer_error)?;

    config_mgr
        .rotate_master_key(&current_password, &new_password)
        .await?;

    println!("Success! Master key rotated. Your old backups are accessible with the new password.");

    Ok(())
}

fn dialoguer_error(err: dialoguer::Error) -> LazarusError {
    LazarusError::Storage(format!("Prompt failed: {}", err))
}
