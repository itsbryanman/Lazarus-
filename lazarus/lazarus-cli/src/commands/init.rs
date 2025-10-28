use clap::Args;
use lazarus_core::config::ConfigManager;
use lazarus_core::error::Result;

#[derive(Args)]
pub struct InitArgs {
    #[arg(short, long, help = "Repository path to initialize")]
    pub repository: String,

    #[arg(short, long, help = "Master password for encryption")]
    pub password: String,
}

pub async fn init(args: &InitArgs) -> Result<()> {
    println!("Initializing repository at: {}", args.repository);

    let config_mgr = ConfigManager::new(&args.repository);
    config_mgr.init_repository(&args.password).await?;

    println!("\n✓ Repository initialized successfully!");
    println!("\nIMPORTANT:");
    println!("  - Keep your master password safe and secure");
    println!("  - Without the password, your backups cannot be recovered");
    println!("  - Consider storing the password in a secure password manager");

    Ok(())
}
