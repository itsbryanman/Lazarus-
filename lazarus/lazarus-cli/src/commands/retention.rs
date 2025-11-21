use std::fmt;

use clap::{Args, ValueEnum};
use lazarus_core::config::{ConfigManager, RetentionPolicy};
use lazarus_core::error::{LazarusError, Result};
use lazarus_core::storage::backend::RetentionMode;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum RetentionModeArg {
    Governance,
    Compliance,
}

impl From<RetentionModeArg> for RetentionMode {
    fn from(arg: RetentionModeArg) -> Self {
        match arg {
            RetentionModeArg::Governance => RetentionMode::Governance,
            RetentionModeArg::Compliance => RetentionMode::Compliance,
        }
    }
}

impl From<RetentionMode> for RetentionModeArg {
    fn from(mode: RetentionMode) -> Self {
        match mode {
            RetentionMode::Governance => RetentionModeArg::Governance,
            RetentionMode::Compliance => RetentionModeArg::Compliance,
        }
    }
}

impl fmt::Display for RetentionModeArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RetentionModeArg::Governance => "governance",
            RetentionModeArg::Compliance => "compliance",
        })
    }
}

#[derive(Args)]
pub struct RetentionArgs {
    #[arg(short, long, help = "Repository path")]
    pub repository: String,

    #[arg(long, help = "Enable immutable retention")]
    pub enable: bool,

    #[arg(long, help = "Disable immutable retention")]
    pub disable: bool,

    #[arg(
        long,
        value_enum,
        help = "Retention enforcement mode (governance/compliance)"
    )]
    pub mode: Option<RetentionModeArg>,

    #[arg(long, help = "Minimum retention window in days")]
    pub min_retention_days: Option<u32>,

    #[arg(long, help = "Enable or disable S3 legal hold", value_parser = clap::value_parser!(bool))]
    pub legal_hold: Option<bool>,

    #[arg(
        long,
        help = "Toggle local filesystem immutability",
        value_parser = clap::value_parser!(bool)
    )]
    pub local_immutability: Option<bool>,
}

pub async fn retention(args: &RetentionArgs) -> Result<()> {
    let config_mgr = ConfigManager::new(&args.repository);
    let mut policy = config_mgr.load_retention_policy().await?;

    if args.enable && args.disable {
        return Err(LazarusError::Storage(
            "--enable and --disable cannot be used together".to_string(),
        ));
    }

    let mut modified = false;
    if args.enable {
        policy.enabled = true;
        modified = true;
    }
    if args.disable {
        policy.enabled = false;
        modified = true;
    }
    if let Some(mode) = args.mode {
        policy.mode = mode.into();
        modified = true;
    }
    if let Some(days) = args.min_retention_days {
        policy.min_retention_days = days;
        modified = true;
    }
    if let Some(legal_hold) = args.legal_hold {
        policy.legal_hold = legal_hold;
        modified = true;
    }
    if let Some(local) = args.local_immutability {
        policy.local_immutability = local;
        modified = true;
    }

    if modified {
        config_mgr.save_retention_policy(&policy).await?;
        println!("Immutable retention policy updated.\n");
    }

    if modified {
        println!("Updated immutable retention policy:");
    } else {
        println!("Current immutable retention policy:");
    }
    print_policy(&policy);

    Ok(())
}

fn print_policy(policy: &RetentionPolicy) {
    let mode = RetentionModeArg::from(policy.mode);
    println!("  Enabled: {}", policy.enabled);
    println!("  Mode: {}", mode);
    if policy.min_retention_days == 0 {
        println!("  Minimum retention: disabled");
    } else {
        println!("  Minimum retention: {} day(s)", policy.min_retention_days);
    }
    println!("  Legal hold: {}", policy.legal_hold);
    println!("  Local immutability: {}", policy.local_immutability);
}
