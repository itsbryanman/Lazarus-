use clap::{Args, Subcommand};
use lazarus_core::error::{LazarusError, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use which::which;

const SCRIPT_RELATIVE: &str = "../scripts/build_recovery_iso.sh";

#[derive(Args)]
pub struct RecoverArgs {
    #[command(subcommand)]
    pub command: RecoverCommand,
}

#[derive(Subcommand)]
pub enum RecoverCommand {
    /// Build the bootable recovery ISO image
    BuildIso(BuildIsoArgs),
}

#[derive(Args)]
pub struct BuildIsoArgs {
    #[arg(
        short,
        long,
        help = "Path to output ISO",
        default_value = "lazarus-recovery.iso"
    )]
    pub output: PathBuf,

    #[arg(long, help = "Optional lazarus-recovery binary to embed")]
    pub binary: Option<PathBuf>,
}

pub async fn recover(args: &RecoverArgs) -> Result<()> {
    match &args.command {
        RecoverCommand::BuildIso(opts) => build_iso(opts),
    }
}

fn build_iso(args: &BuildIsoArgs) -> Result<()> {
    ensure_dependency("xorriso")?;
    ensure_dependency("mtools")?;

    let script_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRIPT_RELATIVE);
    if !script_path.exists() {
        return Err(LazarusError::Storage(format!(
            "Recovery build script not found at {}",
            script_path.display()
        )));
    }

    let mut command = Command::new(&script_path);
    command.arg(args.output.as_os_str());
    if let Some(binary) = &args.binary {
        command.arg(binary);
    }

    let status = command.status().map_err(|e| {
        LazarusError::Storage(format!(
            "Failed to execute {}: {}",
            script_path.display(),
            e
        ))
    })?;

    if status.success() {
        println!("ISO written to {}", args.output.display());
        Ok(())
    } else {
        Err(LazarusError::Storage(format!(
            "ISO build failed with status {}",
            status
        )))
    }
}

fn ensure_dependency(name: &str) -> Result<()> {
    match which(name) {
        Ok(_) => Ok(()),
        Err(_) => Err(LazarusError::Storage(format!(
            "Required dependency '{}' not found in PATH",
            name
        ))),
    }
}
