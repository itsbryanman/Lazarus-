//! Shared shell-out helpers used by multiple collectors.

use std::time::Duration;
use tokio::process::Command;

/// Run a command and return stdout as raw bytes. Fails with a typed
/// string error on non-zero exit, spawn failure, or timeout.
pub(crate) async fn run_capture_bytes(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> std::result::Result<Vec<u8>, String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    match tokio::time::timeout(timeout, cmd.output()).await {
        Ok(Ok(o)) if o.status.success() => Ok(o.stdout),
        Ok(Ok(o)) => Err(format!(
            "{program} exited with {:?}; stderr: {}",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Ok(Err(e)) => Err(format!("failed to spawn {program}: {e}")),
        Err(_) => Err(format!("timeout running {program}")),
    }
}

/// Convenience wrapper: stdout as UTF-8 string.
pub(crate) async fn run_capture_str(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> std::result::Result<String, String> {
    let bytes = run_capture_bytes(program, args, timeout).await?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Tar a directory into memory. Returns the tar stream bytes or a typed
/// error if the source directory does not exist or `tar` is missing.
pub(crate) async fn tar_dir_to_vec(
    dir: &str,
    timeout: Duration,
) -> std::result::Result<Vec<u8>, String> {
    if !std::path::Path::new(dir).exists() {
        return Err(format!("{dir} does not exist"));
    }
    run_capture_bytes("tar", &["-C", dir, "-cf", "-", "."], timeout).await
}
