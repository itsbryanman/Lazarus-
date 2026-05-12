//! LVM thin/CoW snapshot integration.
//!
//! On Linux systems whose data lives on an LVM logical volume, the cleanest
//! way to capture a consistent backup is to ask LVM itself for a copy-on-write
//! snapshot of the volume:
//!
//! ```text
//! lvcreate --snapshot --name lazarus_snap_<ts> --size <size> <volume>
//! mount -o ro <snapshot_dev> /var/lib/lazarus/mounts/<snap_id>/
//! ```
//!
//! While the snapshot exists, writes to the origin volume are diverted to the
//! CoW pool, and reads from `snapshot_dev` reflect the state at snapshot
//! creation. After the backup completes, the snapshot must be unmounted and
//! removed (`lvremove`) — failing to do so eventually fills the CoW pool and
//! ruins write performance on the origin.
//!
//! This module is *Linux-only*. On other platforms the public APIs return an
//! error from [`LvmSnapshot::create`] without shelling out.

use crate::error::{LazarusError, Result};
use crate::snapshot::snapshotter::{BlockSnapshotter, ConsistentMount};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default CoW pool size for snapshots. 5 GiB is what the resurrection plan
/// recommends as a safe default for a long-running backup of a moderately
/// active volume; oversize this for very busy origins.
pub const DEFAULT_COW_SIZE: &str = "5G";

/// Default location to mount snapshots under.
pub const DEFAULT_MOUNT_ROOT: &str = "/var/lib/lazarus/mounts";

/// Options for [`LvmSnapshot::create_with_opts`].
#[derive(Debug, Clone)]
pub struct LvmSnapshotOpts {
    /// CoW pool size string passed to `lvcreate --size`. Defaults to
    /// [`DEFAULT_COW_SIZE`].
    pub cow_size: String,
    /// Root directory under which the snapshot's read-only mount point is
    /// created. Defaults to [`DEFAULT_MOUNT_ROOT`].
    pub mount_root: PathBuf,
    /// Optional override for the snapshot LV name. Defaults to
    /// `lazarus_snap_<unix_timestamp>`.
    pub snapshot_name: Option<String>,
}

impl Default for LvmSnapshotOpts {
    fn default() -> Self {
        Self {
            cow_size: DEFAULT_COW_SIZE.to_string(),
            mount_root: PathBuf::from(DEFAULT_MOUNT_ROOT),
            snapshot_name: None,
        }
    }
}

/// A live LVM CoW snapshot with an associated read-only mount.
///
/// Dropping the value (or calling [`LvmSnapshot::release`]) tears the
/// snapshot down by unmounting and running `lvremove`.
pub struct LvmSnapshot {
    origin_volume: PathBuf,
    snapshot_lv: String,
    vg_name: String,
    snapshot_dev: PathBuf,
    mount_point: PathBuf,
    released: AtomicBool,
}

impl LvmSnapshot {
    /// Create a new LVM snapshot of `volume` with default options. `volume`
    /// must be a path to an LV (e.g. `/dev/vg0/data` or
    /// `/dev/mapper/vg0-data`).
    pub fn create(volume: &Path, snapshot_name: &str) -> Result<Self> {
        let mut opts = LvmSnapshotOpts::default();
        opts.snapshot_name = Some(snapshot_name.to_string());
        Self::create_with_opts(volume, &opts)
    }

    /// Create a snapshot with explicit options.
    pub fn create_with_opts(volume: &Path, opts: &LvmSnapshotOpts) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(LazarusError::Storage(
                "LVM snapshots are only supported on Linux".to_string(),
            ));
        }

        let (vg_name, lv_name) = parse_lv_path(volume)?;
        let snapshot_lv = opts.snapshot_name.clone().unwrap_or_else(default_snap_name);

        // Refuse names that contain shell metacharacters or path separators.
        // We never invoke a shell, but we still validate to keep error
        // messages from `lvcreate` sane.
        if !is_safe_lv_name(&snapshot_lv) {
            return Err(LazarusError::Storage(format!(
                "invalid snapshot LV name: {snapshot_lv}"
            )));
        }

        let lvcreate = Command::new("lvcreate")
            .arg("--snapshot")
            .arg("--name")
            .arg(&snapshot_lv)
            .arg("--size")
            .arg(&opts.cow_size)
            .arg(format!("{vg_name}/{lv_name}"))
            .output()
            .map_err(|e| LazarusError::Storage(format!("lvcreate not runnable: {e}")))?;
        if !lvcreate.status.success() {
            return Err(LazarusError::Storage(format!(
                "lvcreate failed: {}",
                String::from_utf8_lossy(&lvcreate.stderr).trim()
            )));
        }

        let snapshot_dev = PathBuf::from(format!("/dev/{vg_name}/{snapshot_lv}"));
        let mount_point = opts.mount_root.join(&snapshot_lv);
        if let Err(e) = std::fs::create_dir_all(&mount_point) {
            // If we can't create the mount point, roll back the lvcreate.
            let _ = lvremove(&vg_name, &snapshot_lv);
            return Err(LazarusError::Io(e));
        }

        let mount = Command::new("mount")
            .arg("-o")
            .arg("ro")
            .arg(&snapshot_dev)
            .arg(&mount_point)
            .output()
            .map_err(|e| {
                let _ = lvremove(&vg_name, &snapshot_lv);
                LazarusError::Storage(format!("mount not runnable: {e}"))
            })?;
        if !mount.status.success() {
            let stderr = String::from_utf8_lossy(&mount.stderr).trim().to_string();
            let _ = lvremove(&vg_name, &snapshot_lv);
            return Err(LazarusError::Storage(format!("mount failed: {stderr}")));
        }

        Ok(Self {
            origin_volume: volume.to_path_buf(),
            snapshot_lv,
            vg_name,
            snapshot_dev,
            mount_point,
            released: AtomicBool::new(false),
        })
    }

    /// Path to the read-only mount of the snapshot.
    pub fn device_path(&self) -> &Path {
        &self.mount_point
    }

    /// Path to the underlying snapshot block device (`/dev/<vg>/<snap_lv>`).
    pub fn block_device(&self) -> &Path {
        &self.snapshot_dev
    }

    /// The originating volume path that this snapshot was taken from.
    pub fn origin(&self) -> &Path {
        &self.origin_volume
    }

    /// Tear the snapshot down explicitly. Equivalent to dropping the value,
    /// but lets the caller observe any error.
    pub fn release(self) -> Result<()> {
        let mut this = self;
        this.tear_down()
    }

    fn tear_down(&mut self) -> Result<()> {
        if self.released.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // Always attempt umount before lvremove. Best-effort: if the unmount
        // fails (e.g. the kernel was already torn down) we still try to
        // remove the LV.
        let umount_status = Command::new("umount").arg(&self.mount_point).status();
        let lv_status = lvremove(&self.vg_name, &self.snapshot_lv);
        let _ = std::fs::remove_dir(&self.mount_point);
        match (umount_status, lv_status) {
            (Ok(_), Ok(())) => Ok(()),
            (Err(e), _) => Err(LazarusError::Storage(format!(
                "umount not runnable during teardown: {e}"
            ))),
            (_, Err(e)) => Err(e),
        }
    }
}

impl Drop for LvmSnapshot {
    fn drop(&mut self) {
        // Best-effort cleanup; ignore errors here so we don't double-panic.
        let _ = self.tear_down();
    }
}

impl ConsistentMount for LvmSnapshot {
    fn path(&self) -> &Path {
        &self.mount_point
    }

    fn release(mut self: Box<Self>) -> Result<()> {
        self.tear_down()
    }
}

/// Stateless [`BlockSnapshotter`] that produces [`LvmSnapshot`]s with
/// default options.
pub struct LvmSnapshotter;

impl BlockSnapshotter for LvmSnapshotter {
    fn supports(path: &Path) -> bool {
        if !cfg!(target_os = "linux") {
            return false;
        }
        // Cheapest possible check: does the path's underlying device look
        // like a device-mapper LV? We don't actually run any LVM commands
        // here — that's reserved for `snapshot()`.
        path_is_lvm_volume(path).unwrap_or(false)
    }

    fn snapshot(&self, source: &Path) -> Result<Box<dyn ConsistentMount>> {
        let snap = LvmSnapshot::create(source, &default_snap_name())?;
        Ok(Box::new(snap))
    }
}

fn lvremove(vg: &str, lv: &str) -> Result<()> {
    let out = Command::new("lvremove")
        .arg("-f")
        .arg(format!("{vg}/{lv}"))
        .output()
        .map_err(|e| LazarusError::Storage(format!("lvremove not runnable: {e}")))?;
    if !out.status.success() {
        return Err(LazarusError::Storage(format!(
            "lvremove failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn parse_lv_path(volume: &Path) -> Result<(String, String)> {
    // Accept /dev/<vg>/<lv> or /dev/mapper/<vg>-<lv>.
    let s = volume.to_str().ok_or_else(|| {
        LazarusError::Storage(format!("non-UTF8 volume path: {}", volume.display()))
    })?;
    if let Some(rest) = s.strip_prefix("/dev/mapper/") {
        // device-mapper escapes a literal '-' in vg or lv names as '--'. We
        // don't try to decode that here; reject and force the caller to
        // pass /dev/<vg>/<lv> for unambiguous parsing.
        if rest.contains("--") {
            return Err(LazarusError::Storage(format!(
                "ambiguous /dev/mapper name (contains '--'); pass /dev/<vg>/<lv> instead: {s}"
            )));
        }
        if let Some((vg, lv)) = rest.split_once('-') {
            return Ok((vg.to_string(), lv.to_string()));
        }
    }
    if let Some(rest) = s.strip_prefix("/dev/") {
        if let Some((vg, lv)) = rest.split_once('/') {
            if !vg.is_empty() && !lv.is_empty() && !lv.contains('/') {
                return Ok((vg.to_string(), lv.to_string()));
            }
        }
    }
    Err(LazarusError::Storage(format!(
        "not a recognizable LVM volume path: {s}"
    )))
}

fn default_snap_name() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("lazarus_snap_{ts}")
}

fn is_safe_lv_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

fn path_is_lvm_volume(path: &Path) -> Option<bool> {
    // We treat any path under /dev/mapper/ or /dev/<vg>/<lv> as candidate.
    // A more thorough check would `stat` the device and read /sys/dev/block,
    // but for a `supports()` hint this string-level inspection is enough —
    // `snapshot()` will surface a precise error if we're wrong.
    let s = path.to_str()?;
    if let Some(rest) = s.strip_prefix("/dev/mapper/") {
        return Some(!rest.is_empty() && !rest.contains('/'));
    }
    if let Some(rest) = s.strip_prefix("/dev/") {
        // Looking for exactly "<vg>/<lv>" with both components non-empty
        // and no further nesting.
        let mut parts = rest.split('/');
        let vg = parts.next();
        let lv = parts.next();
        let extra = parts.next();
        return Some(
            matches!((vg, lv, extra), (Some(v), Some(l), None) if !v.is_empty() && !l.is_empty()),
        );
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_lv_path() {
        let (vg, lv) = parse_lv_path(Path::new("/dev/vg0/data")).unwrap();
        assert_eq!(vg, "vg0");
        assert_eq!(lv, "data");
    }

    #[test]
    fn parses_simple_dm_mapper_path() {
        let (vg, lv) = parse_lv_path(Path::new("/dev/mapper/vg0-data")).unwrap();
        assert_eq!(vg, "vg0");
        assert_eq!(lv, "data");
    }

    #[test]
    fn rejects_ambiguous_dm_mapper_path() {
        assert!(parse_lv_path(Path::new("/dev/mapper/my--vg-data")).is_err());
    }

    #[test]
    fn rejects_non_lvm_path() {
        assert!(parse_lv_path(Path::new("/home/user/data")).is_err());
        assert!(parse_lv_path(Path::new("/dev/sda1")).is_err());
    }

    #[test]
    fn safe_lv_name_rules() {
        assert!(is_safe_lv_name("lazarus_snap_1700000000"));
        assert!(is_safe_lv_name("snap-2024.01"));
        assert!(!is_safe_lv_name(""));
        assert!(!is_safe_lv_name("snap;rm -rf /"));
        assert!(!is_safe_lv_name("snap with space"));
    }

    #[test]
    fn supports_only_on_linux_lvm_paths() {
        // `supports` should never panic on weird inputs.
        let _ = LvmSnapshotter::supports(Path::new(""));
        let _ = LvmSnapshotter::supports(Path::new("/nonexistent"));
        if cfg!(target_os = "linux") {
            assert!(LvmSnapshotter::supports(Path::new("/dev/vg0/data")));
            assert!(LvmSnapshotter::supports(Path::new("/dev/mapper/vg0-data")));
            assert!(!LvmSnapshotter::supports(Path::new("/home")));
            // Nested paths under /dev/ that aren't <vg>/<lv> shouldn't match.
            assert!(!LvmSnapshotter::supports(Path::new("/dev/a/b/c")));
            assert!(!LvmSnapshotter::supports(Path::new("/dev/sda1")));
        } else {
            assert!(!LvmSnapshotter::supports(Path::new("/dev/vg0/data")));
        }
    }

    #[test]
    fn create_returns_error_when_no_lvm_tools() {
        // In CI without LVM installed, `lvcreate` is missing; we want a
        // clean error rather than a panic.
        if !cfg!(target_os = "linux") {
            let err = LvmSnapshot::create(Path::new("/dev/vg0/data"), "lazarus_snap_test");
            assert!(err.is_err());
        }
    }
}
