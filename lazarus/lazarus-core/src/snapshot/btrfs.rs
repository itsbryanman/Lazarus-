//! Btrfs subvolume snapshot integration.
//!
//! Btrfs supports near-instant, copy-on-write snapshots of subvolumes via
//! `btrfs subvolume snapshot -r <source> <dest>`. The snapshot is itself a
//! subvolume that lives on the same filesystem and is exposed as an
//! ordinary directory tree, so no separate `mount` step is required —
//! reading from `<dest>` reflects the consistent point-in-time state.
//!
//! Cleanup on Drop deletes the snapshot subvolume with
//! `btrfs subvolume delete`.

use crate::error::{LazarusError, Result};
use crate::snapshot::snapshotter::{BlockSnapshotter, ConsistentMount};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default parent directory under which Btrfs snapshots are placed. Must
/// itself live on the same Btrfs filesystem as the source.
pub const DEFAULT_SNAPSHOT_PARENT: &str = "/var/lib/lazarus/btrfs-snaps";

/// A read-only Btrfs subvolume snapshot.
pub struct BtrfsSnapshot {
    source: PathBuf,
    snapshot_path: PathBuf,
    released: AtomicBool,
}

impl BtrfsSnapshot {
    /// Snapshot `source` into a freshly-named subvolume under
    /// [`DEFAULT_SNAPSHOT_PARENT`].
    pub fn create(source: &Path) -> Result<Self> {
        Self::create_in(source, Path::new(DEFAULT_SNAPSHOT_PARENT))
    }

    /// Snapshot `source` into a freshly-named subvolume under `parent`.
    /// `parent` must exist and live on the same Btrfs filesystem as
    /// `source`.
    pub fn create_in(source: &Path, parent: &Path) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(LazarusError::Storage(
                "Btrfs snapshots are only supported on Linux".to_string(),
            ));
        }
        std::fs::create_dir_all(parent)?;

        let snapshot_path = parent.join(default_snap_name());
        let out = Command::new("btrfs")
            .arg("subvolume")
            .arg("snapshot")
            .arg("-r")
            .arg(source)
            .arg(&snapshot_path)
            .output()
            .map_err(|e| LazarusError::Storage(format!("btrfs not runnable: {e}")))?;
        if !out.status.success() {
            return Err(LazarusError::Storage(format!(
                "btrfs subvolume snapshot failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }

        Ok(Self {
            source: source.to_path_buf(),
            snapshot_path,
            released: AtomicBool::new(false),
        })
    }

    /// The originating subvolume the snapshot was taken from.
    pub fn origin(&self) -> &Path {
        &self.source
    }

    /// The snapshot path (read-only subvolume).
    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    /// Tear the snapshot subvolume down explicitly.
    pub fn release(self) -> Result<()> {
        let mut this = self;
        this.tear_down()
    }

    fn tear_down(&mut self) -> Result<()> {
        if self.released.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let out = Command::new("btrfs")
            .arg("subvolume")
            .arg("delete")
            .arg(&self.snapshot_path)
            .output()
            .map_err(|e| LazarusError::Storage(format!("btrfs not runnable: {e}")))?;
        if !out.status.success() {
            return Err(LazarusError::Storage(format!(
                "btrfs subvolume delete failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }
}

impl Drop for BtrfsSnapshot {
    fn drop(&mut self) {
        let _ = self.tear_down();
    }
}

impl ConsistentMount for BtrfsSnapshot {
    fn path(&self) -> &Path {
        &self.snapshot_path
    }

    fn release(mut self: Box<Self>) -> Result<()> {
        self.tear_down()
    }
}

/// Stateless [`BlockSnapshotter`] for Btrfs.
pub struct BtrfsSnapshotter;

impl BlockSnapshotter for BtrfsSnapshotter {
    fn supports(path: &Path) -> bool {
        if !cfg!(target_os = "linux") {
            return false;
        }
        is_btrfs_filesystem(path).unwrap_or(false)
    }

    fn snapshot(&self, source: &Path) -> Result<Box<dyn ConsistentMount>> {
        Ok(Box::new(BtrfsSnapshot::create(source)?))
    }
}

fn default_snap_name() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("lazarus_snap_{ts}")
}

#[cfg(target_os = "linux")]
fn is_btrfs_filesystem(path: &Path) -> Option<bool> {
    // The cheapest reliable indicator: `statfs(2)` and check `f_type`. We
    // prefer this over reading /proc/mounts because it works for any path,
    // mounted or not, and doesn't require parsing.
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    const BTRFS_SUPER_MAGIC: i64 = 0x9123683E;

    let cstr = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: we pass a valid C string and a properly aligned, zero-init
    // statfs struct; the kernel writes to it on success.
    let mut buf: libc_compat::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc_compat::statfs(cstr.as_ptr(), &mut buf) };
    if rc != 0 {
        return Some(false);
    }
    Some(buf.f_type == BTRFS_SUPER_MAGIC)
}

#[cfg(not(target_os = "linux"))]
fn is_btrfs_filesystem(_: &Path) -> Option<bool> {
    Some(false)
}

#[cfg(target_os = "linux")]
mod libc_compat {
    //! Minimal `statfs` binding so we don't take a hard dependency on the
    //! `libc` crate just for one syscall. We only read `f_type`; everything
    //! else is opaque padding.

    use std::os::raw::{c_char, c_int, c_long};

    /// Generous upper bound on the platform-specific tail of the
    /// `statfs` struct. The Linux ABI defines roughly 100 bytes after
    /// `f_type`; FreeBSD's variant is smaller. 256 bytes is comfortably
    /// larger than any known layout, which lets the kernel write into
    /// the buffer without us needing per-arch ifdefs for one syscall.
    pub const STATFS_TAIL_BYTES: usize = 256;

    #[repr(C)]
    pub struct statfs {
        pub f_type: c_long,
        // Opaque, platform-specific tail. Only `f_type` is read.
        _pad: [u8; STATFS_TAIL_BYTES],
    }

    unsafe extern "C" {
        pub fn statfs(path: *const c_char, buf: *mut statfs) -> c_int;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_does_not_panic() {
        let _ = BtrfsSnapshotter::supports(Path::new(""));
        let _ = BtrfsSnapshotter::supports(Path::new("/nonexistent"));
        let _ = BtrfsSnapshotter::supports(Path::new("/tmp"));
    }

    #[test]
    fn create_errors_cleanly_when_btrfs_unavailable() {
        // /tmp is virtually never btrfs in CI; we expect either a missing
        // tool error or a "not on btrfs" error from the binary, but no
        // panic and no leaked snapshot directory.
        let dir = tempfile::tempdir().unwrap();
        let res = BtrfsSnapshot::create_in(dir.path(), dir.path());
        assert!(res.is_err());
    }
}
