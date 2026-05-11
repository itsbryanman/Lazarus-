//! ZFS snapshot integration.
//!
//! ZFS snapshots are taken with `zfs snapshot pool/dataset@<tag>`. The
//! resulting snapshot is exposed (read-only) at the dataset's
//! `.zfs/snapshot/<tag>/` directory automatically — no separate mount step
//! is required if the `snapdir` property is `visible`. For environments
//! where `snapdir=hidden` we fall back to creating a temporary clone with
//! `zfs clone` and mounting it.
//!
//! Cleanup destroys the snapshot (and the clone, if one was created).

use crate::error::{LazarusError, Result};
use crate::snapshot::snapshotter::{BlockSnapshotter, ConsistentMount};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A ZFS snapshot bound to a path the caller can read from.
pub struct ZfsSnapshot {
    /// Fully-qualified ZFS snapshot name, e.g. `tank/data@lazarus-1700000000`.
    snapshot_name: String,
    /// Optional clone created when the snapshot path was not directly
    /// readable. Destroyed during teardown if present.
    clone_name: Option<String>,
    /// Path the consumer reads from. Either the dataset's `.zfs/snapshot/`
    /// path or the clone's mount point.
    visible_path: PathBuf,
    released: AtomicBool,
}

impl ZfsSnapshot {
    /// Create a snapshot of the dataset that contains `source`. `source`
    /// must be a path on a mounted ZFS dataset. The dataset is determined
    /// via `zfs list -H -o name <source>`.
    pub fn create(source: &Path) -> Result<Self> {
        if !cfg!(target_os = "linux") && !cfg!(target_os = "freebsd") {
            return Err(LazarusError::Storage(
                "ZFS snapshots are only supported on Linux and FreeBSD".to_string(),
            ));
        }

        let dataset = resolve_dataset(source)?;
        let mountpoint = dataset_mountpoint(&dataset)?;
        let tag = default_snap_tag();
        let snapshot_name = format!("{dataset}@{tag}");

        let out = Command::new("zfs")
            .arg("snapshot")
            .arg(&snapshot_name)
            .output()
            .map_err(|e| LazarusError::Storage(format!("zfs not runnable: {e}")))?;
        if !out.status.success() {
            return Err(LazarusError::Storage(format!(
                "zfs snapshot failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }

        // Prefer the .zfs/snapshot path. It's always present and requires
        // no extra cleanup beyond destroying the snapshot itself.
        let visible = mountpoint.join(".zfs").join("snapshot").join(&tag);
        if visible.exists() {
            return Ok(Self {
                snapshot_name,
                clone_name: None,
                visible_path: visible,
                released: AtomicBool::new(false),
            });
        }

        // Fall back to a clone for hidden-snapdir setups.
        let clone_name = format!("{dataset}_lazarus_clone_{tag}");
        let clone_out = Command::new("zfs")
            .arg("clone")
            .arg(&snapshot_name)
            .arg(&clone_name)
            .output()
            .map_err(|e| {
                let _ = destroy_snapshot(&snapshot_name);
                LazarusError::Storage(format!("zfs clone not runnable: {e}"))
            })?;
        if !clone_out.status.success() {
            let stderr = String::from_utf8_lossy(&clone_out.stderr).trim().to_string();
            let _ = destroy_snapshot(&snapshot_name);
            return Err(LazarusError::Storage(format!("zfs clone failed: {stderr}")));
        }
        let clone_mp = dataset_mountpoint(&clone_name).unwrap_or_else(|_| {
            // Some pools use legacy mountpoints; fall back to the path zfs
            // mounts the clone at by convention.
            PathBuf::from(format!("/{}", clone_name))
        });
        Ok(Self {
            snapshot_name,
            clone_name: Some(clone_name),
            visible_path: clone_mp,
            released: AtomicBool::new(false),
        })
    }

    /// Path the caller can read the consistent state from.
    pub fn visible_path(&self) -> &Path {
        &self.visible_path
    }

    /// The ZFS snapshot name (`pool/dataset@tag`).
    pub fn snapshot_name(&self) -> &str {
        &self.snapshot_name
    }

    /// Tear the snapshot (and optional clone) down explicitly.
    pub fn release(self) -> Result<()> {
        let mut this = self;
        this.tear_down()
    }

    fn tear_down(&mut self) -> Result<()> {
        if self.released.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // Destroy the clone first; ZFS refuses to destroy a snapshot that
        // has dependent clones.
        if let Some(clone) = &self.clone_name {
            let _ = Command::new("zfs").arg("destroy").arg(clone).output();
        }
        destroy_snapshot(&self.snapshot_name)
    }
}

impl Drop for ZfsSnapshot {
    fn drop(&mut self) {
        let _ = self.tear_down();
    }
}

impl ConsistentMount for ZfsSnapshot {
    fn path(&self) -> &Path {
        &self.visible_path
    }

    fn release(mut self: Box<Self>) -> Result<()> {
        self.tear_down()
    }
}

/// Stateless [`BlockSnapshotter`] for ZFS.
pub struct ZfsSnapshotter;

impl BlockSnapshotter for ZfsSnapshotter {
    fn supports(path: &Path) -> bool {
        // Cheap check: does `zfs list -H -o name <path>` succeed?
        let Ok(out) = Command::new("zfs")
            .arg("list")
            .arg("-H")
            .arg("-o")
            .arg("name")
            .arg(path)
            .output()
        else {
            return false;
        };
        out.status.success() && !out.stdout.is_empty()
    }

    fn snapshot(&self, source: &Path) -> Result<Box<dyn ConsistentMount>> {
        Ok(Box::new(ZfsSnapshot::create(source)?))
    }
}

fn destroy_snapshot(name: &str) -> Result<()> {
    let out = Command::new("zfs")
        .arg("destroy")
        .arg(name)
        .output()
        .map_err(|e| LazarusError::Storage(format!("zfs not runnable: {e}")))?;
    if !out.status.success() {
        return Err(LazarusError::Storage(format!(
            "zfs destroy failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn resolve_dataset(path: &Path) -> Result<String> {
    let out = Command::new("zfs")
        .arg("list")
        .arg("-H")
        .arg("-o")
        .arg("name")
        .arg(path)
        .output()
        .map_err(|e| LazarusError::Storage(format!("zfs not runnable: {e}")))?;
    if !out.status.success() {
        return Err(LazarusError::Storage(format!(
            "zfs list failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() {
        return Err(LazarusError::Storage(
            "zfs list returned empty dataset name".to_string(),
        ));
    }
    Ok(name)
}

fn dataset_mountpoint(dataset: &str) -> Result<PathBuf> {
    let out = Command::new("zfs")
        .arg("get")
        .arg("-H")
        .arg("-o")
        .arg("value")
        .arg("mountpoint")
        .arg(dataset)
        .output()
        .map_err(|e| LazarusError::Storage(format!("zfs not runnable: {e}")))?;
    if !out.status.success() {
        return Err(LazarusError::Storage(format!(
            "zfs get mountpoint failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() || s == "-" || s == "none" || s == "legacy" {
        return Err(LazarusError::Storage(format!(
            "dataset {dataset} has no usable mountpoint ({s})"
        )));
    }
    Ok(PathBuf::from(s))
}

fn default_snap_tag() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("lazarus-{ts}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_does_not_panic_without_zfs() {
        let _ = ZfsSnapshotter::supports(Path::new(""));
        let _ = ZfsSnapshotter::supports(Path::new("/tmp"));
    }

    #[test]
    fn create_errors_cleanly_without_zfs() {
        // CI without ZFS installed should produce a typed error rather
        // than a panic or silent success.
        let dir = tempfile::tempdir().unwrap();
        assert!(ZfsSnapshot::create(dir.path()).is_err());
    }
}
