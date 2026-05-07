//! Common traits for filesystem- and volume-level point-in-time snapshots.
//!
//! Lazarus needs a *consistent* view of a source tree to back up running
//! systems — open databases, busy mailboxes, or a hypervisor's image
//! directory cannot be safely captured by walking files one at a time while
//! they are being mutated. The implementations in this module wrap LVM,
//! Btrfs, ZFS (and any future block-snapshot mechanism) behind a uniform
//! interface so the rest of the backup pipeline can treat them
//! interchangeably.
//!
//! The design follows two principles:
//!
//!   * **RAII teardown.** A [`ConsistentMount`] *must* release its underlying
//!     snapshot when dropped. The OS-level resource (an LVM CoW snapshot, a
//!     Btrfs read-only subvolume, a ZFS snapshot/clone) is precious and must
//!     be cleaned up even if the backup pipeline panics. Implementations
//!     therefore keep a `released` flag and run the teardown in `Drop` if the
//!     caller did not invoke [`ConsistentMount::release`] explicitly.
//!
//!   * **Best-effort detection.** [`BlockSnapshotter::supports`] is a *hint*.
//!     It must never panic and must never modify the system. If the relevant
//!     tooling is unavailable (e.g. `btrfs-progs` not installed) it returns
//!     `false`. The orchestrator can then fall back to file-walk capture.

use crate::error::Result;
use std::path::Path;

/// A handle to a read-only, point-in-time view of `source` on the local
/// filesystem. While the [`ConsistentMount`] is alive, reads at
/// [`ConsistentMount::path`] reflect the state of the source at the moment
/// the snapshot was created, regardless of subsequent writes to the source.
pub trait ConsistentMount: Send + Sync {
    /// The local path at which the snapshot is mounted/exposed.
    fn path(&self) -> &Path;

    /// Tear the snapshot down explicitly. Returning an error here is
    /// informational; the implementation must not leak resources even if the
    /// caller never calls this method (the destructor handles that).
    fn release(self: Box<Self>) -> Result<()>;
}

/// A backend capable of producing a [`ConsistentMount`] for a given source
/// path.
pub trait BlockSnapshotter: Send + Sync {
    /// Quickly check whether this snapshotter can handle `path`. Must not
    /// panic, must not mutate any state, and must tolerate a non-existent or
    /// permission-denied path by returning `false`.
    fn supports(path: &Path) -> bool
    where
        Self: Sized;

    /// Create a snapshot of `source` and return a handle to its consistent
    /// mount point.
    fn snapshot(&self, source: &Path) -> Result<Box<dyn ConsistentMount>>;
}
