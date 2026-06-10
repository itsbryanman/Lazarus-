//! Bare-metal system *capture* (Phase 3).
//!
//! The capture pipeline produces a `SystemFingerprint`: the recipe a
//! restore would need to reconstruct the source machine on a blank disk,
//! potentially on different hardware. File contents themselves (and raw
//! block streams) are produced by the existing backup pipeline; this
//! module captures *everything else* — partition tables, bootloader
//! bytes, LVM/RAID metadata, the network configuration, the package
//! manifest, the kernel/initramfs, and the user database.
//!
//! All collectors are Linux-only and gated with `#[cfg(target_os =
//! "linux")]`. On other platforms `capture_system` returns a typed
//! `Storage("…Linux-only")` error so callers don't have to special-case
//! the platform check themselves. The *public types* in this module are
//! portable so the catalog format does not fork between hosts.
//!
//! Sensitive subsets (`/etc/shadow`, ssh host keys, MOK/Secure Boot
//! state) are encrypted with the repository's *metadata* key and stored
//! as separate chunks. Only their content hash and a small ref struct
//! live inside the fingerprint itself.
//!
//! TODO(phase-future): libvirt VM-level fingerprints; PCI driver
//! compatibility lookup.

pub mod bootloader;
pub mod disk_layout;
pub mod lvm;
pub mod mdadm;
pub mod network;
pub mod packages;
pub mod persist;
pub mod secrets;
pub mod system;
pub mod users;
#[cfg(target_os = "linux")]
pub(crate) mod util;

pub use bootloader::{BiosConfig, BootMode, BootloaderConfig, KernelFileEntry, UefiConfig};
pub use disk_layout::{DiskLayout, GptPartition, MbrPartition, PartitionTable};
pub use lvm::{LogicalVolume, LvmConfig, PhysicalVolume, VgBackup, VolumeGroup};
pub use mdadm::{MdArray, MdadmConfig};
pub use network::{DnsConfig, NetworkConfig, NetworkInterface, RouteEntry};
pub use packages::{PackageEntry, PackageManager, PackageManifest};
pub use persist::FingerprintPersister;
pub use secrets::{SshHostKeysBlob, SshHostKeysRef};
pub use system::{
    capture_system, CaptureOpts, CaptureReport, CaptureWarning, CpuInfo, EnabledService,
    FilesystemInfo, FirmwareInfo, KernelInfo, NamedBlob, SystemFingerprint,
};
pub use users::{UserDatabaseBlob, UserDatabaseRef};

/// Capture-time error type used internally by collectors. Always
/// converted back to `crate::error::LazarusError::Storage` at the
/// orchestrator boundary so the public surface remains a single `Result`.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("capture I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("capture serialization: {0}")]
    Serialization(String),
    #[error("capture timeout running `{0}`")]
    Timeout(String),
    #[error("capture parse error in {component}: {message}")]
    Parse { component: String, message: String },
    #[error("{0}")]
    Other(String),
}

impl From<CaptureError> for crate::error::LazarusError {
    fn from(e: CaptureError) -> Self {
        crate::error::LazarusError::Storage(e.to_string())
    }
}
