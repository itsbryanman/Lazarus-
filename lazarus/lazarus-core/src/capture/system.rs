//! Top-level fingerprint types and the `capture_system` orchestrator.
//!
//! `SystemFingerprint` is the durable on-disk representation of a host's
//! configuration. Adding fields is **always** done with `#[serde(default)]`
//! so older fingerprints continue to deserialize against newer code.
//! Removing fields is a forward-incompatible change and requires bumping
//! [`SystemFingerprint::version`].

use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::bootloader::BootloaderConfig;
use super::disk_layout::DiskLayout;
use super::lvm::LvmConfig;
use super::mdadm::MdadmConfig;
use super::network::NetworkConfig;
use super::packages::PackageManifest;
use super::persist::FingerprintPersister;
use super::secrets::SshHostKeysRef;
use super::users::UserDatabaseRef;

/// Current fingerprint schema version. Phase 3 ships v1.
pub const FINGERPRINT_VERSION: u32 = 1;

/// Everything a restore tool needs to reconstruct a Linux host on bare
/// metal. Encrypted at rest under the *data* key; sensitive sub-blobs
/// (`users`, `ssh_host_keys`) are encrypted under the *metadata* key and
/// referenced here by hash only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemFingerprint {
    pub version: u32,
    pub captured_at_epoch_s: u64,
    pub captured_by: String,
    pub hostname: String,
    #[serde(default)]
    pub fqdn: Option<String>,
    #[serde(default)]
    pub machine_id: Option<String>,
    pub kernel: KernelInfo,
    pub cpu: CpuInfo,
    pub memory_bytes: u64,
    #[serde(default)]
    pub disks: Vec<DiskLayout>,
    #[serde(default)]
    pub lvm: Option<LvmConfig>,
    #[serde(default)]
    pub mdadm: Option<MdadmConfig>,
    #[serde(default)]
    pub filesystems: Vec<FilesystemInfo>,
    #[serde(default)]
    pub fstab: String,
    #[serde(default)]
    pub crypttab: Option<String>,
    pub network: NetworkConfig,
    pub bootloader: BootloaderConfig,
    pub packages: PackageManifest,
    #[serde(default)]
    pub services: Vec<EnabledService>,
    pub users: UserDatabaseRef,
    pub ssh_host_keys: SshHostKeysRef,
    pub firmware: FirmwareInfo,
    #[serde(default)]
    pub warnings: Vec<CaptureWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct KernelInfo {
    pub release: String,
    pub version: String,
    pub arch: String,
    pub cmdline: String,
    pub distro_id: String,
    pub distro_version: String,
    pub init_system: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CpuInfo {
    pub vendor: String,
    pub model: String,
    pub physical_cores: u32,
    pub logical_cores: u32,
    #[serde(default)]
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesystemInfo {
    pub device: String,
    #[serde(default)]
    pub mountpoint: Option<String>,
    pub fstype: String,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub options: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FirmwareInfo {
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub release_date: Option<String>,
    pub uefi: bool,
    pub secure_boot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnabledService {
    pub name: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureWarning {
    pub component: String,
    pub message: String,
    #[serde(default)]
    pub remediation: Option<String>,
}

impl CaptureWarning {
    pub fn new<C: Into<String>, M: Into<String>>(component: C, message: M) -> Self {
        Self {
            component: component.into(),
            message: message.into(),
            remediation: None,
        }
    }

    pub fn with_remediation<R: Into<String>>(mut self, remediation: R) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}

/// Named binary blob shipped inside the fingerprint. Used by collectors
/// that need to record a file's *content* (e.g. `/etc/network/interfaces`)
/// rather than just a path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamedBlob {
    pub name: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CaptureOpts {
    pub include_lvm: bool,
    pub include_mdadm: bool,
    pub include_network: bool,
    pub include_packages: bool,
    pub include_users: bool,
    pub include_ssh_keys: bool,
    pub include_bootloader: bool,
    pub tool_timeout: Duration,
}

impl Default for CaptureOpts {
    fn default() -> Self {
        Self {
            include_lvm: true,
            include_mdadm: true,
            include_network: true,
            include_packages: true,
            include_users: true,
            include_ssh_keys: true,
            include_bootloader: true,
            tool_timeout: Duration::from_secs(30),
        }
    }
}

pub struct CaptureReport {
    pub fingerprint: SystemFingerprint,
    pub elapsed: Duration,
}

/// Linux capture entry-point. The non-Linux variant below returns a
/// typed `Storage(...)` error so platform handling lives here rather
/// than at every call site.
#[cfg(target_os = "linux")]
pub async fn capture_system(
    opts: &CaptureOpts,
    persister: &FingerprintPersister<'_>,
) -> crate::error::Result<CaptureReport> {
    use std::time::Instant;
    let start = Instant::now();

    let mut warnings: Vec<CaptureWarning> = Vec::new();

    // Cheap synchronous collectors first. These read sysfs/procfs and are
    // not expected to block long enough to be worth tokio-ing.
    let (hostname, fqdn, machine_id) = collect_identity();
    let kernel = collect_kernel(&mut warnings);
    let cpu = collect_cpu(&mut warnings);
    let memory_bytes = collect_memory(&mut warnings);
    let filesystems = collect_filesystems(&mut warnings);
    let fstab = std::fs::read_to_string("/etc/fstab").unwrap_or_default();
    let crypttab = std::fs::read_to_string("/etc/crypttab").ok();
    let services = collect_services(opts.tool_timeout).await;
    let firmware = collect_firmware();

    // Each shell-out collector can be slow and is independent of the
    // others; fan them out and join. Each returns its own
    // `(value, Vec<CaptureWarning>)` so the orchestrator only has to
    // merge warnings here.
    let disks_fut = super::disk_layout::discover_disks(opts);
    let network_fut = async {
        if opts.include_network {
            super::network::capture_network(opts).await
        } else {
            Ok((super::network::NetworkConfig::default(), vec![]))
        }
    };
    let packages_fut = async {
        if opts.include_packages {
            super::packages::capture_packages(opts).await
        } else {
            Ok((super::packages::PackageManifest::default(), vec![]))
        }
    };
    let bootloader_fut = async {
        if opts.include_bootloader {
            super::bootloader::capture_bootloader(opts, persister).await
        } else {
            Ok((super::bootloader::BootloaderConfig::default(), vec![]))
        }
    };
    let users_fut = async {
        if opts.include_users {
            super::users::capture_users(opts, persister).await
        } else {
            Ok((super::users::UserDatabaseRef::empty(), vec![]))
        }
    };
    let ssh_fut = async {
        if opts.include_ssh_keys {
            super::secrets::capture_ssh_host_keys(opts, persister).await
        } else {
            Ok((super::secrets::SshHostKeysRef::empty(), vec![]))
        }
    };
    let lvm_fut = async {
        if opts.include_lvm {
            super::lvm::capture_lvm(opts).await
        } else {
            Ok((None, vec![]))
        }
    };
    let mdadm_fut = async {
        if opts.include_mdadm {
            super::mdadm::capture_mdadm(opts).await
        } else {
            Ok((None, vec![]))
        }
    };

    let (disks_r, network_r, packages_r, bootloader_r, users_r, ssh_r, lvm_r, mdadm_r) = tokio::join!(
        disks_fut,
        network_fut,
        packages_fut,
        bootloader_fut,
        users_fut,
        ssh_fut,
        lvm_fut,
        mdadm_fut,
    );

    let (disks, disks_warn) = disks_r?;
    let (network, network_warn) = network_r?;
    let (packages, packages_warn) = packages_r?;
    let (bootloader, bootloader_warn) = bootloader_r?;
    let (users, users_warn) = users_r?;
    let (ssh_host_keys, ssh_warn) = ssh_r?;
    let (lvm, lvm_warn) = lvm_r?;
    let (mdadm, mdadm_warn) = mdadm_r?;

    warnings.extend(disks_warn);
    warnings.extend(network_warn);
    warnings.extend(packages_warn);
    warnings.extend(bootloader_warn);
    warnings.extend(users_warn);
    warnings.extend(ssh_warn);
    warnings.extend(lvm_warn);
    warnings.extend(mdadm_warn);

    let captured_at_epoch_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let captured_by = format!("lazarus/{}", env!("CARGO_PKG_VERSION"));

    let fingerprint = SystemFingerprint {
        version: FINGERPRINT_VERSION,
        captured_at_epoch_s,
        captured_by,
        hostname,
        fqdn,
        machine_id,
        kernel,
        cpu,
        memory_bytes,
        disks,
        lvm,
        mdadm,
        filesystems,
        fstab,
        crypttab,
        network,
        bootloader,
        packages,
        services,
        users,
        ssh_host_keys,
        firmware,
        warnings,
    };

    Ok(CaptureReport {
        fingerprint,
        elapsed: start.elapsed(),
    })
}

#[cfg(not(target_os = "linux"))]
pub async fn capture_system(
    _opts: &CaptureOpts,
    _persister: &FingerprintPersister<'_>,
) -> crate::error::Result<CaptureReport> {
    Err(crate::error::LazarusError::Storage(
        "system fingerprint capture is Linux-only".into(),
    ))
}

// --- Linux-only collectors for the cheap sysfs/procfs bits. -----------------

#[cfg(target_os = "linux")]
fn collect_identity() -> (String, Option<String>, Option<String>) {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let fqdn = std::process::Command::new("hostname")
        .arg("-f")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/var/lib/dbus/machine-id")
                .ok()
                .map(|s| s.trim().to_string())
        });
    (hostname, fqdn, machine_id)
}

#[cfg(target_os = "linux")]
fn collect_kernel(warnings: &mut Vec<CaptureWarning>) -> KernelInfo {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let version = std::fs::read_to_string("/proc/sys/kernel/version")
        .unwrap_or_default()
        .trim()
        .to_string();
    let arch = std::env::consts::ARCH.to_string();
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .unwrap_or_default()
        .trim()
        .to_string();
    let (distro_id, distro_version) = match std::fs::read_to_string("/etc/os-release") {
        Ok(s) => parse_os_release(&s),
        Err(_) => {
            warnings.push(
                CaptureWarning::new("kernel", "/etc/os-release missing")
                    .with_remediation("install systemd or a distro that provides os-release"),
            );
            (String::new(), String::new())
        }
    };
    let init_system = detect_init_system();
    KernelInfo {
        release,
        version,
        arch,
        cmdline,
        distro_id,
        distro_version,
        init_system,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_os_release(s: &str) -> (String, String) {
    let mut id = String::new();
    let mut version = String::new();
    for line in s.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ID=") {
            id = strip_quotes(rest).to_string();
        } else if let Some(rest) = line.strip_prefix("VERSION_ID=") {
            version = strip_quotes(rest).to_string();
        }
    }
    (id, version)
}

#[cfg(target_os = "linux")]
fn strip_quotes(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}

#[cfg(target_os = "linux")]
fn detect_init_system() -> String {
    if std::path::Path::new("/run/systemd/system").exists() {
        "systemd".into()
    } else if std::fs::read_to_string("/proc/1/comm")
        .map(|s| s.trim().to_string())
        .ok()
        .as_deref()
        == Some("init")
    {
        "sysvinit".into()
    } else {
        std::fs::read_to_string("/proc/1/comm")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into())
    }
}

#[cfg(target_os = "linux")]
fn collect_cpu(warnings: &mut Vec<CaptureWarning>) -> CpuInfo {
    let cpuinfo = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(s) => s,
        Err(_) => {
            warnings.push(CaptureWarning::new("cpu", "/proc/cpuinfo unreadable"));
            return CpuInfo::default();
        }
    };
    parse_cpuinfo(&cpuinfo)
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_cpuinfo(s: &str) -> CpuInfo {
    let mut vendor = String::new();
    let mut model = String::new();
    let mut flags: Vec<String> = Vec::new();
    let mut physical_ids = std::collections::BTreeSet::new();
    let mut logical: u32 = 0;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("vendor_id") {
            if vendor.is_empty() {
                vendor = field_value(rest).to_string();
            }
        } else if let Some(rest) = line.strip_prefix("model name") {
            if model.is_empty() {
                model = field_value(rest).to_string();
            }
        } else if let Some(rest) = line.strip_prefix("physical id") {
            if let Ok(n) = field_value(rest).parse::<u32>() {
                physical_ids.insert(n);
            }
        } else if line.starts_with("processor") {
            logical += 1;
        } else if let Some(rest) = line.strip_prefix("flags") {
            if flags.is_empty() {
                flags = field_value(rest)
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
            }
        }
    }
    let physical_cores = if physical_ids.is_empty() {
        logical
    } else {
        physical_ids.len() as u32
    };
    CpuInfo {
        vendor,
        model,
        physical_cores,
        logical_cores: logical,
        flags,
    }
}

#[cfg(target_os = "linux")]
fn field_value(s: &str) -> &str {
    s.split(':').nth(1).unwrap_or("").trim()
}

#[cfg(target_os = "linux")]
fn collect_memory(warnings: &mut Vec<CaptureWarning>) -> u64 {
    let meminfo = match std::fs::read_to_string("/proc/meminfo") {
        Ok(s) => s,
        Err(_) => {
            warnings.push(CaptureWarning::new("memory", "/proc/meminfo unreadable"));
            return 0;
        }
    };
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kib: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return kib.saturating_mul(1024);
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn collect_filesystems(warnings: &mut Vec<CaptureWarning>) -> Vec<FilesystemInfo> {
    let mounts = match std::fs::read_to_string("/proc/mounts") {
        Ok(s) => s,
        Err(_) => {
            warnings.push(CaptureWarning::new(
                "filesystems",
                "/proc/mounts unreadable",
            ));
            return Vec::new();
        }
    };
    parse_proc_mounts(&mounts)
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_proc_mounts(s: &str) -> Vec<FilesystemInfo> {
    let mut out = Vec::new();
    for line in s.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        out.push(FilesystemInfo {
            device: parts[0].to_string(),
            mountpoint: Some(parts[1].to_string()),
            fstype: parts[2].to_string(),
            uuid: None,
            label: None,
            options: Some(parts[3].to_string()),
        });
    }
    out
}

#[cfg(target_os = "linux")]
async fn collect_services(timeout: Duration) -> Vec<EnabledService> {
    use tokio::process::Command;
    let out = match tokio::time::timeout(
        timeout,
        Command::new("systemctl")
            .args([
                "list-unit-files",
                "--state=enabled",
                "--no-legend",
                "--no-pager",
                "--type=service",
            ])
            .output(),
    )
    .await
    {
        Ok(Ok(o)) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_systemctl_enabled(&stdout)
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_systemctl_enabled(s: &str) -> Vec<EnabledService> {
    let mut out = Vec::new();
    for line in s.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        out.push(EnabledService {
            name: parts[0].to_string(),
            state: parts[1].to_string(),
        });
    }
    out
}

#[cfg(target_os = "linux")]
fn collect_firmware() -> FirmwareInfo {
    let uefi = std::path::Path::new("/sys/firmware/efi").exists();
    let mut secure_boot = false;
    if uefi {
        if let Ok(entries) = std::fs::read_dir("/sys/firmware/efi/efivars") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("SecureBoot-") {
                    if let Ok(bytes) = std::fs::read(entry.path()) {
                        // EFI variable format: 4-byte attribute header then data.
                        if bytes.len() >= 5 {
                            secure_boot = bytes[4] == 1;
                        }
                    }
                    break;
                }
            }
        }
    }
    let vendor = std::fs::read_to_string("/sys/class/dmi/id/bios_vendor")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let version = std::fs::read_to_string("/sys/class/dmi/id/bios_version")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let release_date = std::fs::read_to_string("/sys/class/dmi/id/bios_date")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    FirmwareInfo {
        vendor,
        version,
        release_date,
        uefi,
        secure_boot,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_os_release() {
        let s = r#"
NAME="Ubuntu"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
"#;
        let (id, ver) = parse_os_release(s);
        assert_eq!(id, "ubuntu");
        assert_eq!(ver, "22.04");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_minimal_cpuinfo() {
        let s = "\
processor\t: 0\n\
vendor_id\t: GenuineIntel\n\
model name\t: Imaginary CPU @ 2.0GHz\n\
physical id\t: 0\n\
flags\t\t: fpu vme de pse tsc\n\
\n\
processor\t: 1\n\
vendor_id\t: GenuineIntel\n\
model name\t: Imaginary CPU @ 2.0GHz\n\
physical id\t: 0\n\
flags\t\t: fpu vme de pse tsc\n\
";
        let cpu = parse_cpuinfo(s);
        assert_eq!(cpu.vendor, "GenuineIntel");
        assert_eq!(cpu.physical_cores, 1);
        assert_eq!(cpu.logical_cores, 2);
        assert!(cpu.flags.iter().any(|f| f == "fpu"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_proc_mounts() {
        let s = "\
/dev/sda1 / ext4 rw,relatime 0 0\n\
proc /proc proc rw 0 0\n\
";
        let mounts = parse_proc_mounts(s);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].device, "/dev/sda1");
        assert_eq!(mounts[0].mountpoint.as_deref(), Some("/"));
        assert_eq!(mounts[0].fstype, "ext4");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_systemctl_enabled_listing() {
        let s = "\
ssh.service                 enabled\n\
cron.service                enabled\n\
";
        let svcs = parse_systemctl_enabled(s);
        assert_eq!(svcs.len(), 2);
        assert_eq!(svcs[0].name, "ssh.service");
        assert_eq!(svcs[0].state, "enabled");
    }
}
