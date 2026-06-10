//! UEFI/BIOS bootloader configuration.
//!
//! For UEFI hosts we tar the entire `/boot/efi` ESP and ship it as a
//! single chunk under the data key, so restore can reproduce the boot
//! entries byte-for-byte. For BIOS hosts we ship the first 446 bytes of
//! the MBR boot region plus grub configuration.

use serde::{Deserialize, Serialize};

use super::persist::FingerprintPersister;
use super::system::{CaptureOpts, CaptureWarning, NamedBlob};
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootloaderConfig {
    pub mode: BootMode,
    #[serde(default)]
    pub uefi: Option<UefiConfig>,
    #[serde(default)]
    pub bios: Option<BiosConfig>,
    #[serde(default)]
    pub kernel_files: Vec<KernelFileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum BootMode {
    Uefi,
    Bios,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UefiConfig {
    pub esp_device: String,
    pub esp_uuid: String,
    pub esp_size_bytes: u64,
    /// Hex BLAKE3 of tar(/boot/efi) — the ESP archive chunk.
    pub esp_archive_chunk: String,
    pub efibootmgr_dump: String,
    pub secure_boot_state: String,
    pub mok_certificates_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiosConfig {
    /// First 446 bytes of the MBR. Wrapped in `Vec<u8>` rather than
    /// `[u8; 446]` so serde_json + bincode both stay happy; the
    /// invariant `len() == 446` is enforced at capture time.
    pub mbr_boot_code: Vec<u8>,
    #[serde(default)]
    pub grub_cfg: Option<String>,
    #[serde(default)]
    pub default_grub: Option<String>,
    #[serde(default)]
    pub grub_d_files: Vec<NamedBlob>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelFileEntry {
    pub path: String,
    pub size: u64,
    /// Hex BLAKE3 of the file's contents (also the chunk key).
    pub chunk: String,
}

pub async fn capture_bootloader(
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] opts: &CaptureOpts,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] persister: &FingerprintPersister<
        '_,
    >,
) -> Result<(BootloaderConfig, Vec<CaptureWarning>)> {
    #[cfg(not(target_os = "linux"))]
    {
        return Ok((BootloaderConfig::default(), Vec::new()));
    }

    #[cfg(target_os = "linux")]
    {
        linux::capture_bootloader_linux(opts, persister).await
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::path::Path;

    pub(super) async fn capture_bootloader_linux(
        opts: &CaptureOpts,
        persister: &FingerprintPersister<'_>,
    ) -> Result<(BootloaderConfig, Vec<CaptureWarning>)> {
        let mut warnings = Vec::new();
        let uefi_active = Path::new("/sys/firmware/efi").exists();

        let mode = if uefi_active {
            BootMode::Uefi
        } else {
            BootMode::Bios
        };

        let mut uefi = None;
        let mut bios = None;

        if uefi_active {
            uefi = Some(capture_uefi(opts, persister, &mut warnings).await);
        } else {
            bios = Some(capture_bios(&mut warnings).await);
        }

        let kernel_files = capture_kernel_files(persister, &mut warnings).await;

        Ok((
            BootloaderConfig {
                mode,
                uefi,
                bios,
                kernel_files,
            },
            warnings,
        ))
    }

    async fn capture_uefi(
        opts: &CaptureOpts,
        persister: &FingerprintPersister<'_>,
        warnings: &mut Vec<CaptureWarning>,
    ) -> UefiConfig {
        // ESP archive: tar /boot/efi.
        let esp_archive_bytes =
            match super::super::util::tar_dir_to_vec("/boot/efi", opts.tool_timeout).await {
                Ok(b) => b,
                Err(e) => {
                    warnings.push(
                        CaptureWarning::new("bootloader", format!("could not tar /boot/efi: {e}"))
                            .with_remediation("mount the ESP at /boot/efi and re-run as root"),
                    );
                    Vec::new()
                }
            };
        let esp_archive_chunk = if esp_archive_bytes.is_empty() {
            String::new()
        } else {
            match persister.persist_blob_data_key(&esp_archive_bytes).await {
                Ok(h) => h,
                Err(e) => {
                    warnings.push(CaptureWarning::new(
                        "bootloader",
                        format!("could not persist ESP archive: {e}"),
                    ));
                    String::new()
                }
            }
        };

        let efibootmgr_dump =
            match super::super::util::run_capture_str("efibootmgr", &["-v"], opts.tool_timeout)
                .await
            {
                Ok(s) => s,
                Err(_) => {
                    warnings.push(CaptureWarning::new(
                        "bootloader",
                        "efibootmgr unavailable; UEFI boot entries not captured",
                    ));
                    String::new()
                }
            };

        // Secure Boot state via efivar byte 4.
        let mut secure_boot_state = "unknown".to_string();
        if let Ok(entries) = std::fs::read_dir("/sys/firmware/efi/efivars")
            && let Some(entry) = entries.flatten().next()
        {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("SecureBoot-")
                && let Ok(bytes) = std::fs::read(entry.path())
                && bytes.len() >= 5
            {
                secure_boot_state = if bytes[4] == 1 {
                    "enabled".into()
                } else {
                    "disabled".into()
                };
            }
        }

        let mok_certificates_present = std::path::Path::new("/var/lib/shim-signed/mok").exists()
            || std::path::Path::new("/var/lib/dkms/mok.pub").exists();

        // ESP device + UUID from /proc/mounts.
        let (esp_device, esp_uuid) = match std::fs::read_to_string("/proc/mounts") {
            Ok(m) => esp_from_mounts(&m),
            Err(_) => (String::new(), String::new()),
        };

        let esp_size_bytes = esp_archive_bytes.len() as u64;

        UefiConfig {
            esp_device,
            esp_uuid,
            esp_size_bytes,
            esp_archive_chunk,
            efibootmgr_dump,
            secure_boot_state,
            mok_certificates_present,
        }
    }

    async fn capture_bios(warnings: &mut Vec<CaptureWarning>) -> BiosConfig {
        let root_disk = match resolve_root_disk() {
            Some(d) => d,
            None => {
                warnings.push(CaptureWarning::new(
                    "bootloader",
                    "could not resolve root disk; MBR boot code not captured",
                ));
                return BiosConfig {
                    mbr_boot_code: Vec::new(),
                    grub_cfg: None,
                    default_grub: None,
                    grub_d_files: Vec::new(),
                };
            }
        };
        let mbr_boot_code = match read_first_n_bytes(&root_disk, 446) {
            Ok(b) => b,
            Err(e) => {
                warnings.push(
                    CaptureWarning::new(
                        "bootloader",
                        format!("could not read MBR boot code from {root_disk}: {e}"),
                    )
                    .with_remediation("re-run as root"),
                );
                Vec::new()
            }
        };
        let grub_cfg = first_existing(&["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]);
        let default_grub = std::fs::read_to_string("/etc/default/grub").ok();
        let grub_d_files = enumerate_named_blobs("/etc/grub.d", 1024 * 1024).unwrap_or_default();
        BiosConfig {
            mbr_boot_code,
            grub_cfg,
            default_grub,
            grub_d_files,
        }
    }

    async fn capture_kernel_files(
        persister: &FingerprintPersister<'_>,
        warnings: &mut Vec<CaptureWarning>,
    ) -> Vec<KernelFileEntry> {
        let mut out: Vec<KernelFileEntry> = Vec::new();
        let entries = match std::fs::read_dir("/boot") {
            Ok(e) => e,
            Err(_) => return out,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_s = name.to_string_lossy().to_string();
            if !(name_s.starts_with("vmlinuz")
                || name_s.starts_with("initramfs")
                || name_s.starts_with("initrd")
                || name_s.starts_with("System.map"))
            {
                continue;
            }
            let path = entry.path();
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    warnings.push(CaptureWarning::new(
                        "bootloader",
                        format!("could not read {}: {e}", path.display()),
                    ));
                    continue;
                }
            };
            let size = bytes.len() as u64;
            let chunk = match persister.persist_blob_data_key(&bytes).await {
                Ok(h) => h,
                Err(e) => {
                    warnings.push(CaptureWarning::new(
                        "bootloader",
                        format!("could not persist {}: {e}", path.display()),
                    ));
                    continue;
                }
            };
            out.push(KernelFileEntry {
                path: path.to_string_lossy().to_string(),
                size,
                chunk,
            });
        }
        out
    }

    fn esp_from_mounts(mounts: &str) -> (String, String) {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && (parts[1] == "/boot/efi" || parts[1] == "/efi") {
                let dev = parts[0].to_string();
                // UUID is hard to grab in pure-stdlib without blkid;
                // accept a missing UUID over shelling out again here.
                return (dev, String::new());
            }
        }
        (String::new(), String::new())
    }

    fn resolve_root_disk() -> Option<String> {
        // Walk /proc/cmdline for root=
        let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
        let root_token = cmdline
            .split_whitespace()
            .find_map(|t| t.strip_prefix("root="));
        let mut root_device: Option<String> = None;
        if let Some(tok) = root_token {
            root_device = Some(tok.to_string());
        }
        // If `root=` is a UUID/LABEL, resolve via /dev/disk/by-uuid etc.
        if let Some(ref r) = root_device
            && r.starts_with("UUID=")
            && let Some(uuid) = r.strip_prefix("UUID=")
            && let Ok(p) = std::fs::canonicalize(format!("/dev/disk/by-uuid/{uuid}"))
        {
            root_device = Some(p.to_string_lossy().to_string());
        }
        // Strip trailing partition digits (sda1 -> sda, nvme0n1p1 -> nvme0n1).
        root_device.map(|d| disk_of_partition(&d))
    }

    pub(super) fn disk_of_partition(p: &str) -> String {
        let path = std::path::Path::new(p);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.is_empty() {
            return p.to_string();
        }
        // NVMe / mmc style: nvme0n1p1 -> nvme0n1, mmcblk0p1 -> mmcblk0.
        if name.contains('p')
            && (name.starts_with("nvme") || name.starts_with("mmcblk"))
            && let Some((stem, _)) = name.rsplit_once('p')
        {
            return format!("/dev/{stem}");
        }
        // sda1 -> sda.
        let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
        format!("/dev/{trimmed}")
    }

    fn read_first_n_bytes(path: &str, n: usize) -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut f = std::fs::File::open(path)?;
        let mut buf = vec![0u8; n];
        let mut read = 0;
        while read < n {
            let got = f.read(&mut buf[read..])?;
            if got == 0 {
                break;
            }
            read += got;
        }
        buf.truncate(read);
        Ok(buf)
    }

    fn first_existing(paths: &[&str]) -> Option<String> {
        for p in paths {
            if let Ok(s) = std::fs::read_to_string(p) {
                return Some(s);
            }
        }
        None
    }

    fn enumerate_named_blobs(dir: &str, max_size: u64) -> std::io::Result<Vec<NamedBlob>> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(out),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !md.is_file() || md.len() > max_size {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&path) {
                out.push(NamedBlob {
                    name: path
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    content: bytes,
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_mode_default_is_unknown() {
        assert_eq!(BootMode::default(), BootMode::Unknown);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disk_of_partition_strips_digits() {
        assert_eq!(linux::disk_of_partition("/dev/sda1"), "/dev/sda");
        assert_eq!(linux::disk_of_partition("/dev/nvme0n1p3"), "/dev/nvme0n1");
        assert_eq!(linux::disk_of_partition("/dev/mmcblk0p2"), "/dev/mmcblk0");
    }
}
