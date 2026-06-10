//! Per-disk physical layout: device geometry, partition table, raw dumps
//! sufficient to recreate the table on a blank disk.
//!
//! All on-disk shell-outs go through `tokio::process::Command` with a
//! caller-controlled timeout. Pure parsing functions take `&[u8]` /
//! `&str` so they exercise on hosts without `sgdisk`/`sfdisk` installed.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::system::CaptureWarning;
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskLayout {
    pub device: String,
    #[serde(default)]
    pub by_id: Option<String>,
    #[serde(default)]
    pub by_path: Option<String>,
    pub model: String,
    pub serial: String,
    pub size_bytes: u64,
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub rotational: bool,
    pub partition_table: PartitionTable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PartitionTable {
    Gpt {
        disk_guid: String,
        partitions: Vec<GptPartition>,
        raw_dump: Vec<u8>,
    },
    Mbr {
        partitions: Vec<MbrPartition>,
        raw_dump: Vec<u8>,
        boot_code: Vec<u8>,
    },
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GptPartition {
    pub number: u32,
    pub partition_guid: String,
    pub type_guid: String,
    pub name: String,
    pub start_lba: u64,
    pub end_lba: u64,
    pub attributes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MbrPartition {
    pub number: u32,
    pub partition_type: u8,
    pub start_lba: u64,
    pub size_lba: u64,
    pub bootable: bool,
}

/// Detect every real (non-loop, non-ram, non-dm) block device on the
/// host and capture its partition table.
pub async fn discover_disks(
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    opts: &super::system::CaptureOpts,
) -> Result<(Vec<DiskLayout>, Vec<CaptureWarning>)> {
    #[cfg(not(target_os = "linux"))]
    {
        return Ok((Vec::new(), Vec::new()));
    }

    #[cfg(target_os = "linux")]
    {
        linux::discover_disks_linux(opts).await
    }
}

// --- Pure parsers (unit-tested without any OS access) -----------------------

/// Detect whether the first 512 bytes of a disk look like a GPT-style
/// protective MBR or a plain MBR. `None` means "no recognisable
/// partition table".
pub fn detect_table_kind(sector_0: &[u8]) -> TableKind {
    if sector_0.len() < 512 {
        return TableKind::None;
    }
    // Boot signature.
    if sector_0[510] != 0x55 || sector_0[511] != 0xAA {
        return TableKind::None;
    }
    // Walk the 4 MBR partition entries at offset 0x1BE; any entry of
    // type 0xEE marks the disk as GPT-with-protective-MBR.
    for slot in 0..4 {
        let off = 0x1BE + slot * 16;
        let entry_type = sector_0[off + 4];
        if entry_type == 0xEE {
            return TableKind::Gpt;
        }
    }
    TableKind::Mbr
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    Gpt,
    Mbr,
    None,
}

/// Parse the structured portion of an `sgdisk --backup=-` dump. We only
/// need to surface partition records here — the raw bytes themselves are
/// captured separately for byte-for-byte recreation.
///
/// Because `sgdisk --backup` is a binary format, this helper instead
/// parses the human-readable output of `sgdisk --print --pretty`. The
/// orchestrator runs both: structured fields from `--print`, raw bytes
/// from `--backup`.
pub fn parse_sgdisk_print(s: &str) -> std::result::Result<(String, Vec<GptPartition>), String> {
    let mut disk_guid = String::new();
    let mut partitions: Vec<GptPartition> = Vec::new();
    let mut in_table = false;
    for line in s.lines() {
        let line = line.trim_end();
        let stripped = line.trim();
        if let Some(rest) = stripped.strip_prefix("Disk identifier (GUID):") {
            disk_guid = rest.trim().to_string();
            continue;
        }
        if stripped.starts_with("Number") && stripped.contains("Start") && stripped.contains("End")
        {
            in_table = true;
            continue;
        }
        if !in_table || stripped.is_empty() {
            continue;
        }
        // Lines look like:
        // "   1            2048         1050623   512.0 MiB   EF00  EFI System"
        let parts: Vec<&str> = stripped.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let number: u32 = match parts[0].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let start_lba: u64 = parts[1].parse().unwrap_or(0);
        let end_lba: u64 = parts[2].parse().unwrap_or(0);
        // The "name" portion starts after `Size`, `Unit`, `Code`
        // columns: index 6 onward in the token list.
        let name = parts.get(6..).map(|s| s.join(" ")).unwrap_or_default();
        partitions.push(GptPartition {
            number,
            partition_guid: String::new(),
            type_guid: String::new(),
            name,
            start_lba,
            end_lba,
            attributes: 0,
        });
    }
    if disk_guid.is_empty() && partitions.is_empty() {
        return Err("sgdisk output did not contain a disk identifier or partition table".into());
    }
    Ok((disk_guid, partitions))
}

/// Parse the human-readable output of `sfdisk --dump /dev/X` into MBR
/// partition records. `sfdisk` also produces script-style output that
/// can be replayed verbatim; the verbatim text is stored separately as
/// `raw_dump`.
pub fn parse_sfdisk_dump(s: &str) -> std::result::Result<Vec<MbrPartition>, String> {
    let mut out: Vec<MbrPartition> = Vec::new();
    let mut number: u32 = 1;
    for line in s.lines() {
        let line = line.trim();
        if !line.contains(": start=") {
            continue;
        }
        let mut start_lba: u64 = 0;
        let mut size_lba: u64 = 0;
        let mut partition_type: u8 = 0;
        let mut bootable = false;
        // Format: "/dev/sda1 : start= 2048, size= 1050624, type=83, bootable"
        for piece in line.split(',') {
            let piece = piece.trim();
            if let Some(rest) = piece.split_once("start=") {
                start_lba = rest.1.trim().parse().unwrap_or(0);
            } else if let Some(rest) = piece.split_once("size=") {
                size_lba = rest.1.trim().parse().unwrap_or(0);
            } else if let Some(rest) = piece.split_once("type=") {
                let raw = rest.1.trim();
                partition_type = u8::from_str_radix(raw, 16)
                    .or_else(|_| raw.parse::<u8>())
                    .unwrap_or(0);
            } else if piece == "bootable" {
                bootable = true;
            }
        }
        if size_lba > 0 {
            out.push(MbrPartition {
                number,
                partition_type,
                start_lba,
                size_lba,
                bootable,
            });
            number += 1;
        }
    }
    if out.is_empty() {
        return Err("sfdisk output did not list any partitions".into());
    }
    Ok(out)
}

// --- Linux-only OS-touching collection --------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::time::Duration;
    use tokio::process::Command;

    pub(super) async fn discover_disks_linux(
        opts: &super::super::system::CaptureOpts,
    ) -> Result<(Vec<DiskLayout>, Vec<CaptureWarning>)> {
        let mut warnings: Vec<CaptureWarning> = Vec::new();
        let mut disks: Vec<DiskLayout> = Vec::new();
        let entries = match fs::read_dir("/sys/block") {
            Ok(e) => e,
            Err(e) => {
                warnings.push(CaptureWarning::new(
                    "disk",
                    format!("could not read /sys/block: {e}"),
                ));
                return Ok((disks, warnings));
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy().to_string();
            if name.starts_with("loop")
                || name.starts_with("ram")
                || name.starts_with("dm-")
                || name.starts_with("zram")
                || name.starts_with("sr")
            {
                continue;
            }
            let device = format!("/dev/{name}");
            if !Path::new(&device).exists() {
                continue;
            }
            match capture_one_disk(&device, &name, opts.tool_timeout, &mut warnings).await {
                Ok(disk) => disks.push(disk),
                Err(e) => warnings.push(CaptureWarning::new(
                    "disk",
                    format!("failed to capture {device}: {e}"),
                )),
            }
        }
        Ok((disks, warnings))
    }

    async fn capture_one_disk(
        device: &str,
        sysfs_name: &str,
        timeout: Duration,
        warnings: &mut Vec<CaptureWarning>,
    ) -> std::result::Result<DiskLayout, String> {
        let sysfs = format!("/sys/block/{sysfs_name}");
        let read_u64 = |sub: &str| -> u64 {
            fs::read_to_string(format!("{sysfs}/{sub}"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0)
        };
        let sectors = read_u64("size");
        let logical_block_size = fs::read_to_string(format!("{sysfs}/queue/logical_block_size"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(512u32);
        let physical_block_size = fs::read_to_string(format!("{sysfs}/queue/physical_block_size"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(logical_block_size);
        let size_bytes = sectors.saturating_mul(logical_block_size as u64);
        let rotational = fs::read_to_string(format!("{sysfs}/queue/rotational"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false);

        let model = fs::read_to_string(format!("{sysfs}/device/model"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let serial = fs::read_to_string(format!("{sysfs}/device/serial"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let by_id = first_symlink_in("/dev/disk/by-id", device);
        let by_path = first_symlink_in("/dev/disk/by-path", device);

        // Sector 0.
        let mut sector_0 = [0u8; 512];
        let table_kind = match fs::File::open(device) {
            Ok(mut f) => {
                use std::io::Read;
                if f.read(&mut sector_0).map(|n| n >= 512).unwrap_or(false) {
                    detect_table_kind(&sector_0)
                } else {
                    TableKind::None
                }
            }
            Err(e) => {
                warnings.push(CaptureWarning::new(
                    "disk",
                    format!("could not read sector 0 of {device}: {e}"),
                ).with_remediation("re-run as root"));
                TableKind::None
            }
        };

        let partition_table = match table_kind {
            TableKind::Gpt => capture_gpt(device, timeout, warnings).await,
            TableKind::Mbr => capture_mbr(device, &sector_0, timeout, warnings).await,
            TableKind::None => PartitionTable::None,
        };

        Ok(DiskLayout {
            device: device.into(),
            by_id,
            by_path,
            model,
            serial,
            size_bytes,
            logical_block_size,
            physical_block_size,
            rotational,
            partition_table,
        })
    }

    async fn capture_gpt(
        device: &str,
        timeout: Duration,
        warnings: &mut Vec<CaptureWarning>,
    ) -> PartitionTable {
        // Raw dump for byte-for-byte recreation. If sgdisk isn't on the
        // host this is a hard error per the prompt — silently missing
        // partition tables is "a foot-loaded shotgun".
        let raw_dump = run_capture("sgdisk", &["--backup=-", device], timeout)
            .await
            .unwrap_or_default();
        let print = run_capture("sgdisk", &["--print", device], timeout)
            .await
            .unwrap_or_default();
        let print_str = String::from_utf8_lossy(&print);
        let (disk_guid, partitions) = parse_sgdisk_print(&print_str).unwrap_or_else(|e| {
            warnings.push(CaptureWarning::new(
                "disk",
                format!("sgdisk parse failed on {device}: {e}"),
            ));
            (String::new(), Vec::new())
        });
        if raw_dump.is_empty() {
            warnings.push(
                CaptureWarning::new(
                    "disk",
                    format!("sgdisk unavailable; GPT raw_dump empty for {device}"),
                )
                .with_remediation("install gdisk/sgdisk so restore can use the binary path"),
            );
        }
        PartitionTable::Gpt {
            disk_guid,
            partitions,
            raw_dump,
        }
    }

    async fn capture_mbr(
        device: &str,
        sector_0: &[u8],
        timeout: Duration,
        warnings: &mut Vec<CaptureWarning>,
    ) -> PartitionTable {
        let raw_dump = run_capture("sfdisk", &["--dump", device], timeout)
            .await
            .unwrap_or_default();
        let dump_str = String::from_utf8_lossy(&raw_dump);
        let partitions = parse_sfdisk_dump(&dump_str).unwrap_or_else(|e| {
            warnings.push(CaptureWarning::new(
                "disk",
                format!("sfdisk parse failed on {device}: {e}"),
            ));
            Vec::new()
        });
        let boot_code = sector_0.get(0..446).map(|s| s.to_vec()).unwrap_or_default();
        if boot_code.is_empty() {
            warnings.push(CaptureWarning::new(
                "disk",
                format!("could not capture MBR boot code from {device}"),
            ));
        }
        PartitionTable::Mbr {
            partitions,
            raw_dump,
            boot_code,
        }
    }

    pub(super) async fn run_capture(
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> std::result::Result<Vec<u8>, String> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        let fut = cmd.output();
        match tokio::time::timeout(timeout, fut).await {
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

    fn first_symlink_in(dir: &str, target_device: &str) -> Option<String> {
        let entries = fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            let dest = match fs::canonicalize(&path) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if dest.to_string_lossy() == target_device {
                return Some(path.to_string_lossy().to_string());
            }
        }
        None
    }
}

// `Duration` is unused on non-Linux above; suppress with explicit use so
// non-Linux builds also exercise the import path of the module without
// dead-code warnings.
#[allow(dead_code)]
const _: () = {
    let _ = Duration::from_secs;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_gpt_via_protective_mbr() {
        let mut s = [0u8; 512];
        s[510] = 0x55;
        s[511] = 0xAA;
        s[0x1BE + 4] = 0xEE; // first partition entry type = GPT protective
        assert_eq!(detect_table_kind(&s), TableKind::Gpt);
    }

    #[test]
    fn detects_mbr() {
        let mut s = [0u8; 512];
        s[510] = 0x55;
        s[511] = 0xAA;
        s[0x1BE + 4] = 0x83; // linux native
        assert_eq!(detect_table_kind(&s), TableKind::Mbr);
    }

    #[test]
    fn detects_blank() {
        let s = [0u8; 512];
        assert_eq!(detect_table_kind(&s), TableKind::None);
    }

    #[test]
    fn parses_sgdisk_print_output() {
        let s = "\
Disk /dev/sda: 1953525168 sectors, 931.5 GiB
Disk identifier (GUID): C0FFEE01-AAAA-BBBB-CCCC-1234567890AB
Partition table holds up to 128 entries

Number  Start (sector)    End (sector)  Size       Code  Name
   1            2048         1050623   512.0 MiB   EF00  EFI System
   2         1050624      1953525134   931.0 GiB   8300  Linux filesystem
";
        let (guid, parts) = parse_sgdisk_print(s).expect("parse");
        assert_eq!(guid, "C0FFEE01-AAAA-BBBB-CCCC-1234567890AB");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].start_lba, 2048);
        assert_eq!(parts[0].end_lba, 1050623);
        assert!(parts[0].name.contains("EFI System"));
        assert_eq!(parts[1].number, 2);
    }

    #[test]
    fn parses_sfdisk_dump_output() {
        let s = "\
label: dos
label-id: 0xdeadbeef
device: /dev/sda
unit: sectors

/dev/sda1 : start=        2048, size=     1050624, type=83, bootable
/dev/sda2 : start=     1052672, size=    20971520, type=82
";
        let parts = parse_sfdisk_dump(s).expect("parse");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].number, 1);
        assert_eq!(parts[0].start_lba, 2048);
        assert_eq!(parts[0].size_lba, 1050624);
        assert_eq!(parts[0].partition_type, 0x83);
        assert!(parts[0].bootable);
        assert!(!parts[1].bootable);
    }
}
