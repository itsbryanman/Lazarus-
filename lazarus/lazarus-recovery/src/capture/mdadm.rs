//! mdadm (Linux software RAID) capture.

use serde::{Deserialize, Serialize};

use super::system::{CaptureOpts, CaptureWarning};
use lazarus_core::error::Result;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MdadmConfig {
    /// Verbatim `/etc/mdadm/mdadm.conf` (or `/etc/mdadm.conf`).
    pub mdadm_conf: String,
    /// Verbatim `/proc/mdstat`.
    pub mdstat: String,
    #[serde(default)]
    pub arrays: Vec<MdArray>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdArray {
    pub device: String,
    pub uuid: String,
    pub level: String,
    pub raid_devices: u32,
    pub total_devices: u32,
    /// Verbatim output of `mdadm --detail --export <device>`.
    pub detail: String,
}

pub async fn capture_mdadm(
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] opts: &CaptureOpts,
) -> Result<(Option<MdadmConfig>, Vec<CaptureWarning>)> {
    #[cfg(not(target_os = "linux"))]
    {
        return Ok((None, Vec::new()));
    }

    #[cfg(target_os = "linux")]
    {
        linux::capture_mdadm_linux(opts).await
    }
}

/// Parse `mdadm --detail --export <device>` style output:
/// `MD_LEVEL=raid1`, `MD_UUID=...`, etc.
pub fn parse_mdadm_detail_export(s: &str) -> MdArray {
    let mut device = String::new();
    let mut uuid = String::new();
    let mut level = String::new();
    let mut raid_devices: u32 = 0;
    let mut total_devices: u32 = 0;
    for line in s.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("MD_DEVNAME=") {
            device = v.to_string();
        } else if let Some(v) = line.strip_prefix("MD_UUID=") {
            uuid = v.to_string();
        } else if let Some(v) = line.strip_prefix("MD_LEVEL=") {
            level = v.to_string();
        } else if let Some(v) = line.strip_prefix("MD_DEVICES=") {
            raid_devices = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("MD_TOTAL_DEVICES=") {
            total_devices = v.parse().unwrap_or(raid_devices);
        }
    }
    MdArray {
        device,
        uuid,
        level,
        raid_devices,
        total_devices: if total_devices == 0 {
            raid_devices
        } else {
            total_devices
        },
        detail: s.to_string(),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::path::Path;

    pub(super) async fn capture_mdadm_linux(
        opts: &CaptureOpts,
    ) -> Result<(Option<MdadmConfig>, Vec<CaptureWarning>)> {
        let mdstat = match std::fs::read_to_string("/proc/mdstat") {
            Ok(s) => s,
            Err(_) => return Ok((None, Vec::new())),
        };
        if !mdstat.lines().any(|l| l.starts_with("md")) {
            return Ok((None, Vec::new()));
        }
        let mut warnings = Vec::new();
        let mdadm_conf = first_existing(&["/etc/mdadm/mdadm.conf", "/etc/mdadm.conf"])
            .unwrap_or_default();

        let mut arrays = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy().to_string();
                if !(name.starts_with("md") && !name.contains("p")) {
                    continue;
                }
                let dev_path = format!("/dev/{name}");
                if !Path::new(&dev_path).exists() {
                    continue;
                }
                match super::super::util::run_capture_str(
                    "mdadm",
                    &["--detail", "--export", &dev_path],
                    opts.tool_timeout,
                )
                .await
                {
                    Ok(s) => arrays.push(parse_mdadm_detail_export(&s)),
                    Err(e) => warnings.push(CaptureWarning::new(
                        "mdadm",
                        format!("mdadm --detail {dev_path}: {e}"),
                    )),
                }
            }
        }

        Ok((
            Some(MdadmConfig {
                mdadm_conf,
                mdstat,
                arrays,
            }),
            warnings,
        ))
    }

    fn first_existing(paths: &[&str]) -> Option<String> {
        for p in paths {
            if let Ok(s) = std::fs::read_to_string(p) {
                return Some(s);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mdadm_detail() {
        let s = "\
MD_LEVEL=raid1\n\
MD_DEVICES=2\n\
MD_TOTAL_DEVICES=2\n\
MD_UUID=abcd:efgh:1234:5678\n\
MD_DEVNAME=md0\n\
";
        let arr = parse_mdadm_detail_export(s);
        assert_eq!(arr.device, "md0");
        assert_eq!(arr.level, "raid1");
        assert_eq!(arr.raid_devices, 2);
        assert_eq!(arr.uuid, "abcd:efgh:1234:5678");
    }
}
