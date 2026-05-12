//! LVM2 metadata capture.
//!
//! We capture the structured `vgs/pvs/lvs --reportformat json` outputs
//! plus the `vgcfgbackup` text file for every volume group so restore
//! can `vgcfgrestore` byte-for-byte.

use serde::{Deserialize, Serialize};

use super::system::{CaptureOpts, CaptureWarning};
use lazarus_core::error::Result;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LvmConfig {
    #[serde(default)]
    pub physical_volumes: Vec<PhysicalVolume>,
    #[serde(default)]
    pub volume_groups: Vec<VolumeGroup>,
    #[serde(default)]
    pub logical_volumes: Vec<LogicalVolume>,
    #[serde(default)]
    pub vg_backups: Vec<VgBackup>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhysicalVolume {
    pub name: String,
    pub vg_name: String,
    pub uuid: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeGroup {
    pub name: String,
    pub uuid: String,
    pub size_bytes: u64,
    pub free_bytes: u64,
    pub pv_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogicalVolume {
    pub name: String,
    pub vg_name: String,
    pub uuid: String,
    pub size_bytes: u64,
    pub origin: String,
    pub attr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VgBackup {
    pub vg_name: String,
    pub config_text: String,
}

pub async fn capture_lvm(
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] opts: &CaptureOpts,
) -> Result<(Option<LvmConfig>, Vec<CaptureWarning>)> {
    #[cfg(not(target_os = "linux"))]
    {
        return Ok((None, Vec::new()));
    }

    #[cfg(target_os = "linux")]
    {
        linux::capture_lvm_linux(opts).await
    }
}

/// Parse `lvm pvs --reportformat json -o pv_name,vg_name,pv_uuid,pv_size --units b --nosuffix`
/// style output.
pub fn parse_pvs_json(s: &str) -> std::result::Result<Vec<PhysicalVolume>, String> {
    let v: serde_json::Value = serde_json::from_str(s).map_err(|e| e.to_string())?;
    let arr = v
        .pointer("/report/0/pv")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing /report/0/pv".to_string())?;
    let mut out = Vec::new();
    for item in arr {
        out.push(PhysicalVolume {
            name: get_str(item, "pv_name"),
            vg_name: get_str(item, "vg_name"),
            uuid: get_str(item, "pv_uuid"),
            size_bytes: get_u64(item, "pv_size"),
        });
    }
    Ok(out)
}

pub fn parse_vgs_json(s: &str) -> std::result::Result<Vec<VolumeGroup>, String> {
    let v: serde_json::Value = serde_json::from_str(s).map_err(|e| e.to_string())?;
    let arr = v
        .pointer("/report/0/vg")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing /report/0/vg".to_string())?;
    let mut out = Vec::new();
    for item in arr {
        out.push(VolumeGroup {
            name: get_str(item, "vg_name"),
            uuid: get_str(item, "vg_uuid"),
            size_bytes: get_u64(item, "vg_size"),
            free_bytes: get_u64(item, "vg_free"),
            pv_count: get_u64(item, "pv_count") as u32,
        });
    }
    Ok(out)
}

pub fn parse_lvs_json(s: &str) -> std::result::Result<Vec<LogicalVolume>, String> {
    let v: serde_json::Value = serde_json::from_str(s).map_err(|e| e.to_string())?;
    let arr = v
        .pointer("/report/0/lv")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing /report/0/lv".to_string())?;
    let mut out = Vec::new();
    for item in arr {
        out.push(LogicalVolume {
            name: get_str(item, "lv_name"),
            vg_name: get_str(item, "vg_name"),
            uuid: get_str(item, "lv_uuid"),
            size_bytes: get_u64(item, "lv_size"),
            origin: get_str(item, "origin"),
            attr: get_str(item, "lv_attr"),
        });
    }
    Ok(out)
}

fn get_str(v: &serde_json::Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn get_u64(v: &serde_json::Value, k: &str) -> u64 {
    v.get(k)
        .and_then(|x| x.as_str())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::path::Path;

    pub(super) async fn capture_lvm_linux(
        opts: &CaptureOpts,
    ) -> Result<(Option<LvmConfig>, Vec<CaptureWarning>)> {
        if !Path::new("/etc/lvm").exists() {
            return Ok((None, Vec::new()));
        }
        let mut warnings = Vec::new();

        let units = &["--units", "b", "--nosuffix", "--reportformat", "json"];

        let mut pvs_args = vec!["pvs", "-o", "pv_name,vg_name,pv_uuid,pv_size"];
        pvs_args.extend_from_slice(units);
        let physical_volumes = match super::super::util::run_capture_str(
            "lvm",
            &pvs_args,
            opts.tool_timeout,
        )
        .await
        {
            Ok(s) => parse_pvs_json(&s).unwrap_or_else(|e| {
                warnings.push(CaptureWarning::new("lvm", format!("pvs parse: {e}")));
                Vec::new()
            }),
            Err(e) => {
                warnings.push(CaptureWarning::new("lvm", format!("pvs: {e}")));
                Vec::new()
            }
        };

        let mut vgs_args = vec!["vgs", "-o", "vg_name,vg_uuid,vg_size,vg_free,pv_count"];
        vgs_args.extend_from_slice(units);
        let volume_groups = match super::super::util::run_capture_str(
            "lvm",
            &vgs_args,
            opts.tool_timeout,
        )
        .await
        {
            Ok(s) => parse_vgs_json(&s).unwrap_or_else(|e| {
                warnings.push(CaptureWarning::new("lvm", format!("vgs parse: {e}")));
                Vec::new()
            }),
            Err(e) => {
                warnings.push(CaptureWarning::new("lvm", format!("vgs: {e}")));
                Vec::new()
            }
        };

        let mut lvs_args = vec![
            "lvs",
            "-o",
            "lv_name,vg_name,lv_uuid,lv_size,origin,lv_attr",
        ];
        lvs_args.extend_from_slice(units);
        let logical_volumes = match super::super::util::run_capture_str(
            "lvm",
            &lvs_args,
            opts.tool_timeout,
        )
        .await
        {
            Ok(s) => parse_lvs_json(&s).unwrap_or_else(|e| {
                warnings.push(CaptureWarning::new("lvm", format!("lvs parse: {e}")));
                Vec::new()
            }),
            Err(e) => {
                warnings.push(CaptureWarning::new("lvm", format!("lvs: {e}")));
                Vec::new()
            }
        };

        let mut vg_backups: Vec<VgBackup> = Vec::new();
        for vg in &volume_groups {
            let tmp = format!("/tmp/lazarus-vgcfg-{}-{}.txt", vg.name, std::process::id());
            let res = super::super::util::run_capture_str(
                "vgcfgbackup",
                &["-f", &tmp, &vg.name],
                opts.tool_timeout,
            )
            .await;
            match res {
                Ok(_) => match std::fs::read_to_string(&tmp) {
                    Ok(text) => vg_backups.push(VgBackup {
                        vg_name: vg.name.clone(),
                        config_text: text,
                    }),
                    Err(e) => warnings.push(CaptureWarning::new(
                        "lvm",
                        format!("vgcfgbackup of {} unreadable: {e}", vg.name),
                    )),
                },
                Err(e) => warnings.push(CaptureWarning::new(
                    "lvm",
                    format!("vgcfgbackup {} failed: {e}", vg.name),
                )),
            }
            let _ = std::fs::remove_file(&tmp);
        }

        if physical_volumes.is_empty() && volume_groups.is_empty() && logical_volumes.is_empty() {
            return Ok((None, warnings));
        }

        Ok((
            Some(LvmConfig {
                physical_volumes,
                volume_groups,
                logical_volumes,
                vg_backups,
            }),
            warnings,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pvs_report() {
        let s = r#"{
  "report": [
    {
      "pv": [
        {"pv_name": "/dev/sda2", "vg_name": "vg0", "pv_uuid": "AAAA", "pv_size": "536870912000"}
      ]
    }
  ]
}"#;
        let pvs = parse_pvs_json(s).expect("parse");
        assert_eq!(pvs.len(), 1);
        assert_eq!(pvs[0].name, "/dev/sda2");
        assert_eq!(pvs[0].size_bytes, 536870912000);
    }

    #[test]
    fn parses_lvs_report() {
        let s = r#"{
  "report": [
    {
      "lv": [
        {"lv_name": "root", "vg_name": "vg0", "lv_uuid": "X", "lv_size": "10737418240", "origin": "", "lv_attr": "-wi-ao----"}
      ]
    }
  ]
}"#;
        let lvs = parse_lvs_json(s).expect("parse");
        assert_eq!(lvs.len(), 1);
        assert_eq!(lvs[0].name, "root");
        assert_eq!(lvs[0].size_bytes, 10737418240);
    }
}
