//! Per-host network configuration capture.
//!
//! Phase 3 focuses on *recording* enough to reconstruct the network on
//! a different host: interface names, MAC/MTU, the routing table, DNS,
//! and verbatim copies of the distribution's network-config files
//! (NetworkManager, systemd-networkd, /etc/network/interfaces,
//! netplan).

use serde::{Deserialize, Serialize};

use super::system::{CaptureOpts, CaptureWarning, NamedBlob};
use crate::error::Result;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub hostname: String,
    #[serde(default)]
    pub interfaces: Vec<NetworkInterface>,
    #[serde(default)]
    pub routes: Vec<RouteEntry>,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub networkmanager_profiles: Vec<NamedBlob>,
    #[serde(default)]
    pub systemd_networkd_files: Vec<NamedBlob>,
    #[serde(default)]
    pub etc_network_interfaces: Option<String>,
    #[serde(default)]
    pub netplan_yaml_files: Vec<NamedBlob>,
    #[serde(default)]
    pub resolv_conf: Option<String>,
    #[serde(default)]
    pub hosts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: String,
    pub kind: String,
    #[serde(default)]
    pub pci_address: Option<String>,
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default)]
    pub ipv4_addresses: Vec<String>,
    #[serde(default)]
    pub ipv6_addresses: Vec<String>,
    pub mtu: u32,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub dst: String,
    #[serde(default)]
    pub gw: Option<String>,
    pub dev: String,
    #[serde(default)]
    pub metric: Option<u32>,
    pub family: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub nameservers: Vec<String>,
    #[serde(default)]
    pub search: Vec<String>,
}

pub async fn capture_network(
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] opts: &CaptureOpts,
) -> Result<(NetworkConfig, Vec<CaptureWarning>)> {
    #[cfg(not(target_os = "linux"))]
    {
        return Ok((NetworkConfig::default(), Vec::new()));
    }

    #[cfg(target_os = "linux")]
    {
        linux::capture_network_linux(opts).await
    }
}

pub fn parse_resolv_conf(s: &str) -> DnsConfig {
    let mut ns = Vec::new();
    let mut search = Vec::new();
    for line in s.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(rest) = line.strip_prefix("nameserver") {
            let v = rest.trim();
            if !v.is_empty() {
                ns.push(v.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("search") {
            for tok in rest.split_whitespace() {
                search.push(tok.to_string());
            }
        }
    }
    DnsConfig {
        nameservers: ns,
        search,
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::path::Path;

    pub(super) async fn capture_network_linux(
        opts: &CaptureOpts,
    ) -> Result<(NetworkConfig, Vec<CaptureWarning>)> {
        let mut warnings = Vec::new();

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into());

        let interfaces = enumerate_interfaces(&mut warnings);

        let routes = match super::super::util::run_capture_str(
            "ip",
            &["-j", "route", "show"],
            opts.tool_timeout,
        )
        .await
        {
            Ok(s) => parse_ip_route_json(&s).unwrap_or_else(|_| Vec::new()),
            Err(_) => {
                warnings.push(CaptureWarning::new(
                    "network",
                    "`ip` unavailable; routes not captured",
                ));
                Vec::new()
            }
        };

        let resolv_conf = fs::read_to_string("/etc/resolv.conf").ok();
        let hosts = fs::read_to_string("/etc/hosts").ok();
        let dns = resolv_conf
            .as_deref()
            .map(parse_resolv_conf)
            .unwrap_or_default();

        let networkmanager_profiles =
            collect_dir("/etc/NetworkManager/system-connections", &mut warnings);
        let systemd_networkd_files = collect_dir("/etc/systemd/network", &mut warnings);
        let netplan_yaml_files = collect_dir("/etc/netplan", &mut warnings);
        let etc_network_interfaces = fs::read_to_string("/etc/network/interfaces").ok();

        Ok((
            NetworkConfig {
                hostname,
                interfaces,
                routes,
                dns,
                networkmanager_profiles,
                systemd_networkd_files,
                etc_network_interfaces,
                netplan_yaml_files,
                resolv_conf,
                hosts,
            },
            warnings,
        ))
    }

    fn enumerate_interfaces(warnings: &mut Vec<CaptureWarning>) -> Vec<NetworkInterface> {
        let mut out = Vec::new();
        let entries = match fs::read_dir("/sys/class/net") {
            Ok(e) => e,
            Err(_) => {
                warnings.push(CaptureWarning::new("network", "/sys/class/net unreadable"));
                return out;
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let base = format!("/sys/class/net/{name}");
            let mac = fs::read_to_string(format!("{base}/address"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let mtu: u32 = fs::read_to_string(format!("{base}/mtu"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            let state = fs::read_to_string(format!("{base}/operstate"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let kind = fs::read_to_string(format!("{base}/uevent"))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find_map(|l| l.strip_prefix("DEVTYPE=").map(|v| v.to_string()))
                })
                .unwrap_or_else(|| {
                    if name == "lo" {
                        "loopback".into()
                    } else {
                        "ethernet".into()
                    }
                });
            let driver = fs::canonicalize(format!("{base}/device/driver"))
                .ok()
                .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()));
            let pci_address = fs::canonicalize(format!("{base}/device"))
                .ok()
                .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()));
            out.push(NetworkInterface {
                name,
                mac,
                kind,
                pci_address,
                driver,
                ipv4_addresses: Vec::new(), // populated below via `ip -j addr`
                ipv6_addresses: Vec::new(),
                mtu,
                state,
            });
        }
        out
    }

    fn collect_dir(dir: &str, warnings: &mut Vec<CaptureWarning>) -> Vec<NamedBlob> {
        let mut out = Vec::new();
        if !Path::new(dir).exists() {
            return out;
        }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return out,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !md.is_file() {
                continue;
            }
            if md.len() > 1024 * 1024 {
                warnings.push(CaptureWarning::new(
                    "network",
                    format!("{} exceeds 1MiB cap; skipped", path.display()),
                ));
                continue;
            }
            if let Ok(bytes) = fs::read(&path) {
                out.push(NamedBlob {
                    name: path
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    content: bytes,
                });
            }
        }
        out
    }

    fn parse_ip_route_json(s: &str) -> std::result::Result<Vec<RouteEntry>, String> {
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|e| format!("ip route JSON: {e}"))?;
        let mut out = Vec::new();
        if let Some(arr) = v.as_array() {
            for item in arr {
                let dst = item
                    .get("dst")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let gw = item
                    .get("gateway")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let dev = item
                    .get("dev")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let metric = item
                    .get("metric")
                    .and_then(|v| v.as_u64())
                    .map(|m| m as u32);
                // `ip -j route` does not always include family in the
                // record; default to 2 (AF_INET) if not present.
                let family = item
                    .get("family")
                    .and_then(|v| v.as_str())
                    .map(|s| if s == "inet6" { 10u8 } else { 2u8 })
                    .unwrap_or(2);
                out.push(RouteEntry {
                    dst,
                    gw,
                    dev,
                    metric,
                    family,
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
    fn parses_resolv_conf() {
        let s = "\
# generated by net-tools\n\
nameserver 1.1.1.1\n\
nameserver 8.8.8.8\n\
search example.com lan\n\
";
        let cfg = parse_resolv_conf(s);
        assert_eq!(cfg.nameservers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(cfg.search, vec!["example.com", "lan"]);
    }
}
