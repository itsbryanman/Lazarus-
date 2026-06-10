//! Package manifest capture.
//!
//! We snapshot the *list* of installed packages plus the
//! distro-specific repository configuration. Phase 3 deliberately does
//! not snapshot package contents — these come from upstream mirrors
//! during restore.

use serde::{Deserialize, Serialize};

use super::system::{CaptureOpts, CaptureWarning, NamedBlob};
use crate::error::Result;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageManifest {
    pub manager: PackageManager,
    #[serde(default)]
    pub packages: Vec<PackageEntry>,
    #[serde(default)]
    pub repository_files: Vec<NamedBlob>,
    #[serde(default)]
    pub keyrings: Vec<NamedBlob>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageManager {
    Dpkg,
    Rpm,
    Pacman,
    Apk,
    Unknown,
}

impl Default for PackageManager {
    fn default() -> Self {
        PackageManager::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub origin: Option<String>,
    pub explicitly_installed: bool,
}

pub async fn capture_packages(
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] opts: &CaptureOpts,
) -> Result<(PackageManifest, Vec<CaptureWarning>)> {
    #[cfg(not(target_os = "linux"))]
    {
        return Ok((PackageManifest::default(), Vec::new()));
    }

    #[cfg(target_os = "linux")]
    {
        linux::capture_packages_linux(opts).await
    }
}

// --- pure parsers ----------------------------------------------------------

/// Parse the output of `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'`.
pub fn parse_dpkg_query(s: &str) -> Vec<PackageEntry> {
    let mut out = Vec::new();
    for line in s.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let installed = parts.get(3).map(|s| *s == "installed").unwrap_or(true);
        if !installed {
            continue;
        }
        out.push(PackageEntry {
            name: parts[0].to_string(),
            version: parts[1].to_string(),
            architecture: Some(parts[2].to_string()),
            origin: None,
            explicitly_installed: false,
        });
    }
    out
}

/// Parse the output of `rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'`.
pub fn parse_rpm_qa(s: &str) -> Vec<PackageEntry> {
    let mut out = Vec::new();
    for line in s.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 2 {
            continue;
        }
        out.push(PackageEntry {
            name: parts[0].to_string(),
            version: parts[1].to_string(),
            architecture: parts.get(2).map(|s| s.to_string()),
            origin: None,
            explicitly_installed: false,
        });
    }
    out
}

/// Parse the output of `pacman -Q` ("name version" per line).
pub fn parse_pacman_q(s: &str) -> Vec<PackageEntry> {
    let mut out = Vec::new();
    for line in s.lines() {
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let Some(version) = parts.next() else { continue };
        out.push(PackageEntry {
            name: name.to_string(),
            version: version.to_string(),
            architecture: None,
            origin: None,
            explicitly_installed: false,
        });
    }
    out
}

/// Parse the output of `apk info -v` (one `name-version-r0` per line).
pub fn parse_apk_info(s: &str) -> Vec<PackageEntry> {
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Split at the last two dashes: `pkg-1.2.3-r0`.
        // Easier: find last '-r' for the release suffix, then last '-'
        // for the version, then everything before is the name.
        if let Some(r_idx) = line.rfind("-r") {
            let suffix_ok = line[r_idx + 2..].chars().all(|c| c.is_ascii_digit());
            if !suffix_ok {
                continue;
            }
            let trimmed = &line[..r_idx];
            if let Some(dash) = trimmed.rfind('-') {
                let name = &trimmed[..dash];
                let version = &line[dash + 1..];
                out.push(PackageEntry {
                    name: name.to_string(),
                    version: version.to_string(),
                    architecture: None,
                    origin: None,
                    explicitly_installed: false,
                });
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    pub(super) async fn capture_packages_linux(
        opts: &CaptureOpts,
    ) -> Result<(PackageManifest, Vec<CaptureWarning>)> {
        let mut warnings = Vec::new();
        let manager = detect_manager();

        let packages = match manager {
            PackageManager::Dpkg => match super::super::util::run_capture_str(
                "dpkg-query",
                &["-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n"],
                opts.tool_timeout,
            )
            .await
            {
                Ok(s) => parse_dpkg_query(&s),
                Err(e) => {
                    warnings.push(CaptureWarning::new(
                        "packages",
                        format!("dpkg-query failed: {e}"),
                    ));
                    Vec::new()
                }
            },
            PackageManager::Rpm => match super::super::util::run_capture_str(
                "rpm",
                &["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
                opts.tool_timeout,
            )
            .await
            {
                Ok(s) => parse_rpm_qa(&s),
                Err(e) => {
                    warnings.push(CaptureWarning::new(
                        "packages",
                        format!("rpm -qa failed: {e}"),
                    ));
                    Vec::new()
                }
            },
            PackageManager::Pacman => match super::super::util::run_capture_str(
                "pacman",
                &["-Q"],
                opts.tool_timeout,
            )
            .await
            {
                Ok(s) => parse_pacman_q(&s),
                Err(e) => {
                    warnings.push(CaptureWarning::new(
                        "packages",
                        format!("pacman -Q failed: {e}"),
                    ));
                    Vec::new()
                }
            },
            PackageManager::Apk => match super::super::util::run_capture_str(
                "apk",
                &["info", "-v"],
                opts.tool_timeout,
            )
            .await
            {
                Ok(s) => parse_apk_info(&s),
                Err(e) => {
                    warnings.push(CaptureWarning::new(
                        "packages",
                        format!("apk info failed: {e}"),
                    ));
                    Vec::new()
                }
            },
            PackageManager::Unknown => {
                warnings.push(
                    CaptureWarning::new("packages", "no supported package manager detected")
                        .with_remediation(
                            "this is a non-fatal warning; the host is not a supported distro",
                        ),
                );
                Vec::new()
            }
        };

        let repository_files = collect_repo_files(&manager);
        let keyrings = collect_keyrings(&manager);

        Ok((
            PackageManifest {
                manager,
                packages,
                repository_files,
                keyrings,
            },
            warnings,
        ))
    }

    fn detect_manager() -> PackageManager {
        for (path, mgr) in [
            ("/var/lib/dpkg/status", PackageManager::Dpkg),
            ("/var/lib/rpm/Packages", PackageManager::Rpm),
            ("/var/lib/rpm/rpmdb.sqlite", PackageManager::Rpm),
            ("/var/lib/pacman/local", PackageManager::Pacman),
            ("/lib/apk/db/installed", PackageManager::Apk),
        ] {
            if std::path::Path::new(path).exists() {
                return mgr;
            }
        }
        PackageManager::Unknown
    }

    fn collect_repo_files(mgr: &PackageManager) -> Vec<NamedBlob> {
        let dirs: &[&str] = match mgr {
            PackageManager::Dpkg => &["/etc/apt/sources.list.d", "/etc/apt"],
            PackageManager::Rpm => &["/etc/yum.repos.d"],
            PackageManager::Pacman => &["/etc/pacman.d"],
            PackageManager::Apk => &["/etc/apk"],
            PackageManager::Unknown => &[],
        };
        let mut out = Vec::new();
        for dir in dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let md = match entry.metadata() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if !md.is_file() || md.len() > 1024 * 1024 {
                        continue;
                    }
                    if let Ok(bytes) = std::fs::read(entry.path()) {
                        out.push(NamedBlob {
                            name: entry.path().to_string_lossy().to_string(),
                            content: bytes,
                        });
                    }
                }
            }
        }
        out
    }

    fn collect_keyrings(mgr: &PackageManager) -> Vec<NamedBlob> {
        let dirs: &[&str] = match mgr {
            PackageManager::Dpkg => &["/etc/apt/keyrings", "/etc/apt/trusted.gpg.d"],
            PackageManager::Rpm => &["/etc/pki/rpm-gpg"],
            _ => &[],
        };
        let mut out = Vec::new();
        for dir in dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let md = match entry.metadata() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if !md.is_file() || md.len() > 256 * 1024 {
                        continue;
                    }
                    if let Ok(bytes) = std::fs::read(entry.path()) {
                        out.push(NamedBlob {
                            name: entry.path().to_string_lossy().to_string(),
                            content: bytes,
                        });
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dpkg_query() {
        let s = "\
bash\t5.1-6ubuntu1\tamd64\tinstalled\n\
coreutils\t8.32-4.1ubuntu1\tamd64\tinstalled\n\
old-pkg\t1.0\tamd64\tdeinstall\n\
";
        let pkgs = parse_dpkg_query(s);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "bash");
        assert_eq!(pkgs[0].architecture.as_deref(), Some("amd64"));
    }

    #[test]
    fn parses_rpm_qa() {
        let s = "\
bash\t5.1.8-9.el9\tx86_64\n\
coreutils\t8.32-35.el9\tx86_64\n\
";
        let pkgs = parse_rpm_qa(s);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[1].name, "coreutils");
        assert_eq!(pkgs[1].version, "8.32-35.el9");
    }

    #[test]
    fn parses_pacman_q() {
        let s = "\
bash 5.2.026-1\n\
coreutils 9.5-1\n\
";
        let pkgs = parse_pacman_q(s);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].version, "5.2.026-1");
    }

    #[test]
    fn parses_apk_info() {
        let s = "\
busybox-1.36.1-r29\n\
musl-1.2.5-r0\n\
";
        let pkgs = parse_apk_info(s);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "busybox");
        assert_eq!(pkgs[0].version, "1.36.1-r29");
        assert_eq!(pkgs[1].name, "musl");
    }
}
