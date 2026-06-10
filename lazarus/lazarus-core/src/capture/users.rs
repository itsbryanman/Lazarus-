//! User database capture (`/etc/passwd`, `/etc/group`, `/etc/shadow`,
//! `/etc/gshadow`). The non-secret files are copied verbatim into the
//! reference; `/etc/shadow` and `/etc/gshadow` are encrypted under the
//! metadata key and stored as a separate chunk.

use serde::{Deserialize, Serialize};

use super::persist::FingerprintPersister;
use super::system::{CaptureOpts, CaptureWarning};
use crate::error::Result;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserDatabaseRef {
    pub passwd: String,
    pub group: String,
    /// Hex BLAKE3 of the encrypted shadow blob. Empty when shadow was
    /// unreadable (rootless capture).
    #[serde(default)]
    pub shadow_blob_chunk: Option<String>,
}

impl UserDatabaseRef {
    pub fn empty() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserDatabaseBlob {
    pub shadow: String,
    pub gshadow: String,
}

pub async fn capture_users(
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] _opts: &CaptureOpts,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] persister: &FingerprintPersister<
        '_,
    >,
) -> Result<(UserDatabaseRef, Vec<CaptureWarning>)> {
    #[cfg(not(target_os = "linux"))]
    {
        return Ok((UserDatabaseRef::default(), Vec::new()));
    }

    #[cfg(target_os = "linux")]
    {
        let mut warnings = Vec::new();
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_else(|e| {
            warnings.push(CaptureWarning::new(
                "users",
                format!("could not read /etc/passwd: {e}"),
            ));
            String::new()
        });
        let group = std::fs::read_to_string("/etc/group").unwrap_or_else(|e| {
            warnings.push(CaptureWarning::new(
                "users",
                format!("could not read /etc/group: {e}"),
            ));
            String::new()
        });

        let shadow = std::fs::read_to_string("/etc/shadow");
        let gshadow = std::fs::read_to_string("/etc/gshadow");

        let shadow_blob_chunk = match (shadow, gshadow) {
            (Ok(s), gs) => {
                let blob = UserDatabaseBlob {
                    shadow: s,
                    gshadow: gs.unwrap_or_default(),
                };
                match persister.persist_blob_metadata_key(&blob).await {
                    Ok(h) => Some(h),
                    Err(e) => {
                        warnings.push(CaptureWarning::new(
                            "users",
                            format!("could not persist shadow blob: {e}"),
                        ));
                        None
                    }
                }
            }
            (Err(e), _) => {
                warnings.push(
                    CaptureWarning::new("users", format!("/etc/shadow unreadable: {e}"))
                        .with_remediation("re-run as root to capture password hashes"),
                );
                None
            }
        };

        Ok((
            UserDatabaseRef {
                passwd,
                group,
                shadow_blob_chunk,
            },
            warnings,
        ))
    }
}
