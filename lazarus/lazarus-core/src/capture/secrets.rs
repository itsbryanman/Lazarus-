//! Sensitive blobs (currently: SSH host keys). All file contents stored
//! here are encrypted under the *metadata* key.

use serde::{Deserialize, Serialize};

use super::persist::FingerprintPersister;
use super::system::{CaptureOpts, CaptureWarning};
use crate::error::Result;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshHostKeysRef {
    /// Hex BLAKE3 of the encrypted ssh host keys blob, or `None` if
    /// none were found / accessible.
    #[serde(default)]
    pub blob_chunk: Option<String>,
}

impl SshHostKeysRef {
    pub fn empty() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshHostKeysBlob {
    /// Map filename → bytes for everything in `/etc/ssh` that looks like
    /// a key file (private + public).
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
}

pub async fn capture_ssh_host_keys(
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] opts: &CaptureOpts,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] persister: &FingerprintPersister<'_>,
) -> Result<(SshHostKeysRef, Vec<CaptureWarning>)> {
    #[cfg(not(target_os = "linux"))]
    {
        return Ok((SshHostKeysRef::default(), Vec::new()));
    }

    #[cfg(target_os = "linux")]
    {
        let mut warnings = Vec::new();
        let mut blob = SshHostKeysBlob::default();
        let entries = match std::fs::read_dir("/etc/ssh") {
            Ok(e) => e,
            Err(e) => {
                warnings.push(CaptureWarning::new(
                    "ssh",
                    format!("could not read /etc/ssh: {e}"),
                ));
                return Ok((SshHostKeysRef::empty(), warnings));
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = match path.file_name() {
                Some(n) => n.to_string_lossy().to_string(),
                None => continue,
            };
            if !(name.starts_with("ssh_host_") || name == "moduli") {
                continue;
            }
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !md.is_file() || md.len() > 256 * 1024 {
                continue;
            }
            match std::fs::read(&path) {
                Ok(bytes) => {
                    blob.files.insert(name, bytes);
                }
                Err(e) => warnings.push(CaptureWarning::new(
                    "ssh",
                    format!("could not read {}: {e}", path.display()),
                )),
            }
        }
        if blob.files.is_empty() {
            return Ok((SshHostKeysRef::empty(), warnings));
        }
        let blob_chunk = match persister.persist_blob_metadata_key(&blob).await {
            Ok(h) => Some(h),
            Err(e) => {
                warnings.push(CaptureWarning::new(
                    "ssh",
                    format!("could not persist ssh host keys: {e}"),
                ));
                None
            }
        };
        Ok((SshHostKeysRef { blob_chunk }, warnings))
    }
}
