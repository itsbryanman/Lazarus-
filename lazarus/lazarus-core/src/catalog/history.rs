//! Append-only operation history with tamper detection.
//!
//! Every operation that touches the repository (init, backup, prune,
//! key-rotate, restore, verify) appends a `HistoryEntry` to a JSON-lines file
//! at `<repo>/history.log`. Each entry is signed using a keyed BLAKE3 MAC
//! with the metadata key, and embeds the MAC of the previous entry, forming
//! a hash chain. Tampering with any line invalidates every subsequent line.
//!
//! This is intentionally simple and operator-auditable — the file is plain
//! text (one JSON object per line) so it can be tailed and grepped, while
//! still being authenticated.

use crate::error::{LazarusError, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Repository operation kind. Reserve unknown values for forward-compat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Init,
    Backup,
    Prune,
    KeyRotate,
    Restore,
    Verify,
    /// Catch-all for forward compatibility. Older binaries won't break when
    /// they encounter a newer operation type.
    #[serde(other)]
    Other,
}

/// One entry in the history log. Signed with a keyed BLAKE3 MAC over a
/// canonical serialization of every field except `signature` itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Schema version of this entry. Bump when fields are added.
    pub version: u32,
    /// Unix epoch seconds.
    pub timestamp: u64,
    pub operation: Operation,
    /// Hostname or agent id that performed the action.
    pub actor: String,
    /// Free-form details about the operation.
    pub details: serde_json::Value,
    /// Hex-encoded BLAKE3 MAC of the canonical body, including the previous
    /// entry's signature for chaining.
    pub signature: String,
    /// Hex-encoded MAC of the previous entry, or empty for the genesis entry.
    pub prev_signature: String,
}

const HISTORY_FILE: &str = "history.log";
const HISTORY_VERSION: u32 = 1;

/// Append-only handle around the history file. Cheap to construct.
pub struct History {
    path: PathBuf,
    metadata_key: [u8; 32],
}

impl History {
    /// Bind to the history file inside `repo_path`, signing entries with the
    /// provided metadata key.
    pub fn open<P: AsRef<Path>>(repo_path: P, metadata_key: [u8; 32]) -> Self {
        Self {
            path: repo_path.as_ref().join(HISTORY_FILE),
            metadata_key,
        }
    }

    /// Path to the underlying file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a new entry. Computes the signature, chains to the previous
    /// entry's signature, and atomically appends the JSON line.
    pub fn record(
        &self,
        operation: Operation,
        actor: &str,
        details: serde_json::Value,
    ) -> Result<HistoryEntry> {
        let prev = self.last_signature()?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut entry = HistoryEntry {
            version: HISTORY_VERSION,
            timestamp,
            operation,
            actor: actor.to_string(),
            details,
            signature: String::new(),
            prev_signature: prev,
        };
        entry.signature = sign_entry(&entry, &self.metadata_key);

        // Append atomically: open with append mode + sync on the same file.
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(&entry)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        writeln!(f, "{}", line)?;
        f.sync_all()?;
        Ok(entry)
    }

    /// Iterate every entry in the log.
    pub fn entries(&self) -> Result<Vec<HistoryEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let f = fs::File::open(&self.path)?;
        let reader = BufReader::new(f);
        let mut out = Vec::new();
        for (i, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: HistoryEntry = serde_json::from_str(&line).map_err(|e| {
                LazarusError::SerializationError(format!(
                    "history line {} is invalid: {}",
                    i + 1,
                    e
                ))
            })?;
            out.push(entry);
        }
        Ok(out)
    }

    /// Verify the chain end-to-end: every entry's MAC matches its body, and
    /// each entry's `prev_signature` matches the previous line's `signature`.
    pub fn verify(&self) -> Result<HistoryVerifyReport> {
        let entries = self.entries()?;
        let mut report = HistoryVerifyReport {
            total: entries.len(),
            tampered_indices: Vec::new(),
            broken_chain_indices: Vec::new(),
        };
        let mut prev_sig = String::new();
        for (i, entry) in entries.iter().enumerate() {
            // Verify chain link.
            if entry.prev_signature != prev_sig {
                report.broken_chain_indices.push(i);
            }
            // Verify MAC.
            let expected = sign_entry(entry, &self.metadata_key);
            if !constant_time_eq(expected.as_bytes(), entry.signature.as_bytes()) {
                report.tampered_indices.push(i);
            }
            prev_sig = entry.signature.clone();
        }
        Ok(report)
    }

    fn last_signature(&self) -> Result<String> {
        let entries = self.entries()?;
        Ok(entries
            .last()
            .map(|e| e.signature.clone())
            .unwrap_or_default())
    }
}

#[derive(Debug, Clone, Default)]
pub struct HistoryVerifyReport {
    pub total: usize,
    pub tampered_indices: Vec<usize>,
    pub broken_chain_indices: Vec<usize>,
}

impl HistoryVerifyReport {
    pub fn is_clean(&self) -> bool {
        self.tampered_indices.is_empty() && self.broken_chain_indices.is_empty()
    }
}

/// Compute the MAC over a canonical serialization of the entry minus the
/// `signature` field itself. We feed the prev_signature in too so chain
/// modifications are detected as MAC failures, not just "broken chain".
fn sign_entry(entry: &HistoryEntry, key: &[u8; 32]) -> String {
    // Canonical body: every field except `signature`.
    let body = serde_json::json!({
        "version": entry.version,
        "timestamp": entry.timestamp,
        "operation": entry.operation,
        "actor": entry.actor,
        "details": entry.details,
        "prev_signature": entry.prev_signature,
    });
    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
    let mac = blake3::keyed_hash(key, &body_bytes);
    mac.to_hex().to_string()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> [u8; 32] {
        [9u8; 32]
    }

    #[test]
    fn append_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::open(dir.path(), k());
        h.record(Operation::Init, "host-a", serde_json::json!({"version": 1}))
            .unwrap();
        h.record(
            Operation::Backup,
            "host-a",
            serde_json::json!({"snapshot": "snap-1", "bytes": 1024}),
        )
        .unwrap();
        let entries = h.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].operation, Operation::Init);
        assert_eq!(entries[1].operation, Operation::Backup);
        assert!(h.verify().unwrap().is_clean());
    }

    #[test]
    fn chain_links_to_previous_signature() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::open(dir.path(), k());
        h.record(Operation::Init, "host", serde_json::json!({}))
            .unwrap();
        h.record(Operation::Backup, "host", serde_json::json!({}))
            .unwrap();
        let entries = h.entries().unwrap();
        assert_eq!(entries[1].prev_signature, entries[0].signature);
        assert!(h.verify().unwrap().is_clean());
    }

    #[test]
    fn tampering_with_an_entry_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::open(dir.path(), k());
        h.record(Operation::Init, "host", serde_json::json!({}))
            .unwrap();
        h.record(
            Operation::Backup,
            "host",
            serde_json::json!({"snapshot": "snap-1"}),
        )
        .unwrap();

        // Mutate the second line in-place.
        let raw = std::fs::read_to_string(h.path()).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2);
        let mut tampered: HistoryEntry = serde_json::from_str(lines[1]).unwrap();
        tampered.actor = "evil".to_string();
        let new_line = serde_json::to_string(&tampered).unwrap();
        let new_raw = format!("{}\n{}\n", lines[0], new_line);
        std::fs::write(h.path(), new_raw).unwrap();

        let report = h.verify().unwrap();
        assert!(!report.is_clean());
        assert!(report.tampered_indices.contains(&1));
    }

    #[test]
    fn deleting_an_entry_breaks_chain() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::open(dir.path(), k());
        h.record(Operation::Init, "host", serde_json::json!({}))
            .unwrap();
        h.record(Operation::Backup, "host", serde_json::json!({}))
            .unwrap();
        h.record(Operation::Verify, "host", serde_json::json!({}))
            .unwrap();

        let raw = std::fs::read_to_string(h.path()).unwrap();
        let mut lines: Vec<&str> = raw.lines().collect();
        lines.remove(1); // drop the Backup entry
        std::fs::write(h.path(), format!("{}\n{}\n", lines[0], lines[1])).unwrap();

        let report = h.verify().unwrap();
        // The third entry's prev_signature no longer points at the second
        // (now-removed) entry's signature, so the chain check fires.
        assert!(report.broken_chain_indices.contains(&1));
    }
}
