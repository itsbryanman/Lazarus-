use crate::error::{LazarusError, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::AsyncReadExt;

const CANARY_FILENAME: &str = ".lazarus_canary";
const CANARY_SIGNATURE: &[u8] = b"LazarusCanarySignatureV1";
const ENTROPY_SAMPLE_SIZE: usize = 256 * 1024; // 256KB sample per file
const MAX_SCANNED_FILES: usize = 1_000;

/// Compute Shannon entropy for a bytes slice.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for count in counts.iter().copied() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyReason {
    CanaryModified,
    HighEntropy { entropy: f64, threshold: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnomaly {
    pub path: PathBuf,
    pub reason: AnomalyReason,
}

#[derive(Debug, Clone)]
pub enum DetectionVerdict {
    Clean,
    Suspicious,
}

#[derive(Debug, Clone)]
pub struct SnapshotTrust {
    pub score: f64,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DetectionReport {
    pub verdict: DetectionVerdict,
    pub anomalies: Vec<FileAnomaly>,
    pub trust: SnapshotTrust,
}

pub struct DetectionEngine {
    canary_manager: CanaryManager,
    trust_tracker: TrustTracker,
    quarantine_dir: PathBuf,
    entropy_threshold: f64,
}

impl DetectionEngine {
    pub fn new<P: Into<PathBuf>>(repo_root: P) -> Self {
        let repo_root = repo_root.into();
        let trust_tracker = TrustTracker::new(repo_root.join("security_state.json"));
        Self {
            quarantine_dir: repo_root.join("quarantine"),
            canary_manager: CanaryManager::new(),
            trust_tracker,
            entropy_threshold: 7.5,
        }
    }

    /// Analyze the provided paths before performing a backup.
    pub async fn analyze_paths(&self, targets: &[PathBuf]) -> Result<DetectionReport> {
        let mut anomalies = Vec::new();
        let mut entropy_values = Vec::new();

        for target in targets {
            let canary = self.canary_manager.deploy_for(target).await?;
            if !self.canary_manager.validate(&canary).await? {
                anomalies.push(FileAnomaly {
                    path: canary.clone(),
                    reason: AnomalyReason::CanaryModified,
                });
            }

            let files = collect_files(target, MAX_SCANNED_FILES).await?;
            for file_path in files {
                if file_path
                    .file_name()
                    .map(|name| name == CANARY_FILENAME)
                    .unwrap_or(false)
                {
                    continue;
                }

                if let Some(entropy) = self.read_entropy_sample(&file_path).await? {
                    entropy_values.push(entropy);
                    if entropy >= self.entropy_threshold {
                        anomalies.push(FileAnomaly {
                            path: file_path,
                            reason: AnomalyReason::HighEntropy {
                                entropy,
                                threshold: self.entropy_threshold,
                            },
                        });
                    }
                }
            }
        }

        let avg_entropy = if entropy_values.is_empty() {
            0.0
        } else {
            entropy_values.iter().sum::<f64>() / entropy_values.len() as f64
        };

        let trust = self.trust_tracker.observe(avg_entropy).await?;
        let verdict = if !anomalies.is_empty() || trust.score < 0.4 {
            DetectionVerdict::Suspicious
        } else {
            DetectionVerdict::Clean
        };

        if matches!(verdict, DetectionVerdict::Suspicious) {
            self.quarantine(&anomalies).await?;
        }

        Ok(DetectionReport {
            verdict,
            anomalies,
            trust,
        })
    }

    async fn read_entropy_sample(&self, path: &Path) -> Result<Option<f64>> {
        let metadata = fs::metadata(path).await?;
        if !metadata.is_file() {
            return Ok(None);
        }

        if metadata.len() == 0 {
            return Ok(Some(0.0));
        }

        let mut file = fs::File::open(path).await?;
        let mut buffer = vec![0u8; ENTROPY_SAMPLE_SIZE.min(metadata.len() as usize)];
        let mut bytes_read = 0;

        while bytes_read < buffer.len() {
            let read = file.read(&mut buffer[bytes_read..]).await?;
            if read == 0 {
                break;
            }
            bytes_read += read;
        }
        buffer.truncate(bytes_read);

        Ok(Some(shannon_entropy(&buffer)))
    }

    async fn quarantine(&self, anomalies: &[FileAnomaly]) -> Result<()> {
        if anomalies.is_empty() {
            return Ok(());
        }
        fs::create_dir_all(&self.quarantine_dir).await?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        let manifest_path = self
            .quarantine_dir
            .join(format!("manifest-{}.json", timestamp));
        let json = serde_json::to_string_pretty(&anomalies)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        fs::write(&manifest_path, json).await?;

        for anomaly in anomalies {
            if !anomaly.path.is_file() {
                continue;
            }
            if let Some(file_name) = anomaly.path.file_name() {
                let sanitized = file_name.to_string_lossy().replace('/', "_");
                let dest = self
                    .quarantine_dir
                    .join(format!("{}-{}", timestamp, sanitized));
                let _ = fs::copy(&anomaly.path, &dest).await;
            }
        }

        Ok(())
    }
}

struct CanaryManager {
    signature: Vec<u8>,
}

impl CanaryManager {
    fn new() -> Self {
        Self {
            signature: CANARY_SIGNATURE.to_vec(),
        }
    }

    async fn deploy_for(&self, path: &Path) -> Result<PathBuf> {
        let target_dir = if path.is_dir() {
            path.to_path_buf()
        } else {
            path.parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| LazarusError::Storage("Unable to deploy canary".into()))?
        };
        let canary_path = target_dir.join(CANARY_FILENAME);
        if !canary_path.exists() {
            fs::write(&canary_path, &self.signature).await?;
        }
        Ok(canary_path)
    }

    async fn validate(&self, canary_path: &Path) -> Result<bool> {
        let data = fs::read(canary_path).await?;
        Ok(data == self.signature)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TrustState {
    baseline_entropy: f64,
    samples: u64,
    recent: VecDeque<f64>,
}

impl Default for TrustState {
    fn default() -> Self {
        Self {
            baseline_entropy: 0.0,
            samples: 0,
            recent: VecDeque::with_capacity(8),
        }
    }
}

struct TrustTracker {
    state_path: PathBuf,
}

impl TrustTracker {
    fn new(state_path: PathBuf) -> Self {
        Self { state_path }
    }

    async fn observe(&self, measurement: f64) -> Result<SnapshotTrust> {
        let mut state = self.load().await?;
        if state.samples == 0 {
            state.baseline_entropy = measurement;
        } else {
            let alpha = 0.2;
            state.baseline_entropy = (1.0 - alpha) * state.baseline_entropy + alpha * measurement;
        }
        state.samples += 1;
        if state.recent.len() == state.recent.capacity() {
            state.recent.pop_front();
        }
        state.recent.push_back(measurement);

        self.persist(&state).await?;

        let deviation = (measurement - state.baseline_entropy).abs();
        let score = (1.0 - (deviation / 4.0)).clamp(0.0, 1.0);
        let recommendation = if score < 0.4 {
            Some("Recommend restoring last known good snapshot".to_string())
        } else {
            None
        };

        Ok(SnapshotTrust {
            score,
            recommendation,
        })
    }

    async fn load(&self) -> Result<TrustState> {
        if !self.state_path.exists() {
            return Ok(TrustState::default());
        }
        let json = fs::read(&self.state_path).await?;
        let state = serde_json::from_slice(&json)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        Ok(state)
    }

    async fn persist(&self, state: &TrustState) -> Result<()> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let json = serde_json::to_vec_pretty(state)
            .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
        fs::write(&self.state_path, json).await?;
        Ok(())
    }
}

async fn collect_files(root: &Path, max_files: usize) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let metadata = match fs::metadata(root).await {
        Ok(meta) => meta,
        Err(e) => {
            return Err(LazarusError::Io(e));
        }
    };

    if metadata.is_file() {
        files.push(root.to_path_buf());
        return Ok(files);
    }

    if !metadata.is_dir() {
        return Ok(files);
    }

    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let mut read_dir = match fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        while let Some(entry) = read_dir.next_entry().await? {
            let path = entry.path();
            let meta = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                dirs.push(path.clone());
            } else if meta.is_file() {
                files.push(path.clone());
                if files.len() >= max_files {
                    return Ok(files);
                }
            }
        }
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use tempfile::tempdir;

    #[test]
    fn entropy_of_zero_buffer_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0u8; 32]), 0.0);
    }

    #[test]
    fn entropy_of_random_data_is_high() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut data = vec![0u8; 1024];
        rng.fill_bytes(&mut data);
        let entropy = shannon_entropy(&data);
        assert!(entropy > 7.5);
    }

    #[tokio::test]
    async fn detection_flags_canary_tampering() {
        let repo = tempdir().unwrap();
        let target = tempdir().unwrap();
        let engine = DetectionEngine::new(repo.path());
        // Initial run should create canary
        let report = engine
            .analyze_paths(&[target.path().to_path_buf()])
            .await
            .unwrap();
        assert!(matches!(report.verdict, DetectionVerdict::Clean));

        let canary_path = target.path().join(CANARY_FILENAME);
        fs::write(&canary_path, b"tampered").await.unwrap();

        let report = engine
            .analyze_paths(&[target.path().to_path_buf()])
            .await
            .unwrap();
        assert!(matches!(report.verdict, DetectionVerdict::Suspicious));
        assert!(!report.anomalies.is_empty());
    }

    #[tokio::test]
    async fn detection_flags_high_entropy_file() {
        let repo = tempdir().unwrap();
        let target = tempdir().unwrap();
        let file_path = target.path().join("high.bin");
        let mut rng = StdRng::seed_from_u64(42);
        let mut data = vec![0u8; 4096];
        rng.fill_bytes(&mut data);
        fs::write(&file_path, data).await.unwrap();

        let engine = DetectionEngine::new(repo.path());
        let report = engine
            .analyze_paths(&[target.path().to_path_buf()])
            .await
            .unwrap();
        assert!(matches!(report.verdict, DetectionVerdict::Suspicious));
        assert!(
            report
                .anomalies
                .iter()
                .any(|a| matches!(a.reason, AnomalyReason::HighEntropy { .. }))
        );
    }
}
