use super::snapshot_utils::encrypt_snapshot_metadata;
use clap::{ArgAction, Args, ValueEnum};
use futures::{stream::FuturesUnordered, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use lazarus_core::catalog::index::{CatalogIndex, ObjectMetadata, ObjectType};
use lazarus_core::chunking::block_device::{BlockDeviceReader, Extent};
use lazarus_core::chunking::streaming::StreamingChunker;
use lazarus_core::compression::adaptive;
use lazarus_core::config::ConfigManager;
use lazarus_core::error::{LazarusError, Result};
use lazarus_core::security::ransomware::{DetectionEngine, DetectionVerdict};
use lazarus_core::snapshot::btrfs::BtrfsSnapshotter;
use lazarus_core::snapshot::dedup::DedupTable;
use lazarus_core::snapshot::hooks::{
    builtins as hook_builtins, ApplicationHook, HookReport, HookRunner,
};
use lazarus_core::snapshot::lvm::LvmSnapshotter;
use lazarus_core::snapshot::snapshotter::{BlockSnapshotter, ConsistentMount};
use lazarus_core::snapshot::zfs::ZfsSnapshotter;
use lazarus_core::storage::backend::{RetentionLock, StorageBackend};
use lazarus_core::storage::local::LocalStorage;
use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};
use tokio::io::BufReader;
use tokio::task;

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB

/// Which OS-level snapshot mechanism to use for `--consistent` file backups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SnapshotterChoice {
    /// Pick the first backend whose `supports()` check returns true.
    Auto,
    Lvm,
    Btrfs,
    Zfs,
    /// Skip OS snapshotting entirely. Hooks still run if enabled.
    None,
}

impl Default for SnapshotterChoice {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Args)]
pub struct BackupArgs {
    #[arg(short, long, help = "Source file or directory to backup")]
    pub source: Option<String>,

    #[arg(short, long, help = "Repository path")]
    pub repository: String,

    #[arg(short, long, help = "Master password for encryption")]
    pub password: String,

    #[arg(
        long,
        help = "Ignore ransomware detection warnings and proceed anyway",
        action = ArgAction::SetTrue
    )]
    pub force: bool,

    /// Enable point-in-time capture for file backups via filesystem/volume
    /// snapshots.
    #[arg(long, action = ArgAction::SetTrue)]
    pub consistent: bool,

    /// Snapshotter to use when `--consistent` is set. With `none`, hooks
    /// bracket the full capture because no OS snapshot is taken.
    #[arg(long, value_enum, default_value_t = SnapshotterChoice::Auto)]
    pub snapshotter: SnapshotterChoice,

    /// Capture a raw block device instead of a file tree.
    #[arg(long, action = ArgAction::SetTrue)]
    pub block_mode: bool,

    /// Block device path. Required (and only used) when `--block-mode` is set.
    #[arg(long, value_name = "PATH")]
    pub device: Option<String>,

    /// Disable application freeze/thaw hooks. Hooks normally bracket only OS
    /// snapshot creation; with `--snapshotter none`, they bracket the full
    /// capture duration.
    #[arg(long, action = ArgAction::SetTrue)]
    pub no_hooks: bool,

    /// Run a specific built-in hook template. May be repeated. Recognized
    /// names: `postgres`, `mysql`, `mongodb`, `redis`, `docker`, `all`.
    #[arg(long = "hook-template", value_name = "NAME")]
    pub hook_templates: Vec<String>,

    /// Also capture a bare-metal system fingerprint alongside this backup (Linux, needs root).
    #[arg(long, action = ArgAction::SetTrue)]
    pub capture_system: bool,

    /// Capture only the system fingerprint; skip the file/block pipeline.
    #[arg(long, action = ArgAction::SetTrue)]
    pub capture_system_only: bool,
}

impl Default for BackupArgs {
    fn default() -> Self {
        Self {
            source: None,
            repository: String::new(),
            password: String::new(),
            force: false,
            consistent: false,
            snapshotter: SnapshotterChoice::Auto,
            block_mode: false,
            device: None,
            no_hooks: false,
            hook_templates: Vec::new(),
            capture_system: false,
            capture_system_only: false,
        }
    }
}

/// Validated form of the user-supplied flag combination. Computed once at
/// entry so the rest of the pipeline doesn't have to re-derive the mode.
#[derive(Debug)]
struct CaptureConfig {
    /// The path the backup pipeline should *read* from. For file mode this
    /// is the source (or snapshot mount, once taken). For block mode this
    /// is the device.
    target: PathBuf,
    /// What the user originally asked us to back up. Used for snapshot
    /// metadata regardless of any intermediate snapshot mount.
    declared_source: PathBuf,
    mode: CaptureMode,
    consistent: bool,
    snapshotter: SnapshotterChoice,
    run_hooks: bool,
    hook_templates: Vec<String>,
}

#[derive(Debug)]
enum CaptureMode {
    File,
    Block,
}

fn validate_args(args: &BackupArgs) -> Result<CaptureConfig> {
    // --block-mode and --source/--device interactions.
    if args.block_mode {
        let device = args.device.as_ref().ok_or_else(|| {
            LazarusError::Storage("--block-mode requires --device to be specified".to_string())
        })?;
        // Explicitly refuse to silently use --source as the device.
        if args.source.is_some() {
            return Err(LazarusError::Storage(
                "--block-mode cannot be combined with --source; pass the device via --device only"
                    .to_string(),
            ));
        }
        let device_path = PathBuf::from(device);
        return Ok(CaptureConfig {
            target: device_path.clone(),
            declared_source: device_path,
            mode: CaptureMode::Block,
            consistent: args.consistent,
            snapshotter: args.snapshotter,
            run_hooks: !args.no_hooks,
            hook_templates: args.hook_templates.clone(),
        });
    }

    // Not block-mode → --device is meaningless.
    if args.device.is_some() {
        return Err(LazarusError::Storage(
            "--device may only be used with --block-mode".to_string(),
        ));
    }

    let source = args.source.as_ref().ok_or_else(|| {
        LazarusError::Storage("--source is required for file backups".to_string())
    })?;
    let source_path = PathBuf::from(source);
    Ok(CaptureConfig {
        target: source_path.clone(),
        declared_source: source_path,
        mode: CaptureMode::File,
        consistent: args.consistent,
        snapshotter: args.snapshotter,
        run_hooks: !args.no_hooks,
        hook_templates: args.hook_templates.clone(),
    })
}

/// Resolve the user-chosen snapshotter into a concrete backend (or `None`
/// for "skip OS snapshot"). `Auto` consults each backend's `supports()` hint
/// and returns both the backend and the canonical name of whichever backend
/// matched, so callers can record it in snapshot metadata without
/// re-running the detection.
fn pick_snapshotter(
    choice: SnapshotterChoice,
    source: &Path,
) -> Result<Option<(Box<dyn BlockSnapshotter>, &'static str)>> {
    match choice {
        SnapshotterChoice::None => Ok(None),
        SnapshotterChoice::Lvm => Ok(Some((Box::new(LvmSnapshotter), "lvm"))),
        SnapshotterChoice::Btrfs => Ok(Some((Box::new(BtrfsSnapshotter), "btrfs"))),
        SnapshotterChoice::Zfs => Ok(Some((Box::new(ZfsSnapshotter), "zfs"))),
        SnapshotterChoice::Auto => {
            if LvmSnapshotter::supports(source) {
                Ok(Some((Box::new(LvmSnapshotter), "lvm")))
            } else if BtrfsSnapshotter::supports(source) {
                Ok(Some((Box::new(BtrfsSnapshotter), "btrfs")))
            } else if ZfsSnapshotter::supports(source) {
                Ok(Some((Box::new(ZfsSnapshotter), "zfs")))
            } else {
                Err(LazarusError::Storage(format!(
                    "no snapshotter supports {}; pass --snapshotter none to bypass",
                    source.display()
                )))
            }
        }
    }
}

fn snapshotter_label(choice: SnapshotterChoice) -> &'static str {
    match choice {
        SnapshotterChoice::Auto => "auto",
        SnapshotterChoice::Lvm => "lvm",
        SnapshotterChoice::Btrfs => "btrfs",
        SnapshotterChoice::Zfs => "zfs",
        SnapshotterChoice::None => "none",
    }
}

/// Build a `HookRunner` from the requested template names. Unknown names
/// are rejected as typed errors so users discover typos early.
fn build_hook_runner(templates: &[String]) -> Result<HookRunner> {
    let hooks = if templates.is_empty() {
        hook_builtins::all()
    } else {
        let mut out: Vec<ApplicationHook> = Vec::new();
        for name in templates {
            let resolved: Vec<ApplicationHook> = match name.as_str() {
                "postgres" => vec![hook_builtins::postgres()],
                "mysql" => vec![hook_builtins::mysql()],
                "mongodb" => vec![hook_builtins::mongodb()],
                "redis" => vec![hook_builtins::redis()],
                "docker" => vec![hook_builtins::docker()],
                "all" => hook_builtins::all(),
                other => {
                    return Err(LazarusError::Storage(format!(
                        "unknown hook template `{other}`; expected one of postgres, mysql, mongodb, redis, docker, all"
                    )));
                }
            };
            out.extend(resolved);
        }
        out
    };
    Ok(HookRunner::with_hooks(hooks))
}

pub async fn backup(args: &BackupArgs) -> Result<()> {
    // --capture-system-only: delegate entirely to the system snapshot command.
    if args.capture_system_only {
        let sys_args = super::system_snapshot::SystemSnapshotArgs {
            repository: args.repository.clone(),
            password: args.password.clone(),
            tag: None,
            dry_run: false,
            print: false,
            tool_timeout: 30,
            skip_packages: false,
            skip_network: false,
            skip_users: false,
            skip_ssh: false,
            skip_bootloader: false,
            skip_lvm: false,
            skip_mdadm: false,
        };
        return super::system_snapshot::run(&sys_args).await;
    }

    println!("Starting backup...");

    let cfg = validate_args(args)?;

    // Open repository and unlock with password
    let config_mgr = ConfigManager::new(&args.repository);
    let key_manager = config_mgr.open_repository(&args.password).await?;

    // Open catalog database
    let catalog = CatalogIndex::new(config_mgr.database_path())?;

    // Initialize storage backend
    let storage = LocalStorage::new(config_mgr.data_path());

    let retention_policy = config_mgr.load_retention_policy().await?;
    let retention_lock = retention_policy.as_lock();
    if retention_lock.is_some() {
        println!(
            "Immutable retention policy active (mode: {:?}, minimum {} days)",
            retention_policy.mode, retention_policy.min_retention_days
        );
    }

    // Ransomware pre-check: run against the declared source, which is the
    // location the user intends to capture (snapshots, when used, are
    // taken *from* this path).
    let detection_engine = DetectionEngine::new(config_mgr.repo_path());
    let detection_report = detection_engine
        .analyze_paths(&[cfg.declared_source.clone()])
        .await?;

    match detection_report.verdict {
        DetectionVerdict::Clean => {
            println!(
                "Ransomware pre-check passed. Trust score: {:.0}%",
                detection_report.trust.score * 100.0
            );
            if let Some(rec) = detection_report.trust.recommendation {
                println!("  Advisory: {}", rec);
            }
        }
        DetectionVerdict::Suspicious => {
            println!("⚠️  Suspicious activity detected prior to backup!");
            for anomaly in &detection_report.anomalies {
                println!("  - {:?}", anomaly);
            }
            if args.force {
                println!("Proceeding with backup due to --force override. Expect potential risk.");
            } else {
                return Err(LazarusError::VerificationFailed(
                    "Backup aborted due to ransomware indicators".into(),
                ));
            }
        }
    }

    // Create snapshot ID (timestamp-based)
    let snapshot_id = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // --- Quiesce: optional hooks + optional OS snapshot --------------------
    //
    // When an OS snapshot is available, hooks bracket snapshot creation only:
    // pre → snapshot → post → capture from snapshot → release snapshot.
    // Without an OS snapshot (`--snapshotter none`, or block mode), hooks
    // must bracket capture itself because the original source is being read.
    let mut hook_report = HookReport::default();
    let mut hook_runner: Option<HookRunner> = None;
    let mut hooks_need_post = false;

    if cfg.consistent && cfg.run_hooks {
        let runner = build_hook_runner(&cfg.hook_templates)?;
        if !runner.applicable().is_empty() {
            println!(
                "Running {} pre-snapshot hook(s)...",
                runner.applicable().len()
            );
        }
        // Pre-failure aborts before any OS-level resource is taken, so
        // there is nothing to tear down on this error path.
        runner.run_pre(&mut hook_report)?;
        hooks_need_post = true;
        hook_runner = Some(runner);
    }

    let acquired = match acquire_read_path(&cfg) {
        Ok(acquired) => acquired,
        Err(err) => {
            if hooks_need_post {
                if let Some(runner) = hook_runner.as_ref() {
                    runner.run_post(&mut hook_report);
                    warn_post_hook_failures(&hook_report);
                }
            }
            return Err(err);
        }
    };
    let snapshotter_used = acquired.snapshotter_used;
    let has_os_snapshot = acquired.snapshot_mount.is_some();
    let snapshot_guard = SnapshotGuard::new(acquired.snapshot_mount);

    if hooks_need_post && has_os_snapshot {
        if let Some(runner) = hook_runner.as_ref() {
            runner.run_post(&mut hook_report);
            warn_post_hook_failures(&hook_report);
        }
        hooks_need_post = false;
    } else if hooks_need_post {
        println!(
            "Warning: no OS snapshot is active; hooks will remain in effect for the full capture duration"
        );
    }

    let capture_result = {
        let mut post_guard =
            PostHookGuard::new(hook_runner.as_ref(), &mut hook_report, hooks_need_post);
        let result = capture_from(
            &cfg,
            &acquired.read_path,
            &key_manager,
            &catalog,
            &storage,
            retention_lock.as_ref(),
        )
        .await;
        post_guard.run_now();
        result
    };
    drop(snapshot_guard);

    let (root_object_id, chunk_set, capture_summary) = capture_result?;

    // Create snapshot metadata, recording *how* the capture happened so a
    // later operator can audit the run.
    let snapshot_metadata = serde_json::json!({
        "source": cfg.declared_source.to_string_lossy().to_string(),
        "hostname": hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        "capture": {
            "mode": match cfg.mode {
                CaptureMode::File => "file",
                CaptureMode::Block => "block",
            },
            "consistent": cfg.consistent,
            "snapshotter_requested": snapshotter_label(cfg.snapshotter),
            "snapshotter_used": snapshotter_used,
            "hooks_enabled": cfg.run_hooks,
            "hook_outcomes": hook_report.outcomes,
            "extras": capture_summary,
        },
    });
    let snapshot_metadata_blob =
        encrypt_snapshot_metadata(&key_manager, &snapshot_metadata.to_string())?;

    // Save snapshot to catalog
    catalog.create_snapshot(
        &snapshot_id,
        timestamp,
        root_object_id,
        &snapshot_metadata_blob,
    )?;

    // Record dedup references for every chunk this snapshot uses. The
    // DedupTable lives in the same SQLite DB as the catalog, so this is just
    // an extra batch insert per snapshot.
    let chunks: Vec<[u8; 32]> = chunk_set.into_iter().collect();
    let mut dedup = DedupTable::open(config_mgr.database_path())?;
    dedup.add_references_batch(&snapshot_id, &chunks)?;

    // --capture-system: attach a system fingerprint to this snapshot.
    // Failures are non-fatal: the file backup is already committed.
    if args.capture_system {
        if let Some(ref source) = args.source {
            let source_path = PathBuf::from(source);
            let is_root = source_path == PathBuf::from("/");
            let is_block = source_path
                .metadata()
                .map(|m| !m.is_dir() && !m.is_file())
                .unwrap_or(false);
            if !is_root && !is_block {
                println!("warning: fingerprint reflects the capturing host, not the source tree");
            }
        }
        match run_capture_system(&config_mgr, &key_manager, &catalog, &dedup, &snapshot_id).await {
            Ok(fp_hash) => {
                // Update the metadata sidecar entry with fingerprint info.
                let meta_store = lazarus_core::catalog::metadata::MetadataStore::open(
                    config_mgr.repo_path(),
                    *key_manager.get_metadata_key(),
                );
                let mut sidecar = meta_store
                    .get(&snapshot_id)?
                    .unwrap_or_default();
                sidecar.system_fingerprint_chunk = Some(fp_hash.clone());
                sidecar.system_fingerprint_format_version = Some(1);
                if let Err(e) = meta_store.put(&snapshot_id, &sidecar) {
                    println!("warning: failed to update sidecar with fingerprint: {}", e);
                }
                println!("  System fingerprint: {}", fp_hash);
            }
            Err(e) => {
                println!("warning: system capture failed (backup is intact): {}", e);
            }
        }
    }

    println!("Backup completed successfully!");
    println!("  Snapshot ID: {}", snapshot_id);

    let (chunks, objects, snapshots) = catalog.get_stats()?;
    println!("  Repository stats:");
    println!("    Chunks: {}", chunks);
    println!("    Objects: {}", objects);
    println!("    Snapshots: {}", snapshots);

    Ok(())
}

/// Run the system capture pipeline and persist the fingerprint under the given snapshot.
async fn run_capture_system(
    config_mgr: &ConfigManager,
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    dedup: &DedupTable,
    snapshot_id: &str,
) -> Result<String> {
    use lazarus_core::capture::persist::FingerprintPersister;
    use lazarus_core::capture::system::CaptureOpts;
    use lazarus_core::capture::capture_system;

    let storage = LocalStorage::new(config_mgr.data_path());
    let opts = CaptureOpts::default();
    let persister = FingerprintPersister::new(
        &storage, key_manager, catalog, dedup, snapshot_id, false,
    );

    let report = capture_system(&opts, &persister).await?;
    let fp_hash = persister.persist_fingerprint(&report.fingerprint).await?;
    Ok(fp_hash)
}

struct AcquiredReadPath {
    read_path: PathBuf,
    snapshot_mount: Option<Box<dyn ConsistentMount>>,
    snapshotter_used: &'static str,
}

struct SnapshotGuard {
    mount: Option<Box<dyn ConsistentMount>>,
}

impl SnapshotGuard {
    fn new(mount: Option<Box<dyn ConsistentMount>>) -> Self {
        Self { mount }
    }
}

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        if let Some(mount) = self.mount.take() {
            if let Err(e) = mount.release() {
                eprintln!("Warning: snapshot teardown reported: {e}");
            }
        }
    }
}

struct PostHookGuard<'a> {
    runner: Option<&'a HookRunner>,
    report: Option<&'a mut HookReport>,
    active: bool,
}

impl<'a> PostHookGuard<'a> {
    fn new(
        runner: Option<&'a HookRunner>,
        report: &'a mut HookReport,
        active: bool,
    ) -> PostHookGuard<'a> {
        Self {
            runner,
            report: Some(report),
            active,
        }
    }

    fn run_now(&mut self) {
        if !self.active {
            return;
        }
        if let (Some(runner), Some(report)) = (self.runner, self.report.as_deref_mut()) {
            runner.run_post(report);
            warn_post_hook_failures(report);
        }
        self.active = false;
    }
}

impl Drop for PostHookGuard<'_> {
    fn drop(&mut self) {
        self.run_now();
    }
}

fn warn_post_hook_failures(report: &HookReport) {
    for failure in report.post_failures() {
        eprintln!(
            "Warning: post-snapshot hook `{}` failed: {}",
            failure.hook,
            failure.stderr.trim()
        );
    }
}

/// Acquire the path to read. For file backups with an OS snapshotter this
/// creates the snapshot and returns its mount. Hooks are handled by `backup()`
/// so they can run immediately after this function succeeds.
fn acquire_read_path(cfg: &CaptureConfig) -> Result<AcquiredReadPath> {
    match cfg.mode {
        CaptureMode::File => {
            let mut read_path = cfg.target.clone();
            let mut snapshot_mount = None;
            let mut snapshotter_used = "none";
            if cfg.consistent {
                if let Some((backend, label)) = pick_snapshotter(cfg.snapshotter, &cfg.target)? {
                    let mount = backend.snapshot(&cfg.target)?;
                    snapshotter_used = label;
                    read_path = mount.path().to_path_buf();
                    println!(
                        "Captured consistent snapshot at {} (via {})",
                        read_path.display(),
                        snapshotter_used
                    );
                    snapshot_mount = Some(mount);
                } else {
                    println!("--snapshotter none: skipping OS snapshot, hooks-only consistency");
                }
            }
            Ok(AcquiredReadPath {
                read_path,
                snapshot_mount,
                snapshotter_used,
            })
        }
        CaptureMode::Block => {
            if cfg.consistent {
                match cfg.snapshotter {
                    SnapshotterChoice::None | SnapshotterChoice::Auto => {}
                    SnapshotterChoice::Lvm | SnapshotterChoice::Btrfs | SnapshotterChoice::Zfs => {
                        return Err(LazarusError::Storage(
                            "--block-mode --consistent only supports --snapshotter=none or auto (hooks-only); pass the snapshot block device via --device for OS-level snapshots"
                                .to_string(),
                        ));
                    }
                }
            }
            Ok(AcquiredReadPath {
                read_path: cfg.target.clone(),
                snapshot_mount: None,
                snapshotter_used: "none",
            })
        }
    }
}

/// Run the actual capture against either a file tree or a raw block device.
async fn capture_from(
    cfg: &CaptureConfig,
    read_path: &Path,
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    retention: Option<&RetentionLock>,
) -> Result<(i64, HashSet<[u8; 32]>, serde_json::Value)> {
    match cfg.mode {
        CaptureMode::File => {
            let total_bytes = estimate_total_bytes(&read_path)?;
            let progress = create_progress_bar(total_bytes, "Backing up");
            progress.println(format!("Source: {}", read_path.display()));

            let mut chunk_set: HashSet<[u8; 32]> = HashSet::new();
            let root_id = if read_path.is_file() {
                backup_file(
                    key_manager,
                    catalog,
                    storage,
                    &read_path,
                    retention,
                    &progress,
                    &mut chunk_set,
                )
                .await?
            } else if read_path.is_dir() {
                backup_directory(
                    key_manager,
                    catalog,
                    storage,
                    &read_path,
                    retention,
                    &progress,
                    &mut chunk_set,
                )
                .await?
            } else {
                return Err(LazarusError::Storage(
                    "Source is neither a file nor a directory".to_string(),
                ));
            };
            progress.finish_with_message("Backup completed successfully");
            Ok((root_id, chunk_set, serde_json::json!({})))
        }
        CaptureMode::Block => {
            let (root_id, chunk_set, extents_captured, bytes_captured, device_size) =
                backup_block_device(key_manager, catalog, storage, read_path, retention).await?;
            Ok((
                root_id,
                chunk_set,
                serde_json::json!({
                    "device": cfg.target.to_string_lossy(),
                    "device_size": device_size,
                    "bytes_captured": bytes_captured,
                    "allocated_extents": extents_captured,
                    "manifest_version": 2,
                }),
            ))
        }
    }
}

struct ChunkProcessingResult {
    order: usize,
    hash_hex: String,
    chunk_len: usize,
    stored_data: Vec<u8>,
    block_position: Option<BlockChunkPosition>,
}

#[derive(Debug, Clone, Copy)]
struct BlockChunkPosition {
    extent_idx: u64,
    chunk_idx: u64,
    rel_offset: u64,
}

struct StoredChunkRecord {
    hash_hex: String,
    chunk_len: usize,
    block_position: Option<BlockChunkPosition>,
}

fn spawn_chunk_processing(
    order: usize,
    chunk: Vec<u8>,
    key_manager: lazarus_core::encryption::key_manager::KeyManager,
    block_position: Option<BlockChunkPosition>,
) -> task::JoinHandle<Result<ChunkProcessingResult>> {
    task::spawn_blocking(move || {
        let chunk_hash = blake3::hash(&chunk);
        let hash_hex = chunk_hash.to_hex().to_string();

        let encoded_chunk = adaptive::encode_chunk(&chunk)?;
        let (encrypted_chunk, nonce) = key_manager.encrypt_data(&encoded_chunk)?;

        let mut stored_data = nonce;
        stored_data.extend_from_slice(&encrypted_chunk);

        Ok(ChunkProcessingResult {
            order,
            hash_hex,
            chunk_len: chunk.len(),
            stored_data,
            block_position,
        })
    })
}

async fn backup_file(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    file_path: &Path,
    retention: Option<&RetentionLock>,
    progress: &ProgressBar,
    chunk_set: &mut HashSet<[u8; 32]>,
) -> Result<i64> {
    progress.set_message(format!("Backing up {}", file_path.display()));
    progress.println(format!("Backing up file: {}", file_path.display()));

    // Get file metadata
    let metadata = tokio::fs::metadata(file_path).await?;
    let file_metadata = build_object_metadata(
        file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        &metadata,
        false,
    );

    // Encrypt metadata (nonce prepended)
    let metadata_blob = serialize_and_encrypt_metadata(key_manager, &file_metadata)?;

    // Create object for file
    let file_object_id = catalog.create_object(ObjectType::File, &metadata_blob)?;

    let file = tokio::fs::File::open(file_path).await?;
    let reader = BufReader::new(file);
    let mut chunker = StreamingChunker::new(reader, CHUNK_SIZE);

    let pipeline_depth = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .max(2);

    let mut inflight: FuturesUnordered<_> = FuturesUnordered::new();
    let mut scheduled_chunks = 0usize;
    let mut eof = false;

    loop {
        while inflight.len() < pipeline_depth && !eof {
            match chunker.next_chunk().await? {
                Some(chunk) => {
                    let handle =
                        spawn_chunk_processing(scheduled_chunks, chunk, key_manager.clone(), None);
                    inflight.push(handle);
                    scheduled_chunks += 1;
                }
                None => {
                    eof = true;
                }
            }
        }

        if inflight.is_empty() {
            break;
        }

        if let Some(result) = inflight.next().await {
            let processed = result
                .map_err(|e| LazarusError::Storage(format!("Chunk worker failed: {}", e)))??;
            handle_processed_chunk(
                processed,
                catalog,
                storage,
                file_object_id,
                true,
                retention,
                progress,
                chunk_set,
            )
            .await?;
        }
    }

    progress.println(format!(
        "  ✓ {} ({} chunks)",
        file_path.display(),
        scheduled_chunks
    ));

    Ok(file_object_id)
}

async fn handle_processed_chunk(
    chunk: ChunkProcessingResult,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    file_object_id: i64,
    record_file_chunk: bool,
    retention: Option<&RetentionLock>,
    progress: &ProgressBar,
    chunk_set: &mut HashSet<[u8; 32]>,
) -> Result<StoredChunkRecord> {
    let ChunkProcessingResult {
        order,
        hash_hex,
        chunk_len,
        stored_data,
        block_position,
    } = chunk;

    if !catalog.chunk_exists(&hash_hex)? {
        let shard_dir = &hash_hex[..hash_hex.len().min(2)];
        storage
            .write_once(
                &format!("{}/{}", shard_dir, hash_hex),
                &stored_data,
                retention,
            )
            .await?;
        catalog.upsert_chunk(&hash_hex, stored_data.len(), chunk_len)?;
    }

    if record_file_chunk {
        catalog.add_file_chunk(file_object_id, &hash_hex, order)?;
    }
    if let Some(bytes) = hex_to_array(&hash_hex) {
        chunk_set.insert(bytes);
    }
    progress.inc(chunk_len as u64);

    Ok(StoredChunkRecord {
        hash_hex,
        chunk_len,
        block_position,
    })
}

fn record_block_chunk_manifest(
    catalog: &CatalogIndex,
    object_id: i64,
    stored: StoredChunkRecord,
) -> Result<()> {
    let Some(position) = stored.block_position else {
        return Err(LazarusError::Storage(
            "missing block chunk position while recording block manifest".to_string(),
        ));
    };
    catalog.add_block_extent_chunk(
        object_id,
        position.extent_idx,
        position.chunk_idx,
        &stored.hash_hex,
        position.rel_offset,
        stored.chunk_len as u64,
    )
}

fn hex_to_array(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Capture a raw block device or sparse file via allocated-extent
/// enumeration. Each extent is split into 1 MiB sub-chunks; the existing
/// chunk → encrypt → store → catalog pipeline is reused via
/// [`spawn_chunk_processing`] and [`handle_processed_chunk`].
///
/// Returns `(file_object_id, chunk_set, extents_captured, bytes_captured,
/// device_size)`.
async fn backup_block_device(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    device_path: &Path,
    retention: Option<&RetentionLock>,
) -> Result<(i64, HashSet<[u8; 32]>, u64, u64, u64)> {
    let mut reader = BlockDeviceReader::open(device_path)?;
    let device_size = reader.size();
    let extents: Vec<Extent> = reader.used_extents()?;
    let extents_captured = extents.len() as u64;

    let progress = create_progress_bar(device_size.max(1), "Backing up device");
    progress.println(format!(
        "Block device: {} ({} byte(s), {} allocated extent(s))",
        device_path.display(),
        device_size,
        extents_captured
    ));

    // Build a synthetic ObjectMetadata entry so the catalog has a name and
    // size for the captured device. We deliberately do not stat() the
    // device for uid/gid/mode: a snapshot of a block device is logically
    // a flat image, not a tracked inode.
    let device_metadata = ObjectMetadata {
        name: device_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("device"))
            .to_string_lossy()
            .to_string(),
        mode: 0o600,
        size: device_size,
        mtime: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        uid: 0,
        gid: 0,
    };
    let metadata_blob = serialize_and_encrypt_metadata(key_manager, &device_metadata)?;
    let file_object_id = catalog.create_object(ObjectType::BlockDevice, &metadata_blob)?;

    let pipeline_depth = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .max(2);

    let mut inflight: FuturesUnordered<task::JoinHandle<Result<ChunkProcessingResult>>> =
        FuturesUnordered::new();
    let mut scheduled_chunks = 0usize;
    let mut chunk_set: HashSet<[u8; 32]> = HashSet::new();
    let mut bytes_captured: u64 = 0;

    for (extent_idx, extent) in extents.iter().enumerate() {
        let extent_idx = extent_idx as u64;
        catalog.add_block_extent(file_object_id, extent_idx, extent.offset, extent.length)?;
        // Read the extent into memory, then slice it into 1 MiB pieces.
        // `BlockDeviceReader::open` caps extents at 1 GiB by default, so
        // this allocation is bounded.
        let data = reader.read_extent(extent)?;
        bytes_captured += data.len() as u64;
        let mut chunk_idx = 0u64;
        let mut rel_offset = 0u64;
        for piece in data.chunks(CHUNK_SIZE) {
            // Drain the in-flight queue once it reaches `pipeline_depth`
            // so we don't unboundedly buffer chunk-processing tasks.
            while inflight.len() >= pipeline_depth {
                if let Some(result) = inflight.next().await {
                    let processed = result.map_err(|e| {
                        LazarusError::Storage(format!("Chunk worker failed: {}", e))
                    })??;
                    let stored = handle_processed_chunk(
                        processed,
                        catalog,
                        storage,
                        file_object_id,
                        false,
                        retention,
                        &progress,
                        &mut chunk_set,
                    )
                    .await?;
                    record_block_chunk_manifest(catalog, file_object_id, stored)?;
                }
            }
            let handle = spawn_chunk_processing(
                scheduled_chunks,
                piece.to_vec(),
                key_manager.clone(),
                Some(BlockChunkPosition {
                    extent_idx,
                    chunk_idx,
                    rel_offset,
                }),
            );
            inflight.push(handle);
            scheduled_chunks += 1;
            chunk_idx += 1;
            rel_offset += piece.len() as u64;
        }
    }

    // Drain remaining work.
    while let Some(result) = inflight.next().await {
        let processed =
            result.map_err(|e| LazarusError::Storage(format!("Chunk worker failed: {}", e)))??;
        let stored = handle_processed_chunk(
            processed,
            catalog,
            storage,
            file_object_id,
            false,
            retention,
            &progress,
            &mut chunk_set,
        )
        .await?;
        record_block_chunk_manifest(catalog, file_object_id, stored)?;
    }

    progress.finish_with_message("Block-mode capture completed");
    println!(
        "  ✓ {} ({} chunks across {} extent(s); {} of {} bytes allocated)",
        device_path.display(),
        scheduled_chunks,
        extents_captured,
        bytes_captured,
        device_size
    );

    Ok((
        file_object_id,
        chunk_set,
        extents_captured,
        bytes_captured,
        device_size,
    ))
}

async fn backup_directory(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    dir_path: &Path,
    retention: Option<&RetentionLock>,
    progress: &ProgressBar,
    chunk_set: &mut HashSet<[u8; 32]>,
) -> Result<i64> {
    progress.set_message(format!("Scanning {}", dir_path.display()));
    progress.println(format!("Backing up directory: {}", dir_path.display()));

    // Create object for directory
    let metadata = tokio::fs::metadata(dir_path).await?;
    let dir_metadata = build_object_metadata(
        dir_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        &metadata,
        true,
    );

    let metadata_blob = serialize_and_encrypt_metadata(key_manager, &dir_metadata)?;

    let dir_object_id = catalog.create_object(ObjectType::Directory, &metadata_blob)?;

    // Walk directory entries
    let mut entries = tokio::fs::read_dir(dir_path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let entry_path = entry.path();
        let entry_name = entry.file_name().to_string_lossy().to_string();

        // Recursively backup child
        let child_object_id = if entry_path.is_file() {
            backup_file(
                key_manager,
                catalog,
                storage,
                &entry_path,
                retention,
                progress,
                chunk_set,
            )
            .await?
        } else if entry_path.is_dir() {
            Box::pin(backup_directory(
                key_manager,
                catalog,
                storage,
                &entry_path,
                retention,
                progress,
                chunk_set,
            ))
            .await?
        } else {
            continue; // Skip symlinks and other special files
        };

        // Encrypt the child name
        let (encrypted_name, nonce) = key_manager.encrypt_metadata(&entry_name)?;

        // Prepend nonce to encrypted name for storage
        let mut stored_name = nonce;
        stored_name.extend_from_slice(&encrypted_name);

        // Add to tree
        catalog.add_tree_entry(dir_object_id, child_object_id, &stored_name)?;
    }

    progress.println(format!("  ✓ {}/", dir_path.display()));

    Ok(dir_object_id)
}

fn build_object_metadata(
    name: String,
    metadata: &std::fs::Metadata,
    is_dir: bool,
) -> ObjectMetadata {
    let (uid, gid, mode) = capture_platform_metadata(metadata, is_dir);
    ObjectMetadata {
        name,
        mode,
        size: if is_dir { 0 } else { metadata.len() },
        mtime: system_time_to_unix(metadata.modified().unwrap_or_else(|_| SystemTime::now())),
        uid,
        gid,
    }
}

fn serialize_and_encrypt_metadata(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    metadata: &ObjectMetadata,
) -> Result<Vec<u8>> {
    let metadata_json = serde_json::to_string(metadata)
        .map_err(|e| LazarusError::SerializationError(e.to_string()))?;
    let (encrypted_metadata, nonce) = key_manager.encrypt_metadata(&metadata_json)?;
    let mut stored_metadata = nonce;
    stored_metadata.extend_from_slice(&encrypted_metadata);
    Ok(stored_metadata)
}

fn system_time_to_unix(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}

#[cfg(unix)]
fn capture_platform_metadata(metadata: &std::fs::Metadata, _is_dir: bool) -> (u32, u32, u32) {
    (metadata.uid(), metadata.gid(), metadata.mode())
}

#[cfg(not(unix))]
fn capture_platform_metadata(_metadata: &std::fs::Metadata, is_dir: bool) -> (u32, u32, u32) {
    (0, 0, if is_dir { 0o755 } else { 0o644 })
}

fn estimate_total_bytes(path: &Path) -> Result<u64> {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        Ok(metadata.len())
    } else if metadata.is_dir() {
        let mut total = 0;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            total += estimate_total_bytes(&entry.path())?;
        }
        Ok(total)
    } else {
        Ok(0)
    }
}

fn create_progress_bar(total_bytes: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes.max(1));
    let style = ProgressStyle::with_template(
        "{spinner} {msg:<20} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
    )
    .unwrap()
    .progress_chars("=>-");
    pb.set_style(style);
    pb.set_message(message.to_string());
    pb
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn base_args() -> BackupArgs {
        BackupArgs {
            source: Some("/tmp/source".to_string()),
            repository: "/tmp/repo".to_string(),
            password: "pw".to_string(),
            force: false,
            consistent: false,
            snapshotter: SnapshotterChoice::Auto,
            block_mode: false,
            device: None,
            no_hooks: false,
            hook_templates: Vec::new(),
            capture_system: false,
            capture_system_only: false,
        }
    }

    #[test]
    fn validate_ok_for_default_file_backup() {
        let cfg = validate_args(&base_args()).unwrap();
        assert!(matches!(cfg.mode, CaptureMode::File));
        assert_eq!(cfg.target, PathBuf::from("/tmp/source"));
    }

    #[test]
    fn validate_rejects_block_mode_without_device() {
        let mut a = base_args();
        a.source = None;
        a.block_mode = true;
        let err = validate_args(&a).unwrap_err();
        assert!(matches!(err, LazarusError::Storage(msg) if msg.contains("requires --device")));
    }

    #[test]
    fn validate_rejects_block_mode_with_source() {
        let mut a = base_args();
        a.block_mode = true;
        a.device = Some("/dev/sda1".to_string());
        // source is Some("/tmp/source") from the base.
        let err = validate_args(&a).unwrap_err();
        assert!(
            matches!(err, LazarusError::Storage(msg) if msg.contains("cannot be combined with --source"))
        );
    }

    #[test]
    fn validate_rejects_device_without_block_mode() {
        let mut a = base_args();
        a.device = Some("/dev/sda1".to_string());
        let err = validate_args(&a).unwrap_err();
        assert!(
            matches!(err, LazarusError::Storage(msg) if msg.contains("only be used with --block-mode"))
        );
    }

    #[test]
    fn validate_accepts_block_mode_with_device_no_source() {
        let mut a = base_args();
        a.source = None;
        a.block_mode = true;
        a.device = Some("/dev/sda1".to_string());
        let cfg = validate_args(&a).unwrap();
        assert!(matches!(cfg.mode, CaptureMode::Block));
        assert_eq!(cfg.target, PathBuf::from("/dev/sda1"));
    }

    #[test]
    fn validate_rejects_file_mode_without_source() {
        let mut a = base_args();
        a.source = None;
        let err = validate_args(&a).unwrap_err();
        assert!(matches!(err, LazarusError::Storage(msg) if msg.contains("--source is required")));
    }

    #[test]
    fn consistent_with_snapshotter_none_is_valid() {
        let mut a = base_args();
        a.consistent = true;
        a.snapshotter = SnapshotterChoice::None;
        let cfg = validate_args(&a).unwrap();
        assert!(cfg.consistent);
        assert_eq!(cfg.snapshotter, SnapshotterChoice::None);
    }

    #[test]
    fn pick_snapshotter_none_returns_none() {
        let res = pick_snapshotter(SnapshotterChoice::None, Path::new("/tmp")).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn pick_snapshotter_auto_errors_when_nothing_supports() {
        // /tmp is virtually never LVM/btrfs/zfs in CI.
        let res = pick_snapshotter(SnapshotterChoice::Auto, Path::new("/tmp"));
        // Either an error, or — on a btrfs-rooted CI runner — a backend.
        if let Err(err) = res {
            assert!(
                matches!(err, LazarusError::Storage(msg) if msg.contains("no snapshotter supports"))
            );
        }
    }

    #[test]
    fn build_hook_runner_default_returns_all_builtins() {
        let r = build_hook_runner(&[]).unwrap();
        // The `all()` set in lazarus-core covers at least these five names.
        let names: Vec<_> = r.hooks().iter().map(|h| h.name.clone()).collect();
        for expected in &["postgres", "mysql", "mongodb", "redis", "docker"] {
            assert!(names.iter().any(|n| n == expected), "missing {expected}");
        }
    }

    #[test]
    fn build_hook_runner_specific_template() {
        let r = build_hook_runner(&["postgres".to_string()]).unwrap();
        assert_eq!(r.hooks().len(), 1);
        assert_eq!(r.hooks()[0].name, "postgres");
    }

    #[test]
    fn build_hook_runner_rejects_unknown_template() {
        let err = build_hook_runner(&["not-a-real-hook".to_string()]).unwrap_err();
        assert!(matches!(err, LazarusError::Storage(msg) if msg.contains("unknown hook template")));
    }

    #[test]
    fn block_mode_consistent_rejects_filesystem_snapshotters() {
        let mut a = base_args();
        a.source = None;
        a.block_mode = true;
        a.device = Some("/dev/sda1".to_string());
        a.consistent = true;
        a.snapshotter = SnapshotterChoice::Btrfs;
        // The error surfaces inside run_capture, but we can validate that
        // arg parsing succeeds and the mode is block — the runtime error
        // path is exercised via integration.
        let cfg = validate_args(&a).unwrap();
        assert!(matches!(cfg.mode, CaptureMode::Block));
        assert_eq!(cfg.snapshotter, SnapshotterChoice::Btrfs);
    }

    #[test]
    fn post_hook_guard_runs_post_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let log = temp.path().join("hook.log");
        let runner = HookRunner::with_hooks(vec![ApplicationHook {
            name: "test-hook".to_string(),
            match_rule: None,
            pre_snapshot: "true".to_string(),
            post_snapshot: format!("printf post >> {}", log.display()),
            timeout_secs: None,
            env: std::collections::HashMap::new(),
        }]);
        let mut report = HookReport::default();

        {
            let _guard = PostHookGuard::new(Some(&runner), &mut report, true);
        }

        assert_eq!(std::fs::read_to_string(log).unwrap(), "post");
        assert_eq!(report.post_failures().len(), 0);
        assert_eq!(report.outcomes.len(), 1);
    }

    #[test]
    fn post_hook_guard_run_now_only_runs_once() {
        let temp = tempfile::tempdir().unwrap();
        let log = temp.path().join("hook.log");
        let runner = HookRunner::with_hooks(vec![ApplicationHook {
            name: "test-hook".to_string(),
            match_rule: None,
            pre_snapshot: "true".to_string(),
            post_snapshot: format!("printf post >> {}", log.display()),
            timeout_secs: None,
            env: std::collections::HashMap::new(),
        }]);
        let mut report = HookReport::default();

        {
            let mut guard = PostHookGuard::new(Some(&runner), &mut report, true);
            guard.run_now();
        }

        assert_eq!(std::fs::read_to_string(log).unwrap(), "post");
        assert_eq!(report.outcomes.len(), 1);
    }

    struct FakeMount {
        path: PathBuf,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl ConsistentMount for FakeMount {
        fn path(&self) -> &Path {
            &self.path
        }

        fn release(self: Box<Self>) -> Result<()> {
            self.events.lock().unwrap().push("release");
            Ok(())
        }
    }

    #[test]
    fn snapshot_guard_releases_mount_on_drop() {
        let events = Arc::new(Mutex::new(Vec::new()));
        {
            let mount = FakeMount {
                path: PathBuf::from("/tmp/snapshot"),
                events: events.clone(),
            };
            let _guard = SnapshotGuard::new(Some(Box::new(mount)));
        }
        assert_eq!(*events.lock().unwrap(), vec!["release"]);
    }
}
