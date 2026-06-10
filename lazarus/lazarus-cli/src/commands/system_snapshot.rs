use super::snapshot_utils::encrypt_snapshot_metadata;
use clap::Args;
use lazarus_core::capture::persist::FingerprintPersister;
use lazarus_core::capture::system::{CaptureOpts, SystemFingerprint};
use lazarus_core::capture::{capture_system, CaptureWarning};
use lazarus_core::catalog::index::{CatalogIndex, ObjectType};
use lazarus_core::catalog::metadata::{MetadataStore, SnapshotMetadata};
use lazarus_core::config::ConfigManager;
use lazarus_core::error::Result;
use lazarus_core::snapshot::dedup::DedupTable;
use lazarus_core::storage::local::LocalStorage;
use std::time::{Duration, SystemTime};

#[derive(Args)]
pub struct SystemSnapshotArgs {
    #[arg(short, long)]
    pub repository: String,
    #[arg(short, long)]
    pub password: String,
    #[arg(long)]
    pub tag: Option<String>,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub print: bool,
    #[arg(long, default_value_t = 30)]
    pub tool_timeout: u64,
    #[arg(long)]
    pub skip_packages: bool,
    #[arg(long)]
    pub skip_network: bool,
    #[arg(long)]
    pub skip_users: bool,
    #[arg(long)]
    pub skip_ssh: bool,
    #[arg(long)]
    pub skip_bootloader: bool,
    #[arg(long)]
    pub skip_lvm: bool,
    #[arg(long)]
    pub skip_mdadm: bool,
}

pub async fn run(args: &SystemSnapshotArgs) -> Result<()> {
    println!("Capturing system fingerprint...");

    let config_mgr = ConfigManager::new(&args.repository);
    let key_manager = config_mgr.open_repository(&args.password).await?;
    let catalog = CatalogIndex::new(config_mgr.database_path())?;
    let dedup = DedupTable::open(config_mgr.database_path())?;
    let storage = LocalStorage::new(config_mgr.data_path());

    let snapshot_id = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();

    let opts = build_capture_opts(args);
    let persister = FingerprintPersister::new(
        &storage,
        &key_manager,
        &catalog,
        &dedup,
        &snapshot_id,
        args.dry_run,
    );

    let report = capture_system(&opts, &persister).await?;

    if args.dry_run {
        println!("Dry run: captured {} component(s)", component_count(&report.fingerprint));
        print_warnings(&report.fingerprint.warnings);
        println!("Elapsed: {:.2}s", report.elapsed.as_secs_f64());
        return Ok(());
    }

    let fp_hash = persister.persist_fingerprint(&report.fingerprint).await?;

    // Build the catalog object for the fingerprint.
    let fp_metadata = serde_json::json!({
        "fingerprint_chunk": fp_hash,
        "format_version": 1,
    });
    let metadata_blob = encrypt_snapshot_metadata(&key_manager, &fp_metadata.to_string())?;
    let root_object_id = catalog.create_object(ObjectType::SystemFingerprint, &metadata_blob)?;

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let snapshot_metadata_json = serde_json::json!({
        "source": "system",
        "hostname": hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        "type": "system-fingerprint",
    });
    let snapshot_metadata_blob =
        encrypt_snapshot_metadata(&key_manager, &snapshot_metadata_json.to_string())?;
    catalog.create_snapshot(&snapshot_id, timestamp, root_object_id, &snapshot_metadata_blob)?;

    // Write the SnapshotMetadata sidecar entry.
    let meta_store = MetadataStore::open(
        config_mgr.repo_path(),
        *key_manager.get_metadata_key(),
    );
    let sidecar = SnapshotMetadata {
        hostname: Some(
            hostname::get()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        ),
        source: Some("system".into()),
        system_fingerprint_chunk: Some(fp_hash.clone()),
        system_fingerprint_format_version: Some(1),
        tags: args.tag.iter().cloned().collect(),
        ..Default::default()
    };
    meta_store.put(&snapshot_id, &sidecar)?;

    println!("System fingerprint captured successfully.");
    println!("  Snapshot ID: {}", snapshot_id);
    println!("  Fingerprint chunk: {}", fp_hash);
    println!("  Warnings: {}", report.fingerprint.warnings.len());
    println!("  Elapsed: {:.2}s", report.elapsed.as_secs_f64());

    if args.print {
        print_fingerprint(&report.fingerprint);
    }

    Ok(())
}

pub fn build_capture_opts(args: &SystemSnapshotArgs) -> CaptureOpts {
    CaptureOpts {
        include_packages: !args.skip_packages,
        include_network: !args.skip_network,
        include_users: !args.skip_users,
        include_ssh_keys: !args.skip_ssh,
        include_bootloader: !args.skip_bootloader,
        include_lvm: !args.skip_lvm,
        include_mdadm: !args.skip_mdadm,
        tool_timeout: Duration::from_secs(args.tool_timeout),
    }
}

fn component_count(fp: &SystemFingerprint) -> usize {
    let mut count = 1; // always have kernel/cpu/memory
    count += fp.disks.len();
    if fp.lvm.is_some() { count += 1; }
    if fp.mdadm.is_some() { count += 1; }
    count += fp.filesystems.len();
    count += fp.services.len();
    count
}

fn print_warnings(warnings: &[CaptureWarning]) {
    for w in warnings {
        println!("  Warning [{}]: {}", w.component, w.message);
        if let Some(ref r) = w.remediation {
            println!("    Remediation: {}", r);
        }
    }
}

fn print_fingerprint(fp: &SystemFingerprint) {
    // Print a safe JSON representation of the fingerprint. The
    // SystemFingerprint struct does not contain sensitive blob content
    // (only hash refs), so it is safe to serialize directly. The
    // users and ssh_host_keys fields contain only ref hashes and counts.
    match serde_json::to_string_pretty(fp) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize fingerprint: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_opts_skip_flags() {
        let args = SystemSnapshotArgs {
            repository: String::new(),
            password: String::new(),
            tag: None,
            dry_run: false,
            print: false,
            tool_timeout: 30,
            skip_packages: true,
            skip_network: false,
            skip_users: true,
            skip_ssh: false,
            skip_bootloader: true,
            skip_lvm: false,
            skip_mdadm: true,
        };
        let opts = build_capture_opts(&args);
        assert!(!opts.include_packages);
        assert!(opts.include_network);
        assert!(!opts.include_users);
        assert!(opts.include_ssh_keys);
        assert!(!opts.include_bootloader);
        assert!(opts.include_lvm);
        assert!(!opts.include_mdadm);
        assert_eq!(opts.tool_timeout, Duration::from_secs(30));
    }

    #[test]
    fn capture_opts_defaults() {
        let args = SystemSnapshotArgs {
            repository: String::new(),
            password: String::new(),
            tag: None,
            dry_run: false,
            print: false,
            tool_timeout: 60,
            skip_packages: false,
            skip_network: false,
            skip_users: false,
            skip_ssh: false,
            skip_bootloader: false,
            skip_lvm: false,
            skip_mdadm: false,
        };
        let opts = build_capture_opts(&args);
        assert!(opts.include_packages);
        assert!(opts.include_network);
        assert!(opts.include_users);
        assert!(opts.include_ssh_keys);
        assert!(opts.include_bootloader);
        assert!(opts.include_lvm);
        assert!(opts.include_mdadm);
        assert_eq!(opts.tool_timeout, Duration::from_secs(60));
    }
}
