use super::snapshot_utils::{
    calculate_snapshot_size, decrypt_object_metadata, parse_snapshot_metadata,
    parse_snapshot_metadata_value,
};
use clap::Args;
use dialoguer::{Input, Select};
use filetime::{set_file_times, FileTime};
use indicatif::{ProgressBar, ProgressStyle};
use lazarus_core::catalog::index::{CatalogIndex, ObjectMetadata, ObjectType};
use lazarus_core::compression::adaptive;
use lazarus_core::config::ConfigManager;
use lazarus_core::error::{LazarusError, Result};
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
#[cfg(unix)]
use libc;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
#[cfg(unix)]
use std::{ffi::CString, os::unix::ffi::OsStrExt, os::unix::fs::PermissionsExt};
use std::{io, path::Path};
use tokio::io::AsyncWriteExt;

#[derive(Args)]
pub struct RestoreArgs {
    #[arg(short, long, help = "Snapshot ID to restore")]
    pub snapshot: Option<String>,

    #[arg(short, long, help = "Destination path for restore")]
    pub destination: Option<String>,

    #[arg(
        long,
        help = "Target raw device or existing file for block-mode restore"
    )]
    pub device: Option<String>,

    #[arg(
        long,
        help = "Allow overwriting an existing sparse-file destination during block-mode restore"
    )]
    pub allow_overwrite: bool,

    #[arg(long, help = "Verify restored data after restore completes")]
    pub verify: bool,

    #[arg(short, long, help = "Repository path")]
    pub repository: String,

    #[arg(short, long, help = "Master password for decryption")]
    pub password: String,
}

pub async fn restore(args: &RestoreArgs) -> Result<()> {
    println!("Starting restore...");

    // Open repository and unlock with password
    let config_mgr = ConfigManager::new(&args.repository);
    let key_manager = config_mgr.open_repository(&args.password).await?;

    // Open catalog database
    let catalog = CatalogIndex::new(config_mgr.database_path())?;

    // Initialize storage backend
    let storage = LocalStorage::new(config_mgr.data_path());

    let snapshot_id = match args.snapshot.clone() {
        Some(id) => id,
        None => prompt_snapshot_selection(&catalog, &key_manager)?,
    };

    // Get snapshot details
    let snapshot_data = catalog.get_snapshot(&snapshot_id)?.ok_or_else(|| {
        lazarus_core::error::LazarusError::Storage(format!("Snapshot '{}' not found", snapshot_id))
    })?;

    let (root_object_id, encrypted_metadata) = snapshot_data;

    // Get root object
    let (obj_type, encrypted_obj_metadata) =
        catalog.get_object(root_object_id)?.ok_or_else(|| {
            lazarus_core::error::LazarusError::Storage("Root object not found".to_string())
        })?;
    let root_metadata = decrypt_object_metadata(&key_manager, &encrypted_obj_metadata)?;

    // Restore from root
    let total_bytes = calculate_snapshot_size(&catalog, &key_manager, root_object_id)?;
    let progress = create_progress_bar(total_bytes, "Restoring");

    match obj_type {
        ObjectType::File => {
            if args.device.is_some() {
                return Err(LazarusError::Storage(
                    "--device is only valid when restoring a block-mode snapshot".to_string(),
                ));
            }
            let destination = match args.destination.clone() {
                Some(dest) => dest,
                None => prompt_destination(None)?,
            };
            let dest_path = Path::new(&destination);
            progress.println(format!(
                "Restoring snapshot {} to {}",
                snapshot_id,
                dest_path.display()
            ));
            restore_file(
                &key_manager,
                &catalog,
                &storage,
                root_object_id,
                root_metadata,
                dest_path,
                &progress,
            )
            .await?;
            if args.verify {
                verify_file_restore(&key_manager, &catalog, &storage, root_object_id, dest_path)
                    .await?;
            }
        }
        ObjectType::Directory => {
            if args.device.is_some() {
                return Err(LazarusError::Storage(
                    "--device is only valid when restoring a block-mode snapshot".to_string(),
                ));
            }
            let destination = match args.destination.clone() {
                Some(dest) => dest,
                None => prompt_destination(None)?,
            };
            let dest_path = Path::new(&destination);
            progress.println(format!(
                "Restoring snapshot {} to {}",
                snapshot_id,
                dest_path.display()
            ));
            restore_directory(
                &key_manager,
                &catalog,
                &storage,
                root_object_id,
                root_metadata,
                dest_path,
                &progress,
            )
            .await?;
        }
        ObjectType::BlockDevice => {
            let target = block_restore_target(args)?;
            progress.println(format!(
                "Restoring block snapshot {} to {}",
                snapshot_id,
                target.display()
            ));
            ensure_block_manifest_v2(&key_manager, &encrypted_metadata)?;
            restore_block_device(
                &key_manager,
                &catalog,
                &storage,
                root_object_id,
                root_metadata,
                target,
                args.device.is_some(),
                args.allow_overwrite,
                &progress,
            )
            .await?;
            if args.verify {
                verify_block_restore(&key_manager, &catalog, &storage, root_object_id, target)
                    .await?;
            }
        }
        ObjectType::SystemFingerprint => {
            return Err(LazarusError::Storage(
                "this snapshot's root object is a SystemFingerprint; \
                 use `lazarus-cli system-snapshot --show` to inspect it"
                    .into(),
            ));
        }
    }

    progress.finish_with_message("Restore completed successfully");
    println!("✓ Restore completed successfully!");

    Ok(())
}

async fn restore_file(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    file_object_id: i64,
    metadata: ObjectMetadata,
    dest_path: &Path,
    progress: &ProgressBar,
) -> Result<()> {
    progress.set_message(format!("Restoring {}", dest_path.display()));
    progress.println(format!("Restoring file: {}", dest_path.display()));
    // Get file chunks in order
    let chunk_hashes = catalog.get_file_chunks(file_object_id)?;

    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut out = tokio::fs::File::create(dest_path).await?;

    for hash in chunk_hashes {
        let chunk = read_verified_chunk(key_manager, storage, &hash).await?;
        out.write_all(&chunk).await?;
        progress.inc(chunk.len() as u64);
    }
    out.flush().await?;

    apply_metadata(dest_path, &metadata).await?;

    progress.println(format!("  ✓ Restored file: {}", dest_path.display()));

    Ok(())
}

async fn read_verified_chunk(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    storage: &LocalStorage,
    hash: &str,
) -> Result<Vec<u8>> {
    let shard_dir = &hash[..2];
    let stored_data = storage.get(&format!("{}/{}", shard_dir, hash)).await?;

    if stored_data.len() < 12 {
        return Err(LazarusError::EncryptionError(
            "Stored chunk too small".to_string(),
        ));
    }

    let nonce = &stored_data[..12];
    let encrypted_chunk = &stored_data[12..];
    let encoded_chunk = key_manager.decrypt_data(encrypted_chunk, nonce)?;
    let chunk = adaptive::decode_chunk(&encoded_chunk)?;
    let calculated_hash = blake3::hash(&chunk).to_hex().to_string();
    if calculated_hash != hash {
        return Err(LazarusError::VerificationFailed(format!(
            "chunk hash mismatch: expected {hash}, got {calculated_hash}"
        )));
    }
    Ok(chunk)
}

async fn restore_directory(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    dir_object_id: i64,
    metadata: ObjectMetadata,
    dest_path: &Path,
    progress: &ProgressBar,
) -> Result<()> {
    // Create destination directory
    tokio::fs::create_dir_all(dest_path).await?;
    apply_metadata(dest_path, &metadata).await?;

    progress.println(format!("  ✓ Restored directory: {}/", dest_path.display()));

    // Get children
    let children = catalog.get_tree_children(dir_object_id)?;

    for (child_id, encrypted_name) in children {
        // Decrypt child name
        // The encrypted_name contains both nonce and encrypted data
        // We need to split them similar to how we handle chunks
        if encrypted_name.len() < 12 {
            continue; // Skip invalid entries
        }

        let nonce = &encrypted_name[..12];
        let encrypted = &encrypted_name[12..];

        let child_name = key_manager.decrypt_metadata(encrypted, nonce)?;

        // Get child object
        let (child_type, child_metadata_blob) = catalog.get_object(child_id)?.ok_or_else(|| {
            lazarus_core::error::LazarusError::Storage("Child object not found".to_string())
        })?;
        let child_metadata = decrypt_object_metadata(key_manager, &child_metadata_blob)?;

        // Build child path
        let child_path = dest_path.join(&child_name);

        // Recursively restore child
        match child_type {
            ObjectType::File => {
                restore_file(
                    key_manager,
                    catalog,
                    storage,
                    child_id,
                    child_metadata,
                    &child_path,
                    progress,
                )
                .await?;
            }
            ObjectType::Directory => {
                Box::pin(restore_directory(
                    key_manager,
                    catalog,
                    storage,
                    child_id,
                    child_metadata,
                    &child_path,
                    progress,
                ))
                .await?;
            }
            ObjectType::BlockDevice => {
                return Err(LazarusError::Storage(
                    "nested block-device objects are not supported in file-tree restore"
                        .to_string(),
                ));
            }
            ObjectType::SystemFingerprint => {
                return Err(LazarusError::Storage(
                    "nested SystemFingerprint objects are not supported in file-tree restore"
                        .to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn block_restore_target(args: &RestoreArgs) -> Result<&Path> {
    match (args.device.as_deref(), args.destination.as_deref()) {
        (Some(_), Some(_)) => Err(LazarusError::Storage(
            "--device and --destination are mutually exclusive for block-mode restore".to_string(),
        )),
        (Some(device), None) => Ok(Path::new(device)),
        (None, Some(destination)) => Ok(Path::new(destination)),
        (None, None) => Err(LazarusError::Storage(
            "block-mode restore requires --device <PATH> or --destination <PATH>".to_string(),
        )),
    }
}

fn ensure_block_manifest_v2(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    snapshot_metadata: &[u8],
) -> Result<()> {
    let Some(value) = parse_snapshot_metadata_value(key_manager, snapshot_metadata) else {
        return Err(LazarusError::Storage(
            "block snapshot metadata is missing or unreadable".to_string(),
        ));
    };
    let manifest_version = value
        .pointer("/capture/extras/manifest_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if manifest_version < 2 {
        return Err(LazarusError::Storage(
            "block snapshot lacks a v2 extent manifest and cannot be restored safely".to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn restore_block_device(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    object_id: i64,
    metadata: ObjectMetadata,
    target: &Path,
    target_is_device: bool,
    allow_overwrite: bool,
    progress: &ProgressBar,
) -> Result<()> {
    let layout = catalog.get_block_layout(object_id)?;
    validate_block_layout(&layout, metadata.size)?;

    if target_is_device {
        if !target.exists() {
            return Err(LazarusError::Storage(format!(
                "target device {} does not exist",
                target.display()
            )));
        }
    } else if target.exists() && !allow_overwrite {
        return Err(LazarusError::Storage(format!(
            "destination {} already exists; pass --allow-overwrite to replace it",
            target.display()
        )));
    } else if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut out = if target_is_device {
        OpenOptions::new().read(true).write(true).open(target)?
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(target)?
    };

    if target_is_device {
        let target_size = file_or_device_size(&out, target)?;
        if target_size < metadata.size {
            return Err(LazarusError::Storage(format!(
                "target device {} is {} byte(s), smaller than backup size {}",
                target.display(),
                target_size,
                metadata.size
            )));
        }
    } else {
        out.set_len(metadata.size)?;
    }

    for extent in layout.extents {
        for chunk_ref in extent.chunks {
            let chunk = read_verified_chunk(key_manager, storage, &chunk_ref.hash).await?;
            if chunk.len() as u64 != chunk_ref.length {
                return Err(LazarusError::VerificationFailed(format!(
                    "chunk {} length mismatch: manifest {}, decoded {}",
                    chunk_ref.hash,
                    chunk_ref.length,
                    chunk.len()
                )));
            }
            let write_offset = extent
                .offset
                .checked_add(chunk_ref.rel_offset)
                .ok_or_else(|| LazarusError::Storage("block write offset overflow".to_string()))?;
            out.seek(SeekFrom::Start(write_offset))?;
            out.write_all(&chunk)?;
            progress.inc(chunk.len() as u64);
        }
    }
    out.flush()?;
    progress.println(format!("  ✓ Restored block image: {}", target.display()));
    Ok(())
}

fn validate_block_layout(
    layout: &lazarus_core::catalog::index::BlockLayout,
    device_size: u64,
) -> Result<()> {
    let mut allocated_total = 0u64;
    let mut last_extent_end = 0u64;
    for extent in &layout.extents {
        if extent.offset < last_extent_end {
            return Err(LazarusError::VerificationFailed(
                "block extents are not ordered or overlap".to_string(),
            ));
        }
        let extent_end = extent
            .offset
            .checked_add(extent.length)
            .ok_or_else(|| LazarusError::VerificationFailed("block extent overflow".to_string()))?;
        if extent_end > device_size {
            return Err(LazarusError::VerificationFailed(
                "block extent extends past device size".to_string(),
            ));
        }
        let mut chunk_total = 0u64;
        let mut expected_rel = 0u64;
        for chunk in &extent.chunks {
            if chunk.rel_offset != expected_rel {
                return Err(LazarusError::VerificationFailed(
                    "block chunks are not ordered contiguously within an extent".to_string(),
                ));
            }
            expected_rel = expected_rel.checked_add(chunk.length).ok_or_else(|| {
                LazarusError::VerificationFailed("block chunk overflow".to_string())
            })?;
            chunk_total = chunk_total.checked_add(chunk.length).ok_or_else(|| {
                LazarusError::VerificationFailed("block chunk total overflow".to_string())
            })?;
        }
        if chunk_total != extent.length {
            return Err(LazarusError::VerificationFailed(format!(
                "extent {} length mismatch: extent {}, chunks {}",
                extent.extent_idx, extent.length, chunk_total
            )));
        }
        allocated_total = allocated_total.checked_add(extent.length).ok_or_else(|| {
            LazarusError::VerificationFailed("allocated byte total overflow".to_string())
        })?;
        last_extent_end = extent_end;
    }
    if allocated_total > device_size {
        return Err(LazarusError::VerificationFailed(
            "allocated block bytes exceed device size".to_string(),
        ));
    }
    Ok(())
}

fn file_or_device_size(file: &std::fs::File, path: &Path) -> Result<u64> {
    let meta = file.metadata().map_err(LazarusError::Io)?;
    if meta.is_file() {
        return Ok(meta.len());
    }
    let mut probe = file.try_clone().map_err(LazarusError::Io)?;
    let size = probe.seek(SeekFrom::End(0)).map_err(LazarusError::Io)?;
    if size == 0 {
        return Err(LazarusError::Storage(format!(
            "could not determine size of {}",
            path.display()
        )));
    }
    Ok(size)
}

async fn verify_file_restore(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    object_id: i64,
    target: &Path,
) -> Result<()> {
    let mut restored = tokio::fs::File::open(target).await?;
    for hash in catalog.get_file_chunks(object_id)? {
        let expected = read_verified_chunk(key_manager, storage, &hash).await?;
        let mut actual = vec![0u8; expected.len()];
        tokio::io::AsyncReadExt::read_exact(&mut restored, &mut actual).await?;
        if actual != expected {
            return Err(LazarusError::VerificationFailed(format!(
                "restored file differs at chunk {hash}"
            )));
        }
    }
    println!("✓ Restored file verified");
    Ok(())
}

async fn verify_block_restore(
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
    catalog: &CatalogIndex,
    storage: &LocalStorage,
    object_id: i64,
    target: &Path,
) -> Result<()> {
    let layout = catalog.get_block_layout(object_id)?;
    let mut restored = OpenOptions::new().read(true).open(target)?;
    for extent in layout.extents {
        for chunk_ref in extent.chunks {
            let expected = read_verified_chunk(key_manager, storage, &chunk_ref.hash).await?;
            let mut actual = vec![0u8; expected.len()];
            let offset = extent
                .offset
                .checked_add(chunk_ref.rel_offset)
                .ok_or_else(|| LazarusError::Storage("block verify offset overflow".to_string()))?;
            restored.seek(SeekFrom::Start(offset))?;
            std::io::Read::read_exact(&mut restored, &mut actual)?;
            if actual != expected {
                return Err(LazarusError::VerificationFailed(format!(
                    "restored block target differs at chunk {}",
                    chunk_ref.hash
                )));
            }
        }
    }
    println!("✓ Restored block target verified");
    Ok(())
}

fn prompt_snapshot_selection(
    catalog: &CatalogIndex,
    key_manager: &lazarus_core::encryption::key_manager::KeyManager,
) -> Result<String> {
    let snapshots = catalog.list_snapshots()?;
    if snapshots.is_empty() {
        return Err(LazarusError::Storage(
            "No snapshots available in the repository".to_string(),
        ));
    }

    let mut choices = Vec::new();
    for (snapshot_id, timestamp) in snapshots {
        let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let hostname = catalog
            .get_snapshot(&snapshot_id)?
            .and_then(|(_, blob)| parse_snapshot_metadata(key_manager, &blob))
            .and_then(|meta| meta.hostname)
            .unwrap_or_else(|| "Unknown".to_string());

        let label = format!("{}  |  {}  |  {}", snapshot_id, datetime, hostname);
        choices.push((snapshot_id, label));
    }

    let labels: Vec<String> = choices.iter().map(|(_, label)| label.clone()).collect();
    let selection = Select::new()
        .with_prompt("Select snapshot to restore")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(dialoguer_error)?;

    Ok(choices
        .get(selection)
        .map(|(id, _)| id.clone())
        .unwrap_or_else(|| choices[0].0.clone()))
}

fn prompt_destination(default: Option<&str>) -> Result<String> {
    let mut prompt = Input::<String>::new().with_prompt("Destination path");
    if let Some(value) = default {
        prompt = prompt.with_initial_text(value.to_string());
    }
    let destination = prompt.interact_text().map_err(dialoguer_error)?;
    Ok(destination)
}

fn create_progress_bar(total_bytes: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes.max(1));
    let style = ProgressStyle::with_template(
        "{spinner} {msg:<20} [{bar:40.green/black}] {bytes}/{total_bytes} ({eta})",
    )
    .unwrap()
    .progress_chars("=>-");
    pb.set_style(style);
    pb.set_message(message.to_string());
    pb
}

fn dialoguer_error(err: dialoguer::Error) -> LazarusError {
    LazarusError::Io(io::Error::other(err))
}

async fn apply_metadata(path: &Path, metadata: &ObjectMetadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::Permissions;

        if metadata.mode != 0 {
            if let Err(err) =
                tokio::fs::set_permissions(path, Permissions::from_mode(metadata.mode)).await
            {
                eprintln!(
                    "Warning: failed to set permissions on {}: {}",
                    path.display(),
                    err
                );
            }
        }

        if let Err(err) = chown_path(path, metadata.uid, metadata.gid) {
            eprintln!(
                "Warning: failed to set ownership on {}: {}",
                path.display(),
                err
            );
        }
    }

    let mtime = metadata.mtime.min(i64::MAX as u64) as i64;
    let file_time = FileTime::from_unix_time(mtime, 0);
    if let Err(err) = set_file_times(path, file_time, file_time) {
        eprintln!(
            "Warning: failed to apply timestamps on {}: {}",
            path.display(),
            err
        );
    }

    Ok(())
}

#[cfg(unix)]
fn chown_path(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::io::{self, ErrorKind};

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "path contains null byte"))?;
    let res = unsafe { libc::chown(c_path.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) };
    if res == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
