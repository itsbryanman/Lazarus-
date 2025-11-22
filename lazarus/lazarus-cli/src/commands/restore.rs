use super::snapshot_utils::{
    calculate_snapshot_size, decrypt_object_metadata, parse_snapshot_metadata,
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
use std::{io, path::Path};
#[cfg(unix)]
use std::{ffi::CString, os::unix::ffi::OsStrExt, os::unix::fs::PermissionsExt};

#[derive(Args)]
pub struct RestoreArgs {
    #[arg(short, long, help = "Snapshot ID to restore")]
    pub snapshot: Option<String>,

    #[arg(short, long, help = "Destination path for restore")]
    pub destination: Option<String>,

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

    let destination = match args.destination.clone() {
        Some(dest) => dest,
        None => prompt_destination(None)?,
    };

    // Get snapshot details
    let snapshot_data = catalog.get_snapshot(&snapshot_id)?.ok_or_else(|| {
        lazarus_core::error::LazarusError::Storage(format!("Snapshot '{}' not found", snapshot_id))
    })?;

    let (root_object_id, _encrypted_metadata) = snapshot_data;

    // Get root object
    let (obj_type, encrypted_obj_metadata) =
        catalog.get_object(root_object_id)?.ok_or_else(|| {
            lazarus_core::error::LazarusError::Storage("Root object not found".to_string())
        })?;
    let root_metadata = decrypt_object_metadata(&key_manager, &encrypted_obj_metadata)?;

    // Restore from root
    let dest_path = Path::new(&destination);
    let total_bytes = calculate_snapshot_size(&catalog, &key_manager, root_object_id)?;
    let progress = create_progress_bar(total_bytes, "Restoring");
    progress.println(format!(
        "Restoring snapshot {} to {}",
        snapshot_id,
        dest_path.display()
    ));

    match obj_type {
        ObjectType::File => {
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
        }
        ObjectType::Directory => {
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

    let mut file_data = Vec::new();

    for hash in chunk_hashes {
        // Read chunk from storage
        let shard_dir = &hash[..2];
        let stored_data = storage.get(&format!("{}/{}", shard_dir, hash)).await?;

        // Extract nonce (first 12 bytes) and encrypted data
        if stored_data.len() < 12 {
            return Err(lazarus_core::error::LazarusError::EncryptionError(
                "Stored chunk too small".to_string(),
            ));
        }

        let nonce = &stored_data[..12];
        let encrypted_chunk = &stored_data[12..];

        // Decrypt chunk
        let encoded_chunk = key_manager.decrypt_data(encrypted_chunk, nonce)?;

        // Decode chunk (handles adaptive compression header)
        let chunk = adaptive::decode_chunk(&encoded_chunk)?;

        file_data.extend_from_slice(&chunk);
    }

    // Write to destination
    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(dest_path, &file_data).await?;
    apply_metadata(dest_path, &metadata).await?;

    progress.inc(metadata.size);
    progress.println(format!("  ✓ Restored file: {}", dest_path.display()));

    Ok(())
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
        }
    }

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
    let destination = prompt
        .interact_text()
        .map_err(dialoguer_error)?;
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
    LazarusError::Io(io::Error::new(io::ErrorKind::Other, err))
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
