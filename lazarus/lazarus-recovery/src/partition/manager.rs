use std::io::{self, ErrorKind};
use std::process::Command;

use sysinfo::Disks;

#[derive(Debug, Clone)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: Option<String>,
    pub total_space: u64,
}

/// Return a snapshot of the currently attached disks using sysinfo.
pub fn list_disks() -> Vec<DiskInfo> {
    let disks = Disks::new_with_refreshed_list();
    disks
        .iter()
        .map(|disk| DiskInfo {
            name: disk.name().to_string_lossy().to_string(),
            mount_point: disk
                .mount_point()
                .to_str()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty()),
            total_space: disk.total_space(),
        })
        .collect()
}

/// Wipe the selected partition and create a fresh ext4 filesystem so we can
/// restore files into a known-good mount point.
pub fn wipe_and_format(target: &str) -> io::Result<()> {
    let status = Command::new("mkfs.ext4").arg("-F").arg(target).status();

    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(io::Error::new(
            ErrorKind::Other,
            format!("mkfs.ext4 exited with status {status}"),
        )),
        Err(err) => Err(err),
    }
}
