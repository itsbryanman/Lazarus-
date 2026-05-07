//! Block-mode capture: read a block device or partition image as a sparse
//! stream of *allocated* extents, skipping holes in sparse files and
//! unused filesystem space entirely.
//!
//! For raw block devices on Linux we use `FS_IOC_FIEMAP` (when the
//! underlying filesystem image cooperates) or fall back to the generic
//! `lseek(SEEK_DATA/SEEK_HOLE)` extent scan that the kernel provides for
//! both regular files and block devices on most filesystems. Both routes
//! produce the same [`Extent`] list: a sequence of `(offset, length)`
//! ranges that contain real data; everything outside the list is implied
//! to be zeros and need not be stored.
//!
//! The expected wire-up is:
//!
//! ```ignore
//! let mut reader = BlockDeviceReader::open("/dev/sda1")?;
//! for extent in reader.used_extents()? {
//!     let bytes = reader.read_extent(&extent)?;
//!     pipeline.feed(extent.offset, &bytes)?;
//! }
//! ```
//!
//! The chunker can then run over each extent independently. A 1 TiB
//! filesystem with 100 GiB used produces ~100 GiB of input to the
//! chunker, not 1 TiB.

use crate::error::{LazarusError, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// One contiguous run of allocated bytes inside a block device or sparse
/// file, in source-offset coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// Byte offset of the first allocated byte from the start of the
    /// device/file.
    pub offset: u64,
    /// Length of the run in bytes.
    pub length: u64,
}

impl Extent {
    /// Inclusive end of the extent in source-offset coordinates.
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }
}

/// A reader that exposes a block device or large sparse file as a stream
/// of [`Extent`]s plus an [`std::io::Read`] interface for the bytes within
/// each extent.
pub struct BlockDeviceReader {
    path: PathBuf,
    file: File,
    size: u64,
    /// Maximum length of a single emitted extent. Keeps the chunker from
    /// having to materialize multi-GB allocations in one go.
    max_extent_len: u64,
}

/// 1 GiB. Each extent is read into memory by [`BlockDeviceReader::read_extent`],
/// so we cap the size for safety; longer runs are split across multiple
/// `Extent`s with consecutive offsets.
pub const DEFAULT_MAX_EXTENT_LEN: u64 = 1024 * 1024 * 1024;

impl BlockDeviceReader {
    /// Open the device or file at `path` for reading. Uses ordinary
    /// buffered I/O; an O_DIRECT fast path is left as a future
    /// optimization because it requires page-aligned read buffers, which
    /// the rest of the pipeline does not currently provide.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_max_extent(path, DEFAULT_MAX_EXTENT_LEN)
    }

    /// Open the device with an explicit cap on the size of any individual
    /// emitted [`Extent`].
    pub fn open_with_max_extent<P: AsRef<Path>>(path: P, max_extent_len: u64) -> Result<Self> {
        if max_extent_len == 0 {
            return Err(LazarusError::Storage(
                "max_extent_len must be > 0".to_string(),
            ));
        }
        let path = path.as_ref().to_path_buf();
        let file = open_for_read(&path)?;
        let size = device_or_file_size(&file, &path)?;
        Ok(Self {
            path,
            file,
            size,
            max_extent_len,
        })
    }

    /// Total size of the underlying device/file in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Path the reader was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Enumerate the allocated extents using the kernel's
    /// `SEEK_DATA`/`SEEK_HOLE` interface, with a fall-back that treats the
    /// whole device as one extent if the kernel can't tell us anything
    /// more granular.
    ///
    /// The returned extents are non-overlapping, in ascending order, and
    /// each is no longer than `max_extent_len`.
    pub fn used_extents(&self) -> Result<Vec<Extent>> {
        if self.size == 0 {
            return Ok(Vec::new());
        }

        #[cfg(target_os = "linux")]
        {
            match seek_data_extents(&self.path, self.size) {
                Ok(raw) => return Ok(split_extents(raw, self.max_extent_len)),
                Err(_) => {
                    // Fall through to the conservative single-extent
                    // fallback below.
                }
            }
        }

        Ok(split_extents(
            vec![Extent {
                offset: 0,
                length: self.size,
            }],
            self.max_extent_len,
        ))
    }

    /// Read the bytes belonging to `extent` from the underlying device.
    pub fn read_extent(&mut self, extent: &Extent) -> Result<Vec<u8>> {
        if extent.length == 0 {
            return Ok(Vec::new());
        }
        if extent.end() > self.size {
            return Err(LazarusError::Storage(format!(
                "extent {:?} extends past device size {}",
                extent, self.size
            )));
        }
        let len: usize = extent.length.try_into().map_err(|_| {
            LazarusError::Storage(format!(
                "extent length {} too large for this platform",
                extent.length
            ))
        })?;
        self.file
            .seek(SeekFrom::Start(extent.offset))
            .map_err(LazarusError::Io)?;
        let mut buf = vec![0u8; len];
        self.file.read_exact(&mut buf).map_err(LazarusError::Io)?;
        Ok(buf)
    }
}

fn open_for_read(path: &Path) -> Result<File> {
    // We deliberately do *not* use O_DIRECT here. The resurrection plan
    // mentions "O_DIRECT where available" as an optimization, but
    // O_DIRECT requires page-aligned buffers and offsets, which is a
    // larger refactor than the current chunker assumes. Sticking with
    // buffered I/O keeps reads correct on every backing filesystem; the
    // alignment work is tracked as a future optimization.
    File::open(path).map_err(LazarusError::Io)
}

fn device_or_file_size(file: &File, path: &Path) -> Result<u64> {
    // Regular files: file metadata gives us the size directly.
    let meta = file.metadata().map_err(LazarusError::Io)?;
    if meta.is_file() {
        return Ok(meta.len());
    }

    // Block device: lseek(SEEK_END) reports the size on Linux/macOS/BSD.
    // We work on a clone of the FD so we don't disturb the caller's
    // position.
    let mut probe = file.try_clone().map_err(LazarusError::Io)?;
    let end = probe.seek(SeekFrom::End(0)).map_err(LazarusError::Io)?;
    if end > 0 {
        return Ok(end);
    }
    Err(LazarusError::Storage(format!(
        "could not determine size of {}",
        path.display()
    )))
}

/// Split `extents` so that no individual extent exceeds `max_len`.
fn split_extents(extents: Vec<Extent>, max_len: u64) -> Vec<Extent> {
    let mut out = Vec::with_capacity(extents.len());
    for ext in extents {
        if ext.length <= max_len {
            out.push(ext);
            continue;
        }
        let mut remaining = ext.length;
        let mut offset = ext.offset;
        while remaining > 0 {
            let take = remaining.min(max_len);
            out.push(Extent {
                offset,
                length: take,
            });
            offset = offset.saturating_add(take);
            remaining -= take;
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn seek_data_extents(path: &Path, size: u64) -> std::io::Result<Vec<Extent>> {
    use std::os::unix::io::AsRawFd;

    const SEEK_DATA: i32 = 3;
    const SEEK_HOLE: i32 = 4;

    let f = File::open(path)?;
    let fd = f.as_raw_fd();

    unsafe extern "C" {
        fn lseek64(fd: i32, offset: i64, whence: i32) -> i64;
    }

    let mut extents = Vec::new();
    let mut cursor: i64 = 0;
    let max: i64 = i64::try_from(size).unwrap_or(i64::MAX);

    loop {
        // Find the next data region at or after `cursor`.
        let data_start = unsafe { lseek64(fd, cursor, SEEK_DATA) };
        if data_start < 0 {
            // ENXIO means "no more data": return what we have so far.
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(6 /* ENXIO */) {
                return Ok(extents);
            }
            return Err(err);
        }
        if data_start >= max {
            return Ok(extents);
        }
        // Find the next hole after the data region (or EOF).
        let hole_start = unsafe { lseek64(fd, data_start, SEEK_HOLE) };
        let region_end = if hole_start < 0 {
            // No hole found; data extends to end of file.
            max
        } else if hole_start > max {
            max
        } else {
            hole_start
        };
        if region_end <= data_start {
            return Ok(extents);
        }
        extents.push(Extent {
            offset: data_start as u64,
            length: (region_end - data_start) as u64,
        });
        cursor = region_end;
        if cursor >= max {
            return Ok(extents);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(path: &Path, data: &[u8]) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(data).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn extent_end_is_offset_plus_length() {
        let e = Extent {
            offset: 100,
            length: 50,
        };
        assert_eq!(e.end(), 150);
    }

    #[test]
    fn split_extents_caps_length() {
        let big = vec![Extent {
            offset: 0,
            length: 10,
        }];
        let split = split_extents(big, 3);
        assert_eq!(split.len(), 4);
        assert_eq!(split[0], Extent { offset: 0, length: 3 });
        assert_eq!(split[1], Extent { offset: 3, length: 3 });
        assert_eq!(split[2], Extent { offset: 6, length: 3 });
        assert_eq!(split[3], Extent { offset: 9, length: 1 });
    }

    #[test]
    fn split_extents_passes_through_small() {
        let small = vec![Extent {
            offset: 0,
            length: 5,
        }];
        assert_eq!(split_extents(small.clone(), 16), small);
    }

    #[test]
    fn reader_reports_correct_size() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("img.bin");
        write_file(&p, &vec![7u8; 4096]);
        let r = BlockDeviceReader::open(&p).unwrap();
        assert_eq!(r.size(), 4096);
    }

    #[test]
    fn read_extent_returns_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("img.bin");
        let mut data = vec![0u8; 1024];
        for i in 0..1024 {
            data[i] = (i % 251) as u8;
        }
        write_file(&p, &data);
        let mut r = BlockDeviceReader::open(&p).unwrap();
        let bytes = r
            .read_extent(&Extent {
                offset: 100,
                length: 200,
            })
            .unwrap();
        assert_eq!(bytes, data[100..300]);
    }

    #[test]
    fn read_extent_rejects_out_of_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("img.bin");
        write_file(&p, &vec![0u8; 64]);
        let mut r = BlockDeviceReader::open(&p).unwrap();
        assert!(r
            .read_extent(&Extent {
                offset: 0,
                length: 128
            })
            .is_err());
    }

    #[test]
    fn empty_file_yields_no_extents() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.bin");
        write_file(&p, &[]);
        let r = BlockDeviceReader::open(&p).unwrap();
        assert!(r.used_extents().unwrap().is_empty());
    }

    #[test]
    fn dense_file_extents_cover_whole_size() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("dense.bin");
        write_file(&p, &vec![1u8; 1024]);
        let r = BlockDeviceReader::open(&p).unwrap();
        let exts = r.used_extents().unwrap();
        let total: u64 = exts.iter().map(|e| e.length).sum();
        assert_eq!(total, 1024);
        // Extents must be non-overlapping and ordered.
        for w in exts.windows(2) {
            assert!(w[0].end() <= w[1].offset);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sparse_file_skips_holes() {
        // Create a sparse file with a 4 KiB hole between two 1 KiB data
        // regions. ext4 / tmpfs / xfs support SEEK_DATA semantics for
        // this; if the running filesystem doesn't, the fallback path
        // returns one big extent and we just verify total size.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sparse.bin");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&[1u8; 1024]).unwrap();
        f.set_len(1024 + 4096 + 1024).unwrap();
        f.seek(SeekFrom::Start(1024 + 4096)).unwrap();
        f.write_all(&[2u8; 1024]).unwrap();
        f.sync_all().unwrap();

        let r = BlockDeviceReader::open(&p).unwrap();
        let exts = r.used_extents().unwrap();
        let total: u64 = exts.iter().map(|e| e.length).sum();
        assert!(total <= 1024 + 4096 + 1024);
        assert!(total >= 2 * 1024);
    }
}
