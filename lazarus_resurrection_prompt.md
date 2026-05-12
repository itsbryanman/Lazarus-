# Lazarus: Resurrection-Class Backup — Coding Agent Build Plan

You are a senior Rust systems engineer working on **Lazarus**, an open-source backup tool whose explicit north-star goal is **bare-metal resurrection**: take a server that has been physically destroyed, ransomwared, or had its OS disk obliterated, and bring it back to a fully booting, identical state on potentially different hardware, from a single Lazarus repository.

Existing competitors do *parts* of this. Restic/Borg/Kopia handle file-level repositories well but stop at restore. Veeam/Commvault handle bare-metal but are proprietary, expensive, and Windows-centric. Lazarus's wedge: **open-source, Rust, Linux-first bare-metal-and-HIR done right, plus opinionated ransomware survivability.**

You will work through the phases below in order. Each phase has explicit acceptance criteria. Do not skip ahead; foundations matter for a tool people stake their company on.

---

## Repo layout (already in place — work inside this)

```
lazarus/
├── lazarus-core/      # chunking, encryption, catalog, compression, storage backends
├── lazarus-cli/       # operator workflows (backup/restore/init/security/etc.)
├── lazarus-server/    # gRPC controller, job scheduler
├── lazarus-agent/     # endpoint daemon
├── lazarus-recovery/  # bare-metal restore TUI + ISO builder
├── lazarus-common/    # shared DTOs, proto definitions
└── scripts/           # ISO build helpers
```

Many sub-modules exist as **empty files** declared in `mod.rs`. They compile but contain nothing. This plan completes them.

Confirmed-empty files at the start of this work (each is a stub you must implement):

- `lazarus-core/src/snapshot/dedup.rs`
- `lazarus-core/src/snapshot/block_tracker.rs`
- `lazarus-core/src/snapshot/manager.rs`
- `lazarus-core/src/encryption/aes.rs` (real crypto currently lives in `key_manager.rs`; this file should hold the streaming AEAD wrapper)
- `lazarus-core/src/encryption/vault.rs`
- `lazarus-core/src/catalog/history.rs`
- `lazarus-core/src/catalog/metadata.rs`
- `lazarus-core/src/storage/distributed.rs`
- `lazarus-core/src/compression/zstd.rs` (re-export wrapper)
- `lazarus-recovery/src/boot/iso_builder.rs`
- `lazarus-recovery/src/boot/pxe.rs`
- `lazarus-recovery/src/boot/usb.rs`
- `lazarus-recovery/src/hardware/detection.rs`
- `lazarus-recovery/src/hardware/drivers.rs`
- `lazarus-recovery/src/hardware/compatibility.rs`
- `lazarus-recovery/src/partition/resize.rs`
- `lazarus-recovery/src/restore/bare_metal.rs`
- `lazarus-recovery/src/restore/instant.rs`
- `lazarus-recovery/src/restore/file_level.rs`
- `lazarus-recovery/src/restore/app_level.rs`
- `lazarus-cli/src/interactive/wizard.rs`
- `lazarus-cli/src/interactive/progress.rs`
- `lazarus-cli/src/output/formatter.rs`
- `lazarus-cli/src/output/json.rs`

---

## Architectural principles (apply throughout every phase)

1. **No silent data loss, ever.** Every write goes `temp → fsync → rename`. Every read verifies the chunk hash before returning bytes to the caller. A corrupted chunk should produce a typed error, never garbage data.
2. **Every byte is encrypted client-side before leaving the host.** Cloud backends never see plaintext. Repo metadata is encrypted with a separate key from chunk data so list operations don't leak filenames.
3. **Deterministic chunk IDs.** Use BLAKE3 of plaintext for chunk identity (cheaper than SHA-256, cryptographically strong, parallelizable). Never use a hash of ciphertext — that breaks dedup across keys.
4. **Repositories are append-only by default.** Pruning is a separate, auditable operation that produces a tombstone log.
5. **Forward compatibility.** Every on-disk struct gets a version byte. Every gRPC message is a proto with reserved field numbers.
6. **Restore must work without the original machine, the original kernel, or the original network.** This is the resurrection contract. Code with it in mind.
7. **Tests are not optional.** Every public function in `lazarus-core` needs at least one unit test. Every CLI command needs an integration test that round-trips through a tempdir repo. Every restore-path change requires a "kill the source, restore, byte-compare" test.
8. **Linux-first, cross-platform-ready.** Use `cfg(unix)` / `cfg(target_os = "linux")` gates explicitly. Don't write anything that paints us into a Linux corner without leaving a clear extension point for Windows/macOS.

---

## Phase 1 — Foundation hardening

**Goal:** close the gaps in the existing code so the current happy-path is bulletproof before we add new capability.

### 1.1 Implement `snapshot/dedup.rs`

A `DedupTable` backed by SQLite that tracks `chunk_hash -> reference_count`. Operations:

```rust
pub struct DedupTable { /* ... */ }

impl DedupTable {
    pub fn open(db_path: &Path) -> Result<Self>;
    pub fn add_reference(&self, chunk_hash: &[u8; 32], snapshot_id: &str) -> Result<u64>; // returns new refcount
    pub fn remove_reference(&self, chunk_hash: &[u8; 32], snapshot_id: &str) -> Result<u64>;
    pub fn unreferenced_chunks(&self) -> Result<Vec<[u8; 32]>>;
    pub fn stats(&self) -> Result<DedupStats>;
}
```

Schema additions to the existing catalog DB:

```sql
CREATE TABLE IF NOT EXISTS ChunkRefs (
    chunk_hash BLOB NOT NULL,
    snapshot_id TEXT NOT NULL,
    PRIMARY KEY (chunk_hash, snapshot_id),
    FOREIGN KEY (snapshot_id) REFERENCES Snapshots(id) ON DELETE CASCADE
);
CREATE INDEX idx_chunkrefs_hash ON ChunkRefs(chunk_hash);
```

Wire `DedupTable::add_reference` into `backup.rs` for every chunk written. Wire `unreferenced_chunks` into `prune.rs` to drive deletion.

**Acceptance:** `lazarus-cli backup` of the same directory twice produces a second snapshot whose disk usage delta equals only changed-byte regions plus catalog overhead. Add a test `tests/dedup_round_trip.rs` that asserts this within 2% tolerance.

### 1.2 Implement `snapshot/block_tracker.rs`

The block tracker records, per file, the chunk boundaries and hashes of the *previous* snapshot so the next backup can do change-detection without rehashing identical files.

```rust
pub struct BlockTracker { /* ... */ }

impl BlockTracker {
    pub fn open(repo_path: &Path) -> Result<Self>;
    pub fn record_file(&self, path: &Path, mtime: u64, size: u64, chunks: &[ChunkRef]) -> Result<()>;
    pub fn lookup_unchanged(&self, path: &Path, mtime: u64, size: u64) -> Result<Option<Vec<ChunkRef>>>;
}
```

Heuristic: if `(path, mtime, size)` matches the previous record, reuse the chunk list verbatim — no re-read of the file. This is the standard "fast path" in mature backup tools.

**Acceptance:** A second `backup` over an unchanged 10GB directory completes in under 10% of the time of the initial backup. Add `tests/incremental_speed.rs`.

### 1.3 Implement `snapshot/manager.rs`

The high-level orchestrator that today's `backup.rs` and `restore.rs` assemble inline. Pull the orchestration into a `SnapshotManager` so it can be reused by the gRPC server, agent, and recovery TUI without duplicating logic.

```rust
pub struct SnapshotManager {
    catalog: CatalogIndex,
    storage: Box<dyn StorageBackend>,
    keys: KeyManager,
    dedup: DedupTable,
    block_tracker: BlockTracker,
}

impl SnapshotManager {
    pub async fn create_snapshot(&self, source: &Path, opts: SnapshotOpts) -> Result<SnapshotId>;
    pub async fn restore_snapshot(&self, id: &SnapshotId, dest: &Path, opts: RestoreOpts) -> Result<()>;
    pub async fn verify_snapshot(&self, id: &SnapshotId, mode: VerifyMode) -> Result<VerifyReport>;
    pub async fn prune(&self, policy: &RetentionPolicy) -> Result<PruneReport>;
    pub async fn list_snapshots(&self) -> Result<Vec<SnapshotSummary>>;
}
```

Refactor `backup.rs`, `restore.rs`, `prune.rs`, `verify.rs` to delegate to `SnapshotManager`. The CLI commands become thin argument parsers.

**Acceptance:** Existing CLI test suite still passes. The agent code (`lazarus-agent/src/main.rs`) gets a refactor to use `SnapshotManager` instead of shelling to the CLI.

### 1.4 Implement `catalog/history.rs` and `catalog/metadata.rs`

`history.rs` — append-only log of every operation against the repo (init, backup, prune, key-rotate, restore). Each entry signed with the metadata key. Tampering detection.

```rust
pub struct History { /* ... */ }

#[derive(Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: u64,
    pub operation: Operation, // Backup, Prune, KeyRotate, Restore, Verify
    pub actor: String,        // hostname or agent id
    pub details: serde_json::Value,
    pub signature: Vec<u8>,
}
```

`metadata.rs` — encrypted blob containing snapshot tags, descriptions, retention overrides. Separated from `index.rs` so we can reload metadata independently when displaying the snapshot list (faster TUI, no need to scan the chunk catalog).

**Acceptance:** Tampering with a history entry on disk causes `lazarus-cli verify --history` to flag it. Add `tests/tamper_detection.rs`.

### 1.5 Implement `encryption/aes.rs` and `encryption/vault.rs`

`aes.rs` — streaming AEAD wrapper. Currently `backup.rs` does AES-GCM encryption inline; pull it into `aes.rs` as a `StreamingEncryptor` / `StreamingDecryptor` that handles nonce derivation deterministically from chunk hash + counter (so the same plaintext under the same key gets the same ciphertext, preserving dedup).

```rust
pub struct StreamingEncryptor { /* ... */ }

impl StreamingEncryptor {
    pub fn new(key: &[u8; 32]) -> Self;
    pub fn encrypt_chunk(&self, chunk_hash: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>>;
    pub fn decrypt_chunk(&self, chunk_hash: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>>;
}
```

Nonce construction: first 12 bytes of `BLAKE3(chunk_hash || key_epoch)`. Document the nonce derivation in the source. **Critical:** include `key_epoch` so post-rotation chunks don't collide nonces with pre-rotation chunks under the same key material.

`vault.rs` — local encrypted credential store for storage backend secrets (S3 access keys, SSH passphrases). Encrypted with the metadata key. Avoids forcing the operator to put cloud creds in plaintext config.

**Acceptance:** Replace inline crypto in `backup.rs` and `restore.rs` with `StreamingEncryptor`. Existing repos must still decrypt (write a one-shot upgrade path or version the chunk header).

### 1.6 Add a Merkle-tree repository verifier

New module `lazarus-core/src/integrity/merkle.rs`. Build a Merkle tree over chunk hashes per snapshot. Store the root in the snapshot metadata. `verify --merkle` re-computes and compares.

**Acceptance:** Bit-flip a chunk file on disk; `lazarus-cli verify --merkle` identifies the exact chunk and which snapshots reference it.

---

## Phase 2 — Block-level snapshotting

**Goal:** stop relying on filesystem walks for the *capture* step. A running database, an open VM image, or a busy mailbox cannot be safely captured by reading files one at a time. We need consistent point-in-time snapshots.

### 2.1 LVM thin snapshot integration

New module `lazarus-core/src/snapshot/lvm.rs`.

```rust
pub struct LvmSnapshot { /* ... */ }

impl LvmSnapshot {
    pub fn create(volume: &Path, snapshot_name: &str) -> Result<Self>;
    pub fn device_path(&self) -> &Path;
    pub fn release(self) -> Result<()>; // also runs in Drop
}
```

Shell out to `lvcreate --snapshot --name lazarus_snap_<ts> --size 5G <volume>`. Mount the snapshot read-only at `/var/lib/lazarus/mounts/<snap_id>/`. Backup runs against the mount, releases the snapshot on completion.

**Acceptance:** A test that creates a 1GB LVM thin volume, populates it, kicks off a backup, and verifies the backup contains the consistent state even if writes continue during the backup. Skip with `#[cfg(skip_if_no_lvm)]` if the test environment lacks LVM.

### 2.2 Btrfs and ZFS snapshots

New modules `lazarus-core/src/snapshot/btrfs.rs` and `lazarus-core/src/snapshot/zfs.rs`. Both implement a common `BlockSnapshotter` trait:

```rust
pub trait BlockSnapshotter: Send + Sync {
    fn supports(path: &Path) -> bool where Self: Sized;
    fn snapshot(&self, source: &Path) -> Result<Box<dyn ConsistentMount>>;
}

pub trait ConsistentMount: Send + Sync {
    fn path(&self) -> &Path;
    // Drop implementation tears down the snapshot
}
```

Btrfs: `btrfs subvolume snapshot -r <source> <snapshot_path>`. ZFS: `zfs snapshot pool/dataset@lazarus-<ts>` then `zfs clone` to mount read-write or use the `.zfs/snapshot/` path.

### 2.3 Application freeze/thaw hooks

New module `lazarus-core/src/snapshot/hooks.rs`. Pre-snapshot and post-snapshot scripts configured per repo:

```toml
[[hooks.application]]
name = "postgres"
match = { service = "postgresql" }
pre_snapshot = "psql -c 'SELECT pg_backup_start(''lazarus'')'"
post_snapshot = "psql -c 'SELECT pg_backup_stop()'"
```

Built-in hook libraries for: PostgreSQL, MySQL/MariaDB, MongoDB, Redis (BGSAVE), libvirt VMs (`virsh suspend`/`resume` or QEMU guest agent fsfreeze), Docker (`docker pause`/`unpause` or volume snapshot).

**Acceptance:** Backup of a running PostgreSQL DB produces a snapshot that, when restored, opens cleanly without WAL-recovery warnings.

### 2.4 Block-mode capture

Currently we walk files. Add a `--block-mode` flag that captures the entire device or partition as a sparse stream of chunks, including filesystem internals. This is mandatory for proper bare-metal restore (Phase 3).

In `lazarus-core/src/chunking/block_device.rs`:

```rust
pub struct BlockDeviceReader { /* ... */ }

impl BlockDeviceReader {
    pub fn open(device: &Path) -> Result<Self>; // O_DIRECT where available
    pub fn used_extents(&self) -> Result<Vec<Extent>>; // FIEMAP / ext4 / btrfs / xfs
    pub fn read_extent(&mut self, extent: &Extent) -> Result<Vec<u8>>;
}
```

Use `FS_IOC_FIEMAP` to enumerate only allocated extents — never back up holes in sparse files or unused filesystem blocks. This makes a 1TB filesystem with 100GB used cost ~100GB of backup, not 1TB.

**Acceptance:** Block-mode backup of a 100GB partition with 10GB used produces a repo no larger than 11GB after compression.

### 2.6 Restore correctness and block-mode restore

Snapshot-backed file backups must run application hooks only around point-in-time
snapshot creation: pre hook, create snapshot/consistent mount, post hook, capture
from the snapshot mount, release the snapshot. Snapshot release is best-effort and
must still run if capture fails. If snapshot creation fails after pre hooks ran,
post hooks still run so applications are thawed/unlocked.

When `--consistent --snapshotter none` is used, there is no OS snapshot. Hooks
therefore bracket the actual capture: pre hook, capture from the original source,
post hook. Operators should expect database locks or paused containers to last for
the full backup duration in this mode.

Block-mode backups store a typed extent manifest: original device size, allocated
extent offsets/lengths, and ordered chunk hashes with offsets relative to each
extent. Restore can recreate either a sparse image at `--destination` or write to
an existing raw target via `--device`; holes between allocated extents are left
sparse/zero-filled rather than written as data.

---

## Phase 3 — Bare-metal capture

**Goal:** capture *everything needed to rebuild a bootable machine*, not just files. Partition table, bootloader, EFI system partition, LVM/RAID layout, network config, kernel and initramfs. After this phase, a Lazarus repository contains all the information to reconstruct the source machine on a blank disk.

### 3.1 System fingerprint capture

New CLI subcommand: `lazarus-cli system-snapshot`. New module `lazarus-recovery/src/capture/system.rs`. Captures:

- Hostname, FQDN, machine-id (`/etc/machine-id`)
- Kernel version, distribution, init system
- CPU topology, memory size (informational, for HIR compatibility check)
- All block devices: model, serial, size, by-id paths
- Partition tables (GPT and MBR via `sgdisk --backup` and `sfdisk --dump`)
- LVM metadata: `vgcfgbackup`
- mdadm RAID config: `/etc/mdadm/mdadm.conf` and `mdadm --detail --scan`
- Filesystem types and UUIDs per partition (`blkid`)
- `/etc/fstab`, `/etc/crypttab`
- Network configuration: NetworkManager profiles, systemd-networkd, `/etc/network/interfaces`, MAC addresses, routing table
- Installed packages: `dpkg --get-selections` or `rpm -qa` or `pacman -Qq`
- Bootloader: `/boot/grub/grub.cfg`, `/boot/efi/`, `/etc/default/grub`, `efibootmgr -v`
- systemd unit enablement state: `systemctl list-unit-files --state=enabled`
- Users and groups: `/etc/passwd`, `/etc/shadow`, `/etc/group` (these are sensitive — encrypt with metadata key)
- SSH host keys: `/etc/ssh/ssh_host_*`

Output: a structured `SystemFingerprint` JSON document, encrypted, stored as a special chunk type in the repo, indexed by snapshot ID.

```rust
#[derive(Serialize, Deserialize)]
pub struct SystemFingerprint {
    pub version: u32,
    pub captured_at: u64,
    pub hostname: String,
    pub kernel: KernelInfo,
    pub disks: Vec<DiskLayout>,
    pub lvm: Option<LvmConfig>,
    pub mdadm: Option<MdadmConfig>,
    pub network: NetworkConfig,
    pub bootloader: BootloaderConfig,
    pub packages: PackageManifest,
    // ... etc
}
```

**Acceptance:** Snapshot a Linux VM, dump the fingerprint, manually verify it contains enough information to reconstruct the system without referring to the original machine.

### 3.2 Bootloader and ESP capture

New module `lazarus-recovery/src/capture/bootloader.rs`. Specific handling:

- For UEFI: full byte-exact capture of `/boot/efi` partition contents
- For BIOS: capture MBR boot code (first 446 bytes of disk) and `/boot/grub/`
- Secure Boot keys: dump `/etc/secureboot/`, `MOK` certificates if present
- Kernel + initramfs from `/boot/`

These are tracked separately from regular file backups so restore knows to put them back in the right place with the right permissions.

### 3.3 Disk layout serialization

New module `lazarus-recovery/src/capture/disk_layout.rs`.

```rust
#[derive(Serialize, Deserialize)]
pub struct DiskLayout {
    pub device: String,         // /dev/sda
    pub by_id: String,           // /dev/disk/by-id/...
    pub model: String,
    pub serial: String,
    pub size_bytes: u64,
    pub partition_table: PartitionTable,
}

#[derive(Serialize, Deserialize)]
pub enum PartitionTable {
    Gpt { partitions: Vec<GptPartition>, raw_dump: Vec<u8> /* sgdisk --backup */ },
    Mbr { partitions: Vec<MbrPartition>, raw_dump: Vec<u8> /* sfdisk --dump */ },
}
```

Restore uses `raw_dump` for byte-exact recreation when the target disk is the same size or larger. The structured representation is for the case where the operator is restoring to a different-size disk and needs partition resizing (Phase 5).

**Acceptance:** Capture, restore to a blank disk, boot the result. Hostname, IP, package set, all match.

---

## Phase 4 — Recovery environment

**Goal:** A bootable Lazarus recovery image that an operator can put on a USB stick or PXE-boot, that brings up enough hardware to reach the repository, and walks through restore. The current `build_recovery_iso.sh` is a starting point but needs real depth.

### 4.1 Real ISO builder

Implement `lazarus-recovery/src/boot/iso_builder.rs`. Replace the shell script with a proper Rust builder that:

- Pulls Alpine minirootfs (configurable to other base distros)
- Bundles the `lazarus-recovery` binary, `cryptsetup`, `lvm2`, `mdadm`, `parted`, `sgdisk`, `e2fsprogs`, `xfsprogs`, `btrfs-progs`, `zfs` if available, `dosfstools`, `efibootmgr`, `grub`, `nbd`, `iproute2`, `ethtool`, `wpa_supplicant`, `dhcpcd`, `curl`, `openssh-client`, `chrony`
- Bundles a *broad* set of kernel modules for storage controllers (mpt3sas, megaraid_sas, nvme, ahci, virtio_blk, virtio_scsi, hv_storvsc, vmw_pvscsi) and network drivers (e1000e, ixgbe, igb, mlx4, mlx5, virtio_net, hv_netvsc, vmxnet3)
- Generates a UEFI + BIOS hybrid ISO via `xorriso`
- Embeds a "first-boot script" that auto-launches the recovery TUI

```rust
pub struct IsoBuilder { /* ... */ }

impl IsoBuilder {
    pub fn new() -> Self;
    pub fn base_image(self, image: BaseImage) -> Self;
    pub fn extra_modules(self, modules: Vec<String>) -> Self;
    pub fn extra_packages(self, packages: Vec<String>) -> Self;
    pub fn embed_repository_endpoint(self, endpoint: &str) -> Self; // optional pre-config
    pub fn build(self, output: &Path) -> Result<()>;
}
```

**Acceptance:** `cargo run -p lazarus-recovery -- build-iso --output recovery.iso`. Boot the ISO in QEMU, confirm TUI launches and can see virtio storage and network.

### 4.2 USB writer

`lazarus-recovery/src/boot/usb.rs` — wrap `dd` with proper safety: enumerate removable devices, refuse to write to anything that mounts a system path, prompt for confirmation with the device serial.

### 4.3 PXE bootstrap

`lazarus-recovery/src/boot/pxe.rs` — generate a PXE config (pxelinux.cfg or iPXE script), TFTP-servable kernel + initrd extracted from the ISO. Document the DHCP options needed.

### 4.4 Recovery TUI hardening

The existing `lazarus-recovery/src/main.rs` is OK as a starting point but needs:

- Network config wizard before repository connection (DHCP, static, WiFi)
- Storage backend selection that actually works for S3/SSH (currently the strings exist but the flow doesn't wire credentials)
- Disk detection and selection for restore target
- Pre-restore plan display: "This will wipe /dev/sda (Samsung SSD 970, 500GB), recreate partitions per snapshot fingerprint, restore 247GB. Continue?"
- Restore progress with rate, ETA, current chunk
- Post-restore actions: install bootloader, regenerate initramfs, prompt to reboot

Use the existing `ratatui` setup. Pull the orchestration into `lazarus-recovery/src/restore/engine.rs` (already exists, extend it).

---

## Phase 5 — Hardware-Independent Restore (HIR)

**Goal:** The killer feature. Restore a snapshot from machine A onto machine B with completely different hardware, and have it boot. This is what Veeam built an empire on. We do it in the open.

### 5.1 Hardware detection

`lazarus-recovery/src/hardware/detection.rs`:

```rust
pub struct HardwareInventory {
    pub cpu: CpuInfo,         // /proc/cpuinfo
    pub memory_bytes: u64,
    pub storage_controllers: Vec<PciDevice>,
    pub network_controllers: Vec<PciDevice>,
    pub display_controllers: Vec<PciDevice>,
    pub usb_devices: Vec<UsbDevice>,
    pub firmware: FirmwareInfo, // dmidecode -t bios
}

pub fn detect_current() -> Result<HardwareInventory>;
```

Parse `/sys/bus/pci/devices/*` directly rather than shelling to `lspci`. Read `vendor`, `device`, `class`, `subsystem_vendor`, `subsystem_device`. Map class codes to "storage", "network", etc.

### 5.2 Driver compatibility database

`lazarus-recovery/src/hardware/compatibility.rs`. Bundled compressed JSON mapping `(vendor_id, device_id) -> kernel_module_name`. Source from upstream `pci.ids` plus the kernel modules.alias file (parsed from a stock Alpine kernel build).

```rust
pub struct DriverDatabase { /* ... */ }

impl DriverDatabase {
    pub fn load_bundled() -> Result<Self>;
    pub fn module_for(&self, device: &PciDevice) -> Option<&str>;
    pub fn modules_for_inventory(&self, inv: &HardwareInventory) -> Vec<String>;
}
```

### 5.3 Initramfs regeneration

`lazarus-recovery/src/hardware/drivers.rs`. After file restore but before reboot:

1. `chroot` into the restored root
2. Detect distro (`/etc/os-release`)
3. Inject required modules into the initramfs config:
   - Debian/Ubuntu: append to `/etc/initramfs-tools/modules`, run `update-initramfs -u`
   - RHEL/Fedora: edit `/etc/dracut.conf.d/lazarus.conf`, run `dracut --force`
   - Arch: edit `/etc/mkinitcpio.conf`, run `mkinitcpio -P`
4. Verify the new initramfs contains the modules: `lsinitrd | grep <module>`

### 5.4 Bootloader rewrite

`lazarus-recovery/src/restore/bare_metal.rs`. After file restore:

1. Detect target boot mode (UEFI vs BIOS) from firmware
2. UEFI: `efibootmgr --create --disk /dev/<target> --part <esp_part> --loader '\EFI\<distro>\shimx64.efi' --label "<distro> (Lazarus restored)"`
3. BIOS: `grub-install --target=i386-pc /dev/<target>`, `update-grub`
4. Update `/boot/grub/grub.cfg` if root device path changed (UUIDs should make this unnecessary, but verify)

### 5.5 UUID and identifier rewriting

When the target disk has a different size or device path, partition UUIDs may legitimately match (we restore from raw dump) but if the operator chose a *different* layout (e.g., consolidated partitions on a smaller disk), we need to:

- Rewrite `/etc/fstab` with new UUIDs
- Rewrite `/etc/crypttab` similarly
- Rewrite GRUB config root references
- Update `/etc/mdadm/mdadm.conf` array UUIDs

Build a `UuidRewriter` that scans the restored filesystem for any reference to old UUIDs and substitutes new ones, with confirmation.

### 5.6 Network adapter renaming

systemd's `predictable network interface names` mean `enp0s3` on the source becomes `enp0s4` on the target (or `eth0` if firmware reports differently). Without remediation, the restored system boots without networking.

`lazarus-recovery/src/restore/bare_metal.rs::fix_network()`:

1. Read source's `NetworkConfig` from fingerprint
2. Read target's detected NICs
3. If MACs match: write a `/etc/systemd/network/10-lazarus-restore.link` file pinning the old name to the new MAC
4. If MACs don't match (HIR case): present a TUI mapping screen ("Source had eth0 (192.168.1.10), target has enp0s31f6 — apply config to this interface?")
5. Rewrite NetworkManager / netplan / interfaces files with the chosen mapping

**Acceptance:** Snapshot Ubuntu 22.04 VM in VirtualBox with virtio NIC. Restore into KVM with e1000 NIC. Restored VM boots, has network, hostname is correct.

---

## Phase 6 — Instant restore

**Goal:** A 5TB database doesn't have time to wait for a 5TB restore. We want the restored VM to be **booting in 60 seconds** while the data hydrates in the background.

### 6.1 FUSE-mounted snapshot

`lazarus-recovery/src/restore/instant.rs`. Use `fuser` crate (or `polyfuse`) to expose a snapshot as a read-only filesystem. When the kernel reads a block, we fetch the chunk on demand from the repository, cache it locally, and return it.

```rust
pub struct InstantMount { /* ... */ }

impl InstantMount {
    pub async fn mount(snapshot: SnapshotId, mountpoint: &Path) -> Result<Self>;
    pub fn cache_dir(&self) -> &Path;
    pub fn unmount(self) -> Result<()>;
}
```

### 6.2 NBD server for VM instant boot

`lazarus-recovery/src/restore/instant.rs::serve_nbd()`. Implement the NBD protocol so a hypervisor can boot a VM directly off the snapshot, with reads going through Lazarus to the repo. The hypervisor's copy-on-write layer captures changes locally; nightly/weekly we reverse-merge into a permanent restore.

### 6.3 Background hydration

While the FUSE/NBD mount is serving live reads, a background task pre-fetches all chunks into the local cache, prioritized by:

1. Files referenced in the restored system's `/boot` and root filesystem core paths
2. Files matching access patterns recorded during the most recent backup (collect this in Phase 1.2 block tracker)
3. Everything else, in chunk-order for sequential disk efficiency

### 6.4 Application-level instant restore

`lazarus-recovery/src/restore/app_level.rs`. Database-aware restore: instead of restoring a full filesystem, restore a single PostgreSQL database into a running cluster, or a single MySQL table. Uses application freeze/thaw hooks from Phase 2.3 in reverse.

**Acceptance:** Time-to-shell on a 100GB restore should be under 90 seconds. Add `tests/instant_restore_timing.rs`.

---

## Phase 7 — Immutability and air-gap

**Goal:** Survive ransomware that compromises the backup admin account. Survive insider threat. Survive a flat-out destruction attempt against the repo.

### 7.1 WORM mode

Repository config gains a `retention_lock` mode:

```toml
[retention]
mode = "compliance"       # or "governance"
min_retention_days = 30
```

In `compliance` mode, no operation — not even `prune`, not even with the master password, not even `rm` from the OS — can delete a chunk before its retention expires. Implementation:

- For S3 backend: enable Object Lock with retention period equal to snapshot retention
- For local backend: set `chattr +i` on chunk files (Linux immutable bit), require root + reboot to clear
- For SSH backend: enforce server-side via a Lazarus-aware sftp-server replacement (out of scope this phase, document as future)

Add `lazarus-cli security retention --mode compliance --min-days 30`.

### 7.2 Append-only repository mode

A separate mode where the repo accepts new snapshots but rejects any operation that would modify existing data. Catches a compromised backup-client trying to nuke history before encrypting the source.

### 7.3 Pull-based backup architecture

Currently the agent pushes data to storage. Add a mode where the agent runs no inbound port and the *server* initiates the connection. If the agent host is compromised, the attacker still can't reach the server to issue malicious prune commands.

In `lazarus-server/src/agent_manager.rs`: long-lived connection initiated by agent, mTLS-pinned, server-issued job tokens.

### 7.4 Air-gap rotation

A scheduler that mounts an external backup target (USB drive, tape library, separate server) only during the backup window, then unmounts and disconnects. Combined with WORM mode, this is the strongest defense available.

`lazarus-cli airgap schedule --target /mnt/backup-vault --window "Sun 02:00-04:00"`.

### 7.5 Cryptographic timestamping

For compliance use cases (HIPAA, financial), each snapshot's Merkle root gets timestamped against an RFC 3161 TSA. Proves the snapshot existed at a given time and hasn't been backdated.

**Acceptance:** Run `chattr -i` on a chunk file under compliance mode, attempt deletion: must fail with a clear error. Run `lazarus-cli prune` with retention policy active: existing snapshots within the retention window must remain.

---

## Phase 8 — Distributed and erasure-coded storage

**Goal:** Survive the loss of an entire backup site.

### 8.1 Reed-Solomon erasure coding

`lazarus-core/src/storage/erasure.rs`. Split each chunk into `K` data shards plus `M` parity shards. Distribute shards across `K+M` storage backends. Lose any `M` and the chunk is still recoverable.

Use the `reed-solomon-erasure` crate (already in the Rust ecosystem and audited).

### 8.2 Multi-target replication

`lazarus-core/src/storage/distributed.rs`. A `DistributedBackend` wraps multiple `StorageBackend` implementations and writes each chunk to all of them (or a quorum, configurable). Reads fall through to the first available.

```toml
[storage]
mode = "replicated"
quorum = 2

[[storage.targets]]
name = "primary-s3"
backend = "s3"
bucket = "lazarus-primary"
region = "us-east-1"

[[storage.targets]]
name = "secondary-b2"
backend = "s3"   # B2 has S3-compatible API
endpoint = "s3.us-west-002.backblazeb2.com"

[[storage.targets]]
name = "local-nas"
backend = "ssh"
host = "nas.lan"
path = "/volume1/lazarus"
```

### 8.3 Chunk health tracking

The catalog grows a `ChunkHealth` table tracking last-verified timestamp and per-target availability. A background scrubber (`lazarus-cli scrub`) re-reads chunks on rotation, flags any whose hash doesn't match, triggers re-replication from healthy copies.

**Acceptance:** Configure replicated storage with three targets. Delete all chunks from one target. Scrub reports the missing chunks and re-replicates them. Restore continues to work throughout.

---

## Phase 9 — Productionization

**Goal:** Make Lazarus pleasant to operate at scale.

### 9.1 Observability

- Prometheus metrics endpoint on the agent and server (`/metrics`)
- Per-snapshot duration, throughput, dedup ratio, compression ratio, error counts
- OpenTelemetry tracing spans for backup/restore pipelines
- Structured JSON logging via `tracing` + `tracing-subscriber`

### 9.2 Output formatters

`lazarus-cli/src/output/formatter.rs` and `output/json.rs`. Make every CLI command support `--format json` for scripting.

### 9.3 Interactive wizard

`lazarus-cli/src/interactive/wizard.rs`. First-time setup wizard: detect environment, suggest storage backend, generate secure passwords, set up retention policy, schedule first backup. The "make this not scary" feature.

### 9.4 Repo migration tools

`lazarus-cli repo migrate --from <old> --to <new>` for moving between storage backends. `lazarus-cli repo upgrade` for repo format version bumps.

### 9.5 Documentation

`docs/` with:
- Quickstart (15-min path to first backup + first restore)
- Bare-metal restore runbook (the headline scenario)
- HIR runbook (different hardware)
- Security model (threat model, what we defend against, what we don't)
- Operations guide (monitoring, alerting, troubleshooting)
- Architecture deep-dive (for contributors)

---

## Testing strategy (cross-cutting)

Every phase ships with tests. Specifically:

1. **Unit tests** colocated with source.
2. **Integration tests** in `<crate>/tests/` that round-trip through real tempdir repositories.
3. **End-to-end tests** in `tests/e2e/` using QEMU: spin up a VM, backup it, destroy it, restore it on a fresh disk, verify it boots and matches.
4. **Chaos tests** in `tests/chaos/`: corrupt random chunks, kill the backup process mid-snapshot, fill the disk during backup, simulate network partitions.
5. **Regression corpus**: every bug fix adds a test that fails on the bad code and passes on the fix. No exceptions.

Tests must run under `cargo test` with no special setup beyond what's in `scripts/test-setup.sh` (which the agent should create — installs LVM tools, FUSE, etc., on the CI runner).

---

## Non-goals (explicitly out of scope)

- **Windows agent.** We will design APIs that don't preclude it, but no Windows code in this build. VSS, NTFS USN journal, BCD editing — separate future project.
- **macOS agent.** Same reasoning.
- **GUI.** TUI is enough. A web UI is a 12-month project of its own.
- **Cloud orchestration.** Kubernetes operators, Terraform providers, etc. Later.
- **Full filesystem implementation.** We piggyback on existing filesystems (ext4, xfs, btrfs, zfs). No bespoke FS work.

---

## Working agreement with the operator (Bryan)

- Open a draft PR per phase. Do not bundle phases.
- Each PR description includes: what shipped, what was deferred and why, test results, manual-testing notes, any breaking changes.
- After Phase 1 and Phase 5, request a hands-on testing pass on real hardware before merging — these are the points where bare-metal-correctness has to be empirically verified, not just unit-tested.
- License stays MIT. Any added dependency must be MIT, Apache-2.0, BSD, or MPL-2.0. No GPL/AGPL pulled into the core crates (it would block commercial dual-licensing if we ever go that route).
- Do not add telemetry, opt-in analytics, "phone home" behavior, or third-party SaaS dependencies. This is sovereign-storage software; it never talks to anything the operator didn't configure.
- When in doubt about scope, ask. When in doubt about correctness, write a test. When in doubt about security, fail closed.

---

## Begin with Phase 1.1.

Open a working branch `phase-1-foundations`. Read the existing code in `lazarus-core/src/snapshot/`, `lazarus-core/src/catalog/index.rs`, `lazarus-cli/src/commands/backup.rs`, and `lazarus-cli/src/commands/prune.rs` before writing a line of new code. Confirm your understanding of the existing chunk-write path, then implement `DedupTable` per 1.1 above. Run the full test suite before opening the PR.

Good luck. Build it like the world is going to depend on it — because for whoever uses Lazarus to bring their company back from the dead, it will.
