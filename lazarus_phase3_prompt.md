# Lazarus — Phase 3: Bare-Metal Capture (Coding Agent Prompt)

You are a senior Rust systems engineer working on **Lazarus**, the open-source bare-metal-and-HIR backup tool. Phases 1 (foundation hardening) and 2 (block-level snapshotting, hooks, block-mode capture + block-mode restore with manifest v2) are complete. Next: **Phase 3 — Bare-Metal Capture**.

The resurrection contract: a Lazarus repository must contain *everything* needed to reconstruct the source machine on a blank disk on potentially different hardware. Today the repo holds file contents and (with `--block-mode`) raw block streams with per-chunk extent/offset manifests. Missing: the *recipe* for rebuilding the system — partition tables, bootloader bytes, LVM/RAID metadata, network config, package manifest, kernel/initramfs, user database.

Branch `phase-3-bare-metal-capture`. No phase bundling. PR description: what shipped, what was deferred, test output, manual-test notes, breaking changes.

---

## Existing code to integrate with

- `lazarus-core/src/catalog/index.rs` — `CatalogIndex`, `ObjectType { File=0, Directory=1, BlockDevice=2 }`, `ObjectMetadata`, `create_object`, `create_snapshot`, `get_object`. Add `ObjectType::SystemFingerprint = 3`, update the integer match arm.
- `lazarus-core/src/catalog/metadata.rs` — **sidecar** `SnapshotMetadata { tags, description, retention_days, source, hostname }` (not the catalog's per-snapshot encrypted blob). Persists as `<repo>/snapshot_metadata.json`, file-level `METADATA_VERSION = 1`, current loader errors on version mismatch. Extend struct, convert loader to accept v1+v2.
- `lazarus-core/src/encryption/key_manager.rs` — `KeyManager::encrypt_data(&[u8])` and `encrypt_metadata(&str)` both return `(ciphertext, nonce)`. Add `encrypt_metadata_bytes(&[u8])` / `decrypt_metadata_bytes` for bincode blobs.
- `lazarus-core/src/storage/backend.rs` — `StorageBackend::put(key, data) / get / list / delete / write_once / set_retention_lock`. Chunks keyed by hex BLAKE3 of plaintext; stored layout `nonce || ciphertext`.
- `lazarus-core/src/snapshot/dedup.rs` — `DedupTable::add_reference(&[u8;32], &snapshot_id)`. Fingerprint and sensitive-blob chunks register here so prune respects them.
- `lazarus-cli/src/commands/backup.rs` (1358 lines). `BackupArgs` has `source, repository, password, force, consistent, snapshotter, block_mode, device, no_hooks, hook_templates`. Block-mode object-metadata JSON carries `manifest_version: 2`; `record_block_chunk_manifest` runs per chunk. Add `--capture-system` / `--capture-system-only`; existing block path untouched.
- `lazarus-cli/src/commands/restore.rs` (675 lines), block-mode restore via `restore_block_device` + `ensure_block_manifest_v2`. **Phase 3 does NOT touch restore.** Add `// TODO(phase-4-5)` markers where fingerprint consumption hooks in.

Match existing style/errors. Use `Result<T>` from `lazarus_core::error`. `#[serde(default)]` over breaking changes.

---

## Principles

- **Linux-first, gated explicitly.** Collectors `#[cfg(target_os = "linux")]`. Non-Linux stub returns `LazarusError::Storage("capture is Linux-only".into())`. Public types stay portable.
- **Graceful degradation.** Missing tool / privilege / config → emit `CaptureWarning`, continue. Fingerprint records its own completeness.
- **Fail loud on must-haves.** Detected GPT but couldn't dump it → error. A silently missing partition table is a foot-loaded shotgun.
- **Encrypted at rest.** AEAD pipeline. Sensitive subset uses the metadata key.
- **Forward-compatible.** `SystemFingerprint::version: u32`. 8-byte magic+version header inside AEAD plaintext.
- **No `unwrap()` outside `#[cfg(test)]`.**
- **Shell-outs via `tokio::process::Command` with timeouts.** 30s default, 5 min for `dpkg-query`/`rpm -qa`. Stream stdout for large outputs.
- **No telemetry, phone-home, or SaaS.**

---

## Cargo additions

`lazarus-recovery/Cargo.toml`:

```toml
[dependencies]
lazarus-core = { path = "../lazarus-core" }
lazarus-common = { path = "../lazarus-common" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
bincode = { version = "2", features = ["serde"] }
blake3 = "1"
tokio = { workspace = true, features = ["fs", "process", "time", "macros", "rt-multi-thread", "io-util"] }
tracing = "0.1"
thiserror = "1"
anyhow = "1"
hex = "0.4"
sysinfo = "0.30"
nix = { version = "0.27", features = ["fs", "mount", "ioctl"] }
uuid = { version = "1", features = ["v4", "serde"] }

[target.'cfg(target_os = "linux")'.dependencies]
procfs = "0.16"
```

All licenses MIT / Apache-2.0 / BSD / MPL-2.0.

## Module tree

```
lazarus-recovery/src/capture/
├── mod.rs              # capture_system(), CaptureOpts, CaptureReport, FingerprintPersister
├── system.rs           # SystemFingerprint, KernelInfo, CpuInfo, FirmwareInfo, orchestrator
├── disk_layout.rs      # DiskLayout, PartitionTable, GptPartition, MbrPartition
├── bootloader.rs       # BootloaderConfig, UEFI/BIOS, ESP archive, kernel files
├── network.rs          # NetworkConfig + NetworkInterface + RouteEntry + DnsConfig
├── packages.rs         # PackageManifest: dpkg/rpm/pacman/apk
├── users.rs            # UserDatabaseRef + UserDatabaseBlob (metadata-key encrypted)
├── secrets.rs          # SshHostKeysRef + SshHostKeysBlob, MOK, secureboot
├── lvm.rs              # LvmConfig: vgcfgbackup + structured PV/VG/LV
├── mdadm.rs            # MdadmConfig
├── persist.rs          # FingerprintPersister
└── tests/fixtures/     # sample sgdisk/sfdisk dumps, sample fstabs
```

Wire `pub mod capture;` into `lazarus-recovery/src/lib.rs` (create if absent) so `lazarus_recovery::capture::*` is importable. Add `lazarus-cli/src/commands/system_snapshot.rs`, register in `commands/mod.rs` and `main.rs` clap router.

---

## Type specs

### `capture/system.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemFingerprint {
    pub version: u32,                       // starts at 1
    pub captured_at_epoch_s: u64,
    pub captured_by: String,
    pub hostname: String,
    pub fqdn: Option<String>,
    pub machine_id: Option<String>,
    pub kernel: KernelInfo,
    pub cpu: CpuInfo,
    pub memory_bytes: u64,
    pub disks: Vec<DiskLayout>,
    pub lvm: Option<LvmConfig>,
    pub mdadm: Option<MdadmConfig>,
    pub filesystems: Vec<FilesystemInfo>,
    pub fstab: String,
    pub crypttab: Option<String>,
    pub network: NetworkConfig,
    pub bootloader: BootloaderConfig,
    pub packages: PackageManifest,
    pub services: Vec<EnabledService>,
    pub users: UserDatabaseRef,
    pub ssh_host_keys: SshHostKeysRef,
    pub firmware: FirmwareInfo,
    pub warnings: Vec<CaptureWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelInfo {
    pub release: String, pub version: String, pub arch: String,
    pub cmdline: String, pub distro_id: String, pub distro_version: String,
    pub init_system: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub vendor: String, pub model: String,
    pub physical_cores: u32, pub logical_cores: u32,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemInfo {
    pub device: String, pub mountpoint: Option<String>, pub fstype: String,
    pub uuid: Option<String>, pub label: Option<String>, pub options: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareInfo {
    pub vendor: Option<String>, pub version: Option<String>, pub release_date: Option<String>,
    pub uefi: bool, pub secure_boot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnabledService { pub name: String, pub state: String }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureWarning {
    pub component: String, pub message: String, pub remediation: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CaptureOpts {
    pub include_lvm: bool, pub include_mdadm: bool, pub include_network: bool,
    pub include_packages: bool, pub include_users: bool, pub include_ssh_keys: bool,
    pub include_bootloader: bool,
    pub tool_timeout: std::time::Duration,
}
// Default: every include_* = true, tool_timeout = 30s.

pub struct CaptureReport { pub fingerprint: SystemFingerprint, pub elapsed: std::time::Duration }

#[cfg(target_os = "linux")]
pub async fn capture_system(opts: &CaptureOpts, persister: &FingerprintPersister<'_>)
    -> lazarus_core::error::Result<CaptureReport>;

#[cfg(not(target_os = "linux"))]
pub async fn capture_system(_opts: &CaptureOpts, _persister: &FingerprintPersister<'_>)
    -> lazarus_core::error::Result<CaptureReport>
{ Err(lazarus_core::error::LazarusError::Storage("system fingerprint capture is Linux-only".into())) }
```

Orchestrator uses `tokio::join!` for independent collectors. Sensitive blobs persist via the passed `FingerprintPersister` (metadata key); only their `*Ref` (hash + counts) embed in the fingerprint.

### `capture/disk_layout.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskLayout {
    pub device: String,
    pub by_id: Option<String>, pub by_path: Option<String>,
    pub model: String, pub serial: String,
    pub size_bytes: u64,
    pub logical_block_size: u32, pub physical_block_size: u32,
    pub rotational: bool,
    pub partition_table: PartitionTable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PartitionTable {
    Gpt { disk_guid: String, partitions: Vec<GptPartition>, raw_dump: Vec<u8> },
    Mbr { partitions: Vec<MbrPartition>, raw_dump: Vec<u8>, boot_code: [u8; 446] },
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GptPartition {
    pub number: u32, pub partition_guid: String, pub type_guid: String,
    pub name: String, pub start_lba: u64, pub end_lba: u64, pub attributes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MbrPartition {
    pub number: u32, pub partition_type: u8,
    pub start_lba: u64, pub size_lba: u64, pub bootable: bool,
}

pub async fn discover_disks(opts: &CaptureOpts) -> Result<Vec<DiskLayout>>;
```

walk `/sys/block/`, filter `loop*` / `ram*` / `dm-*`. `by_id`/`by_path` via `readlink` on `/dev/disk/by-{id,path}/*`. Model/serial from `/sys/block/<dev>/device/{model,serial}` (NVMe: `/sys/class/nvme/`), fallback `lsblk -ndo MODEL,SERIAL`. Table type by reading sector 0: `0x55AA` + protective MBR (type `0xEE`) → GPT. `sgdisk --backup=- /dev/X` for GPT raw_dump; `sfdisk --dump` for MBR. MBR `boot_code` = first 446 bytes of `/dev/X`. Missing sgdisk/sfdisk → fall back to `parted --machine print`, emit warning that `raw_dump` is empty (restore must use structured path).

**Extract parsers as pure `fn(&[u8]) -> Result<...>` so they unit-test against fixtures without OS access.**

### `capture/bootloader.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootloaderConfig {
    pub mode: BootMode,
    pub uefi: Option<UefiConfig>,
    pub bios: Option<BiosConfig>,
    pub kernel_files: Vec<KernelFileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BootMode { Uefi, Bios, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UefiConfig {
    pub esp_device: String, pub esp_uuid: String, pub esp_size_bytes: u64,
    pub esp_archive_chunk: String,        // hex BLAKE3 of tar(/boot/efi)
    pub efibootmgr_dump: String,
    pub secure_boot_state: String,
    pub mok_certificates_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiosConfig {
    pub mbr_boot_code: [u8; 446],
    pub grub_cfg: Option<String>,
    pub default_grub: Option<String>,
    pub grub_d_files: Vec<NamedBlob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelFileEntry {
    pub path: String, pub size: u64, pub chunk: String,    // hex BLAKE3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedBlob { pub name: String, pub content: Vec<u8> }

pub async fn capture_bootloader(opts: &CaptureOpts, persister: &FingerprintPersister<'_>)
    -> Result<BootloaderConfig>;
```

UEFI detected via `/sys/firmware/efi/`. Secure Boot state from `/sys/firmware/efi/efivars/SecureBoot-*` (byte 4 = state). ESP archive: `tar -C /boot/efi -cf -` → bytes → `persister.persist_blob_data_key(&bytes)` → hex hash. MBR boot code: 446 bytes from disk holding root (resolve via `/proc/cmdline` `root=` or `findmnt -no SOURCE /` then `lsblk -no PKNAME`). Kernel files: enumerate `/boot/vmlinuz*`, `/boot/initramfs-*`, `/boot/initrd*`, `/boot/System.map-*`; each → `persist_blob_data_key`; record hex hash.

### `capture/network.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub hostname: String,
    pub interfaces: Vec<NetworkInterface>,
    pub routes: Vec<RouteEntry>,
    pub dns: DnsConfig,
    pub networkmanager_profiles: Vec<NamedBlob>,
    pub systemd_networkd_files: Vec<NamedBlob>,
    pub etc_network_interfaces: Option<String>,
    pub netplan_yaml_files: Vec<NamedBlob>,
    pub resolv_conf: Option<String>,
    pub hosts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String, pub mac: String, pub kind: String,
    pub pci_address: Option<String>, pub driver: Option<String>,
    pub ipv4_addresses: Vec<String>, pub ipv6_addresses: Vec<String>,
    pub mtu: u32, pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry { pub dst: String, pub gw: Option<String>, pub dev: String, pub metric: Option<u32>, pub family: u8 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig { pub nameservers: Vec<String>, pub search: Vec<String> }
```

`/sys/class/net/<iface>/` for MAC/MTU/operstate; driver via `/sys/class/net/<iface>/device/driver/` symlink. Addresses/routes from `ip -j addr` / `ip -j route show` (JSON), fallback to `getifaddrs` via `nix`. Profile dirs → `Vec<NamedBlob>`; skip files > 1 MiB and warn.

### `capture/packages.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub manager: PackageManager,
    pub packages: Vec<PackageEntry>,
    pub repositories: Vec<NamedBlob>,
    pub manual_install_marks: Option<String>,
    pub raw_dump: NamedBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackageManager { Dpkg, Rpm, Pacman, Apk, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageEntry {
    pub name: String, pub version: String,
    pub architecture: Option<String>, pub state: String,
}
```

Detect via `which`. dpkg: `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'`. rpm: `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\tinstalled\n'`. pacman: `pacman -Qq` + `pacman -Qm`. apk: `apk info -v`. Stream stdout line-by-line via `Command::stdout(Stdio::piped()) + BufReader::lines()`. 5-minute timeout default.

### `capture/users.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDatabaseRef {
    pub blob_chunk: String,         // hex BLAKE3, metadata-key encrypted
    pub user_count: u32, pub group_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UserDatabaseBlob {
    pub passwd: String, pub shadow: String, pub group: String,
    pub gshadow: Option<String>, pub sudoers: Option<String>,
    pub sudoers_d: Vec<NamedBlob>,
}

pub async fn capture_users(opts: &CaptureOpts) -> Result<(UserDatabaseBlob, u32, u32)>;
```

Orchestrator computes blob, persists via `persister.persist_blob_metadata_key(&blob)`, embeds `UserDatabaseRef` (hash + counts only). Shadow unreadable → emit warning, store empty shadow with marker line `# LAZARUS_PHASE3: shadow unavailable, capture ran without root`.

### `capture/secrets.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshHostKeysRef { pub blob_chunk: String, pub algorithms: Vec<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SshHostKeysBlob {
    pub keys: Vec<NamedBlob>,                // /etc/ssh/ssh_host_*_key{,.pub}
    pub sshd_config: Option<String>,
    pub secureboot_dir: Vec<NamedBlob>,
    pub mok_dir: Vec<NamedBlob>,
}
```

Same metadata-key persistence pattern as users.rs.

### `capture/lvm.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LvmConfig {
    pub vg_backups: Vec<VgBackup>,
    pub pvs: Vec<PhysicalVolume>, pub vgs: Vec<VolumeGroup>, pub lvs: Vec<LogicalVolume>,
    pub etc_lvm: Vec<NamedBlob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VgBackup { pub vg_name: String, pub backup: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalVolume { pub device: String, pub vg_name: String, pub uuid: String, pub size_bytes: u64 }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeGroup { pub name: String, pub uuid: String, pub extent_size_bytes: u64, pub free_extents: u64, pub total_extents: u64 }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalVolume { pub name: String, pub vg_name: String, pub uuid: String, pub size_bytes: u64, pub origin: Option<String>, pub thin_pool: Option<String> }

pub async fn capture_lvm(opts: &CaptureOpts) -> Result<Option<LvmConfig>>;
```

`pvs/vgs/lvs --reportformat json`, fallback plain text for ancient LVM. `vgcfgbackup -f - <vg>` per VG. `None` if no PVs.

### `capture/mdadm.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdadmConfig {
    pub mdadm_conf: Option<String>,
    pub detail_scan: String,
    pub arrays: Vec<MdArray>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdArray {
    pub device: String, pub uuid: String, pub level: String,
    pub component_devices: Vec<String>, pub state: String,
}
```

`None` if no `/dev/md*`.

### `capture/persist.rs`

```rust
use lazarus_core::catalog::index::CatalogIndex;
use lazarus_core::encryption::key_manager::KeyManager;
use lazarus_core::snapshot::dedup::DedupTable;
use lazarus_core::storage::backend::StorageBackend;

pub struct FingerprintPersister<'a> {
    pub backend: &'a dyn StorageBackend,
    pub keys: &'a KeyManager,
    pub catalog: &'a CatalogIndex,
    pub dedup: &'a DedupTable,
    pub snapshot_id: &'a str,
    pub dry_run: bool,    // buffers writes; deterministic hashes returned without backend.put
}

impl<'a> FingerprintPersister<'a> {
    /// data key. LZFP header + bincode(SystemFingerprint). Returns hex hash.
    pub async fn persist_fingerprint(&self, fp: &SystemFingerprint) -> Result<String>;
    /// data key. Raw bytes (ESP archive, kernel files). Returns hex hash.
    pub async fn persist_blob_data_key(&self, plaintext: &[u8]) -> Result<String>;
    /// metadata key. LZBP header + bincode(blob). Returns hex hash.
    pub async fn persist_blob_metadata_key<T: serde::Serialize>(&self, blob: &T) -> Result<String>;
    pub async fn load_fingerprint(&self, hex_hash: &str) -> Result<SystemFingerprint>;
    pub async fn load_blob_metadata_key<T: serde::de::DeserializeOwned>(&self, hex_hash: &str) -> Result<T>;
}
```

Wire format inside the AEAD plaintext for fingerprint:

```
[4 bytes magic "LZFP"] [4 bytes version le u32] [bincode v2 payload]
```

For sensitive blobs: magic `"LZBP"`, same structure. Storage key is hex BLAKE3 of the *plaintext* (header + bincode), matching existing chunk convention. Stored bytes are `nonce || ciphertext` (matches `backup_file`). Register every chunk with `DedupTable::add_reference(hash_bytes, snapshot_id)`.

---

## Catalog / metadata schema changes

### 1. `ObjectType::SystemFingerprint = 3`

In `lazarus-core/src/catalog/index.rs`:

```rust
pub enum ObjectType { File = 0, Directory = 1, BlockDevice = 2, SystemFingerprint = 3 }
```

Update integer match in `get_object` to include `3 => SystemFingerprint`. Default fallback stays `File` (forward compat on unknown ints), but log a warning via `tracing::warn!`.

A system-only snapshot's root object has type `SystemFingerprint` and no children; its encrypted metadata blob carries JSON `{ "fingerprint_chunk": "<hex>", "format_version": 1 }`. A hybrid snapshot has a normal root type and additionally a `system_fingerprint_chunk` set on the sidecar `SnapshotMetadata`.

### 2. Sidecar `SnapshotMetadata` extension

In `lazarus-core/src/catalog/metadata.rs`:

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMetadata {
    #[serde(default)] pub tags: Vec<String>,
    #[serde(default)] pub description: Option<String>,
    #[serde(default)] pub retention_days: Option<u32>,
    #[serde(default)] pub source: Option<String>,
    #[serde(default)] pub hostname: Option<String>,
    #[serde(default)] pub system_fingerprint_chunk: Option<String>,
    #[serde(default)] pub system_fingerprint_format_version: Option<u32>,
}
```

Replace `METADATA_VERSION = 1` with:

```rust
const METADATA_VERSION_CURRENT: u32 = 2;
const METADATA_VERSION_MIN_SUPPORTED: u32 = 1;
```

Loader: accept any version in `[MIN_SUPPORTED, CURRENT]`. New fields default via `#[serde(default)]`. Re-save as `CURRENT` on next write. Error above `CURRENT`. Add `tests/metadata_v1_v2_migration.rs`: write v1 file with old schema, load with new code, assert success and new fields default to `None`.

### 3. Dedup references

Every fingerprint/blob/ESP/kernel chunk registers via `DedupTable::add_reference(hash_bytes, snapshot_id)`. No new tables.

### 4. `list` enhancements

In `lazarus-cli/src/commands/list.rs`: for each snapshot, fetch root object via `catalog.get_object(root_object_id)`. Display "Kind" column with `files` / `block` / `system` / `hybrid` (hybrid = non-SystemFingerprint root + non-None `system_fingerprint_chunk` in sidecar).

---

## KeyManager additive

In `lazarus-core/src/encryption/key_manager.rs`, add:

```rust
pub fn encrypt_metadata_bytes(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
pub fn decrypt_metadata_bytes(&self, encrypted: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
```

Same metadata key as `encrypt_metadata(&str)` but accepts arbitrary bytes. Implementation mirrors `encrypt_data` with `metadata_key` instead of `repo_key`. Refactor `encrypt_metadata(&str)` to delegate to `encrypt_metadata_bytes(s.as_bytes())` for reuse. Unit test: round-trip a `Vec<u8>` containing non-UTF-8 bytes.

---

## CLI: `system-snapshot`

`lazarus-cli/src/commands/system_snapshot.rs`:

```rust
#[derive(Args)]
pub struct SystemSnapshotArgs {
    #[arg(short, long)] pub repository: String,
    #[arg(short, long)] pub password: String,
    #[arg(long)] pub tag: Option<String>,
    #[arg(long)] pub dry_run: bool,
    #[arg(long)] pub print: bool,
    #[arg(long, default_value_t = 30)] pub tool_timeout: u64,
    #[arg(long)] pub skip_packages: bool,
    #[arg(long)] pub skip_network: bool,
    #[arg(long)] pub skip_users: bool,
    #[arg(long)] pub skip_ssh: bool,
    #[arg(long)] pub skip_bootloader: bool,
    #[arg(long)] pub skip_lvm: bool,
    #[arg(long)] pub skip_mdadm: bool,
}

pub async fn run(args: SystemSnapshotArgs) -> Result<()>;
```

Flow:
1. `ConfigManager::new(&args.repository).open_repository(&args.password).await?` → `KeyManager`.
2. Open `CatalogIndex`, `DedupTable`, `LocalStorage`, `MetadataStore::open(&repo, *key_mgr.get_metadata_key())`.
3. Generate `snapshot_id` (timestamped UUID, matching existing backup.rs convention).
4. Build `FingerprintPersister { backend, keys, catalog, dedup, snapshot_id, dry_run }`.
5. Build `CaptureOpts` from flags.
6. `let CaptureReport { fingerprint, elapsed } = capture_system(&opts, &persister).await?;`.
7. `--dry-run`: print summary (counts, warnings, elapsed), exit. The persister has already buffered writes without touching the backend.
8. Else: `let fp_hash = persister.persist_fingerprint(&fingerprint).await?`.
9. Encrypt JSON `{ "fingerprint_chunk": fp_hash, "format_version": 1 }` via metadata key → `catalog.create_object(ObjectType::SystemFingerprint, &blob)` → `root_object_id`.
10. `catalog.create_snapshot(&snapshot_id, timestamp, root_object_id, &empty_snapshot_metadata_blob)`.
11. `metadata_store.put(&snapshot_id, &SnapshotMetadata { hostname, source: Some("system".into()), system_fingerprint_chunk: Some(fp_hash.clone()), system_fingerprint_format_version: Some(1), tags: args.tag.into_iter().collect(), ..Default::default() })`.
12. Print snapshot_id, fingerprint chunk hash, warnings count, elapsed. With `--print`, also dump JSON of the non-sensitive fingerprint subset to stdout.

### `backup.rs` modifications

Add to `BackupArgs`:

```rust
#[arg(long, default_value_t = true, action = ArgAction::Set)]
pub capture_system: bool,

#[arg(long, action = ArgAction::SetTrue)]
pub capture_system_only: bool,
```

- `--capture-system-only` → delegate to `system_snapshot::run` with derived args; skip file/block pipeline.
- Else, after existing file/block pipeline finishes and snapshot row is inserted: run `capture_system`, persist fingerprint, write `MetadataStore` entry's `system_fingerprint_chunk` and `system_fingerprint_format_version`. Existing block-mode `manifest_version: 2` path untouched.
- `--capture-system` set but `--source` is neither `/` nor a block device: warn "fingerprint reflects capturing host, not source tree". Proceed.

---

## Tests

Every new module gets `#[cfg(test)]` unit tests for parse/serialize functions. Plus these integration tests:

- `lazarus-recovery/tests/capture_smoke.rs` — run `capture_system` with defaults + tempdir `LocalStorage` + tempdir SQLite catalog. Assert: warnings non-fatal; hostname/kernel/distro_id non-empty; ≥1 disk; ≥1 network interface (loopback); `packages.manager != Unknown` OR explaining warning. CI runs rootless: shadow warning expected, lvm `None` expected.
- `lazarus-recovery/tests/disk_layout_parsing.rs` — pure parsers vs `tests/fixtures/` (sgdisk dump, sfdisk dump, `/sys/block/sda/*` snapshots). Assert GPT fields populated; MBR boot_code exactly 446 bytes.
- `lazarus-recovery/tests/fingerprint_versioning.rs` — synthetic v1 fingerprint → persist → reload → deep-equal (modulo `captured_at_epoch_s`). Tamper test: flip a byte in stored ciphertext, write back, assert typed error on load.
- `lazarus-recovery/tests/warnings_propagation.rs` — mock LVM detector reporting "no LVM tools"; assert Ok return, `lvm == None`, warning entry `component == "lvm"`.
- `lazarus-cli/tests/system_snapshot_round_trip.rs` — init tempdir repo, `--dry-run` then real run, capture snapshot_id, `lazarus-cli list` shows it with kind `system`. Open repo programmatically, read sidecar, load fingerprint chunk, deserialize, assert non-sensitive fields match `--print`.
- `lazarus-core/tests/metadata_v1_v2_migration.rs` — write v1 `snapshot_metadata.json` manually, load via new `MetadataStore`, assert load succeeds, new fields default to `None`, next `put` rewrites as v2.

Manual test on a Debian/Ubuntu VM with sudo: `system-snapshot --dry-run`, then real run with `--print`, then `backup --source / --capture-system`, then `list`. Include resulting `fingerprint.json` in the PR (elide hostnames/MACs of the dev host).

---

## Acceptance criteria

1. `cargo build --release` succeeds across the workspace.
2. `cargo test --workspace` passes including new tests.
3. `cargo clippy --workspace --all-targets -- -D warnings` clean.
4. `cargo fmt --check` clean.
5. `lazarus-cli system-snapshot --help` renders all flags.
6. Fresh Ubuntu 22.04 VM with root: capture completes <60s. Fingerprint contains hostname, machine-id, kernel info, all disks with partition tables + `raw_dump`, ≥1 interface with MAC and IPs, package manifest, bootloader (UEFI on UEFI VM with ESP archive hash + kernel hashes), fstab, services list.
7. Without root: capture completes, emits documented warnings for shadow, MBR boot code, `vgcfgbackup`. No panic.
8. Without LVM: `lvm == None`, single informational warning.
9. Fingerprint chunk round-trips: persist → reload → deep-equal (modulo `captured_at_epoch_s`).
10. Pre-Phase-3 repositories still open and list — `MetadataStore` handles missing new fields; `snapshot_metadata.json` v1 files migrate to v2 on next write.
11. All Phase 1/2 tests still pass — including block-mode backup/restore round-trip with manifest v2.
12. PR description states what's deferred (restore-side fingerprint consumption → Phase 4/5; Windows/macOS → non-goal; bootloader signing verification → Phase 5).

---

## Out of scope

Restore-side consumption of `SystemFingerprint` (Phase 4/5) — drop `// TODO(phase-5): consume SystemFingerprint here` markers in `lazarus-recovery/src/restore/{bare_metal,engine}.rs` and `lazarus-cli/src/commands/restore.rs` near snapshot-kind dispatch. Recovery ISO consuming fingerprints (Phase 4). PCI driver compatibility lookup (Phase 5). Windows/macOS capture — explicit non-goal. libvirt VM-level fingerprints — `TODO(phase-future)` in `capture/mod.rs`.

---

## Working agreement

One PR, one phase. Read existing code first: `catalog/{index,metadata}.rs`, `encryption/key_manager.rs`, `storage/backend.rs`, `snapshot/dedup.rs`, `commands/{backup,restore}.rs`. Match style and error handling. New deps MIT / Apache-2.0 / BSD / MPL-2.0 only. Uncertain about scope → smallest version that meets acceptance, bigger version behind `TODO(phase-future)`. Uncertain about correctness → write a test. Uncertain about security → fail closed.

Build order: `capture/mod.rs` + `capture/system.rs` types → commit + open draft PR for early review. Then `persist.rs` and catalog/metadata schema changes (these unlock everything). Then collectors in dependency order: `disk_layout` → `bootloader` → `lvm` → `mdadm` → `network` → `packages` → `users` → `secrets`. Then CLI command and `backup.rs` integration. Tests alongside each module.

The next person to use Lazarus to bring back a dead server will read whatever this phase produces under duress at 3 a.m. Build accordingly.
