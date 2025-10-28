# **Lazarus - Complete Technical Breakdown & Project Structure**

## **Project Architecture Overview**

Lazarus will use a **Cargo workspace** structure with multiple crates for modularity and code reuse. Here's the complete file structure blueprint:

```
lazarus/
├── Cargo.toml                    # Workspace root
├── README.md
├── LICENSE
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
│
├── lazarus-core/                 # Core backup engine
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── snapshot/
│       │   ├── mod.rs
│       │   ├── manager.rs       # Snapshot orchestration
│       │   ├── block_tracker.rs # Changed block tracking
│       │   └── dedup.rs         # Deduplication engine
│       ├── storage/
│       │   ├── mod.rs
│       │   ├── backend.rs       # Storage trait definition
│       │   ├── local.rs         # Local filesystem storage
│       │   ├── s3.rs           # S3-compatible storage
│       │   ├── ssh.rs          # SSH/SFTP backend
│       │   └── distributed.rs  # Multi-location storage
│       ├── compression/
│       │   ├── mod.rs
│       │   ├── zstd.rs         # Zstandard compression
│       │   └── adaptive.rs     # Adaptive compression
│       ├── encryption/
│       │   ├── mod.rs
│       │   ├── aes.rs          # AES-256 encryption
│       │   ├── key_manager.rs  # Key derivation & management
│       │   └── vault.rs        # Secure key storage
│       ├── catalog/
│       │   ├── mod.rs
│       │   ├── index.rs        # File index database
│       │   ├── metadata.rs     # Backup metadata
│       │   └── history.rs      # Backup history tracking
│       └── error.rs
│
├── lazarus-agent/                # Client agent daemon
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── daemon/
│       │   ├── mod.rs
│       │   ├── service.rs      # System service integration
│       │   ├── scheduler.rs    # Backup scheduling
│       │   └── watcher.rs      # File system monitoring
│       ├── system/
│       │   ├── mod.rs
│       │   ├── vss.rs          # Windows VSS integration
│       │   ├── lvm.rs          # Linux LVM snapshots
│       │   ├── zfs.rs          # ZFS snapshot support
│       │   └── btrfs.rs        # Btrfs snapshot support
│       ├── hooks/
│       │   ├── mod.rs
│       │   ├── pre_backup.rs   # Pre-backup scripts
│       │   ├── post_backup.rs  # Post-backup scripts
│       │   └── executor.rs     # Hook execution engine
│       ├── monitoring/
│       │   ├── mod.rs
│       │   ├── metrics.rs      # Performance metrics
│       │   ├── health.rs       # Health checks
│       │   └── alerts.rs       # Alert management
│       └── config.rs
│
├── lazarus-server/               # Central management server
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── api/
│       │   ├── mod.rs
│       │   ├── grpc/
│       │   │   ├── mod.rs
│       │   │   ├── backup.rs   # Backup service
│       │   │   ├── restore.rs  # Restore service
│       │   │   └── management.rs
│       │   └── rest/
│       │       ├── mod.rs
│       │       ├── routes.rs   # HTTP endpoints
│       │       └── handlers.rs
│       ├── orchestrator/
│       │   ├── mod.rs
│       │   ├── job_manager.rs  # Job queue & execution
│       │   ├── scheduler.rs    # Central scheduling
│       │   └── coordinator.rs  # Multi-client coordination
│       ├── storage_pool/
│       │   ├── mod.rs
│       │   ├── manager.rs      # Storage pool management
│       │   ├── balancer.rs     # Load balancing
│       │   └── replication.rs  # Data replication
│       ├── database/
│       │   ├── mod.rs
│       │   ├── schema.rs       # Database schema
│       │   ├── migrations/     # SQL migrations
│       │   └── queries.rs
│       └── auth/
│           ├── mod.rs
│           ├── authentication.rs
│           └── authorization.rs
│
├── lazarus-recovery/             # Recovery environment
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── boot/
│       │   ├── mod.rs
│       │   ├── iso_builder.rs  # Bootable ISO creation
│       │   ├── pxe.rs         # Network boot support
│       │   └── usb.rs         # USB recovery media
│       ├── restore/
│       │   ├── mod.rs
│       │   ├── bare_metal.rs  # Bare metal restoration
│       │   ├── file_level.rs  # File/folder restore
│       │   ├── app_level.rs   # Application restore
│       │   └── instant.rs     # Instant recovery mount
│       ├── hardware/
│       │   ├── mod.rs
│       │   ├── detection.rs   # Hardware detection
│       │   ├── drivers.rs     # Driver injection
│       │   └── compatibility.rs
│       └── partition/
│           ├── mod.rs
│           ├── manager.rs     # Partition management
│           └── resize.rs      # Partition resizing
│
├── lazarus-cli/                  # Command-line interface
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── commands/
│       │   ├── mod.rs
│       │   ├── backup.rs      # Backup commands
│       │   ├── restore.rs     # Restore commands
│       │   ├── verify.rs      # Verification commands
│       │   ├── list.rs        # List backups
│       │   └── config.rs      # Configuration
│       ├── interactive/
│       │   ├── mod.rs
│       │   ├── wizard.rs      # Interactive wizards
│       │   └── progress.rs    # Progress indicators
│       └── output/
│           ├── mod.rs
│           ├── formatter.rs   # Output formatting
│           └── json.rs        # JSON output
│
├── lazarus-web/                  # Web dashboard
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs
│   │   ├── server/
│   │   │   ├── mod.rs
│   │   │   ├── websocket.rs  # Real-time updates
│   │   │   └── static.rs     # Static file serving
│   │   └── handlers/
│   │       ├── mod.rs
│   │       └── dashboard.rs
│   └── static/
│       ├── index.html
│       ├── css/
│       ├── js/
│       └── assets/
│
├── lazarus-common/               # Shared types and utilities
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── types/
│       │   ├── mod.rs
│       │   ├── backup.rs     # Backup types
│       │   ├── manifest.rs   # Manifest structure
│       │   └── savefile.rs   # Savefile format
│       ├── protocol/
│       │   ├── mod.rs
│       │   ├── messages.rs   # Protocol messages
│       │   └── serialization.rs
│       ├── utils/
│       │   ├── mod.rs
│       │   ├── checksum.rs   # Checksum utilities
│       │   ├── time.rs       # Time utilities
│       │   └── size.rs       # Size calculations
│       └── constants.rs
│
├── lazarus-plugins/              # Plugin system
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── interface/
│       │   ├── mod.rs
│       │   └── traits.rs     # Plugin traits
│       ├── loader/
│       │   ├── mod.rs
│       │   └── dynamic.rs    # Dynamic loading
│       └── builtin/
│           ├── mod.rs
│           ├── docker.rs     # Docker integration
│           ├── kubernetes.rs # K8s backup
│           ├── database.rs   # Database plugins
│           └── vm.rs         # VM backup plugins
│
├── lazarus-tests/               # Integration tests
│   ├── Cargo.toml
│   └── tests/
│       ├── integration/
│       ├── performance/
│       └── disaster_recovery/
│
├── docs/
│   ├── architecture/
│   ├── api/
│   ├── user-guide/
│   └── development/
│
├── scripts/
│   ├── build.sh
│   ├── install.sh
│   └── release.sh
│
├── configs/
│   ├── lazarus.default.toml    # Default configuration
│   ├── systemd/
│   │   └── lazarus-agent.service
│   └── examples/
│
└── proto/                       # Protocol Buffer definitions
    ├── backup.proto
    ├── restore.proto
    └── common.proto
```

## **Key Module Descriptions**

### **lazarus-core**
The heart of Lazarus - contains all core backup logic:
- **Snapshot Engine**: Block-level tracking, incremental backups
- **Storage Abstraction**: Unified interface for all storage backends
- **Deduplication**: Content-defined chunking with SHA256
- **Compression**: Adaptive compression based on data type
- **Encryption**: AES-256-GCM with secure key management

### **lazarus-agent**
Lightweight client daemon that runs on each system:
- **System Integration**: VSS (Windows), LVM/ZFS/Btrfs (Linux) snapshots
- **Continuous Protection**: File system monitoring for real-time backups
- **Application Hooks**: Pre/post backup scripts for databases, services
- **Resource Management**: CPU/memory/bandwidth throttling

### **lazarus-server**
Central orchestration and management:
- **Multi-Client Management**: Handle hundreds of clients
- **Job Orchestration**: Queue management, priority scheduling
- **Storage Pool Management**: Distribute data across multiple backends
- **API Gateway**: gRPC for agents, REST for web UI

### **lazarus-recovery**
Disaster recovery tools:
- **Bootable Media Creation**: ISO/USB/PXE boot images
- **Universal Restore**: Hardware-independent restoration
- **Driver Injection**: Automatic driver detection and injection
- **Partition Management**: Resize, remap, convert partitions

### **lazarus-cli**
Power user command-line interface:
```bash
lazarus backup create --full --compress --encrypt
lazarus restore point --id abc123 --target /dev/sda
lazarus verify --latest
lazarus mount --backup-id xyz789 --path /mnt/recovery
```

### **lazarus-web**
Modern web dashboard:
- **Real-time Monitoring**: WebSocket-based live updates
- **Visual Analytics**: Storage usage, backup trends
- **Restore Wizard**: Step-by-step guided recovery
- **Job Management**: Schedule, monitor, control backups

## **Core Type Definitions**

```rust
// lazarus-common/src/types/manifest.rs
pub struct BackupManifest {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub backup_type: BackupType,
    pub parent_id: Option<Uuid>,
    pub system_info: SystemInfo,
    pub chunks: Vec<ChunkReference>,
    pub metadata: HashMap<String, Value>,
}

// lazarus-common/src/types/savefile.rs
pub struct SaveFile {
    pub header: SaveFileHeader,
    pub manifest: BackupManifest,
    pub data_blocks: Vec<DataBlock>,
    pub checksums: ChecksumMap,
}

// lazarus-core/src/storage/backend.rs
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}
```

## **Database Schema**

```sql
-- lazarus-server/src/database/schema.sql
CREATE TABLE backups (
    id UUID PRIMARY KEY,
    client_id UUID NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    type VARCHAR(20) NOT NULL,
    size_bytes BIGINT NOT NULL,
    chunks_count INTEGER NOT NULL,
    status VARCHAR(20) NOT NULL,
    metadata JSONB
);

CREATE TABLE clients (
    id UUID PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    os_type VARCHAR(50),
    last_seen TIMESTAMP,
    config JSONB
);

CREATE TABLE jobs (
    id UUID PRIMARY KEY,
    client_id UUID REFERENCES clients(id),
    type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    scheduled_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT
);
```

## **Configuration Structure**

```toml
# configs/lazarus.default.toml
[agent]
hostname = "auto"
port = 7100
schedule = "0 2 * * *"  # 2 AM daily

[storage]
primary = { type = "local", path = "/var/lazarus/storage" }
secondary = { type = "s3", bucket = "lazarus-backups", region = "us-east-1" }

[backup]
compression = "zstd"
compression_level = 3
encryption = true
deduplication = true
chunk_size = "4MB"

[retention]
daily = 7
weekly = 4
monthly = 12
yearly = 5
```
# **Lazarus - Key Technical Advantages & Unique Selling Propositions**

## **Core Technical Differentiators**

### **1. Unified Savefile Architecture**
**What makes it unique:**
- **Single-file system images** that contain complete system state (think macOS Time Machine meets PC gaming save states)
- **Mountable savefiles** - directly mount any backup as a virtual drive without full restoration
- **Atomic rollback capability** - instantly switch between system states like git branches

**Advantage over competitors:**
- **Veeam/Acronis**: Complex chain dependencies, multiple files per backup
- **Borg/Restic**: Repository-based, not portable single files
- **Our approach**: Each savefile is self-contained and portable

### **2. Adaptive Intelligence Engine**
```rust
// Smart backup decisions based on system behavior
pub struct AdaptiveEngine {
    file_priority_map: HashMap<PathBuf, Priority>,
    pattern_recognition: MachineLearning,
    performance_optimizer: ResourceManager,
}
```

**Unique capabilities:**
- **Predictive scheduling**: ML-based prediction of optimal backup windows
- **Smart chunking**: Different chunk sizes for different file types (4KB for code, 1MB for media)
- **Priority-aware backups**: Critical files backed up more frequently automatically
- **Workload-aware throttling**: Automatically adjusts resource usage based on system activity

### **3. True Hybrid Architecture**
**Revolutionary approach:**
- **Peer-to-peer backup mesh**: Clients can backup to each other, not just to server
- **Distributed deduplication**: Dedup across entire infrastructure, not just per-client
- **Edge computing model**: Process backups at edge before centralizing

**Comparison:**
- Traditional solutions: Hub-and-spoke model only
- Lazarus: Mesh network with intelligent routing

## **Killer Features That Don't Exist Elsewhere**

### **1. Time Travel Debugging**
```bash
lazarus timewarp --date "2024-01-15 14:30" --mount /debug
# System state from that exact moment mounted for investigation
lazarus diff --from "yesterday" --to "today" --filter "config"
# See exactly what changed between backups
```

### **2. Backup Bisection**
```bash
lazarus bisect --good "2024-01-01" --bad "today" --test "./check_issue.sh"
# Automatically finds when an issue was introduced, like git bisect
```

### **3. Cross-Platform Live Migration**
- **P2V2P in one step**: Physical → Virtual → Physical without intermediate steps
- **Hardware abstraction layer**: Restore Linux backup to different distro, Windows 10 to 11
- **Architecture translation**: x86 → ARM backup restoration (with emulation layer)

### **4. Semantic Deduplication**
Beyond block-level dedup:
- **Content-aware deduplication**: Understands file formats (dedups similar PDFs, images)
- **Cross-file compression**: Compress similar content across different files
- **Temporal compression**: Only store deltas for time-series data

## **Performance Innovations**

### **1. Zero-Impact Backups**
- **eBPF-based monitoring** (Linux): Zero overhead file tracking
- **Memory-mapped operations**: Direct memory access without file I/O
- **Kernel bypass networking**: DPDK/io_uring for maximum throughput
- **GPU acceleration**: Use GPU for compression/encryption when available

### **2. Instant Recovery Technology**
```rust
// Start using system immediately while restore continues in background
pub struct InstantRecovery {
    priority_queue: BTreeMap<Priority, Vec<Block>>,
    prefetcher: PredictiveCache,
    lazy_restore: BackgroundWorker,
}
```
- **Boot in <30 seconds** regardless of backup size
- **On-demand block streaming**: Fetch data as needed
- **Predictive prefetching**: AI predicts next needed blocks

## **Power User Specific Advantages**

### **1. Infrastructure as Code Native**
```yaml
# lazarus.yaml - Declarative backup configuration
backups:
  - name: production-db
    source: postgres://prod-db
    schedule: "*/15 * * * *"  # Every 15 minutes
    retention: 
      snapshots: 96  # 24 hours of 15-min snapshots
    hooks:
      pre: "pg_start_backup()"
      post: "pg_stop_backup()"
```

### **2. Programmatic Control**
```python
# Full Python SDK for automation
import lazarus

backup = lazarus.create_backup(
    paths=["/data", "/config"],
    tags={"env": "prod", "version": "2.1.0"}
)

# Restore specific files from specific backup
lazarus.restore(
    backup_id=backup.id,
    files=["*.conf"],
    target="/tmp/configs",
    point_in_time="2024-01-15T10:00:00Z"
)
```

### **3. Container & Orchestration Native**
- **Kubernetes operator**: Backs up entire clusters with CRDs
- **Container layer caching**: Only backup changed container layers
- **Stateful set awareness**: Coordinate backups across distributed systems

## **Market Positioning Advantages**

### **vs. Enterprise Solutions (Veeam, Acronis)**
| Feature | Veeam/Acronis | Lazarus |
|---------|---------------|----------|
| License Cost | $500-5000/server | Free/Open Source |
| Minimum Resources | 8GB RAM, dedicated server | 512MB RAM, runs anywhere |
| Complexity | Requires training | Intuitive for Linux/DevOps users |
| Vendor Lock-in | Proprietary formats | Open formats, no lock-in |

### **vs. Open Source (Borg, Restic, Duplicati)**
| Feature | Borg/Restic | Lazarus |
|---------|-------------|----------|
| Bare Metal Recovery | No | Yes, with bootable media |
| Application-Aware | Limited | Full support with hooks |
| Central Management | No/Limited | Full orchestration server |
| Live System Backup | Filesystem only | Full system with VSS/LVM |
| UI Options | CLI only | CLI + Web + API |

### **vs. Cloud Solutions (Backblaze, Carbonite)**
| Feature | Cloud Backup | Lazarus |
|---------|--------------|----------|
| Data Sovereignty | Cloud only | Your infrastructure |
| Bandwidth Costs | Ongoing | One-time local storage |
| Recovery Speed | Limited by internet | Local network speeds |
| Privacy | Third-party controlled | Fully private |

## **Unique Technical Stack Advantages**

### **Rust-Powered Benefits**
- **Memory safety**: No crashes or data corruption from memory bugs
- **Performance**: C++ level performance with better concurrency
- **Single binary deployment**: No dependencies, runtime, or interpreter needed
- **Cross-compilation**: Build for any platform from any platform

### **Modern Architecture Benefits**
- **gRPC + REST**: Best of both worlds for different use cases
- **WebAssembly plugins**: Safe, sandboxed plugin execution
- **io_uring** (Linux): Cutting-edge async I/O for maximum performance
- **QUIC protocol**: Faster, more reliable network transfers than TCP

## **The "Killer" USPs Summary**

1. **"Save states for servers"** - Gaming-inspired simplicity for complex infrastructure
2. **"Time machine for everything"** - Not just files, but complete system states
3. **"Git for system administration"** - Branch, merge, bisect your infrastructure
4. **"Zero trust, zero cost"** - Enterprise features without enterprise pricing
5. **"Backup that thinks"** - AI-driven optimization and predictive protection

## **Why Lazarus Wins**

**For Homelabbers:**
- Finally, a backup solution that understands containers and VMs natively
- No license anxiety when adding more servers
- Community-driven features for real needs

**For Power Users:**
- Scriptable everything with proper APIs
- Treats infrastructure as code, not clicking through GUIs
- Respects your time with smart automation

**For Security-Conscious:**
- Audit every line of code
- Your data never leaves your control
- Encryption by default, zero-knowledge architecture

This combination of technical innovation, user-focused design, and open-source philosophy creates a backup solution that doesn't exist in the current market - one that's simultaneously more powerful than enterprise solutions and more accessible than current open-source alternatives.
