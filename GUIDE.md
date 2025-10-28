Here is the comprehensive technical design documentation for the **Lazarus - Advanced Backup & Recovery Suite**, based on the full scope of your project plan.

This document is intended to serve as the foundational blueprint for the development team.

-----

# **Lazarus: Advanced Backup & Recovery Suite**

## **Technical Design Document & System Specification**

**Version:** 1.0
**Status:** DRAFT

### 1\. Introduction & Vision

#### 1.1 Project Mission

To create a high-performance, secure, and flexible backup and recovery suite that rivals enterprise-grade solutions. Lazarus will be built on modern technologies (Rust) and principles (zero-knowledge encryption, content-defined deduplication) to provide a single, unified solution for protecting workloads ranging from single developer machines to complex homelab and small-business environments (VMs, containers).

#### 1.2 Core Principles

  * **Safety & Security:** Code safety (Rust) and data security (zero-knowledge, end-to-end encryption) are paramount.
  * **Performance:** All operations (backup, restore, deduplication) must be high-performance, leveraging multi-threading, modern compression (Zstd), and efficient chunking.
  * **Efficiency:** Minimize storage footprint through global, content-defined deduplication and compression.
  * **Flexibility:** Support a wide array of storage backends, user interfaces (CLI, Web, GUI), and operating systems.
  * **Resilience:** Backups are useless if they can't be restored. The system will prioritize verification, integrity checks, and robust bare-metal recovery.

#### 1.3 Key Terminology

  * **Repository:** The storage location where all backups, metadata, and data chunks are stored.
  * **Agent:** The lightweight client software (`lazarus-agent`) that runs on a machine to perform backups.
  * **Server:** The central management component (`lazarus-server`) that orchestrates agents, manages schedules, and provides APIs.
  * **Chunk:** A small, variable-sized piece of data, (e.g., 8KB-16MB) derived from Content-Defined Chunking.
  * **Chunk Hash:** The unique ID of a chunk (e.g., BLAKE3), which is the basis for deduplication.
  * **Snapshot:** A point-in-time metadata record of a backup, representing a complete file system tree.
  * **BMR:** Bare Metal Recovery. Restoring a complete system from a bootable recovery environment.

-----

### 2\. System Architecture (High-Level)

The system is designed as a client-server model, but the client (agent) can also be used in a **standalone mode** for simple, local-only backups.

```
                  +-------------------+
[Web Dashboard] <-> | REST API (HTTPS)  |
                  +-------------------+
                          ^
                          |
+------------------------------------------------------+
|               Lazarus Server (Rust)               |
|                                                      |
| [Job Orchestrator] [Schedule Manager] [Webhooks]     |
| [Storage Pool Mgr] [User Auth] [Reporting]           |
|                                                      |
+----------------------+-------------------------------+
           ^           |
           | gRPC      | (Metadata DB - SQLite/Postgres)
           | (mTLS)    |
           v           v
+----------------------+-------------------------------+
|  Lazarus Agent(s) |  Storage Backend Interface (Trait) |
|                      |                                |
| [Snapshot Mgr]       |   +----------------------------+
| [Chunker (CDC)]      |   | [Local Disk/NAS]           |
| [Compressor (Zstd)]  |   | [S3/B2/Wasabi]             |
| [Encryptor (AES)]    |   | [SSH/SFTP]                 |
| [Local Cache]        |   | [Google Drive/OneDrive]    |
+----------------------+   +----------------------------+
(On Target Machines)       (In Repository Location)
```

-----

### 3\. Component Deep-Dive

#### 3.1 Client Agent (`lazarus-agent`)

  * **Technology:** Rust
  * **Type:** Lightweight, cross-platform daemon/service (or standalone CLI binary).
  * **Responsibilities:**
      * **Snapshotting:** Integrates with OS-native snapshot APIs (VSS on Windows, LVM/Btrfs/APFS on Linux/macOS) for "hot" backups.
      * **Filesystem Walking:** Scans the file system for changes.
      * **Chunking:** Uses **Content-Defined Chunking (CDC)** (e.g., FastCDC algorithm) to split files into variable-size chunks.
      * **Hashing:** Calculates the BLAKE3 hash of each *uncompressed* chunk.
      * **Deduplication:** Maintains a local index (or checks with the server) to identify which chunk hashes already exist in the repository.
      * **Compression:** Compresses new chunks using **Zstandard**.
      * **Encryption:** Encrypts new, compressed chunks using **AES-256-GCM** with a per-chunk key.
      * **Communication:** Communicates with the `lazarus-server` via gRPC for job instructions, chunk uploads, and metadata reporting.
      * **Throttling:** Manages bandwidth and CPU usage.
      * **Caching:** Maintains a local cache of chunk hashes and metadata to speed up incremental backups.

#### 3.2 Server Component (`lazarus-server`)

  * **Technology:** Rust
  * **Type:** Central management service.
  * **Responsibilities:**
      * **Job Orchestration:** Manages all backup, restore, verify, and prune jobs for all connected agents.
      * **Scheduling:** A cron-like scheduler for running jobs based on user-defined policies (e.g., "Daily", "Hourly").
      * **Metadata Database:** Manages the central database (see Schema) that stores all snapshot info, file trees, and chunk mappings.
      * **Storage Pool Management:** Abstracted interface for managing one or more repositories.
      * **API Layer (gRPC):** Exposes a secure gRPC API for agents.
      * **API Layer (REST):** Exposes a secure REST API for the Web Dashboard and external tools (Ansible, Terraform).
      * **Alerting & Reporting:** Sends notifications (email, webhooks) on job success/failure.
      * **Multi-Client Support:** Manages policies, clients, and storage for a multi-user or multi-machine environment.

#### 3.3 Storage Backend

  * **Architecture:** A Rust `Storage` trait will be defined with a common interface:
    ```rust
    trait StorageBackend {
        fn put_chunk(&self, hash: &str, data: Vec<u8>) -> Result<()>;
        fn get_chunk(&self, hash: &str) -> Result<Vec<u8>>;
        fn list_snapshots(&self) -> Result<Vec<String>>;
        // ... etc.
    }
    ```
  * **Implementations:**
      * `LocalStorage`: For NAS, external drives, etc.
      * `S3Storage`: For any S3-compatible service (S3, B2, Wasabi).
      * `SftpStorage`: For remote SSH/SFTP servers.
      * `CloudStorage`: For Google Drive, OneDrive (via their respective APIs).

#### 3.4 Recovery Environment

  * **Type:** Bootable ISO/USB, generated by the Lazarus tool.
  * **Base OS:** A minimal Linux distro (e.g., Alpine).
  * **Contents:**
      * The `lazarus` binary in a "recovery" mode.
      * Network and storage drivers for broad hardware compatibility.
      * Partition management tools.
      * A simple TUI (Terminal User Interface) or CLI to:
        1.  Configure network.
        2.  Connect to the repository (local, S3, etc.).
        3.  Select a snapshot.
        4.  Select a target disk.
        5.  Perform a **Bare Metal Restore**.
  * **Key Feature: Universal Restore:** The BMR process must include a **driver injection** step, allowing the user to provide necessary storage/network drivers for the restored OS to boot on new/different hardware.

-----

### 4\. Core Technology & Concepts

#### 4.1 Repository Structure

We will adopt a content-addressable model, *not* a monolithic `.sav` file. This is essential for deduplication.

```
/path/to/backup-repo/
├── config         (Repo-wide settings, encryption keys, salt)
├── data/          (All data chunks, named by hash, in sharded dirs)
│   ├── 0a/
│   │   └── 0a1b2c... (encrypted/compressed chunk)
│   ├── 0b/
│   │   └── 0b3d4e...
│   └── ...
├── indexes/       (The central SQLite database: index.db)
└── snapshots/     (Small, encrypted JSON/metadata files)
    ├── 2025-10-28T140000.snapshot
    └── 2025-10-29T140000.snapshot
```

#### 4.2 Encryption & Key Management

  * **Model:** Zero-Knowledge. The server *never* has access to unencrypted data or the user's master password.
  * **Process (Repo Creation):**
    1.  User provides a **Master Password**.
    2.  A random, high-entropy `salt` is generated.
    3.  A `MasterKey` is derived using **Argon2id(Password, Salt)**. This key is *never* stored.
    4.  A `RepositoryEncryptionKey` (for data) and a `MetadataEncryptionKey` (for metadata/filenames) are generated.
    5.  These two keys are encrypted with the `MasterKey` and stored in the `config` file.
  * **Process (Backup):**
    1.  User provides the password (or it's in a keyfile/keychain).
    2.  `MasterKey` is re-derived.
    3.  `MasterKey` decrypts the `RepositoryEncryptionKey` and `MetadataEncryptionKey` into memory.
    4.  Data chunks are encrypted with `RepositoryEncryptionKey`.
    5.  Filenames and metadata (in `index.db` and `.snapshot` files) are encrypted with `MetadataEncryptionKey`.
  * **Consequence:** A lost password means irrecoverably lost data. This is a feature, not a bug.

#### 4.3 Database Schema (SQLite - `index.db`)

This schema provides the "index" to map files to their constituent chunks.

```sql
-- Stores every unique, compressed, and encrypted block of data.
CREATE TABLE Chunks (
    hash TEXT PRIMARY KEY,    -- BLAKE3 hash of uncompressed data
    stored_size INTEGER NOT NULL, -- Size of compressed/encrypted data
    uncompressed_size INTEGER NOT NULL
);

-- Represents a single version of a file or directory.
CREATE TABLE Objects (
    object_id INTEGER PRIMARY KEY,
    type INTEGER NOT NULL,      -- 0=FILE, 1=DIRECTORY
    -- Encrypted JSON blob: { "name": "file.txt", "mode": 0644, ...}
    metadata BLOB NOT NULL
);

-- Defines the directory structure (links parent dir to child objects).
CREATE TABLE Tree (
    parent_object_id INTEGER NOT NULL,
    child_object_id INTEGER NOT NULL,
    -- Encrypted name of the child object
    encrypted_name BLOB NOT NULL, 
    PRIMARY KEY (parent_object_id, encrypted_name),
    FOREIGN KEY (parent_object_id) REFERENCES Objects(object_id),
    FOREIGN KEY (child_object_id) REFERENCES Objects(object_id)
);

-- Maps a file Object to its list of Chunks in the correct order.
CREATE TABLE FileChunks (
    file_object_id INTEGER NOT NULL,
    chunk_hash TEXT NOT NULL,
    chunk_order INTEGER NOT NULL, -- Order of this chunk (0, 1, 2...)
    PRIMARY KEY (file_object_id, chunk_order),
    FOREIGN KEY (file_object_id) REFERENCES Objects(object_id),
    FOREIGN KEY (chunk_hash) REFERENCES Chunks(hash)
);

-- The top-level entry point for a backup.
CREATE TABLE Snapshots (
    snapshot_id TEXT PRIMARY KEY, -- e.g., "2025-10-28T14:30:00"
    timestamp INTEGER NOT NULL,
    root_object_id INTEGER NOT NULL, -- The object_id of the root dir
    -- Encrypted JSON: { "hostname": "prod", "tags": ["daily"] }
    metadata BLOB NOT NULL,
    FOREIGN KEY (root_object_id) REFERENCES Objects(object_id)
);
```

-----

### 5\. Feature Specification

#### 5.1 Backup

  * **Backup Strategy:**
      * **3-2-1 Rule:** The system will facilitate this by allowing easy replication of repositories to different storage pools (e.g., `LocalStorage` + `S3Storage`).
      * **GFS Rotation:** `prune` jobs will support Grandfather-Father-Son retention policies (e.g., keep all dailies for 7 days, 4 weeklies, 12 monthlies).
      * **Priority Tiers:** Job scheduler will allow tagging of jobs with priorities.
  * **Capabilities:**
      * **Application-Aware:** For v1, this will be handled via **Pre/Post-backup hooks** (e.g., a pre-hook script dumps a DB, Lazarus backs up the `.sql` file).
      * **VM/Container:** Native integration (Proxmox, K8s) will be a post-v1 feature. The v1 solution is to run the agent *inside* the VM/container.

#### 5.2 Restore

  * **Scenarios:**
      * **File-level:** Restore individual files/folders to their original location or a new one.
      * **System-level:** BMR from the recovery environment.
  * **Tools:**
      * **Instant Recovery:** A `lazarus mount` command (using FUSE/Dokan) will mount any snapshot as a read-only virtual drive for instant file browsing.
      * **P2V/V2P:** BMR naturally supports this. Restoring a physical machine to a VM (P2V) is a standard use case.

#### 5.3 Verification

  * **Automatic Checks:** A `verify` job will run on a schedule.
  * **Process:**
    1.  Checks `index.db` for internal consistency.
    2.  Randomly samples N% of chunks from the `data/` directory.
    3.  Fetches them, decrypts, and re-hashes to ensure the hash matches (detects bit rot).
    4.  *(Advanced)* Simulates a "test restore" by re-building a file tree in memory.

-----

### 6\. User Interfaces

#### 6.1 CLI Tool (`lazarus`)

This is the core tool. It must support both standalone and agent modes.

  * `lazarus init-repo --storage-type s3 ...` (Standalone)
  * `lazarus register --server https://server-url` (Agent)
  * `lazarus backup --path /home --policy Daily`
  * `lazarus snapshots`
  * `lazarus restore <snapshot_id>:/path/to/file /local/dest`
  * `lazarus mount <snapshot_id> /mnt/snapshot`
  * `lazarus verify --repo-path /mnt/backups`
  * `lazarus prune --keep-daily 7 --keep-weekly 4 ...`

#### 6.2 Web Dashboard

  * **Frontend:** React / Vue / Svelte (TBD)
  * **Backend:** Talks to the `lazarus-server` REST API.
  * **Key Sections:**
      * **Dashboard:** At-a-glance status of all clients, repositories, and recent jobs.
      * **Clients:** Manage registered agents.
      * **Repositories:** Configure storage pools.
      * **Policies:** Create and assign backup schedules and retention rules.
      * **Restore:** A wizard-based GUI for file-level restore.
      * **Reporting:** Job history, storage usage, etc.

#### 6.3 Native GUI (Optional)

  * **Technology:** (TBD - e.g., Tauri, Flutter)
  * **Function:** A system tray icon for quick status, manual backup/restore initiation, and file browsing. This is a low-priority, post-v1 feature.

-----

### 7\. API Specification (High-Level)

#### 7.1 gRPC API (Agent \<-\> Server)

  * **Security:** Mutual TLS (mTLS) with pre-shared keys or certificates.
  * **Services:**
      * `AgentService`:
          * `RegisterAgent(RegisterRequest)`: Agent introduces itself.
          * `GetJobs(AgentStatus)`: Agent polls for new jobs.
          * `StartJob(JobReport)`: Agent acknowledges job start.
          * `ReportProgress(JobProgress)`: Agent streams logs/status.
          * `CompleteJob(JobReport)`: Agent reports success/failure.
      * `ChunkService`:
          * `CheckChunksExist(stream ChunkHash)`: Agent sends a list of hashes.
          * `UploadChunk(stream ChunkData)`: Agent uploads new chunks.

#### 7.2 REST API (WebUI \<-\> Server)

  * **Security:** Token-based authentication (JWT).
  * **Endpoints:**
      * `GET /api/v1/clients`: List all agents.
      * `GET /api/v1/clients/{id}`: Get agent details.
      * `GET /api/v1/snapshots`: List all snapshots.
      * `POST /api/v1/restore`: Start a file-level restore job.
      * `GET /api/v1/policies`: List all backup policies.
      * `POST /api/v1/policies`: Create a new policy.

-----

### 8\. Phased Rollout (Development Roadmap)

This is a massive project. It must be built in phases.

#### **Phase 1: The Core (MVP)**

  * **Goal:** A powerful, standalone CLI tool.
  * **Features:**
      * Rust CLI binary (`lazarus`).
      * **Standalone mode only.**
      * Storage: `LocalStorage` and `S3Storage`.
      * Core commands: `init`, `backup`, `restore`.
      * Encryption, Compression, and **Fixed-Size Chunking** (easier to implement than CDC).
      * BMR Recovery ISO.
  * **Outcome:** A best-in-class *local* backup tool.

#### **Phase 2: The Server**

  * **Goal:** Centralized management.
  * **Features:**
      * Build `lazarus-server`.
      * Implement gRPC and REST APIs.
      * Implement the `index.db` schema.
      * Build `lazarus-agent` and client-server communication.
      * Port the CLI to be an "agent" mode.
  * **Outcome:** A working client-server system, manageable via API/CLI.

#### **Phase 3: The Polish & Web UI**

  * **Goal:** A user-friendly, multi-user experience.
  * **Features:**
      * Build the Web Dashboard.
      * Implement advanced scheduling, alerting, and GFS pruning.
      * `lazarus mount` (FUSE/Dokan) feature.
  * **Outcome:** A complete, usable suite for homelabs and small businesses.

#### **Phase 4: The Advanced Engine**

  * **Goal:** Enterprise-grade performance and features.
  * **Features:**
      * Upgrade the chunking engine from **Fixed-Size** to **Content-Defined Chunking (CDC)**. This is a *major* engineering task.
      * Native Application-Aware handlers (Proxmox, K8s, DBs).
      * "Universal Restore" (BMR driver injection).
      * Native GUI.
  * **Outcome:** The final, ambitious vision.