# Lazarus Gap Analysis Report

## Executive Summary

I've completed a comprehensive audit of the Lazarus codebase against the architectural vision in `GUIDE.md`. The project has made significant progress on Phase 1 and Phase 2, with solid implementations of encryption, chunking, and basic backup/restore. However, **critical production blockers exist in state persistence, job orchestration, metadata handling, and bare metal recovery**. The system is currently in **late alpha state**, not production-ready.

---

## 1. Critical Missing Components
**These features are completely absent but required for MVP functionality:**

### 1.1 Pruning/Garbage Collection (`lazarus-core`)
**Status:** ❌ **NOT IMPLEMENTED**

**Evidence:**
- `lazarus-cli/src/commands/mod.rs:1-8` - No `prune` module exists
- `lazarus-core/src/catalog/index.rs` - No methods to:
  - Find unreferenced chunks (orphans)
  - Delete chunk records from database
  - Delete snapshot records
- `lazarus-core/src/storage/backend.rs:48` - `delete()` trait method exists but unused
- Searched entire codebase for prune logic: only found in proto definitions

**Impact:** Repositories will grow indefinitely. Old snapshots cannot be removed, chunks cannot be garbage collected.

**What exists instead:** `retention.rs` only handles *immutable retention policies* (S3 Object Lock), not actual data deletion.

---

### 1.2 Server State Persistence (`lazarus-server`)
**Status:** 🔴 **CRITICAL FLAW**

**Evidence:**
- `lazarus-server/src/job_scheduler.rs:45` - Jobs stored in `Arc<RwLock<HashMap<String, Job>>>`
- `lazarus-server/src/agent_manager.rs:29` - Agents stored in `Arc<RwLock<HashMap<String, Agent>>>`

**Impact:**
- **Server restart = data loss**: All scheduled jobs and agent registrations lost
- No job history
- No audit trail
- Cannot survive crashes

**Required:** SQLite or Postgres persistence for `jobs` and `agents` tables.

---

### 1.3 Job Triggering Logic (`lazarus-server`)
**Status:** 🟡 **STUBBED**

**Evidence:**
- `lazarus-server/src/job_scheduler.rs:165-173` - The `run()` loop only calls `check_stale_jobs()`
- No cron parsing logic
- No automatic job creation based on schedules
- No GFS (Grandfather-Father-Son) retention policy implementation

**What exists:** Basic job state transitions (Pending → Assigned → InProgress → Completed/Failed)

**What's missing:** Actual scheduling, cron-like triggers, GFS rotation policies mentioned in `GUIDE.md:240`.

---

### 1.4 Metadata Preservation in Backup/Restore
**Status:** 🟡 **PARTIALLY IMPLEMENTED**

**Evidence (Backup):**
- `lazarus-agent/src/main.rs:280-376` - Agent backup captures NO file metadata
- No `mode`, `mtime`, `ownership` recorded
- `ObjectMetadata` struct exists in `catalog/index.rs:14-20` but not populated

**Evidence (Restore):**
- `lazarus-cli/src/commands/restore.rs:109` - Uses `tokio::fs::write()` with default permissions
- Line 45, 48: `_encrypted_obj_metadata` is read then ignored
- No `chmod`, `chown`, or `utime` calls

**Impact:** Restored files have wrong permissions, timestamps, and ownership. **BMR will fail** on system files requiring specific modes.

---

### 1.5 Bare Metal Recovery Implementation
**Status:** ❌ **UI MOCKUP ONLY**

**Evidence:**
- `lazarus-recovery/src/main.rs:154-160` - Hardcoded dummy snapshots
- `lazarus-recovery/src/main.rs:165` - Comment: "Snapshot selected - would trigger restore"
- All module files are **0 bytes** (confirmed via `wc -l`):
  - `boot/iso_builder.rs` - 0 lines
  - `boot/pxe.rs` - 0 lines
  - `restore/bare_metal.rs` - 0 lines
  - `hardware/drivers.rs` - 0 lines
  - `partition/manager.rs` - 0 lines

**What exists:** A 352-line Ratatui TUI with navigation, but no backend integration.

**What's missing:** Everything promised in `GUIDE.md:124-138` - ISO generation, partition management, driver injection, actual restore logic.

---

## 2. "Stubbed" Functionality
**Code exists but uses placeholders or incomplete implementations:**

### 2.1 Agent Job Handler (`lazarus-agent`)
**Status:** 🟡 **PARTIAL**

**Evidence:**
- `lazarus-agent/src/main.rs:199-201` - Only `JobType::BACKUP` (0) handled
- RESTORE, VERIFY, PRUNE cases return `"Unknown job type"` error

**Impact:** Agents cannot execute server-pushed restore/verify/prune jobs.

---

### 2.2 Agent Directory Backup
**Status:** 🟡 **NON-RECURSIVE**

**Evidence:**
- `lazarus-agent/src/main.rs:257-258` - Explicit comment: "For simplicity, we'll just backup files in the directory (non-recursive)"
- Only processes immediate children

**Impact:** Cannot backup directory trees from agent-based backups.

---

### 2.3 Deduplication Index (`lazarus-core`)
**Status:** 🟡 **BASIC IMPLEMENTATION**

**Evidence:**
- `lazarus-core/src/snapshot/dedup.rs` - **File is empty** (2 lines)
- `lazarus-core/src/catalog/index.rs:92-103` - `upsert_chunk()` uses `INSERT OR IGNORE`
- No transaction batching
- No `PRAGMA journal_mode=WAL` or `PRAGMA synchronous=NORMAL`
- No concurrent write optimization

**Impact:** SQLite will lock on concurrent writes from multiple agents. Performance will degrade significantly under multi-agent load.

---

### 2.4 Adaptive Compression
**Status:** ❌ **NOT IMPLEMENTED**

**Evidence:**
- `lazarus-core/src/compression/adaptive.rs` - **File is empty** (2 lines)
- Only Zstandard level 3 compression used everywhere

**Impact:** No detection of already-compressed files (e.g., JPEGs, videos). Wasted CPU cycles.

---

### 2.5 Ransomware Detection Integration
**Status:** ✅ **IMPLEMENTED BUT UNUSED**

**Surprising finding:** `lazarus-core/src/security/ransomware.rs` contains a **fully implemented** ransomware detection engine:
- Shannon entropy calculation
- Canary file deployment/validation
- Trust score tracking with baseline deviation
- Quarantine functionality
- Comprehensive tests (lines 384-430)

**BUT:** This code is never called! No integration in:
- `lazarus-cli/src/commands/backup.rs`
- `lazarus-agent/src/main.rs`

**Impact:** A valuable security feature sits dormant.

---

## 3. Architectural Risks

### 3.1 SQLite Concurrency (HIGH RISK)
**Issue:** No WAL mode, no transaction batching, no connection pooling.

**Location:** `lazarus-core/src/catalog/index.rs:39-90`

**Consequence:** Multiple agents writing to the same repository will experience:
- Lock contention
- `SQLITE_BUSY` errors
- Backup failures

**Fix Required:**
```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
-- Batch inserts in transactions
BEGIN IMMEDIATE;
INSERT INTO Chunks ...;
COMMIT;
```

---

### 3.2 Agent gRPC Reconnection (MEDIUM RISK)
**Issue:** No retry logic on connection failures.

**Location:** `lazarus-agent/src/main.rs:359-367` - Chunk upload fails immediately if network drops.

**Consequence:**
- Long-running backups fail on transient network issues
- No resume capability

**What exists:** Heartbeat loop logs errors but doesn't reconnect (`main.rs:399-401`).

---

### 3.3 In-Memory Server State (HIGH RISK)
**Already covered in Section 1.2.** This is the **most critical architectural flaw**.

---

### 3.4 Encryption Key Derivation (LOW RISK, INFORMATIONAL)
**Issue:** Argon2id parameters not configurable.

**Location:** Referenced in `config.rs` but parameters hardcoded in core.

**Recommendation:** Expose `time_cost`, `memory_cost`, `parallelism` in `config.json` for high-security environments.

---

## 4. Next Steps Implementation Plan

### Phase A: Production Blockers (Beta Readiness)
**Priority:** 🔴 CRITICAL - Must complete before any Beta release

#### A.1 Server Persistence Layer (ETA: 3-5 days)
- [ ] Create SQLite schema for jobs and agents
- [ ] Refactor `JobScheduler` to use database
- [ ] Refactor `AgentManager` to use database
- [ ] Add migration logic for schema updates
- [ ] **Test:** Server restart without data loss

**Files to modify:**
- `lazarus-server/src/job_scheduler.rs`
- `lazarus-server/src/agent_manager.rs`
- New file: `lazarus-server/src/database.rs`

---

#### A.2 Metadata Preservation (ETA: 2-3 days)
- [ ] Agent: Capture `mode`, `mtime`, `uid`, `gid` during backup
- [ ] Core: Store metadata in `Objects.metadata` encrypted blob
- [ ] CLI: Apply metadata during restore using `std::fs::set_permissions()`, `filetime::set_file_mtime()`
- [ ] Cross-platform: Handle Windows vs. Unix permissions

**Files to modify:**
- `lazarus-agent/src/main.rs:280-376`
- `lazarus-cli/src/commands/restore.rs:69-171`
- `lazarus-core/src/catalog/index.rs` (use existing `ObjectMetadata`)

---

#### A.3 SQLite Concurrency Optimization (ETA: 1-2 days)
- [ ] Enable WAL mode on catalog init
- [ ] Wrap chunk inserts in transactions (batch of 100)
- [ ] Add connection pooling (r2d2 or sqlx)
- [ ] **Test:** Multi-agent backup to shared repository

**Files to modify:**
- `lazarus-core/src/catalog/index.rs:39-90`

---

#### A.4 Agent Reconnection Logic (ETA: 2 days)
- [ ] Implement exponential backoff for gRPC reconnection
- [ ] Add chunk upload queue (persist to local cache on failure)
- [ ] Resume incomplete chunk uploads on reconnect
- [ ] **Test:** Kill server mid-backup, verify resume

**Files to modify:**
- `lazarus-agent/src/main.rs:58-86` (connection management)
- `lazarus-agent/src/main.rs:344-372` (chunk upload)

---

### Phase B: Core Functionality Gaps (ETA: 1-2 weeks)
**Priority:** 🟡 HIGH - Required for feature completeness

#### B.1 Implement Prune Command (ETA: 3-4 days)
- [ ] Add `delete_snapshot()` to `CatalogIndex`
- [ ] Implement `find_unreferenced_chunks()` (LEFT JOIN query)
- [ ] Add `delete_chunk()` to `StorageBackend` implementations
- [ ] Create `lazarus-cli/src/commands/prune.rs`
- [ ] Implement GFS retention policy logic (keep daily/weekly/monthly)
- [ ] **Test:** Delete old snapshots, verify chunk removal

**New files:**
- `lazarus-cli/src/commands/prune.rs`

**Modified files:**
- `lazarus-core/src/catalog/index.rs`
- `lazarus-core/src/storage/local.rs`
- `lazarus-core/src/storage/s3.rs`

---

#### B.2 Job Scheduler Enhancement (ETA: 4-5 days)
- [ ] Integrate `cron` crate for schedule parsing
- [ ] Add periodic job creation based on policies
- [ ] Implement GFS snapshot tagging (daily/weekly/monthly)
- [ ] Link prune logic to scheduler
- [ ] Add job history table (for auditing)
- [ ] **Test:** Schedule job runs automatically

**Files to modify:**
- `lazarus-server/src/job_scheduler.rs`
- Add dependency: `cron = "0.12"`

---

#### B.3 Complete Agent Job Handlers (ETA: 2 days)
- [ ] Implement `JobType::RESTORE` handler
- [ ] Implement `JobType::VERIFY` handler
- [ ] Implement `JobType::PRUNE` handler
- [ ] Add recursive directory traversal
- [ ] **Test:** Server-triggered restore/verify/prune

**Files to modify:**
- `lazarus-agent/src/main.rs:171-224`
- `lazarus-agent/src/main.rs:226-278` (add recursion)

---

#### B.4 Integrate Ransomware Detection (ETA: 1 day)
- [ ] Add `--enable-ransomware-detection` flag to backup command
- [ ] Call `DetectionEngine::analyze_paths()` before backup
- [ ] Halt backup if `DetectionVerdict::Suspicious` (with override flag)
- [ ] Report anomalies to user
- [ ] **Test:** Backup directory with high-entropy files

**Files to modify:**
- `lazarus-cli/src/commands/backup.rs`
- `lazarus-agent/src/main.rs` (if agent-side detection desired)

---

### Phase C: Bare Metal Recovery (ETA: 2-3 weeks)
**Priority:** 🟢 MEDIUM - Post-Beta feature

#### C.1 Implement Restore Logic (ETA: 5-7 days)
- [ ] Integrate `lazarus-core` into recovery binary
- [ ] Replace dummy snapshots with real `CatalogIndex::list_snapshots()`
- [ ] Implement actual restore in `restore/bare_metal.rs`
- [ ] Add partition detection using `lsblk` or `libudev`
- [ ] Add partition formatting (ext4, xfs, btrfs)
- [ ] **Test:** Restore snapshot to blank disk

**Files to modify:**
- `lazarus-recovery/src/main.rs:152-162`
- `lazarus-recovery/src/restore/bare_metal.rs` (implement from scratch)
- `lazarus-recovery/src/partition/manager.rs` (implement from scratch)

---

#### C.2 ISO Builder (ETA: 5-7 days)
- [ ] Research: Use `mkisofs`/`genisoimage` or Rust crate (e.g., `fatfs`)
- [ ] Create Alpine Linux base layer
- [ ] Bundle `lazarus-recovery` binary
- [ ] Add network drivers (common NICs)
- [ ] Implement `boot/iso_builder.rs`
- [ ] **Test:** Boot ISO in QEMU, connect to S3 repo, restore

**Files to modify:**
- `lazarus-recovery/src/boot/iso_builder.rs` (implement from scratch)

---

#### C.3 Driver Injection (Advanced) (ETA: 3-5 days)
- [ ] Detect hardware differences (storage controllers, NICs)
- [ ] Allow user to provide driver pack via USB
- [ ] Inject drivers into restored OS (modify initramfs or Windows registry)
- [ ] **Test:** Restore physical machine to different hardware

**Files to modify:**
- `lazarus-recovery/src/hardware/drivers.rs` (implement from scratch)

---

### Phase D: Polish & Production Readiness (ETA: 1-2 weeks)
**Priority:** 🔵 LOW - Post-feature-complete

#### D.1 Adaptive Compression
- [ ] Implement file type detection (magic bytes)
- [ ] Skip compression for `.jpg`, `.png`, `.mp4`, `.zip`, etc.
- [ ] Benchmark compression ratio vs. CPU time

**Files to modify:**
- `lazarus-core/src/compression/adaptive.rs`

---

#### D.2 Verification Enhancements
- [ ] Add SQLite integrity check (`PRAGMA integrity_check`)
- [ ] Add sampling mode (verify N% of chunks instead of all)
- [ ] Implement test restore (restore snapshot to temp dir)

**Files to modify:**
- `lazarus-cli/src/commands/verify.rs`

---

#### D.3 Testing & Documentation
- [ ] Integration tests for multi-agent scenarios
- [ ] Disaster recovery drill (kill server mid-backup)
- [ ] Update README with known limitations
- [ ] Add `ARCHITECTURE.md` with this gap analysis

---

## Summary Table

| Component | Status | Criticality | ETA |
|-----------|--------|-------------|-----|
| Server Persistence | ❌ Missing | 🔴 Critical | 3-5 days |
| Metadata Preservation | 🟡 Partial | 🔴 Critical | 2-3 days |
| SQLite Concurrency | ⚠️ Risk | 🔴 Critical | 1-2 days |
| Agent Reconnection | ⚠️ Risk | 🟡 High | 2 days |
| Prune/GC | ❌ Missing | 🟡 High | 3-4 days |
| Job Scheduler | 🟡 Stub | 🟡 High | 4-5 days |
| Agent Job Handlers | 🟡 Partial | 🟡 High | 2 days |
| Ransomware Integration | ✅ Unused | 🟢 Medium | 1 day |
| BMR Restore Logic | ❌ Mockup | 🟢 Medium | 5-7 days |
| ISO Builder | ❌ Missing | 🟢 Medium | 5-7 days |
| Adaptive Compression | ❌ Missing | 🔵 Low | 2-3 days |

**Total Beta Readiness:** ~10-12 days for Phase A (Critical blockers)
**Total Feature Completeness:** ~4-6 weeks for Phases A+B+C

---

## Positive Highlights

Despite the gaps, the following are **production-quality implementations**:

✅ **Encryption & Key Management** (`lazarus-core/src/encryption/`) - Solid Argon2id + AES-256-GCM
✅ **Content-Defined Chunking** (`lazarus-core/src/chunking/cdc.rs`) - FastCDC correctly implemented
✅ **Verification Logic** (`lazarus-cli/src/commands/verify.rs`) - Full integrity checks
✅ **gRPC Protocol** (`lazarus-common/proto/`) - Well-designed agent-server API
✅ **Ransomware Detection** (`lazarus-core/src/security/ransomware.rs`) - Impressive, just needs integration
✅ **Storage Abstraction** (`lazarus-core/src/storage/backend.rs`) - Clean trait design

---

## Recommendations

1. **Immediate Action (Week 1):** Focus on Phase A (production blockers). These are showstoppers.
2. **Week 2-3:** Phase B (core functionality). This brings the system to feature parity with the README claims.
3. **Week 4-6:** Phase C (BMR). This is complex and can be deferred for initial beta users who only need file-level restore.
4. **Documentation:** Update README.md to reflect "Beta" status and add "Known Limitations" section.
5. **Testing:** Before any public release, run multi-agent load tests and disaster recovery drills.

---

**End of Gap Analysis Report**
Generated: 2025-11-21
Auditor: Claude (Sonnet 4.5)
Lines of code reviewed: ~8,000+ across 50+ files
