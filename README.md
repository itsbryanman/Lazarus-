# Lazarus

[![GitHub Repo](https://img.shields.io/badge/GitHub-itsbryanman%2FLazarus--181717?style=for-the-badge&logo=github)](https://github.com/itsbryanman/Lazarus-)
[![Stars](https://img.shields.io/github/stars/itsbryanman/Lazarus-?style=for-the-badge&logo=github)](https://github.com/itsbryanman/Lazarus-/stargazers)
[![Forks](https://img.shields.io/github/forks/itsbryanman/Lazarus-?style=for-the-badge&logo=github)](https://github.com/itsbryanman/Lazarus-/network/members)
[![Issues](https://img.shields.io/github/issues/itsbryanman/Lazarus-?style=for-the-badge&logo=github)](https://github.com/itsbryanman/Lazarus-/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/itsbryanman/Lazarus-?style=for-the-badge&logo=github)](https://github.com/itsbryanman/Lazarus-/pulls)
[![CI](https://img.shields.io/github/actions/workflow/status/itsbryanman/Lazarus-/ci.yml?branch=master&style=for-the-badge&logo=githubactions)](https://github.com/itsbryanman/Lazarus-/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/itsbryanman/Lazarus-?style=for-the-badge&logo=github)](https://github.com/itsbryanman/Lazarus-/releases/latest)
[![Crates.io](https://img.shields.io/crates/v/lazarus?style=for-the-badge&logo=rust)](https://crates.io/crates/lazarus)
[![Docs.rs](https://img.shields.io/docsrs/lazarus?style=for-the-badge&logo=docs.rs)](https://docs.rs/lazarus)
[![License](https://img.shields.io/github/license/itsbryanman/Lazarus-?style=for-the-badge)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/itsbryanman/Lazarus-?style=for-the-badge&logo=github)](https://github.com/itsbryanman/Lazarus-/commits/main/)
[![Top Language](https://img.shields.io/github/languages/top/itsbryanman/Lazarus-?style=for-the-badge)](https://github.com/itsbryanman/Lazarus-)
[![Repo Size](https://img.shields.io/github/repo-size/itsbryanman/Lazarus-?style=for-the-badge)](https://github.com/itsbryanman/Lazarus-)

```
 #                                                 
#         ##   ######   ##   #####  #    #  ####  
#        #  #      #   #  #  #    # #    # #      
#       #    #    #   #    # #    # #    #  ####  
#       ######   #    ###### #####  #    #      # 
#       #    #  #     #    # #   #  #    # #    # 
####### #    # ###### #    # #    #  ####   ####  
```

> **"The Unkillable, Enterprise-Grade Backup Solution for Bare Metal & Cloud."**

Lazarus is the ops team’s bunker. It streams multi-terabyte disks with megabytes of RAM, atomically commits every chunk, and lets you rotate master keys whenever policy demands—all while the server orchestrates restore/prune jobs across fleets.

## Feature Highlights

- 🛡️ **AES-256-GCM Encryption** with Master Key Rotation – zero-knowledge client-side crypto plus instant credential rollover.
- ⚡ **Zero-Copy Streaming Pipeline** – feed BufReader chunks to hashing/compression/encryption workers; never OOM again.
- ⚛️ **Atomic Writes** – write → fsync → rename guarantees crash-proof durability on local targets.
- 🕸️ **Server Orchestrated** – Agents execute Backup/Restore/Prune jobs driven by the control plane.

## Professional Usage

```bash
# Install (from source)
git clone https://github.com/itsbryanman/Lazarus-.git
cd Lazarus/lazarus
cargo build --release
```

```bash
# Initialize a hardened repository
./target/release/lazarus-cli init \
  --repository /srv/lazarus/repo \
  --password 'UltraSecret!'
```

```bash
# Consistent file backup. With the default snapshotter selection, application
# hooks run only around OS snapshot creation: pre hook → snapshot → post hook →
# capture from snapshot → release snapshot.
./target/release/lazarus-cli backup \
  --source /srv/data \
  --repository /srv/lazarus/repo \
  --password 'UltraSecret!' \
  --consistent
```

```bash
# Hooks-only consistency. No OS snapshot is taken, so pre/post hooks bracket
# the full capture and may hold database locks or paused containers until the
# backup completes.
./target/release/lazarus-cli backup \
  --source /srv/data \
  --repository /srv/lazarus/repo \
  --password 'UltraSecret!' \
  --consistent \
  --snapshotter none
```

```bash
# Block-mode backup and sparse-file restore. Block snapshots record allocated
# extents and chunk offsets so restore can preserve sparse holes.
./target/release/lazarus-cli backup \
  --block-mode \
  --device /dev/vg0/root-snap \
  --repository /srv/lazarus/repo \
  --password 'UltraSecret!'

./target/release/lazarus-cli restore \
  --snapshot 2026-05-12T11:23:08 \
  --destination /tmp/root.img \
  --repository /srv/lazarus/repo \
  --password 'UltraSecret!' \
  --verify

# To restore to an existing raw device instead, use --device. Lazarus refuses
# targets smaller than the recorded device size.
./target/release/lazarus-cli restore \
  --snapshot 2026-05-12T11:23:08 \
  --device /dev/vg0/root-restore \
  --repository /srv/lazarus/repo \
  --password 'UltraSecret!'
```

```bash
# Rotate the master key when credentials change
./target/release/lazarus-cli security rotate-key \
  --repository /srv/lazarus/repo
# Prompts for old + new password (with confirmation)
```

Need the whole stack?

```
lazarus/
├── lazarus-core     # Chunking, streaming, encryption, catalog
├── lazarus-cli      # Operator workflows (init/backup/restore/security)
├── lazarus-server   # gRPC controller & job scheduler
├── lazarus-agent    # Managed endpoint daemon
├── lazarus-recovery # Bare metal / ISO generation
└── lazarus-common   # Shared DTOs/utilities
```

## License

MIT License – see [LICENSE](LICENSE).
