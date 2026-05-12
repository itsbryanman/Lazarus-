//! Library surface for `lazarus-recovery`.
//!
//! The binary in `main.rs` provides the interactive recovery TUI. This
//! library exposes the Phase 3 *capture* pipeline so the `lazarus-cli`
//! crate (and tests) can drive `capture_system` and the
//! `FingerprintPersister` without dragging in the TUI dependencies.
//!
//! TODO(phase-future): expose libvirt VM-level fingerprints alongside the
//! per-host `SystemFingerprint`.

pub mod capture;
