//! Library surface for `lazarus-recovery`.
//!
//! The binary in `main.rs` provides the interactive recovery TUI. This
//! library re-exports the Phase 3 *capture* pipeline from `lazarus-core`
//! so the `lazarus-cli` crate (and tests) can drive `capture_system` and
//! the `FingerprintPersister` without dragging in the TUI dependencies.
//!
//! TODO(phase-future): expose libvirt VM-level fingerprints alongside the
//! per-host `SystemFingerprint`.

pub use lazarus_core::capture;
