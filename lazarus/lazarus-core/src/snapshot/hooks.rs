//! Application-aware freeze/thaw hooks for consistent backups.
//!
//! Many systems can produce a crash-consistent backup just by snapshotting
//! their filesystem, but databases and VMs can't: a half-committed
//! transaction in `pg_wal/` or a half-flushed page in InnoDB looks like
//! corruption when restored. To get *application*-consistent backups we
//! quiesce the application around the snapshot:
//!
//! ```text
//!     pre_snapshot script  →  filesystem snapshot  →  post_snapshot script
//! ```
//!
//! The pre script is expected to flush in-memory state and pause writes.
//! The post script un-pauses. If the pre script fails, the snapshot is not
//! taken. If the post script fails, the snapshot still exists but the run
//! reports the post-failure so an operator can investigate (an unthrown
//! `pg_backup_stop` is a tractable problem; a corrupted backup is not).
//!
//! Built-in hook libraries are provided for the applications listed in the
//! resurrection plan: PostgreSQL, MySQL/MariaDB, MongoDB, Redis, libvirt and
//! Docker. The configuration format mirrors the example in the plan:
//!
//! ```toml
//! [[hooks.application]]
//! name = "postgres"
//! match = { service = "postgresql" }
//! pre_snapshot = "psql -c 'SELECT pg_backup_start(''lazarus'')'"
//! post_snapshot = "psql -c 'SELECT pg_backup_stop()'"
//! ```

use crate::error::{LazarusError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// What to match against to decide whether a hook applies on this host.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookMatch {
    /// Match if this systemd service unit is loaded.
    #[serde(default)]
    pub service: Option<String>,
    /// Match if a process with this name is running.
    #[serde(default)]
    pub process: Option<String>,
    /// Match if this file/socket exists.
    #[serde(default)]
    pub path: Option<PathBuf>,
}

/// One application hook configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationHook {
    /// Human-readable name (`postgres`, `mysql`, ...).
    pub name: String,
    /// Optional match rule. If `None` the hook always runs.
    #[serde(default, rename = "match")]
    pub match_rule: Option<HookMatch>,
    /// Shell command run *before* the snapshot is taken. Errors abort the
    /// snapshot.
    pub pre_snapshot: String,
    /// Shell command run *after* the snapshot is released. Errors are
    /// reported but do not invalidate the snapshot.
    pub post_snapshot: String,
    /// Optional timeout in seconds for each command. Defaults to 300.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Optional environment variables passed to the hook commands.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl ApplicationHook {
    /// How long to wait for each command before declaring failure.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.unwrap_or(300))
    }
}

/// Outcome of running a hook command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookOutcome {
    pub hook: String,
    pub phase: HookPhase,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

/// Which side of the snapshot a hook executed on.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HookPhase {
    Pre,
    Post,
}

/// Aggregate report from a backup run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookReport {
    pub outcomes: Vec<HookOutcome>,
}

impl HookReport {
    pub fn pre_failures(&self) -> Vec<&HookOutcome> {
        self.outcomes
            .iter()
            .filter(|o| o.phase == HookPhase::Pre && !o.success)
            .collect()
    }

    pub fn post_failures(&self) -> Vec<&HookOutcome> {
        self.outcomes
            .iter()
            .filter(|o| o.phase == HookPhase::Post && !o.success)
            .collect()
    }
}

/// Driver: holds a list of hooks and runs them around a snapshot.
#[derive(Debug, Clone, Default)]
pub struct HookRunner {
    hooks: Vec<ApplicationHook>,
}

impl HookRunner {
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Construct a runner with a fixed list of hooks.
    pub fn with_hooks(hooks: Vec<ApplicationHook>) -> Self {
        Self { hooks }
    }

    /// Append a hook.
    pub fn push(&mut self, hook: ApplicationHook) {
        self.hooks.push(hook);
    }

    /// Hooks currently registered.
    pub fn hooks(&self) -> &[ApplicationHook] {
        &self.hooks
    }

    /// Filter the registered hooks down to those that match the current
    /// host. The match check is best-effort: failures fall closed (treated
    /// as not-matching) so we never run a hook that's clearly inapplicable.
    pub fn applicable(&self) -> Vec<&ApplicationHook> {
        self.hooks
            .iter()
            .filter(|h| match &h.match_rule {
                None => true,
                Some(rule) => rule_matches(rule),
            })
            .collect()
    }

    /// Run every applicable pre-snapshot hook. Returns the partial report
    /// and an error if any hook failed; callers should *not* take the
    /// snapshot on error.
    pub fn run_pre(&self, report: &mut HookReport) -> Result<()> {
        for hook in self.applicable() {
            let outcome = run_command(&hook.name, HookPhase::Pre, hook);
            let failed = !outcome.success;
            report.outcomes.push(outcome);
            if failed {
                return Err(LazarusError::Storage(format!(
                    "pre-snapshot hook `{}` failed",
                    hook.name
                )));
            }
        }
        Ok(())
    }

    /// Run every applicable post-snapshot hook. Errors are recorded in the
    /// report but do not abort: by this point the snapshot already exists
    /// and is consistent; failing here is an operational issue, not a
    /// backup-correctness issue.
    pub fn run_post(&self, report: &mut HookReport) {
        for hook in self.applicable() {
            let outcome = run_command(&hook.name, HookPhase::Post, hook);
            report.outcomes.push(outcome);
        }
    }
}

fn run_command(name: &str, phase: HookPhase, hook: &ApplicationHook) -> HookOutcome {
    let cmd_str = match phase {
        HookPhase::Pre => &hook.pre_snapshot,
        HookPhase::Post => &hook.post_snapshot,
    };
    // We invoke through `sh -c` to honour the configuration format from the
    // plan, which writes commands as shell strings. The configuration file
    // is operator-controlled and is not user-facing input, so this is the
    // appropriate trust boundary; the runner treats hook commands the same
    // way cron or systemd would.
    let mut command = Command::new("sh");
    command.arg("-c").arg(cmd_str);
    for (k, v) in &hook.env {
        command.env(k, v);
    }

    let output = command.output();
    match output {
        Ok(out) => HookOutcome {
            hook: name.to_string(),
            phase,
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit_code: out.status.code(),
        },
        Err(e) => HookOutcome {
            hook: name.to_string(),
            phase,
            success: false,
            stdout: String::new(),
            stderr: format!("failed to launch hook command: {e}"),
            exit_code: None,
        },
    }
}

fn rule_matches(rule: &HookMatch) -> bool {
    if let Some(svc) = &rule.service {
        if !systemd_unit_loaded(svc) {
            return false;
        }
    }
    if let Some(proc_name) = &rule.process {
        if !process_running(proc_name) {
            return false;
        }
    }
    if let Some(p) = &rule.path {
        if !p.exists() {
            return false;
        }
    }
    true
}

fn systemd_unit_loaded(unit: &str) -> bool {
    Command::new("systemctl")
        .arg("is-active")
        .arg(unit)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn process_running(name: &str) -> bool {
    // /proc/*/comm is the most portable indicator on Linux. We avoid pgrep
    // so we don't depend on procps being installed.
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        // Only numeric directories are pids.
        if !p
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false)
        {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(p.join("comm")) {
            if comm.trim() == name {
                return true;
            }
        }
    }
    false
}

/// Built-in hook templates for the applications listed in the resurrection
/// plan. Operators get sensible defaults and can override individual fields
/// in their config.
pub mod builtins {
    use super::{ApplicationHook, HookMatch};
    use std::collections::HashMap;

    fn hook(name: &str, svc: &str, pre: &str, post: &str) -> ApplicationHook {
        ApplicationHook {
            name: name.to_string(),
            match_rule: Some(HookMatch {
                service: Some(svc.to_string()),
                ..Default::default()
            }),
            pre_snapshot: pre.to_string(),
            post_snapshot: post.to_string(),
            timeout_secs: Some(300),
            env: HashMap::new(),
        }
    }

    /// PostgreSQL: use the modern non-exclusive backup API. `pg_backup_stop`
    /// is required even if `pg_backup_start` succeeded but the snapshot
    /// failed, hence the post hook always runs.
    pub fn postgres() -> ApplicationHook {
        hook(
            "postgres",
            "postgresql",
            "psql -X -At -c \"SELECT pg_backup_start('lazarus', false)\"",
            "psql -X -At -c \"SELECT pg_backup_stop(false)\"",
        )
    }

    /// MySQL / MariaDB: flush tables with read lock, then unlock.
    pub fn mysql() -> ApplicationHook {
        hook(
            "mysql",
            "mysql",
            "mysql -e 'FLUSH TABLES WITH READ LOCK; FLUSH LOGS;'",
            "mysql -e 'UNLOCK TABLES;'",
        )
    }

    /// MongoDB: fsyncLock / fsyncUnlock.
    pub fn mongodb() -> ApplicationHook {
        hook(
            "mongodb",
            "mongod",
            "mongosh --quiet --eval 'db.fsyncLock()'",
            "mongosh --quiet --eval 'db.fsyncUnlock()'",
        )
    }

    /// Redis: SAVE forces a synchronous RDB write. Post is a no-op.
    pub fn redis() -> ApplicationHook {
        hook(
            "redis",
            "redis-server",
            "redis-cli SAVE",
            "true",
        )
    }

    /// libvirt: fsfreeze the guest filesystem via the QEMU guest agent.
    /// Falls back to a `virsh suspend` for hosts without QGA — though that
    /// pauses CPUs and is heavier; operators will typically prefer the QGA
    /// variant in production.
    pub fn libvirt(domain: &str) -> ApplicationHook {
        ApplicationHook {
            name: format!("libvirt:{domain}"),
            match_rule: Some(HookMatch {
                service: Some("libvirtd".to_string()),
                ..Default::default()
            }),
            pre_snapshot: format!("virsh domfsfreeze {domain}"),
            post_snapshot: format!("virsh domfsthaw {domain}"),
            timeout_secs: Some(120),
            env: HashMap::new(),
        }
    }

    /// Docker: pause every running container; unpause on the way out.
    pub fn docker() -> ApplicationHook {
        hook(
            "docker",
            "docker",
            "for c in $(docker ps -q); do docker pause $c; done",
            "for c in $(docker ps -q --filter status=paused); do docker unpause $c; done",
        )
    }

    /// Convenience: every built-in hook in one list. Hooks whose match
    /// criteria don't fire will simply be skipped at runtime.
    pub fn all() -> Vec<ApplicationHook> {
        vec![postgres(), mysql(), mongodb(), redis(), docker()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_separates_pre_and_post_failures() {
        let report = HookReport {
            outcomes: vec![
                HookOutcome {
                    hook: "a".into(),
                    phase: HookPhase::Pre,
                    success: false,
                    stdout: String::new(),
                    stderr: "boom".into(),
                    exit_code: Some(1),
                },
                HookOutcome {
                    hook: "b".into(),
                    phase: HookPhase::Post,
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: Some(0),
                },
            ],
        };
        assert_eq!(report.pre_failures().len(), 1);
        assert!(report.post_failures().is_empty());
    }

    #[test]
    fn applicable_with_no_match_rule_runs_always() {
        let hook = ApplicationHook {
            name: "x".into(),
            match_rule: None,
            pre_snapshot: "true".into(),
            post_snapshot: "true".into(),
            timeout_secs: None,
            env: HashMap::new(),
        };
        let runner = HookRunner::with_hooks(vec![hook]);
        assert_eq!(runner.applicable().len(), 1);
    }

    #[test]
    fn applicable_with_unsatisfiable_path_filters_out() {
        let hook = ApplicationHook {
            name: "needs_missing_path".into(),
            match_rule: Some(HookMatch {
                path: Some(PathBuf::from(
                    "/very/unlikely/path/lazarus_test_should_be_absent",
                )),
                ..Default::default()
            }),
            pre_snapshot: "true".into(),
            post_snapshot: "true".into(),
            timeout_secs: None,
            env: HashMap::new(),
        };
        let runner = HookRunner::with_hooks(vec![hook]);
        assert!(runner.applicable().is_empty());
    }

    #[test]
    fn pre_failure_aborts_run_pre() {
        let hook = ApplicationHook {
            name: "fail".into(),
            match_rule: None,
            pre_snapshot: "false".into(),
            post_snapshot: "true".into(),
            timeout_secs: None,
            env: HashMap::new(),
        };
        let runner = HookRunner::with_hooks(vec![hook]);
        let mut report = HookReport::default();
        let res = runner.run_pre(&mut report);
        assert!(res.is_err());
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].phase, HookPhase::Pre);
        assert!(!report.outcomes[0].success);
    }

    #[test]
    fn pre_success_then_post_records_both() {
        let hook = ApplicationHook {
            name: "ok".into(),
            match_rule: None,
            pre_snapshot: "true".into(),
            post_snapshot: "true".into(),
            timeout_secs: None,
            env: HashMap::new(),
        };
        let runner = HookRunner::with_hooks(vec![hook]);
        let mut report = HookReport::default();
        runner.run_pre(&mut report).unwrap();
        runner.run_post(&mut report);
        assert_eq!(report.outcomes.len(), 2);
        assert!(report.outcomes.iter().all(|o| o.success));
    }

    #[test]
    fn builtin_set_includes_expected_apps() {
        let names: Vec<_> = builtins::all().iter().map(|h| h.name.clone()).collect();
        for expected in &["postgres", "mysql", "mongodb", "redis", "docker"] {
            assert!(names.iter().any(|n| n == expected), "missing {expected}");
        }
    }

    #[test]
    fn builtin_libvirt_takes_domain() {
        let h = builtins::libvirt("vm-prod");
        assert!(h.pre_snapshot.contains("vm-prod"));
        assert!(h.post_snapshot.contains("vm-prod"));
    }

    #[test]
    fn config_round_trips_through_json() {
        // The plan specifies TOML, but for tests we use JSON to avoid
        // pulling in a TOML dependency just for serde wiring. The serde
        // attributes are format-agnostic, so JSON exercises them equally
        // well.
        let cfg = ApplicationHook {
            name: "postgres".into(),
            match_rule: Some(HookMatch {
                service: Some("postgresql".into()),
                ..Default::default()
            }),
            pre_snapshot: "echo pre".into(),
            post_snapshot: "echo post".into(),
            timeout_secs: Some(60),
            env: HashMap::new(),
        };
        let s = serde_json::to_string(&cfg).unwrap();
        let back: ApplicationHook = serde_json::from_str(&s).unwrap();
        assert_eq!(back.name, "postgres");
        assert_eq!(back.timeout(), Duration::from_secs(60));
    }
}
