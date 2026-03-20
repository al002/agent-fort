use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};

use af_policy::{CommandRuleSet, StaticPolicy};
use tracing::{info, warn};

use crate::command_rule_loader::LoadedCommandRules;
use crate::static_policy_parser::LoadedPolicy;
use crate::{
    CommandRuleLoader, PolicyDirectoryWatcher, PolicyInfraError, PolicyInfraResult,
    PolicyReloadError, PolicyRuntimeConfig, PolicyStatus, StaticPolicyParser,
};

pub struct PolicyRuntime {
    config: PolicyRuntimeConfig,
    state: Arc<RwLock<RuntimeState>>,
    stop_tx: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
pub struct ActivePolicy {
    pub revision: u64,
    pub policy: Arc<StaticPolicy>,
    pub command_rules: Arc<CommandRuleSet>,
}

#[derive(Debug)]
struct RuntimeState {
    active: ActivePolicy,
    last_reload_error: Option<PolicyReloadError>,
}

impl std::fmt::Debug for PolicyRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolicyRuntime")
            .field("config", &self.config)
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl PolicyRuntime {
    pub fn start(config: PolicyRuntimeConfig) -> PolicyInfraResult<Self> {
        let initial = load_policy_bundle(&config, 1)?;
        let state = Arc::new(RwLock::new(RuntimeState {
            active: initial,
            last_reload_error: None,
        }));

        let watcher = PolicyDirectoryWatcher::start_many(config.watch_roots())?;
        let (stop_tx, stop_rx) = mpsc::channel();
        let worker_state = Arc::clone(&state);
        let worker_config = config.clone();
        let worker = thread::spawn(move || {
            run_reload_worker(worker_config, watcher, worker_state, stop_rx);
        });

        Ok(Self {
            config,
            state,
            stop_tx,
            worker: Some(worker),
        })
    }

    pub fn config(&self) -> &PolicyRuntimeConfig {
        &self.config
    }

    pub fn active_policy(&self) -> PolicyInfraResult<ActivePolicy> {
        Ok(self.read_state()?.active.clone())
    }

    pub fn status(&self) -> PolicyInfraResult<PolicyStatus> {
        let state = self.read_state()?;
        Ok(PolicyStatus {
            revision: state.active.revision,
            policy_revision: state.active.policy.revision,
            command_rules_revision: state.active.command_rules.revision,
            command_rules_count: state.active.command_rules.rules.len(),
            last_reload_error: state.last_reload_error.clone(),
        })
    }

    fn read_state(&self) -> PolicyInfraResult<std::sync::RwLockReadGuard<'_, RuntimeState>> {
        self.state
            .read()
            .map_err(|_| PolicyInfraError::RuntimeStatePoisoned)
    }
}

impl Drop for PolicyRuntime {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_reload_worker(
    config: PolicyRuntimeConfig,
    watcher: PolicyDirectoryWatcher,
    state: Arc<RwLock<RuntimeState>>,
    stop_rx: mpsc::Receiver<()>,
) {
    loop {
        if stop_rx.try_recv().is_ok() {
            return;
        }

        let changed = match watcher.recv_timeout(config.poll_interval) {
            Ok(Some(())) => true,
            Ok(None) => continue,
            Err(error) => {
                stop_worker(&state, "policy watcher stopped", &error);
                return;
            }
        };
        if !changed {
            continue;
        }

        let next_runtime_revision = match state.read() {
            Ok(guard) => guard.active.revision + 1,
            Err(_) => {
                warn!("policy runtime state poisoned before reload");
                return;
            }
        };

        match load_policy_bundle(&config, next_runtime_revision) {
            Ok(active) => {
                let policy_revision = active.policy.revision;
                let command_rules_count = active.command_rules.rules.len();
                match state.write() {
                    Ok(mut guard) => {
                        guard.active = active;
                        guard.last_reload_error = None;
                    }
                    Err(_) => {
                        warn!("policy runtime state poisoned while applying reload");
                        return;
                    }
                }
                info!(
                    runtime_revision = next_runtime_revision,
                    policy_revision, command_rules_count, "policy reload applied"
                );
            }
            Err(error) => {
                warn!(
                    runtime_revision = next_runtime_revision,
                    error = %error,
                    "policy reload rejected; keeping previous snapshot"
                );
                record_reload_error(&state, Some(next_runtime_revision), error.to_string());
            }
        }
    }
}

fn stop_worker(
    state: &Arc<RwLock<RuntimeState>>,
    message: &'static str,
    error: &impl std::fmt::Display,
) {
    warn!(error = %error, "{message}");
    record_reload_error(state, None, error.to_string());
}

fn record_reload_error(
    state: &Arc<RwLock<RuntimeState>>,
    attempted_revision: Option<u64>,
    message: String,
) {
    if let Ok(mut guard) = state.write() {
        guard.last_reload_error = Some(PolicyReloadError {
            attempted_revision: attempted_revision.unwrap_or(guard.active.revision + 1),
            message,
        });
    }
}

fn load_policy_bundle(
    config: &PolicyRuntimeConfig,
    runtime_revision: u64,
) -> PolicyInfraResult<ActivePolicy> {
    let loaded_policy: LoadedPolicy = StaticPolicyParser.parse(&config.root)?;
    let loaded_rules: LoadedCommandRules =
        if let Some(command_rules) = config.command_rules.as_ref() {
            CommandRuleLoader.load(&command_rules.root, command_rules.strict, runtime_revision)?
        } else {
            LoadedCommandRules {
                rules: CommandRuleSet {
                    revision: runtime_revision,
                    rules: Vec::new(),
                },
            }
        };

    Ok(ActivePolicy {
        revision: runtime_revision,
        policy: Arc::new(loaded_policy.policy),
        command_rules: Arc::new(loaded_rules.rules),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn loads_initial_static_policy_before_starting_reload_worker() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("static_policy.yaml"), policy_yaml(1)).expect("write policy");

        let runtime = PolicyRuntime::start(
            PolicyRuntimeConfig::new(&root).with_poll_interval(Duration::from_millis(20)),
        )
        .expect("start runtime");

        let active = runtime
            .active_policy()
            .expect("read active policy snapshot");
        assert_eq!(active.revision, 1);
        assert_eq!(active.policy.revision, 1);
    }

    #[test]
    fn hot_reload_applies_policy_updates_atomically() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("static_policy.yaml"), policy_yaml(1)).expect("write policy");

        let runtime = PolicyRuntime::start(
            PolicyRuntimeConfig::new(&root).with_poll_interval(Duration::from_millis(20)),
        )
        .expect("start runtime");

        fs::write(root.join("static_policy.yaml"), policy_yaml(2)).expect("update policy");
        wait_until_runtime_revision(&runtime, 2);

        let active = runtime.active_policy().expect("read active policy");
        assert_eq!(active.revision, 2);
        assert_eq!(active.policy.revision, 2);
    }

    #[test]
    fn failed_reload_keeps_previous_snapshot_and_records_error() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("static_policy.yaml"), policy_yaml(1)).expect("write policy");

        let runtime = PolicyRuntime::start(
            PolicyRuntimeConfig::new(&root).with_poll_interval(Duration::from_millis(20)),
        )
        .expect("start runtime");

        fs::write(
            root.join("static_policy.yaml"),
            "version: 1\nrevision: bad\ndefault_action: deny\n",
        )
        .expect("write invalid policy");

        wait_until_error(&runtime);
        let active = runtime.active_policy().expect("active policy");
        assert_eq!(active.policy.revision, 1);
        assert_eq!(active.revision, 1);
    }

    #[test]
    fn loads_and_hot_reloads_command_rules() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let policy_root = temp_dir.path().join("policies");
        let rule_root = temp_dir.path().join("command-rules");
        fs::create_dir_all(&policy_root).expect("create policy dir");
        fs::create_dir_all(&rule_root).expect("create rule dir");
        fs::write(policy_root.join("static_policy.yaml"), policy_yaml(1)).expect("write policy");
        fs::write(
            rule_root.join("00-base.rules"),
            r#"
command_rule(
    pattern = ["echo"],
    capabilities = cap(),
)
"#,
        )
        .expect("write initial rules");

        let runtime = PolicyRuntime::start(
            PolicyRuntimeConfig::new(&policy_root)
                .with_command_rules(&rule_root, true)
                .with_poll_interval(Duration::from_millis(20)),
        )
        .expect("start runtime");
        let active = runtime.active_policy().expect("read active policy");
        assert_eq!(active.command_rules.rules.len(), 1);

        fs::write(
            rule_root.join("10-extra.rules"),
            r#"
command_rule(
    pattern = ["ls"],
    capabilities = cap(),
)
"#,
        )
        .expect("write updated rules");
        wait_until_runtime_revision(&runtime, 2);

        let active = runtime.active_policy().expect("read active policy");
        assert_eq!(active.command_rules.rules.len(), 2);
    }

    fn wait_until_runtime_revision(runtime: &PolicyRuntime, target_revision: u64) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let status = runtime.status().expect("runtime status");
            if status.revision >= target_revision {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timeout waiting policy runtime reload"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_until_error(runtime: &PolicyRuntime) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let status = runtime.status().expect("runtime status");
            if status.last_reload_error.is_some() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timeout waiting policy runtime error"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn policy_yaml(revision: u64) -> String {
        format!(
            r#"
version: 1
revision: {revision}
default_action: deny
capabilities:
  fs_read: ["/work/**"]
  fs_write: ["/work/**"]
  fs_delete: ["/work/**"]
  net_connect: []
  allow_host_exec: false
  allow_process_control: false
  allow_privilege: false
  allow_credential_access: false
backends:
  backend_order: ["sandbox"]
  capability_limits:
    sandbox:
      fs_read: ["/work/**"]
      fs_write: ["/work/**"]
      fs_delete: ["/work/**"]
      net_connect: []
      allow_host_exec: false
      allow_process_control: false
      allow_privilege: false
      allow_credential_access: false
  profiles:
    sandbox:
      type: sandbox
      profile_id: "sandbox-default"
      network_default: "deny"
      writable_roots: ["/work/**"]
      readonly_roots: ["/usr/**"]
      syscall_policy: "baseline"
      limits:
        cpu_ms: 1000
        memory_mb: 128
        pids: 64
        disk_mb: 256
        timeout_ms: 60000
"#
        )
    }
}
