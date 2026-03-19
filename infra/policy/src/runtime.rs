use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};

use af_policy::StaticPolicyDocument;
use tracing::{info, warn};

use crate::debounce::merge_debounced;
use crate::yaml_parser::LoadedStaticPolicy;
use crate::{
    PolicyDirectoryLoader, PolicyDirectoryWatcher, PolicyInfraError, PolicyInfraResult,
    PolicyReloadError, PolicyRuntimeConfig, PolicyStatus, YamlParser,
};

pub struct PolicyRuntime {
    config: PolicyRuntimeConfig,
    state: Arc<RwLock<RuntimeState>>,
    stop_tx: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
pub struct ActiveStaticPolicy {
    pub revision: u64,
    pub file_count: usize,
    pub document: Arc<StaticPolicyDocument>,
}

#[derive(Debug)]
struct RuntimeState {
    active: ActiveStaticPolicy,
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
        let initial = load_static_policy(&config, 1)?;
        let state = Arc::new(RwLock::new(RuntimeState {
            active: initial,
            last_reload_error: None,
        }));

        let watcher = PolicyDirectoryWatcher::start(config.root.clone())?;
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

    pub fn active_static_policy(&self) -> PolicyInfraResult<ActiveStaticPolicy> {
        Ok(self.read_state()?.active.clone())
    }

    pub fn status(&self) -> PolicyInfraResult<PolicyStatus> {
        let state = self.read_state()?;
        Ok(PolicyStatus {
            revision: state.active.revision,
            file_count: state.active.file_count,
            static_policy_revision: state.active.document.revision,
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

        let first = match watcher.recv_timeout(config.poll_interval) {
            Ok(Some(event)) => event,
            Ok(None) => continue,
            Err(error) => {
                stop_worker(&state, "policy watcher stopped", &error);
                return;
            }
        };

        let merged = match merge_debounced(first, config.debounce, |timeout| {
            watcher.recv_timeout(timeout)
        }) {
            Ok(event) => event,
            Err(error) => {
                stop_worker(&state, "policy watcher debounce failed", &error);
                return;
            }
        };

        let next_runtime_revision = match state.read() {
            Ok(guard) => guard.active.revision + 1,
            Err(_) => {
                warn!("policy runtime state poisoned before reload");
                return;
            }
        };

        match load_static_policy(&config, next_runtime_revision) {
            Ok(active) => {
                let static_policy_revision = active.document.revision;
                let file_count = active.file_count;
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
                    static_policy_revision,
                    file_count,
                    changed_paths = ?merged.paths,
                    "policy reload applied"
                );
            }
            Err(error) => {
                warn!(
                    runtime_revision = next_runtime_revision,
                    changed_paths = ?merged.paths,
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

fn load_static_policy(
    config: &PolicyRuntimeConfig,
    runtime_revision: u64,
) -> PolicyInfraResult<ActiveStaticPolicy> {
    let loaded: LoadedStaticPolicy =
        YamlParser.parse_static_policy(PolicyDirectoryLoader::new(config.root.clone()).load()?)?;

    Ok(ActiveStaticPolicy {
        revision: runtime_revision,
        file_count: loaded.snapshot.file_count(),
        document: Arc::new(loaded.document),
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
            PolicyRuntimeConfig::new(&root)
                .with_debounce(Duration::from_millis(30))
                .with_poll_interval(Duration::from_millis(20)),
        )
        .expect("start runtime");

        let active = runtime
            .active_static_policy()
            .expect("read active policy snapshot");
        assert_eq!(active.revision, 1);
        assert_eq!(active.document.revision, 1);
        assert_eq!(active.file_count, 1);
    }

    #[test]
    fn hot_reload_applies_policy_updates_atomically() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("static_policy.yaml"), policy_yaml(1)).expect("write policy");

        let runtime = PolicyRuntime::start(
            PolicyRuntimeConfig::new(&root)
                .with_debounce(Duration::from_millis(30))
                .with_poll_interval(Duration::from_millis(20)),
        )
        .expect("start runtime");

        fs::write(root.join("static_policy.yaml"), policy_yaml(2)).expect("update policy");
        wait_until_runtime_revision(&runtime, 2);

        let active = runtime.active_static_policy().expect("read active policy");
        assert_eq!(active.revision, 2);
        assert_eq!(active.document.revision, 2);
    }

    #[test]
    fn failed_reload_keeps_previous_snapshot_and_records_error() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("static_policy.yaml"), policy_yaml(1)).expect("write policy");

        let runtime = PolicyRuntime::start(
            PolicyRuntimeConfig::new(&root)
                .with_debounce(Duration::from_millis(30))
                .with_poll_interval(Duration::from_millis(20)),
        )
        .expect("start runtime");

        fs::write(
            root.join("static_policy.yaml"),
            "version: 1\nrevision: bad\ndefault_action: deny\n",
        )
        .expect("write invalid policy");

        wait_until_error(&runtime);
        let active = runtime.active_static_policy().expect("active policy");
        assert_eq!(active.document.revision, 1);
        assert_eq!(active.revision, 1);
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
  capability_matrix:
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
