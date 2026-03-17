use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};

use tracing::{info, warn};

use crate::debounce::merge_debounced;
use crate::{
    CelCompiler, CompiledPolicies, PolicyDirectoryLoader, PolicyDirectoryWatcher, PolicyInfraError,
    PolicyInfraResult, PolicyReloadError, PolicyRuntimeConfig, PolicyStatus, YamlParser,
};

pub struct PolicyRuntime {
    config: PolicyRuntimeConfig,
    state: Arc<RwLock<RuntimeState>>,
    stop_tx: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Debug)]
struct RuntimeState {
    active: Arc<CompiledPolicies>,
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
        let initial = load_and_compile(&config, 1)?;
        let state = Arc::new(RwLock::new(RuntimeState {
            active: Arc::new(initial),
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

    pub fn compiled(&self) -> PolicyInfraResult<Arc<CompiledPolicies>> {
        Ok(Arc::clone(&self.read_state()?.active))
    }

    pub fn status(&self) -> PolicyInfraResult<PolicyStatus> {
        let state = self.read_state()?;
        Ok(PolicyStatus {
            revision: state.active.revision,
            file_count: state.active.file_count(),
            rule_count: state.active.rule_count(),
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

        let next_revision = match state.read() {
            Ok(guard) => guard.active.revision + 1,
            Err(_) => {
                warn!("policy runtime state poisoned before reload");
                return;
            }
        };

        match load_and_compile(&config, next_revision) {
            Ok(compiled) => {
                let file_count = compiled.file_count();
                let rule_count = compiled.rule_count();
                match state.write() {
                    Ok(mut guard) => {
                        guard.active = Arc::new(compiled);
                        guard.last_reload_error = None;
                    }
                    Err(_) => {
                        warn!("policy runtime state poisoned while applying reload");
                        return;
                    }
                }
                info!(
                    revision = next_revision,
                    file_count,
                    rule_count,
                    changed_paths = ?merged.paths,
                    "policy reload applied"
                );
            }
            Err(error) => {
                warn!(
                    revision = next_revision,
                    changed_paths = ?merged.paths,
                    error = %error,
                    "policy reload rejected; keeping previous snapshot"
                );
                record_reload_error(&state, Some(next_revision), error.to_string());
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

fn load_and_compile(
    config: &PolicyRuntimeConfig,
    revision: u64,
) -> PolicyInfraResult<CompiledPolicies> {
    let snapshot = PolicyDirectoryLoader::new(config.root.clone()).load()?;
    let loaded = YamlParser.parse(snapshot)?;
    CelCompiler.compile(loaded, revision)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn loads_initial_compiled_snapshot_before_starting_reload_worker() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(
            root.join("base.yaml"),
            r#"
version: 1
rules:
  - id: allow-base
    kind: allow
    when: true
    effect:
      decision: allow
"#,
        )
        .expect("write base policy");

        let runtime = PolicyRuntime::start(
            PolicyRuntimeConfig::new(&root)
                .with_debounce(Duration::from_millis(30))
                .with_poll_interval(Duration::from_millis(20)),
        )
        .expect("start runtime");

        let compiled = runtime.compiled().expect("read compiled set");
        assert_eq!(compiled.revision, 1);
        assert_eq!(compiled.rule_count(), 1);
    }

    #[test]
    fn hot_reload_applies_create_update_and_delete_changes() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(
            root.join("base.yaml"),
            r#"
version: 1
rules:
  - id: allow-base
    kind: allow
    when: true
    effect:
      decision: allow
"#,
        )
        .expect("write base policy");

        let runtime = PolicyRuntime::start(
            PolicyRuntimeConfig::new(&root)
                .with_debounce(Duration::from_millis(30))
                .with_poll_interval(Duration::from_millis(20)),
        )
        .expect("start runtime");

        fs::write(
            root.join("extra.yaml"),
            r#"
version: 1
rules:
  - id: ask-network
    kind: approval
    when: facts.requires_network
    effect:
      decision: ask
"#,
        )
        .expect("create extra policy");
        wait_until_revision(&runtime, 2);
        assert_eq!(runtime.status().expect("status").rule_count, 2);

        fs::write(
            root.join("base.yaml"),
            r#"
version: 1
rules:
  - id: allow-base
    kind: allow
    when: false
    effect:
      decision: deny
"#,
        )
        .expect("update base policy");
        wait_until_revision(&runtime, 3);

        fs::remove_file(root.join("extra.yaml")).expect("delete extra policy");
        wait_until_revision(&runtime, 4);
        assert_eq!(runtime.status().expect("status").rule_count, 1);
    }

    #[test]
    fn failed_reload_keeps_previous_snapshot_and_records_error() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(
            root.join("base.yaml"),
            r#"
version: 1
rules:
  - id: allow-base
    kind: allow
    when: true
    effect:
      decision: allow
"#,
        )
        .expect("write base policy");

        let runtime = PolicyRuntime::start(
            PolicyRuntimeConfig::new(&root)
                .with_debounce(Duration::from_millis(30))
                .with_poll_interval(Duration::from_millis(20)),
        )
        .expect("start runtime");

        fs::write(
            root.join("base.yaml"),
            r#"
version: 1
rules:
  - id: allow-base
    kind: allow
    when: facts.
    effect:
      decision: allow
"#,
        )
        .expect("write invalid policy");

        wait_until_error(&runtime);
        let status = runtime.status().expect("status");
        assert_eq!(status.revision, 1);
        assert_eq!(status.rule_count, 1);
        assert!(status.last_reload_error.is_some());
    }

    fn wait_until_revision(runtime: &PolicyRuntime, expected_revision: u64) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let status = runtime.status().expect("status");
            if status.revision >= expected_revision {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "timed out waiting for policy revision {expected_revision}, current {:?}",
                    status
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_until_error(runtime: &PolicyRuntime) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let status = runtime.status().expect("status");
            if status.last_reload_error.is_some() {
                return;
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for reload error, current {:?}", status);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
