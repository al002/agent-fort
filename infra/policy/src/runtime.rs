use af_policy::{PolicyDirectorySnapshot, PolicyReloadReason, PolicyReloadRequest};

use crate::debounce::merge_debounced;
use crate::{
    PolicyDirectoryLoader, PolicyDirectorySourceConfig, PolicyDirectoryWatcher, PolicyInfraResult,
    PolicyRuntimeEvent,
};

pub struct PolicyDirectoryRuntime {
    config: PolicyDirectorySourceConfig,
    snapshot: PolicyDirectorySnapshot,
    watcher: PolicyDirectoryWatcher,
}

impl std::fmt::Debug for PolicyDirectoryRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolicyDirectoryRuntime")
            .field("config", &self.config)
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

impl PolicyDirectoryRuntime {
    pub fn start(config: PolicyDirectorySourceConfig) -> PolicyInfraResult<Self> {
        let snapshot = PolicyDirectoryLoader::new(config.root.clone()).load()?;
        let watcher = PolicyDirectoryWatcher::start(config.root.clone())?;
        Ok(Self {
            config,
            snapshot,
            watcher,
        })
    }

    pub fn config(&self) -> &PolicyDirectorySourceConfig {
        &self.config
    }

    pub fn snapshot(&self) -> &PolicyDirectorySnapshot {
        &self.snapshot
    }

    pub fn recv_event(&self) -> PolicyInfraResult<PolicyRuntimeEvent> {
        let first = self.watcher.recv()?;
        self.finish_reload_request(first)
    }

    pub fn recv_event_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> PolicyInfraResult<Option<PolicyRuntimeEvent>> {
        let first = match self.watcher.recv_timeout(timeout)? {
            Some(event) => event,
            None => return Ok(None),
        };

        self.finish_reload_request(first).map(Some)
    }

    fn finish_reload_request(
        &self,
        first: crate::PolicyWatchEvent,
    ) -> PolicyInfraResult<PolicyRuntimeEvent> {
        let _ = merge_debounced(first, self.config.debounce_window, |timeout| {
            self.watcher.recv_timeout(timeout)
        })?;
        Ok(self.reload_requested())
    }

    fn reload_requested(&self) -> PolicyRuntimeEvent {
        PolicyRuntimeEvent::ReloadRequested(PolicyReloadRequest {
            root: self.config.root.clone(),
            reason: PolicyReloadReason::FilesystemChange,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn loads_initial_snapshot_before_watching_for_changes() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("base.yaml"), "version: 1").expect("write policy file");

        let runtime = PolicyDirectoryRuntime::start(PolicyDirectorySourceConfig::new(&root))
            .expect("start policy runtime");

        assert_eq!(runtime.snapshot().file_count(), 1);
    }

    #[test]
    fn emits_debounced_reload_requests() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("base.yaml"), "version: 1").expect("write policy file");

        let runtime = PolicyDirectoryRuntime::start(
            PolicyDirectorySourceConfig::new(&root).with_debounce_window(Duration::from_millis(50)),
        )
        .expect("start policy runtime");

        fs::write(root.join("base.yaml"), "version: 2").expect("rewrite policy file");
        fs::write(root.join("base.yaml"), "version: 3").expect("rewrite policy file again");

        let event = runtime
            .recv_event_timeout(Duration::from_secs(2))
            .expect("receive debounced event")
            .expect("event should arrive");
        assert!(matches!(event, PolicyRuntimeEvent::ReloadRequested(_)));
    }
}
