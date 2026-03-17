use std::path::PathBuf;
use std::time::Duration;

use af_policy::PolicyReloadRequest;

pub const DEFAULT_POLICY_WATCH_DEBOUNCE: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDirectorySourceConfig {
    pub root: PathBuf,
    pub debounce_window: Duration,
}

impl PolicyDirectorySourceConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            debounce_window: DEFAULT_POLICY_WATCH_DEBOUNCE,
        }
    }

    pub fn with_debounce_window(mut self, debounce_window: Duration) -> Self {
        self.debounce_window = debounce_window;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyWatchEvent {
    pub root: PathBuf,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRuntimeEvent {
    ReloadRequested(PolicyReloadRequest),
}
