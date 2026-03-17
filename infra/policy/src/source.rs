use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_WATCH_DEBOUNCE: Duration = Duration::from_millis(150);
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRuntimeConfig {
    pub root: PathBuf,
    pub debounce: Duration,
    pub poll_interval: Duration,
}

impl PolicyRuntimeConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            debounce: DEFAULT_WATCH_DEBOUNCE,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    pub fn with_debounce(mut self, debounce: Duration) -> Self {
        self.debounce = debounce;
        self
    }

    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyWatchEvent {
    pub root: PathBuf,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReloadError {
    pub attempted_revision: u64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStatus {
    pub revision: u64,
    pub file_count: usize,
    pub rule_count: usize,
    pub last_reload_error: Option<PolicyReloadError>,
}
