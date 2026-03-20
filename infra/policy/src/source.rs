use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRulesConfig {
    pub root: PathBuf,
    pub strict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRuntimeConfig {
    pub root: PathBuf,
    pub command_rules: Option<CommandRulesConfig>,
    pub poll_interval: Duration,
}

impl PolicyRuntimeConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            command_rules: None,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    pub fn with_command_rules(mut self, root: impl Into<PathBuf>, strict: bool) -> Self {
        self.command_rules = Some(CommandRulesConfig {
            root: root.into(),
            strict,
        });
        self
    }

    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReloadError {
    pub attempted_revision: u64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStatus {
    pub revision: u64,
    pub policy_revision: u64,
    pub command_rules_revision: u64,
    pub command_rules_count: usize,
    pub last_reload_error: Option<PolicyReloadError>,
}
