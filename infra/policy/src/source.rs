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

    pub fn watch_roots(&self) -> Vec<PathBuf> {
        let mut roots = vec![self.root.clone()];
        if let Some(command_rules) = self.command_rules.as_ref() {
            roots.push(command_rules.root.clone());
        }
        roots.sort();
        roots.dedup();
        roots
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn watch_roots_contains_policy_root_without_command_rules() {
        let config = PolicyRuntimeConfig::new("/workspace/policies");
        assert_eq!(
            config.watch_roots(),
            vec![PathBuf::from("/workspace/policies")]
        );
    }

    #[test]
    fn watch_roots_dedupes_policy_and_command_rules_root() {
        let config = PolicyRuntimeConfig::new("/workspace/policies")
            .with_command_rules("/workspace/policies", true);
        assert_eq!(
            config.watch_roots(),
            vec![PathBuf::from("/workspace/policies")]
        );
    }

    #[test]
    fn watch_roots_contains_both_policy_and_command_rules_roots() {
        let config = PolicyRuntimeConfig::new("/workspace/policies")
            .with_command_rules("/workspace/command-rules", true);
        assert_eq!(
            config.watch_roots(),
            vec![
                PathBuf::from("/workspace/command-rules"),
                PathBuf::from("/workspace/policies"),
            ]
        );
    }
}
