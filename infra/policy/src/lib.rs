mod command_rule_loader;
mod command_rule_parser;
mod runtime;
mod source;
mod static_policy_parser;
mod watcher;

pub use command_rule_loader::{CommandRuleLoader, LoadedCommandRules};
pub use command_rule_parser::CommandRuleParser;
pub use runtime::{ActivePolicy, PolicyRuntime};
pub use source::{
    CommandRulesConfig, DEFAULT_POLL_INTERVAL, PolicyReloadError, PolicyRuntimeConfig, PolicyStatus,
};
pub use static_policy_parser::{LoadedPolicy, StaticPolicyParser};
pub use watcher::PolicyDirectoryWatcher;

use std::path::PathBuf;

use thiserror::Error;

pub type PolicyInfraResult<T> = Result<T, PolicyInfraError>;

#[derive(Debug, Error)]
pub enum PolicyInfraError {
    #[error("policy directory is not readable: {path}")]
    DirectoryNotReadable { path: PathBuf },
    #[error("static policy file not found under directory: {root}")]
    StaticPolicyMissing { root: PathBuf },
    #[error("policy watcher backend is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("policy watcher channel closed unexpectedly")]
    WatchChannelClosed,
    #[error("policy watcher backend failed: {message}")]
    WatchBackend { message: String },
    #[error("policy YAML parse failed for {path}: {message}")]
    YamlParse { path: String, message: String },
    #[error("invalid policy in {path}: {message}")]
    InvalidPolicy { path: String, message: String },
    #[error("policy runtime state lock was poisoned")]
    RuntimeStatePoisoned,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
