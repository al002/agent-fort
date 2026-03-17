mod debounce;
mod cel_compiler;
mod directory_loader;
mod runtime;
mod source;
mod watcher;
mod yaml_parser;

pub use af_policy::{PolicyDirectorySnapshot, PolicyFile, PolicyReloadReason, PolicyReloadRequest};
pub use cel_compiler::{CelCompiler, CompiledPolicies, CompiledRule};
pub use directory_loader::PolicyDirectoryLoader;
pub use runtime::PolicyRuntime;
pub use source::{
    DEFAULT_POLL_INTERVAL, DEFAULT_WATCH_DEBOUNCE, PolicyReloadError, PolicyRuntimeConfig,
    PolicyStatus, PolicyWatchEvent,
};
pub use watcher::PolicyDirectoryWatcher;
pub use yaml_parser::YamlParser;

use std::path::PathBuf;

use thiserror::Error;

pub type PolicyInfraResult<T> = Result<T, PolicyInfraError>;

#[derive(Debug, Error)]
pub enum PolicyInfraError {
    #[error("policy directory is not readable: {path}")]
    DirectoryNotReadable { path: PathBuf },
    #[error("policy watcher backend is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("policy watcher channel closed unexpectedly")]
    WatchChannelClosed,
    #[error("policy watcher backend failed: {message}")]
    WatchBackend { message: String },
    #[error("policy YAML parse failed for {path}: {message}")]
    YamlParse { path: String, message: String },
    #[error("invalid policy document in {path}: {message}")]
    InvalidDocument { path: String, message: String },
    #[error("duplicate policy rule id `{rule_id}` found in {first_path} and {second_path}")]
    DuplicateRuleId {
        rule_id: String,
        first_path: String,
        second_path: String,
    },
    #[error("CEL compile failed for rule `{rule_id}` in {path}: {message}")]
    CelCompile {
        rule_id: String,
        path: String,
        message: String,
    },
    #[error("CEL execution failed for rule `{rule_id}`: {message}")]
    CelExecution { rule_id: String, message: String },
    #[error("policy evaluation context must serialize to a CEL map at the top level")]
    InvalidEvaluationContext,
    #[error("policy CEL expression for rule `{rule_id}` did not evaluate to bool: got {actual_type}")]
    NonBooleanResult {
        rule_id: String,
        actual_type: String,
    },
    #[error("policy runtime state lock was poisoned")]
    RuntimeStatePoisoned,
    #[error("CEL serialization error: {0}")]
    CelSerialization(#[from] cel::SerializationError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
