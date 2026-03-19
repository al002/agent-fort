mod debounce;
mod directory_loader;
mod runtime;
mod source;
mod watcher;
mod yaml_parser;

pub use af_policy::{PolicyDirectorySnapshot, PolicyFile, PolicyReloadReason, PolicyReloadRequest};
pub use directory_loader::PolicyDirectoryLoader;
pub use runtime::{ActiveStaticPolicy, PolicyRuntime};
pub use source::{
    DEFAULT_POLL_INTERVAL, DEFAULT_WATCH_DEBOUNCE, PolicyReloadError, PolicyRuntimeConfig,
    PolicyStatus, PolicyWatchEvent,
};
pub use watcher::PolicyDirectoryWatcher;
pub use yaml_parser::{LoadedStaticPolicy, YamlParser};

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
    #[error("invalid policy document in {path}: {message}")]
    InvalidDocument { path: String, message: String },
    #[error("policy runtime state lock was poisoned")]
    RuntimeStatePoisoned,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
