mod debounce;
mod directory_loader;
mod runtime;
mod source;
mod watcher;

pub use af_policy::{PolicyDirectorySnapshot, PolicyFile, PolicyReloadReason, PolicyReloadRequest};
pub use directory_loader::PolicyDirectoryLoader;
pub use runtime::PolicyDirectoryRuntime;
pub use source::{
    DEFAULT_POLICY_WATCH_DEBOUNCE, PolicyDirectorySourceConfig, PolicyRuntimeEvent,
    PolicyWatchEvent,
};
pub use watcher::PolicyDirectoryWatcher;

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
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
