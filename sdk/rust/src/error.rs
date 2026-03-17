use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SdkError>;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("bootstrap executable not found via install-root convention or download source")]
    BootstrapNotFound,

    #[error("bundle manifest is required because install-root manifest does not exist")]
    BundleManifestRequired,

    #[error("bootstrap download failed from `{url}`: {message}")]
    BootstrapDownloadFailed { url: String, message: String },

    #[error("bootstrap checksum mismatch for {path:?}: expected {expected}, got {actual}")]
    BootstrapChecksumMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("bootstrap executable was blocked on {path:?}: {message}")]
    BootstrapExecutionBlocked { path: PathBuf, message: String },

    #[error("bootstrap command `{command}` timed out after {timeout_ms} ms")]
    BootstrapCommandTimeout { command: String, timeout_ms: u64 },

    #[error("bootstrap command `{command}` failed: {message}")]
    BootstrapCommandFailed { command: String, message: String },

    #[error("bootstrap returned invalid output for `{command}`: {message}")]
    BootstrapInvalidOutput { command: String, message: String },

    #[error("bootstrap reported error for `{command}`: {error}")]
    BootstrapReportedError { command: String, error: String },

    #[error("bootstrap task join failed: {0}")]
    BootstrapTaskJoin(String),

    #[error("transport error: {0}")]
    Transport(#[from] af_rpc_transport::TransportError),

    #[error("daemon rpc error ({code}): {message}")]
    DaemonRpc { code: String, message: String },

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}
