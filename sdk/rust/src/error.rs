use std::path::PathBuf;

use thiserror::Error;

/// SDK result alias.
pub type Result<T> = std::result::Result<T, SdkError>;

/// Error type returned by SDK operations.
///
/// # Example
/// ```no_run
/// use af_sdk::{AgentFortClient, Result, SdkConfig, SdkError};
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let config = SdkConfig::new("my-agent", None);
///     let _sync = AgentFortClient::initialize(config.clone()).await?;
///     let mut client = AgentFortClient::connect(config).await?;
///     match client.ping().await {
///         Ok(_) => {}
///         Err(SdkError::Transport(_)) => {}
///         Err(other) => return Err(other),
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug, Error)]
pub enum SdkError {
    /// No bootstrap executable could be found or downloaded.
    #[error("bootstrap executable not found via install-root convention or download source")]
    BootstrapNotFound,

    /// Sync requires a manifest source:
    /// - explicit [`crate::BootstrapConfig::bundle_manifest`] (local path or URL), or
    /// - local `<install_root>/manifest.json`.
    ///
    /// SDK does not provide a default online manifest URL.
    #[error("bundle manifest is required because install-root manifest does not exist")]
    BundleManifestRequired,

    /// Download or read of bootstrap binary failed.
    #[error("bootstrap download failed from `{url}`: {message}")]
    BootstrapDownloadFailed {
        /// Source URL or local path used for bootstrap fetch.
        url: String,
        /// Underlying fetch/read failure message.
        message: String,
    },

    /// Downloaded bootstrap checksum does not match expected value.
    #[error("bootstrap checksum mismatch for {path:?}: expected {expected}, got {actual}")]
    BootstrapChecksumMismatch {
        /// Output path where downloaded bootstrap binary was written.
        path: PathBuf,
        /// Expected SHA-256 checksum for current target.
        expected: String,
        /// Actual SHA-256 checksum computed from downloaded bytes.
        actual: String,
    },

    /// Bootstrap executable appears blocked by host security controls.
    #[error("bootstrap executable was blocked on {path:?}: {message}")]
    BootstrapExecutionBlocked {
        /// Bootstrap executable path that failed to spawn.
        path: PathBuf,
        /// Platform-specific diagnostic message.
        message: String,
    },

    /// Bootstrap subcommand exceeded timeout.
    #[error("bootstrap command `{command}` timed out after {timeout_ms} ms")]
    BootstrapCommandTimeout {
        /// Bootstrap subcommand name (`sync` or `start`).
        command: String,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /// Bootstrap process exited unsuccessfully.
    #[error("bootstrap command `{command}` failed: {message}")]
    BootstrapCommandFailed {
        /// Bootstrap subcommand name (`sync` or `start`).
        command: String,
        /// Captured process error detail.
        message: String,
    },

    /// Bootstrap output was malformed or incompatible with expected schema.
    #[error("bootstrap returned invalid output for `{command}`: {message}")]
    BootstrapInvalidOutput {
        /// Bootstrap subcommand name (`sync` or `start`).
        command: String,
        /// Parsing/validation failure detail.
        message: String,
    },

    /// Bootstrap explicitly returned `ok=false` payload.
    #[error("bootstrap reported error for `{command}`: {error}")]
    BootstrapReportedError {
        /// Bootstrap subcommand name (`sync` or `start`).
        command: String,
        /// Error message reported by bootstrap JSON payload.
        error: String,
    },

    /// Joining asynchronous bootstrap worker task failed.
    #[error("bootstrap task join failed: {0}")]
    BootstrapTaskJoin(String),

    /// RPC transport error.
    #[error("transport error: {0}")]
    Transport(#[from] af_rpc_transport::TransportError),

    /// Daemon returned RPC-layer error response.
    #[error("daemon rpc error ({code}): {message}")]
    DaemonRpc {
        /// Daemon RPC error code name.
        code: String,
        /// Daemon RPC error message.
        message: String,
    },

    /// Protocol-level decoding or semantic contract error.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Local I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Current platform or operation is not implemented in SDK.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}
