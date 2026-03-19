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
    BootstrapDownloadFailed { url: String, message: String },

    /// Downloaded bootstrap checksum does not match expected value.
    #[error("bootstrap checksum mismatch for {path:?}: expected {expected}, got {actual}")]
    BootstrapChecksumMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    /// Bootstrap executable appears blocked by host security controls.
    #[error("bootstrap executable was blocked on {path:?}: {message}")]
    BootstrapExecutionBlocked { path: PathBuf, message: String },

    /// Bootstrap subcommand exceeded timeout.
    #[error("bootstrap command `{command}` timed out after {timeout_ms} ms")]
    BootstrapCommandTimeout { command: String, timeout_ms: u64 },

    /// Bootstrap process exited unsuccessfully.
    #[error("bootstrap command `{command}` failed: {message}")]
    BootstrapCommandFailed { command: String, message: String },

    /// Bootstrap output was malformed or incompatible with expected schema.
    #[error("bootstrap returned invalid output for `{command}`: {message}")]
    BootstrapInvalidOutput { command: String, message: String },

    /// Bootstrap explicitly returned `ok=false` payload.
    #[error("bootstrap reported error for `{command}`: {error}")]
    BootstrapReportedError { command: String, error: String },

    /// Joining asynchronous bootstrap worker task failed.
    #[error("bootstrap task join failed: {0}")]
    BootstrapTaskJoin(String),

    /// RPC transport error.
    #[error("transport error: {0}")]
    Transport(#[from] af_rpc_transport::TransportError),

    /// Daemon returned RPC-layer error response.
    #[error("daemon rpc error ({code}): {message}")]
    DaemonRpc { code: String, message: String },

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
