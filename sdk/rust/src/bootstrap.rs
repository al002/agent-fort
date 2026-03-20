//! Bootstrap orchestration for daemon installation, sync, and startup.
//!
//! This module wraps the `af-bootstrap` binary lifecycle used by the SDK.

use std::path::PathBuf;
use std::process::ExitStatus;

use af_rpc_transport::Endpoint;
use serde::Deserialize;

mod paths;
mod process;
mod source;

pub use paths::{
    bootstrap_path_lookup_order_hint, default_endpoint_uri, default_install_root_path,
    default_manifest_path, default_policy_dir_path, install_root_has_manifest,
};

const DEFAULT_COMMAND_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_STARTUP_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_PING_INTERVAL_MS: u64 = 200;
const DEFAULT_LOCAL_DEV_BOOTSTRAP_DIR: &str = "target/debug";
const ENV_POLICY_DIR: &str = "AF_POLICY_DIR";
const EXPECTED_BOOTSTRAP_SHA256_LINUX_X86_64: &str =
    "e935437defc54009b8cddbd8b946f9b1f5a20feb71cef5c0fdac32c4f6e3e0c3";

#[cfg(windows)]
const DEFAULT_ENDPOINT: &str = "npipe://agent-fortd";
#[cfg(not(windows))]
const DEFAULT_ENDPOINT: &str = "unix:///tmp/agent-fortd.sock";

/// Bootstrap configuration for locating/downloading and running `af-bootstrap`.
///
/// # Example
/// ```
/// use af_sdk::{BootstrapConfig, default_endpoint_uri, default_install_root_path};
///
/// let config = BootstrapConfig {
///     install_root: Some(default_install_root_path()),
///     endpoint: Some(default_endpoint_uri().to_string()),
///     ..Default::default()
/// };
/// assert!(config.install_root.is_some());
/// ```
#[derive(Debug, Clone, Default)]
pub struct BootstrapConfig {
    /// Bootstrap binary source.
    ///
    /// Supported forms:
    /// - local path (absolute or relative),
    /// - `file://` URL,
    /// - `http://` / `https://` URL.
    ///
    /// When `None`, SDK uses the local development path convention.
    pub bootstrap_binary_url: Option<String>,
    /// Installation root directory used by bootstrap commands.
    ///
    /// When `None`, platform-specific default is used.
    pub install_root: Option<PathBuf>,
    /// Optional bundle manifest source for `sync`.
    ///
    /// If this is `None`, SDK falls back to local
    /// [`default_manifest_path`](crate::default_manifest_path), that is
    /// `<install_root>/manifest.json`.
    ///
    /// When that local file does not exist, `sync` fails with
    /// [`crate::SdkError::BundleManifestRequired`].
    ///
    /// There is no built-in online default manifest URL. To use an online
    /// manifest, pass an explicit `https://...` source here.
    pub bundle_manifest: Option<String>,
    /// Daemon endpoint URI passed to bootstrap.
    ///
    /// When `None`, SDK uses [`default_endpoint_uri`].
    pub endpoint: Option<String>,
    /// Policy directory passed to bootstrap `start`.
    ///
    /// If not provided, SDK checks `AF_POLICY_DIR` and then defaults to
    /// `<current_dir>/policies`.
    pub policy_dir: Option<PathBuf>,
    /// Optional store path passed to bootstrap `start`.
    pub store_path: Option<PathBuf>,
}

/// Combined result of `sync` + `start` bootstrap execution.
#[derive(Debug, Clone)]
pub struct BootstrapRunResult {
    /// Resolved filesystem path to bootstrap executable.
    pub bootstrap_path: PathBuf,
    /// Output of `sync` command.
    pub sync: Option<BootstrapSyncOutput>,
    /// Output of `start` command.
    pub start: BootstrapStartOutput,
}

/// Result of running only bootstrap `sync`.
#[derive(Debug, Clone)]
pub struct BootstrapSyncResult {
    /// Resolved filesystem path to bootstrap executable.
    pub bootstrap_path: PathBuf,
    /// Output of `sync` command.
    pub sync: Option<BootstrapSyncOutput>,
}

/// Parsed JSON output from bootstrap `sync`.
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapSyncOutput {
    /// Success flag from bootstrap JSON output.
    pub ok: bool,
    /// Bootstrap/daemon bundle version.
    pub version: String,
    /// Installed daemon executable path.
    pub daemon_path: String,
    /// Installed bubblewrap executable path.
    pub bwrap_path: String,
    /// Installed helper executable path.
    pub helper_path: String,
    /// Endpoint configured for daemon runtime.
    pub endpoint: String,
    /// Installation state file path.
    pub install_state_path: String,
}

/// Parsed JSON output from bootstrap `start`.
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapStartOutput {
    /// Success flag from bootstrap JSON output.
    pub ok: bool,
    /// Effective daemon endpoint.
    pub endpoint: String,
    /// Whether bootstrap started the daemon in this invocation.
    pub started: bool,
    /// Daemon process id when available.
    pub daemon_pid: Option<u32>,
    /// Daemon instance identifier.
    pub daemon_instance_id: String,
}

/// Orchestrates bootstrap command execution.
///
/// Use this type when you need explicit control over whether to run full flow,
/// `sync` only, or `start` only.
///
/// # Example
/// ```no_run
/// use af_sdk::{BootstrapConfig, BootstrapRunner, Result};
///
/// fn main() -> Result<()> {
///     let runner = BootstrapRunner::new(BootstrapConfig::default());
///     let _sync = runner.sync_only()?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BootstrapRunner {
    config: BootstrapConfig,
}

#[derive(Debug)]
struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Deserialize)]
struct BootstrapErrorOutput {
    ok: bool,
    error: String,
}

#[derive(Debug, Clone)]
struct ResolvedBootstrapConfig {
    bootstrap_binary_url: String,
    install_root: PathBuf,
    bundle_manifest: Option<String>,
    endpoint: String,
    policy_dir: PathBuf,
    store_path: Option<PathBuf>,
}

impl BootstrapRunner {
    /// Creates a runner from bootstrap configuration.
    pub fn new(config: BootstrapConfig) -> Self {
        Self { config }
    }

    /// Runs full prepare flow:
    /// 1. Resolve bootstrap location (download if needed),
    /// 2. Execute `sync`,
    /// 3. Execute `start`.
    ///
    /// # Errors
    /// Returns bootstrap resolution/download, process execution, JSON parsing,
    /// endpoint validation, and I/O errors.
    pub fn prepare_and_start(&self) -> crate::error::Result<BootstrapRunResult> {
        let resolved = self.resolve_config()?;
        let bootstrap_path = paths::resolve_bootstrap_path(&resolved, true)?;
        let sync_output = process::run_sync_if_needed(&bootstrap_path, &resolved)?;
        let start = process::run_start(&bootstrap_path, &resolved)?;

        Ok(BootstrapRunResult {
            bootstrap_path,
            sync: sync_output,
            start,
        })
    }

    /// Runs bootstrap `sync` only.
    ///
    /// This command may download bootstrap binary when not found under install root.
    ///
    /// # Errors
    /// Returns bootstrap resolution/download, process execution, JSON parsing,
    /// endpoint validation, and I/O errors.
    pub fn sync_only(&self) -> crate::error::Result<BootstrapSyncResult> {
        let resolved = self.resolve_config()?;
        let bootstrap_path = paths::resolve_bootstrap_path(&resolved, true)?;
        let sync = process::run_sync_if_needed(&bootstrap_path, &resolved)?;
        Ok(BootstrapSyncResult {
            bootstrap_path,
            sync,
        })
    }

    /// Runs bootstrap `start` only.
    ///
    /// Unlike [`Self::prepare_and_start`], this method does not download bootstrap
    /// when the binary is missing from install root.
    ///
    /// # Errors
    /// Returns bootstrap execution, endpoint validation, and I/O errors.
    pub fn start_only(&self) -> crate::error::Result<BootstrapStartOutput> {
        let resolved = self.resolve_config()?;
        let bootstrap_path = paths::resolve_bootstrap_path(&resolved, false)?;
        process::run_start(&bootstrap_path, &resolved)
    }

    fn resolve_config(&self) -> crate::error::Result<ResolvedBootstrapConfig> {
        let install_root = self
            .config
            .install_root
            .clone()
            .unwrap_or_else(paths::default_install_root);

        let endpoint = self
            .config
            .endpoint
            .clone()
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let _ = Endpoint::parse(&endpoint)?;

        let bootstrap_binary_url = self
            .config
            .bootstrap_binary_url
            .clone()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(source::default_local_bin);

        let policy_dir = paths::resolve_policy_dir(
            self.config
                .policy_dir
                .clone()
                .or_else(|| std::env::var_os(ENV_POLICY_DIR).map(PathBuf::from))
                .unwrap_or_else(paths::default_policy_dir),
        )?;

        Ok(ResolvedBootstrapConfig {
            bootstrap_binary_url,
            install_root,
            bundle_manifest: self.config.bundle_manifest.clone(),
            endpoint,
            policy_dir,
            store_path: self.config.store_path.clone(),
        })
    }
}
