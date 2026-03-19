//! Rust SDK for agent-fort (a security runtime for AI agents)
//!
//! The crate exposes two usage levels:
//! - [`AgentFortClient`] for high-level lifecycle management (bootstrap + reconnect).
//! - [`RuntimeClient`] for direct RPC-style calls.
//!
//! # Typical Flow
//! 1. Initialize and connect a client.
//! 2. Create a session.
//! 3. Create a task using session credentials.
//!
//! # Quick Start
//! ```no_run
//! use af_sdk::{AgentFortClient, BootstrapConfig, Result, SdkConfig, SdkError, exec_operation};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // sync binary first, then connect.
//!     let config = SdkConfig::new(
//!         "my-agent",
//!         Some(BootstrapConfig {
//!             // Required for end users: where to fetch/load af-bootstrap.
//!             bootstrap_binary_url: Some(
//!                 "https://example.com/agent-fort/bootstrap/linux-x86_64/af-bootstrap".to_string(),
//!             ),
//!             // Optional: set explicit manifest source (local path or URL).
//!             bundle_manifest: Some("https://example.com/manifest.json".to_string()),
//!             ..Default::default()
//!         }),
//!     );
//!     let _sync = AgentFortClient::initialize(config.clone()).await?;
//!     let mut client = AgentFortClient::connect(config).await?;
//!     let pong = client.ping().await?;
//!     println!("daemon status: {}", pong.status);
//!
//!     let mut sessions = client.sessions().await?;
//!     let session = sessions.create_session().await?;
//!     drop(sessions);
//!
//!     let session_id = session.session_id.clone();
//!     let rebind_token = session
//!         .lease
//!         .ok_or_else(|| SdkError::Protocol("CreateSessionResponse missing lease".to_string()))?
//!         .rebind_token;
//!
//!     let mut tasks = client.tasks().await?;
//!     let _task = tasks
//!         .create(
//!             session_id,
//!             rebind_token,
//!             exec_operation("echo hello from af-sdk"),
//!             Some("exec: echo hello from af-sdk".to_string()),
//!         )
//!         .await?;
//!     Ok(())
//! }
//! ```
//!
//! # Manifest Source (Sync)
//! When running bootstrap `sync` (`AgentFortClient::initialize` / `bootstrap`):
//! - default manifest source is local [`default_manifest_path`], i.e.
//!   `<install_root>/manifest.json`
//! - there is no built-in online default manifest URL
//! - for online manifest, set `bootstrap.bundle_manifest = Some("https://...")`
//!
//! ```no_run
//! use af_sdk::{AgentFortClient, BootstrapConfig, Result, SdkConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let config = SdkConfig::new(
//!         "my-agent",
//!         Some(BootstrapConfig {
//!             bootstrap_binary_url: Some(
//!                 "https://example.com/agent-fort/bootstrap/linux-x86_64/af-bootstrap".to_string(),
//!             ),
//!             bundle_manifest: Some("https://example.com/manifest.json".to_string()),
//!             ..Default::default()
//!         }),
//!     );
//!     let _ = AgentFortClient::initialize(config).await?;
//!     Ok(())
//! }
//! ```

mod approval;
mod bootstrap;
mod client;
mod error;
mod operation;
mod runtime;
mod session;
mod task;

pub use approval::ApprovalClient;
pub use bootstrap::{
    BootstrapConfig, BootstrapRunResult, BootstrapRunner, BootstrapStartOutput,
    BootstrapSyncOutput, BootstrapSyncResult, bootstrap_path_lookup_order_hint,
    default_endpoint_uri, default_install_root_path, default_manifest_path,
    default_policy_dir_path, install_root_has_manifest,
};
pub use client::{AgentFortClient, SdkConfig};
pub use error::{Result, SdkError};
pub use operation::exec_operation;
pub use runtime::{CreateSessionOptions, RuntimeClient};
pub use session::SessionClient;
pub use task::TaskClient;

/// Raw task operation payload used by task creation APIs.
///
/// Valid operation kinds in capability-first mode:
/// - `exec`
/// - `fs.read`
/// - `fs.write`
/// - `net`
/// - `tool`
///
/// For shell execution tasks, prefer [`exec_operation`].
pub use af_rpc_proto::TaskOperation;
