use af_rpc_proto::PingResponse;
use af_rpc_transport::TransportError;

use crate::approval::ApprovalClient;
use crate::bootstrap::{
    BootstrapConfig, BootstrapRunResult, BootstrapRunner, BootstrapStartOutput,
    BootstrapSyncResult, default_endpoint_uri,
};
use crate::error::{Result, SdkError};
use crate::runtime::RuntimeClient;
use crate::session::SessionClient;
use crate::task::TaskClient;

/// SDK-wide client configuration.
///
/// This configuration is consumed by [`AgentFortClient::connect`], and is reused
/// when the client lazily starts or reconnects to the daemon.
#[derive(Debug, Clone)]
pub struct SdkConfig {
    /// Bootstrap behavior and paths used when runtime connection cannot be established.
    pub bootstrap: BootstrapConfig,
    /// Default agent name used for session creation.
    pub agent_name: String,
}

impl SdkConfig {
    /// Creates a new configuration and merges optional bootstrap overrides with defaults.
    ///
    /// Fields set in `bootstrap` override the SDK defaults, while omitted fields
    /// keep their default values.
    ///
    /// # Examples
    /// ```
    /// use af_sdk::{BootstrapConfig, SdkConfig};
    ///
    /// let config = SdkConfig::new(
    ///     "worker-agent",
    ///     Some(BootstrapConfig {
    ///         endpoint: Some("unix:///tmp/agent-fortd.sock".to_string()),
    ///         ..Default::default()
    ///     }),
    /// );
    /// assert_eq!(config.agent_name, "worker-agent");
    /// assert_eq!(
    ///     config.bootstrap.endpoint.as_deref(),
    ///     Some("unix:///tmp/agent-fortd.sock")
    /// );
    /// ```
    pub fn new(agent_name: impl Into<String>, bootstrap: Option<BootstrapConfig>) -> Self {
        let defaults = BootstrapConfig::default();
        let bootstrap = match bootstrap {
            Some(override_bootstrap) => BootstrapConfig {
                bootstrap_binary_url: override_bootstrap
                    .bootstrap_binary_url
                    .or(defaults.bootstrap_binary_url),
                install_root: override_bootstrap.install_root.or(defaults.install_root),
                bundle_manifest: override_bootstrap
                    .bundle_manifest
                    .or(defaults.bundle_manifest),
                endpoint: override_bootstrap.endpoint.or(defaults.endpoint),
                policy_dir: override_bootstrap.policy_dir.or(defaults.policy_dir),
                store_path: override_bootstrap.store_path.or(defaults.store_path),
            },
            None => defaults,
        };

        Self {
            bootstrap,
            agent_name: agent_name.into(),
        }
    }
}

/// High-level SDK client that manages daemon availability and sub-clients.
///
/// `AgentFortClient` is intended as the main entry point:
/// - lazy-connects on first use,
/// - optionally bootstraps daemon startup if needed,
/// - retries a ping once after transport failure.
///
/// # Example
/// ```no_run
/// use af_sdk::{AgentFortClient, Result, SdkConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let config = SdkConfig::new("my-agent", None);
///     let _sync = AgentFortClient::initialize(config.clone()).await?;
///     let mut client = AgentFortClient::connect(config).await?;
///     let _pong = client.ping().await?;
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct AgentFortClient {
    config: SdkConfig,
    runtime: Option<RuntimeClient>,
    bootstrap_result: Option<BootstrapRunResult>,
}

impl AgentFortClient {
    /// Runs bootstrap sync only, using the embedded bootstrap config in [`SdkConfig`].
    ///
    /// # Errors
    /// Returns bootstrap execution errors and join errors from the spawned blocking task.
    ///
    /// # Example
    /// ```no_run
    /// use af_sdk::{AgentFortClient, Result, SdkConfig};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let config = SdkConfig::new("my-agent", None);
    ///     let _sync = AgentFortClient::initialize(config.clone()).await?;
    ///     let _client = AgentFortClient::connect(config).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn initialize(config: SdkConfig) -> Result<BootstrapSyncResult> {
        Self::initialize_bootstrap(config.bootstrap).await
    }

    /// Creates a client handle without immediately connecting to the daemon.
    ///
    /// Actual runtime connection is deferred until an operation like [`Self::ping`]
    /// or sub-client acquisition is executed.
    ///
    /// Recommended lifecycle for end users is:
    /// 1. call [`Self::initialize`] once (sync/install),
    /// 2. then call `connect` for runtime usage.
    ///
    /// # Errors
    /// This method currently does not perform I/O and returns `Ok` in normal cases.
    pub async fn connect(config: SdkConfig) -> Result<Self> {
        Ok(Self {
            config,
            runtime: None,
            bootstrap_result: None,
        })
    }

    /// Runs bootstrap sync + start in a blocking worker thread.
    ///
    /// This method does not create an [`AgentFortClient`].
    ///
    /// # Errors
    /// Returns bootstrap execution errors and join errors from the spawned blocking task.
    ///
    /// # Example
    /// ```no_run
    /// use af_sdk::{AgentFortClient, BootstrapConfig, Result};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let _result = AgentFortClient::bootstrap(BootstrapConfig::default()).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn bootstrap(config: BootstrapConfig) -> Result<BootstrapRunResult> {
        tokio::task::spawn_blocking(move || BootstrapRunner::new(config).prepare_and_start())
            .await
            .map_err(|error| SdkError::BootstrapTaskJoin(error.to_string()))?
    }

    /// Runs bootstrap sync only.
    ///
    /// Use this when startup is handled elsewhere but installation/sync still needs
    /// to be prepared.
    ///
    /// # Errors
    /// Returns bootstrap execution errors and join errors from the spawned blocking task.
    pub async fn initialize_bootstrap(config: BootstrapConfig) -> Result<BootstrapSyncResult> {
        tokio::task::spawn_blocking(move || BootstrapRunner::new(config).sync_only())
            .await
            .map_err(|error| SdkError::BootstrapTaskJoin(error.to_string()))?
    }

    async fn bootstrap_start(config: BootstrapConfig) -> Result<BootstrapStartOutput> {
        tokio::task::spawn_blocking(move || BootstrapRunner::new(config).start_only())
            .await
            .map_err(|error| SdkError::BootstrapTaskJoin(error.to_string()))?
    }

    /// Creates a connected client from an existing bootstrap result.
    ///
    /// This is useful when bootstrap is orchestrated externally and the caller wants
    /// to hand over the known daemon endpoint.
    ///
    /// # Errors
    /// Returns a transport/protocol error when runtime cannot connect to
    /// `bootstrap_result.start.endpoint`.
    pub async fn connect_with_bootstrap(
        bootstrap_result: BootstrapRunResult,
        config: SdkConfig,
    ) -> Result<Self> {
        let runtime =
            RuntimeClient::connect(&bootstrap_result.start.endpoint, config.agent_name.clone())
                .await?;
        Ok(Self {
            config,
            runtime: Some(runtime),
            bootstrap_result: Some(bootstrap_result),
        })
    }

    /// Returns endpoint URI from configuration (without validating connectivity).
    pub fn configured_endpoint_uri(&self) -> String {
        self.config
            .bootstrap
            .endpoint
            .clone()
            .unwrap_or_else(|| default_endpoint_uri().to_string())
    }

    /// Returns currently connected endpoint URI, or `None` when not connected yet.
    pub fn endpoint_uri(&self) -> Option<String> {
        self.runtime
            .as_ref()
            .map(|runtime| runtime.endpoint().as_uri())
    }

    /// Returns bootstrap result if this client performed a bootstrap start.
    pub fn bootstrap_result(&self) -> Option<&BootstrapRunResult> {
        self.bootstrap_result.as_ref()
    }

    /// Performs daemon ping.
    ///
    /// If a transport failure occurs, the runtime connection is dropped and recreated
    /// once before retrying ping.
    ///
    /// # Errors
    /// Returns endpoint parsing, transport, bootstrap, or daemon RPC protocol errors.
    pub async fn ping(&mut self) -> Result<PingResponse> {
        if self.runtime.is_none() {
            self.ensure_runtime().await?;
        }

        let ping_result = {
            let runtime = self
                .runtime
                .as_mut()
                .expect("runtime must exist after ensure_runtime");
            runtime.ping().await
        };

        match ping_result {
            Ok(response) => Ok(response),
            Err(SdkError::Transport(_)) => {
                self.runtime = None;
                self.ensure_runtime().await?;
                self.runtime
                    .as_mut()
                    .expect("runtime must exist after restart")
                    .ping()
                    .await
            }
            Err(error) => Err(error),
        }
    }

    /// Returns a session sub-client bound to this runtime connection.
    ///
    /// The sub-client mutably borrows this client runtime for its lifetime.
    ///
    /// # Example
    /// ```no_run
    /// use af_sdk::{AgentFortClient, Result, SdkConfig};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let config = SdkConfig::new("my-agent", None);
    ///     let _sync = AgentFortClient::initialize(config.clone()).await?;
    ///     let mut client = AgentFortClient::connect(config).await?;
    ///     let mut sessions = client.sessions().await?;
    ///     let _session = sessions.create_session().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn sessions(&mut self) -> Result<SessionClient<'_>> {
        self.ensure_runtime().await?;
        Ok(SessionClient::new(
            self.runtime
                .as_mut()
                .expect("runtime must exist after ensure_runtime"),
        ))
    }

    /// Returns a task sub-client bound to this runtime connection.
    ///
    /// The sub-client mutably borrows this client runtime for its lifetime.
    ///
    /// # Example
    /// ```no_run
    /// use af_sdk::{AgentFortClient, Result, SdkConfig, SdkError, exec_operation};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let config = SdkConfig::new("my-agent", None);
    ///     let _sync = AgentFortClient::initialize(config.clone()).await?;
    ///     let mut client = AgentFortClient::connect(config).await?;
    ///
    ///     let session = {
    ///         let mut sessions = client.sessions().await?;
    ///         sessions.create_session().await?
    ///     };
    ///     let session_id = session.session_id.clone();
    ///     let rebind_token = session
    ///         .lease
    ///         .ok_or_else(|| SdkError::Protocol("CreateSessionResponse missing lease".to_string()))?
    ///         .rebind_token;
    ///
    ///     let mut tasks = client.tasks().await?;
    ///     let _created = tasks
    ///         .create(
    ///             session_id,
    ///             rebind_token,
    ///             exec_operation("echo hello"),
    ///             Some("exec: echo hello".to_string()),
    ///             None,
    ///         )
    ///         .await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn tasks(&mut self) -> Result<TaskClient<'_>> {
        self.ensure_runtime().await?;
        Ok(TaskClient::new(
            self.runtime
                .as_mut()
                .expect("runtime must exist after ensure_runtime"),
        ))
    }

    /// Returns an approval sub-client bound to this runtime connection.
    ///
    /// The sub-client mutably borrows this client runtime for its lifetime.
    ///
    /// # Example
    /// ```no_run
    /// use af_sdk::{AgentFortClient, Result, SdkConfig};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let config = SdkConfig::new("my-agent", None);
    ///     let _sync = AgentFortClient::initialize(config.clone()).await?;
    ///     let mut client = AgentFortClient::connect(config).await?;
    ///     let _approvals = client.approvals().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn approvals(&mut self) -> Result<ApprovalClient<'_>> {
        self.ensure_runtime().await?;
        Ok(ApprovalClient::new(
            self.runtime
                .as_mut()
                .expect("runtime must exist after ensure_runtime"),
        ))
    }

    async fn ensure_runtime(&mut self) -> Result<()> {
        if self.runtime.is_some() {
            return Ok(());
        }

        let endpoint = self.configured_endpoint_uri();
        match RuntimeClient::connect(&endpoint, self.config.agent_name.clone()).await {
            Ok(runtime) => {
                self.runtime = Some(runtime);
                return Ok(());
            }
            Err(SdkError::Transport(TransportError::InvalidEndpoint(_))) => {
                return Err(SdkError::Transport(TransportError::InvalidEndpoint(
                    endpoint,
                )));
            }
            Err(_) => {}
        }

        let start = Self::bootstrap_start(self.config.bootstrap.clone()).await?;
        let runtime =
            RuntimeClient::connect(&start.endpoint, self.config.agent_name.clone()).await?;
        self.runtime = Some(runtime);
        Ok(())
    }
}
