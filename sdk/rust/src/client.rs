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

#[derive(Debug, Clone, Default)]
pub struct SdkConfig {
    pub bootstrap: BootstrapConfig,
}

#[derive(Debug)]
pub struct AgentFortClient {
    config: SdkConfig,
    runtime: Option<RuntimeClient>,
    bootstrap_result: Option<BootstrapRunResult>,
}

impl AgentFortClient {
    pub async fn connect(config: SdkConfig) -> Result<Self> {
        Ok(Self {
            config,
            runtime: None,
            bootstrap_result: None,
        })
    }

    pub async fn bootstrap(config: BootstrapConfig) -> Result<BootstrapRunResult> {
        tokio::task::spawn_blocking(move || BootstrapRunner::new(config).prepare_and_start())
            .await
            .map_err(|error| SdkError::BootstrapTaskJoin(error.to_string()))?
    }

    pub async fn initialize(config: SdkConfig) -> Result<BootstrapSyncResult> {
        Self::initialize_bootstrap(config.bootstrap).await
    }

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

    pub async fn connect_with_bootstrap(bootstrap_result: BootstrapRunResult) -> Result<Self> {
        let runtime = RuntimeClient::connect(&bootstrap_result.start.endpoint).await?;
        Ok(Self {
            config: SdkConfig::default(),
            runtime: Some(runtime),
            bootstrap_result: Some(bootstrap_result),
        })
    }

    pub fn configured_endpoint_uri(&self) -> String {
        self.config
            .bootstrap
            .endpoint
            .clone()
            .unwrap_or_else(|| default_endpoint_uri().to_string())
    }

    pub fn endpoint_uri(&self) -> Option<String> {
        self.runtime
            .as_ref()
            .map(|runtime| runtime.endpoint().as_uri())
    }

    pub fn bootstrap_result(&self) -> Option<&BootstrapRunResult> {
        self.bootstrap_result.as_ref()
    }

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

    pub async fn sessions(&mut self) -> Result<SessionClient<'_>> {
        self.ensure_runtime().await?;
        Ok(SessionClient::new(
            self.runtime
                .as_mut()
                .expect("runtime must exist after ensure_runtime"),
        ))
    }

    pub async fn tasks(&mut self) -> Result<TaskClient<'_>> {
        self.ensure_runtime().await?;
        Ok(TaskClient::new(
            self.runtime
                .as_mut()
                .expect("runtime must exist after ensure_runtime"),
        ))
    }

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
        match RuntimeClient::connect(&endpoint).await {
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
        let runtime = RuntimeClient::connect(&start.endpoint).await?;
        self.runtime = Some(runtime);
        Ok(())
    }
}
