use anyhow::Result;
use tracing::info;

use crate::config::DaemonConfig;
use crate::helper_client::HelperClient;
use crate::rpc_controller::RpcController;
use crate::server::DaemonServer;

#[derive(Debug)]
pub struct BootstrappedDaemon {
    config: DaemonConfig,
    server: DaemonServer,
    _helper_client: HelperClient,
}

impl BootstrappedDaemon {
    pub fn new(config: DaemonConfig) -> Result<Self> {
        let controller = RpcController::new(config.daemon_instance_id.clone());
        let daemon_info = controller.daemon_info();
        info!(
            daemon_instance_id = %config.daemon_instance_id,
            routes = ?daemon_info.info.map(|info| info.routes).unwrap_or_default(),
            "rpc controller ready"
        );

        let server = DaemonServer::bind(config.endpoint.clone(), controller)?;
        let helper_client = HelperClient::new(
            config.helper_path.clone(),
            config.bwrap_path.clone(),
            config.cgroup_root.clone(),
        );
        Ok(Self {
            config,
            server,
            _helper_client: helper_client,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!(
            daemon_instance_id = %self.config.daemon_instance_id,
            endpoint = %self.config.endpoint.as_uri(),
            helper_path = %self.config.helper_path.display(),
            bwrap_path = %self.config.bwrap_path.display(),
            "agent-fortd started"
        );
        self.server.run().await
    }
}
