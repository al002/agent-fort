use anyhow::Result;
use tracing::info;

use crate::config::DaemonConfig;
use crate::rpc_controller::RpcController;
use crate::server::DaemonServer;

#[derive(Debug)]
pub struct BootstrappedDaemon {
    config: DaemonConfig,
    server: DaemonServer,
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
        Ok(Self { config, server })
    }

    pub async fn run(self) -> Result<()> {
        info!(
            daemon_instance_id = %self.config.daemon_instance_id,
            endpoint = %self.config.endpoint.as_uri(),
            "agent-fortd started"
        );
        self.server.run().await
    }
}
