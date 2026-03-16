use af_rpc_transport::{Endpoint, RpcServer};
use anyhow::{Context, Result};
use tracing::{error, info};

use crate::rpc_controller::RpcController;

#[derive(Debug)]
pub struct DaemonServer {
    endpoint: Endpoint,
    server: RpcServer,
    controller: RpcController,
}

impl DaemonServer {
    pub fn bind(endpoint: Endpoint, controller: RpcController) -> Result<Self> {
        let server = RpcServer::bind(endpoint.clone()).context("bind rpc server")?;
        Ok(Self {
            endpoint,
            server,
            controller,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!(endpoint = %self.endpoint.as_uri(), "daemon rpc server listening");

        loop {
            let connection = self
                .server
                .accept()
                .await
                .context("accept rpc connection")?;
            let controller = self.controller.clone();
            tokio::spawn(async move {
                if let Err(error) = controller.handle_connection(connection).await {
                    error!(error = %error, "rpc connection failed");
                }
            });
        }
    }
}
