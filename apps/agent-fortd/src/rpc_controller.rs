use std::sync::Arc;

use af_rpc_proto::{DaemonInfo, GetDaemonInfoResponse, PingRequest, PingResponse};
use af_rpc_transport::RpcConnection;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct RpcController {
    state: Arc<ControllerState>,
}

#[derive(Debug)]
struct ControllerState {
    daemon_instance_id: String,
}

impl RpcController {
    pub fn new(daemon_instance_id: String) -> Self {
        Self {
            state: Arc::new(ControllerState { daemon_instance_id }),
        }
    }

    pub fn daemon_info(&self) -> GetDaemonInfoResponse {
        GetDaemonInfoResponse {
            info: Some(DaemonInfo {
                daemon_instance_id: self.state.daemon_instance_id.clone(),
                protocol: "rpc-transport.v1".to_string(),
                routes: vec!["Ping".to_string(), "GetDaemonInfo".to_string()],
            }),
        }
    }

    pub async fn handle_connection(&self, mut connection: RpcConnection) -> Result<()> {
        // Current transport carries one protobuf payload without method metadata.
        // The startup probe only needs Ping for daemon readiness.
        let _request: PingRequest = connection.read_message().await?;

        let response = PingResponse {
            status: "ok".to_string(),
            daemon_instance_id: self.state.daemon_instance_id.clone(),
        };
        connection.write_message(&response).await?;
        Ok(())
    }
}
