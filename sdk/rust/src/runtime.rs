use af_rpc_proto::{PingRequest, PingResponse};
use af_rpc_transport::{Endpoint, RpcClient};

use crate::error::Result;

#[derive(Debug)]
pub struct RuntimeClient {
    endpoint: Endpoint,
    transport: RpcClient,
}

impl RuntimeClient {
    pub async fn connect(endpoint_raw: &str) -> Result<Self> {
        let endpoint = Endpoint::parse(endpoint_raw)?;
        let transport = RpcClient::connect(endpoint.clone()).await?;
        Ok(Self {
            endpoint,
            transport,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub async fn ping(&mut self) -> Result<PingResponse> {
        self.transport
            .roundtrip::<PingRequest, PingResponse>(&PingRequest {})
            .await
            .map_err(Into::into)
    }
}
