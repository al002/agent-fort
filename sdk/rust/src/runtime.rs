use af_rpc_proto::codec::{decode_message, encode_message};
use af_rpc_proto::{
    CreateSessionRequest, CreateSessionResponse, PingRequest, PingResponse, RpcErrorCode,
    RpcMethod, RpcRequest, RpcResponse, rpc_response,
};
use af_rpc_transport::{Endpoint, RpcClient};
use uuid::Uuid;

use crate::error::{Result, SdkError};

#[derive(Debug, Clone)]
pub struct CreateSessionOptions {
    pub agent_name: Option<String>,
    pub policy_profile: Option<String>,
    pub lease_ttl_secs: Option<u64>,
}

impl Default for CreateSessionOptions {
    fn default() -> Self {
        Self {
            agent_name: None,
            policy_profile: None,
            lease_ttl_secs: None,
        }
    }
}

impl CreateSessionOptions {
    pub fn with_agent_name(agent_name: impl Into<String>) -> Self {
        Self {
            agent_name: Some(agent_name.into()),
            policy_profile: None,
            lease_ttl_secs: None,
        }
    }
}

#[derive(Debug)]
pub struct RuntimeClient {
    endpoint: Endpoint,
    transport: RpcClient,
    session_agent_name: String,
    client_instance_id: String,
}

impl RuntimeClient {
    pub async fn connect(
        endpoint_raw: &str,
        session_agent_name: impl Into<String>,
    ) -> Result<Self> {
        let endpoint = Endpoint::parse(endpoint_raw)?;
        let transport = RpcClient::connect(endpoint.clone()).await?;
        Ok(Self {
            endpoint,
            transport,
            session_agent_name: session_agent_name.into(),
            client_instance_id: Uuid::new_v4().to_string(),
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub async fn ping(&mut self) -> Result<PingResponse> {
        let payload = self
            .call_rpc(RpcMethod::Ping, encode_message(&PingRequest {}))
            .await?;
        decode_message::<PingResponse>(&payload)
            .map_err(|error| SdkError::Protocol(format!("decode PingResponse failed: {error}")))
    }

    pub async fn create_session(
        &mut self,
        options: CreateSessionOptions,
    ) -> Result<CreateSessionResponse> {
        let request = CreateSessionRequest {
            agent_name: options
                .agent_name
                .unwrap_or_else(|| self.session_agent_name.clone()),
            policy_profile: options
                .policy_profile
                .unwrap_or_else(|| "default".to_string()),
            client_instance_id: self.client_instance_id.clone(),
            lease_ttl_secs: options.lease_ttl_secs.or(Some(300)),
        };
        let payload = self
            .call_rpc(RpcMethod::CreateSession, encode_message(&request))
            .await?;
        decode_message::<CreateSessionResponse>(&payload).map_err(|error| {
            SdkError::Protocol(format!("decode CreateSessionResponse failed: {error}"))
        })
    }

    async fn call_rpc(&mut self, method: RpcMethod, payload: Vec<u8>) -> Result<Vec<u8>> {
        let request = RpcRequest {
            method: method as i32,
            payload,
        };
        let response = self
            .transport
            .roundtrip::<RpcRequest, RpcResponse>(&request)
            .await?;
        match response.outcome {
            Some(rpc_response::Outcome::Payload(payload)) => Ok(payload),
            Some(rpc_response::Outcome::Error(error)) => {
                let code = RpcErrorCode::try_from(error.code)
                    .map(|code| format!("{code:?}"))
                    .unwrap_or_else(|_| format!("UNKNOWN({})", error.code));
                Err(SdkError::DaemonRpc {
                    code,
                    message: error.message,
                })
            }
            None => Err(SdkError::Protocol(
                "daemon response missing outcome".to_string(),
            )),
        }
    }
}
