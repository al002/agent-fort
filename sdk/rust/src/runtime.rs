use af_rpc_proto::codec::{decode_message, encode_message};
use af_rpc_proto::{
    ApprovalDecision, CreateSessionRequest, CreateSessionResponse, CreateTaskRequest,
    CreateTaskResponse, GetApprovalRequest, GetApprovalResponse, PingRequest, PingResponse,
    RespondApprovalRequest, RespondApprovalResponse, RpcErrorCode, RpcMethod, RpcRequest,
    RpcResponse, TaskOperation, rpc_response,
};
use af_rpc_transport::{Endpoint, RpcClient};
use uuid::Uuid;

use crate::error::{Result, SdkError};

/// Options for `CreateSession` RPC calls.
#[derive(Debug, Clone)]
pub struct CreateSessionOptions {
    /// Agent name for the created session.
    ///
    /// When omitted, [`RuntimeClient`] uses the name passed to [`RuntimeClient::connect`].
    pub agent_name: Option<String>,
    /// Session lease TTL in seconds.
    ///
    /// When omitted, runtime defaults to `300` seconds.
    pub lease_ttl_secs: Option<u64>,
}

impl Default for CreateSessionOptions {
    fn default() -> Self {
        Self {
            agent_name: None,
            lease_ttl_secs: None,
        }
    }
}

impl CreateSessionOptions {
    /// Creates options with a specific agent name and default lease TTL behavior.
    ///
    /// # Examples
    /// ```
    /// use af_sdk::CreateSessionOptions;
    ///
    /// let options = CreateSessionOptions::with_agent_name("worker");
    /// assert_eq!(options.agent_name.as_deref(), Some("worker"));
    /// assert_eq!(options.lease_ttl_secs, None);
    /// ```
    pub fn with_agent_name(agent_name: impl Into<String>) -> Self {
        Self {
            agent_name: Some(agent_name.into()),
            lease_ttl_secs: None,
        }
    }
}

/// Low-level runtime RPC client.
///
/// This type directly maps to daemon RPC methods and exposes protocol-native
/// request/response types.
///
/// Prefer [`crate::AgentFortClient`] for automatic bootstrap/reconnect behavior.
#[derive(Debug)]
pub struct RuntimeClient {
    endpoint: Endpoint,
    transport: RpcClient,
    session_agent_name: String,
    client_instance_id: String,
}

impl RuntimeClient {
    /// Connects to a daemon endpoint and initializes client identity.
    ///
    /// `session_agent_name` becomes the default session agent name for
    /// [`Self::create_session`] calls that do not override it via
    /// [`CreateSessionOptions`].
    ///
    /// # Errors
    /// Returns endpoint parsing or transport connection errors.
    ///
    /// # Example
    /// ```no_run
    /// use af_sdk::{Result, RuntimeClient};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let _runtime = RuntimeClient::connect("unix:///tmp/agent-fortd.sock", "my-agent").await?;
    ///     Ok(())
    /// }
    /// ```
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

    /// Returns the parsed daemon endpoint for this connection.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Returns stable client instance ID generated at connection time.
    ///
    /// This value is reused across all RPC calls made through this runtime client.
    pub fn client_instance_id(&self) -> &str {
        &self.client_instance_id
    }

    /// Sends `Ping` RPC and returns daemon version/status payload.
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    pub async fn ping(&mut self) -> Result<PingResponse> {
        let payload = self
            .call_rpc(RpcMethod::Ping, encode_message(&PingRequest {}))
            .await?;
        decode_message::<PingResponse>(&payload)
            .map_err(|error| SdkError::Protocol(format!("decode PingResponse failed: {error}")))
    }

    /// Creates a new session.
    ///
    /// The request always carries this runtime's `client_instance_id`.
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    ///
    /// # Example
    /// ```no_run
    /// use af_sdk::{CreateSessionOptions, Result, RuntimeClient};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let mut runtime = RuntimeClient::connect("unix:///tmp/agent-fortd.sock", "my-agent").await?;
    ///     let _resp = runtime.create_session(CreateSessionOptions::default()).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn create_session(
        &mut self,
        options: CreateSessionOptions,
    ) -> Result<CreateSessionResponse> {
        let request = CreateSessionRequest {
            agent_name: options
                .agent_name
                .unwrap_or_else(|| self.session_agent_name.clone()),
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

    /// Creates a task under an existing session.
    ///
    /// Valid operation kinds in capability-first mode:
    /// - `exec`
    /// - `fs.read`
    /// - `fs.write`
    /// - `net`
    /// - `tool`
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    pub async fn create_task(
        &mut self,
        session_id: String,
        rebind_token: String,
        operation: TaskOperation,
        goal: Option<String>,
    ) -> Result<CreateTaskResponse> {
        let request = CreateTaskRequest {
            session_id,
            client_instance_id: self.client_instance_id.clone(),
            rebind_token,
            goal,
            operation: Some(operation),
        };
        let payload = self
            .call_rpc(RpcMethod::CreateTask, encode_message(&request))
            .await?;
        decode_message::<CreateTaskResponse>(&payload).map_err(|error| {
            SdkError::Protocol(format!("decode CreateTaskResponse failed: {error}"))
        })
    }

    /// Fetches an approval object by approval ID.
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    pub async fn get_approval(
        &mut self,
        session_id: String,
        approval_id: String,
        rebind_token: String,
    ) -> Result<GetApprovalResponse> {
        let request = GetApprovalRequest {
            session_id,
            approval_id,
            client_instance_id: self.client_instance_id.clone(),
            rebind_token,
        };
        let payload = self
            .call_rpc(RpcMethod::GetApproval, encode_message(&request))
            .await?;
        decode_message::<GetApprovalResponse>(&payload).map_err(|error| {
            SdkError::Protocol(format!("decode GetApprovalResponse failed: {error}"))
        })
    }

    /// Submits an approval decision.
    ///
    /// `idempotency_key` should be unique per logical decision operation to support
    /// safe retries.
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    pub async fn respond_approval(
        &mut self,
        session_id: String,
        approval_id: String,
        decision: ApprovalDecision,
        idempotency_key: String,
        reason: Option<String>,
        rebind_token: String,
    ) -> Result<RespondApprovalResponse> {
        let request = RespondApprovalRequest {
            session_id,
            approval_id,
            decision: decision as i32,
            idempotency_key,
            reason,
            client_instance_id: self.client_instance_id.clone(),
            rebind_token,
        };
        let payload = self
            .call_rpc(RpcMethod::RespondApproval, encode_message(&request))
            .await?;
        decode_message::<RespondApprovalResponse>(&payload).map_err(|error| {
            SdkError::Protocol(format!("decode RespondApprovalResponse failed: {error}"))
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
