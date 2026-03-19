use af_rpc_proto::{Approval, ApprovalDecision, PingResponse, RespondApprovalResponse};

use crate::error::Result;
use crate::runtime::RuntimeClient;

/// Approval-focused API surface.
///
/// This client is created from [`crate::AgentFortClient::approvals`] and borrows
/// the underlying runtime connection mutably.
#[derive(Debug)]
pub struct ApprovalClient<'a> {
    runtime: &'a mut RuntimeClient,
}

impl<'a> ApprovalClient<'a> {
    pub(crate) fn new(runtime: &'a mut RuntimeClient) -> Self {
        Self { runtime }
    }

    /// Pings the daemon through the shared runtime connection.
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    pub async fn ping_daemon(&mut self) -> Result<PingResponse> {
        self.runtime.ping().await
    }

    /// Fetches a single approval by ID.
    ///
    /// Returns protocol error when daemon omits `approval` in the response payload.
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
    pub async fn get(
        &mut self,
        session_id: String,
        approval_id: String,
        rebind_token: String,
    ) -> Result<Approval> {
        let response = self
            .runtime
            .get_approval(session_id, approval_id, rebind_token)
            .await?;
        response.approval.ok_or_else(|| {
            crate::error::SdkError::Protocol("GetApprovalResponse missing approval".to_string())
        })
    }

    /// Responds to an approval with accept/reject decision.
    ///
    /// `idempotency_key` should be unique for each logical decision submit.
    ///
    /// # Errors
    /// Returns transport, RPC, or protocol decode errors.
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
    ///     let mut approvals = client.approvals().await?;
    ///     let decision = todo!();
    ///     let _resp = approvals
    ///         .respond(
    ///             "session-id".to_string(),
    ///             "approval-id".to_string(),
    ///             decision,
    ///             "idempotency-key-1".to_string(),
    ///             Some("approved by policy".to_string()),
    ///             "rebind-token".to_string(),
    ///         )
    ///         .await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn respond(
        &mut self,
        session_id: String,
        approval_id: String,
        decision: ApprovalDecision,
        idempotency_key: String,
        reason: Option<String>,
        rebind_token: String,
    ) -> Result<RespondApprovalResponse> {
        self.runtime
            .respond_approval(
                session_id,
                approval_id,
                decision,
                idempotency_key,
                reason,
                rebind_token,
            )
            .await
    }
}
