use af_rpc_proto::{Approval, ApprovalDecision, PingResponse, RespondApprovalResponse};

use crate::error::Result;
use crate::runtime::RuntimeClient;

#[derive(Debug)]
pub struct ApprovalClient<'a> {
    runtime: &'a mut RuntimeClient,
}

impl<'a> ApprovalClient<'a> {
    pub(crate) fn new(runtime: &'a mut RuntimeClient) -> Self {
        Self { runtime }
    }

    pub async fn ping_daemon(&mut self) -> Result<PingResponse> {
        self.runtime.ping().await
    }

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
