#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub approval_id: String,
    pub session_id: String,
    pub task_id: String,
    pub trace_id: String,
    pub capability: String,
    pub operation: String,
    pub status: ApprovalStatus,
    pub policy_reason: String,
    pub risk_class: String,
    pub command_class: String,
    pub input_brief_json: String,
    pub requested_runtime_backend: String,
    pub resolved_runtime_backend: String,
    pub requires_network: bool,
    pub requires_pty: bool,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub responded_at_ms: Option<u64>,
    pub response_reason: Option<String>,
    pub response_idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalSummary {
    pub approval_id: String,
    pub status: ApprovalStatus,
    pub expires_at_ms: u64,
    pub task_id: String,
    pub capability: String,
    pub operation: String,
    pub policy_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApproval {
    pub approval_id: String,
    pub session_id: String,
    pub task_id: String,
    pub trace_id: String,
    pub capability: String,
    pub operation: String,
    pub status: ApprovalStatus,
    pub policy_reason: String,
    pub risk_class: String,
    pub command_class: String,
    pub input_brief_json: String,
    pub requested_runtime_backend: String,
    pub resolved_runtime_backend: String,
    pub requires_network: bool,
    pub requires_pty: bool,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespondApprovalCommand {
    pub session_id: String,
    pub approval_id: String,
    pub decision: ApprovalDecision,
    pub idempotency_key: String,
    pub reason: Option<String>,
    pub responded_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPendingApprovalsQuery {
    pub session_id: String,
    pub limit: u32,
    pub after_approval_id: Option<String>,
}
