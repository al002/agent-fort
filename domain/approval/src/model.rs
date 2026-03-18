use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalItem {
    pub kind: String,
    pub target: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub approval_id: String,
    pub session_id: String,
    pub task_id: String,
    pub trace_id: String,
    pub status: ApprovalStatus,
    pub summary: String,
    pub details: Option<String>,
    pub items: Vec<ApprovalItem>,
    pub policy_reason: String,
    pub policy_revision: u64,
    pub execution_contract_json: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub responded_at_ms: Option<u64>,
    pub response_reason: Option<String>,
    pub response_idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApproval {
    pub approval_id: String,
    pub session_id: String,
    pub task_id: String,
    pub trace_id: String,
    pub status: ApprovalStatus,
    pub summary: String,
    pub details: Option<String>,
    pub items: Vec<ApprovalItem>,
    pub policy_reason: String,
    pub policy_revision: u64,
    pub execution_contract_json: String,
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
