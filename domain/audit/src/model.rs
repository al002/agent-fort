#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    IpcPeerUnauthorized,
    SessionCreated,
    SessionTerminated,
    TaskCreated,
    TaskStarted,
    TaskCompleted,
    TaskFailed,
    TaskCancelled,
    ApprovalCreated,
    ApprovalApproved,
    ApprovalDenied,
    ApprovalExpired,
    ApprovalCancelled,
    PolicyDenied,
    InvocationStarted,
    InvocationAwaitingApproval,
    InvocationResumedAfterApproval,
    InvocationCompleted,
    InvocationDenied,
    InvocationCancelled,
    InvocationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub seq: u64,
    pub ts_ms: u64,
    pub trace_id: String,
    pub session_id: Option<String>,
    pub task_id: Option<String>,
    pub event_type: AuditEventType,
    pub payload_json: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEvent {
    pub ts_ms: u64,
    pub trace_id: String,
    pub session_id: Option<String>,
    pub task_id: Option<String>,
    pub event_type: AuditEventType,
    pub payload_json: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCursor {
    pub after_seq: Option<u64>,
    pub limit: u32,
}
