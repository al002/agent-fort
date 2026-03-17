use af_audit::AuditEventType;

use crate::{StoreError, StoreResult};

pub(crate) fn audit_event_type_to_db(event_type: AuditEventType) -> &'static str {
    match event_type {
        AuditEventType::IpcPeerUnauthorized => "IPC_PEER_UNAUTHORIZED",
        AuditEventType::SessionCreated => "SESSION_CREATED",
        AuditEventType::SessionTerminated => "SESSION_TERMINATED",
        AuditEventType::TaskCreated => "TASK_CREATED",
        AuditEventType::TaskStarted => "TASK_STARTED",
        AuditEventType::TaskCompleted => "TASK_COMPLETED",
        AuditEventType::TaskFailed => "TASK_FAILED",
        AuditEventType::TaskCancelled => "TASK_CANCELLED",
        AuditEventType::ApprovalCreated => "APPROVAL_CREATED",
        AuditEventType::ApprovalApproved => "APPROVAL_APPROVED",
        AuditEventType::ApprovalDenied => "APPROVAL_DENIED",
        AuditEventType::ApprovalExpired => "APPROVAL_EXPIRED",
        AuditEventType::ApprovalCancelled => "APPROVAL_CANCELLED",
        AuditEventType::PolicyDenied => "POLICY_DENIED",
        AuditEventType::InvocationStarted => "INVOCATION_STARTED",
        AuditEventType::InvocationAwaitingApproval => "INVOCATION_AWAITING_APPROVAL",
        AuditEventType::InvocationResumedAfterApproval => "INVOCATION_RESUMED_AFTER_APPROVAL",
        AuditEventType::InvocationCompleted => "INVOCATION_COMPLETED",
        AuditEventType::InvocationDenied => "INVOCATION_DENIED",
        AuditEventType::InvocationCancelled => "INVOCATION_CANCELLED",
        AuditEventType::InvocationFailed => "INVOCATION_FAILED",
    }
}

pub(crate) fn audit_event_type_from_db(event_type: &str) -> StoreResult<AuditEventType> {
    match event_type {
        "IPC_PEER_UNAUTHORIZED" => Ok(AuditEventType::IpcPeerUnauthorized),
        "SESSION_CREATED" => Ok(AuditEventType::SessionCreated),
        "SESSION_TERMINATED" => Ok(AuditEventType::SessionTerminated),
        "TASK_CREATED" => Ok(AuditEventType::TaskCreated),
        "TASK_STARTED" => Ok(AuditEventType::TaskStarted),
        "TASK_COMPLETED" => Ok(AuditEventType::TaskCompleted),
        "TASK_FAILED" => Ok(AuditEventType::TaskFailed),
        "TASK_CANCELLED" => Ok(AuditEventType::TaskCancelled),
        "APPROVAL_CREATED" => Ok(AuditEventType::ApprovalCreated),
        "APPROVAL_APPROVED" => Ok(AuditEventType::ApprovalApproved),
        "APPROVAL_DENIED" => Ok(AuditEventType::ApprovalDenied),
        "APPROVAL_EXPIRED" => Ok(AuditEventType::ApprovalExpired),
        "APPROVAL_CANCELLED" => Ok(AuditEventType::ApprovalCancelled),
        "POLICY_DENIED" => Ok(AuditEventType::PolicyDenied),
        "INVOCATION_STARTED" => Ok(AuditEventType::InvocationStarted),
        "INVOCATION_AWAITING_APPROVAL" => Ok(AuditEventType::InvocationAwaitingApproval),
        "INVOCATION_RESUMED_AFTER_APPROVAL" => Ok(AuditEventType::InvocationResumedAfterApproval),
        "INVOCATION_COMPLETED" => Ok(AuditEventType::InvocationCompleted),
        "INVOCATION_DENIED" => Ok(AuditEventType::InvocationDenied),
        "INVOCATION_CANCELLED" => Ok(AuditEventType::InvocationCancelled),
        "INVOCATION_FAILED" => Ok(AuditEventType::InvocationFailed),
        _ => Err(StoreError::Internal(format!(
            "invalid audit event type in db: {event_type}"
        ))),
    }
}
