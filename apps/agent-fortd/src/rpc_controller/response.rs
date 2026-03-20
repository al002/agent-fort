use super::*;

pub(super) fn ok(payload: Vec<u8>) -> RpcResponse {
    RpcResponse {
        outcome: Some(rpc_response::Outcome::Payload(payload)),
    }
}

pub(super) fn err(code: RpcErrorCode, message: impl Into<String>) -> RpcResponse {
    RpcResponse {
        outcome: Some(rpc_response::Outcome::Error(RpcError {
            code: code as i32,
            message: message.into(),
        })),
    }
}

pub(super) fn rpc_error_details(response: &RpcResponse) -> Option<(RpcErrorCode, String)> {
    let rpc_response::Outcome::Error(error) = response.outcome.as_ref()? else {
        return None;
    };
    let code = RpcErrorCode::try_from(error.code).ok()?;
    Some((code, error.message.clone()))
}

pub(super) fn map_store_error(error: StoreError, context: &str) -> RpcResponse {
    match error {
        StoreError::Conflict(message) => err(
            RpcErrorCode::InvalidTaskState,
            format!("{context} conflict: {message}"),
        ),
        StoreError::NotFound(message) => err(
            RpcErrorCode::StoreError,
            format!("{context} not found: {message}"),
        ),
        other => err(
            RpcErrorCode::StoreError,
            format!("{context} failed: {other}"),
        ),
    }
}

pub(super) fn map_session_error(error: SessionAppError) -> RpcResponse {
    match error {
        SessionAppError::Validation { message } => err(RpcErrorCode::BadRequest, message),
        SessionAppError::Store { message } => err(RpcErrorCode::StoreError, message),
        SessionAppError::Audit { message } => err(RpcErrorCode::AuditWriteFailed, message),
        SessionAppError::Internal { message } => err(RpcErrorCode::InternalError, message),
    }
}

pub(super) fn map_task_error(error: TaskAppError) -> RpcResponse {
    match error {
        TaskAppError::Validation { message } => err(RpcErrorCode::BadRequest, message),
        TaskAppError::NotFound { .. } => err(RpcErrorCode::TaskNotFound, "task not found"),
        TaskAppError::InvalidState { message } => err(RpcErrorCode::InvalidTaskState, message),
        TaskAppError::Store { message } => err(RpcErrorCode::StoreError, message),
        TaskAppError::Audit { message } => err(RpcErrorCode::AuditWriteFailed, message),
        TaskAppError::Internal { message } => err(RpcErrorCode::InternalError, message),
    }
}

pub(super) fn map_approval_error(error: ApprovalAppError) -> RpcResponse {
    match error {
        ApprovalAppError::Validation { message } => err(RpcErrorCode::BadRequest, message),
        ApprovalAppError::NotFound { .. } => {
            err(RpcErrorCode::ApprovalNotFound, "approval not found")
        }
        ApprovalAppError::Expired { .. } => err(RpcErrorCode::ApprovalExpired, "approval expired"),
        ApprovalAppError::IdempotencyConflict { .. } => err(
            RpcErrorCode::ApprovalIdempotencyConflict,
            "approval idempotency conflict",
        ),
        ApprovalAppError::InvalidState { message } => {
            err(RpcErrorCode::ApprovalInvalidState, message)
        }
        ApprovalAppError::Store { message } => err(RpcErrorCode::StoreError, message),
        ApprovalAppError::Audit { message } => err(RpcErrorCode::AuditWriteFailed, message),
        ApprovalAppError::Internal { message } => err(RpcErrorCode::InternalError, message),
    }
}

pub(super) fn map_task_repo_error(error: af_task::TaskRepositoryError) -> RpcResponse {
    match error {
        af_task::TaskRepositoryError::NotFound { .. } => {
            err(RpcErrorCode::TaskNotFound, "task not found")
        }
        af_task::TaskRepositoryError::Validation { message } => {
            err(RpcErrorCode::BadRequest, message)
        }
        af_task::TaskRepositoryError::InvalidState { message }
        | af_task::TaskRepositoryError::Conflict { message } => {
            err(RpcErrorCode::InvalidTaskState, message)
        }
        af_task::TaskRepositoryError::AlreadyExists { .. }
        | af_task::TaskRepositoryError::Storage { .. } => err(
            RpcErrorCode::StoreError,
            format!("task repository failed: {error}"),
        ),
    }
}

pub(super) fn map_approval_repo_error(error: af_approval::ApprovalRepositoryError) -> RpcResponse {
    match error {
        af_approval::ApprovalRepositoryError::Validation { message } => {
            err(RpcErrorCode::BadRequest, message)
        }
        af_approval::ApprovalRepositoryError::AlreadyExists { .. }
        | af_approval::ApprovalRepositoryError::Conflict { .. }
        | af_approval::ApprovalRepositoryError::Storage { .. }
        | af_approval::ApprovalRepositoryError::NotFound { .. }
        | af_approval::ApprovalRepositoryError::Expired { .. }
        | af_approval::ApprovalRepositoryError::IdempotencyConflict { .. }
        | af_approval::ApprovalRepositoryError::InvalidState { .. } => err(
            RpcErrorCode::StoreError,
            format!("approval repository failed: {error}"),
        ),
    }
}

pub(super) fn map_audit_repo_error(error: af_audit::AuditRepositoryError) -> RpcResponse {
    err(
        RpcErrorCode::AuditWriteFailed,
        format!("audit repository failed: {error}"),
    )
}

pub(super) fn map_session_lookup_error(error: SessionRepositoryError) -> RpcResponse {
    match error {
        SessionRepositoryError::NotFound { .. } => {
            err(RpcErrorCode::SessionNotFound, "session not found")
        }
        SessionRepositoryError::AlreadyExists { .. }
        | SessionRepositoryError::Conflict { .. }
        | SessionRepositoryError::Validation { .. }
        | SessionRepositoryError::Storage { .. } => err(
            RpcErrorCode::StoreError,
            format!("session lookup failed: {error}"),
        ),
    }
}
