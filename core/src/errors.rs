use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionAppError {
    #[error("session validation failed: {message}")]
    Validation { message: String },
    #[error("session storage failed: {message}")]
    Store { message: String },
    #[error("session audit write failed: {message}")]
    Audit { message: String },
    #[error("session internal error: {message}")]
    Internal { message: String },
}

#[derive(Debug, Error)]
pub enum ApprovalAppError {
    #[error("approval validation failed: {message}")]
    Validation { message: String },
    #[error("approval not found: session_id={session_id}, approval_id={approval_id}")]
    NotFound {
        session_id: String,
        approval_id: String,
    },
    #[error("approval expired: approval_id={approval_id}")]
    Expired { approval_id: String },
    #[error("approval idempotency conflict: approval_id={approval_id}")]
    IdempotencyConflict { approval_id: String },
    #[error("approval invalid state: {message}")]
    InvalidState { message: String },
    #[error("approval storage failed: {message}")]
    Store { message: String },
    #[error("approval audit write failed: {message}")]
    Audit { message: String },
    #[error("approval internal error: {message}")]
    Internal { message: String },
}

#[derive(Debug, Error)]
pub enum TaskAppError {
    #[error("task validation failed: {message}")]
    Validation { message: String },
    #[error("task not found: session_id={session_id}, task_id={task_id}")]
    NotFound { session_id: String, task_id: String },
    #[error("task invalid state: {message}")]
    InvalidState { message: String },
    #[error("task storage failed: {message}")]
    Store { message: String },
    #[error("task audit write failed: {message}")]
    Audit { message: String },
    #[error("task internal error: {message}")]
    Internal { message: String },
}

#[derive(Debug, Error)]
pub enum CapabilityGrantAppError {
    #[error("capability grant validation failed: {message}")]
    Validation { message: String },
    #[error("capability grant conflict: {message}")]
    Conflict { message: String },
    #[error("capability grant policy denied: {message}")]
    PolicyDenied { message: String },
    #[error("capability grant storage failed: {message}")]
    Store { message: String },
    #[error("capability grant internal error: {message}")]
    Internal { message: String },
}
