use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApprovalRepositoryError {
    #[error("approval not found: session_id={session_id}, approval_id={approval_id}")]
    NotFound {
        session_id: String,
        approval_id: String,
    },
    #[error("approval already exists: approval_id={approval_id}")]
    AlreadyExists { approval_id: String },
    #[error("approval expired: approval_id={approval_id}")]
    Expired { approval_id: String },
    #[error("approval idempotency conflict: approval_id={approval_id}")]
    IdempotencyConflict { approval_id: String },
    #[error("approval invalid state transition: {message}")]
    InvalidState { message: String },
    #[error("approval conflict: {message}")]
    Conflict { message: String },
    #[error("approval validation failed: {message}")]
    Validation { message: String },
    #[error("approval storage failure: {message}")]
    Storage { message: String },
}
