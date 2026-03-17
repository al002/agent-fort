use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionRepositoryError {
    #[error("session not found: {session_id}")]
    NotFound { session_id: String },
    #[error("session already exists: {session_id}")]
    AlreadyExists { session_id: String },
    #[error("session state conflict: {message}")]
    Conflict { message: String },
    #[error("session validation failed: {message}")]
    Validation { message: String },
    #[error("session storage failure: {message}")]
    Storage { message: String },
}
