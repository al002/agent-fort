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
