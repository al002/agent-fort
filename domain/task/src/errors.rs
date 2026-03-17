use thiserror::Error;

#[derive(Debug, Error)]
pub enum TaskRepositoryError {
    #[error("task not found: session_id={session_id}, task_id={task_id}")]
    NotFound { session_id: String, task_id: String },
    #[error("task already exists: session_id={session_id}, task_id={task_id}")]
    AlreadyExists { session_id: String, task_id: String },
    #[error("task invalid state transition: {message}")]
    InvalidState { message: String },
    #[error("task conflict: {message}")]
    Conflict { message: String },
    #[error("task validation failed: {message}")]
    Validation { message: String },
    #[error("task storage failure: {message}")]
    Storage { message: String },
}
