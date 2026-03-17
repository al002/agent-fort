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
