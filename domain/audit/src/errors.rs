use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditRepositoryError {
    #[error("audit validation failed: {message}")]
    Validation { message: String },
    #[error("audit storage failure: {message}")]
    Storage { message: String },
}
