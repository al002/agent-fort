use crate::errors::AuditRepositoryError;
use crate::model::{AuditCursor, AuditEvent, NewAuditEvent};

pub trait AuditRepository: Send + Sync {
    fn append_event(&self, event: NewAuditEvent) -> Result<AuditEvent, AuditRepositoryError>;

    fn list_by_trace(
        &self,
        trace_id: &str,
        cursor: AuditCursor,
    ) -> Result<Vec<AuditEvent>, AuditRepositoryError>;

    fn list_by_session(
        &self,
        session_id: &str,
        cursor: AuditCursor,
    ) -> Result<Vec<AuditEvent>, AuditRepositoryError>;

    fn list_by_task(
        &self,
        task_id: &str,
        cursor: AuditCursor,
    ) -> Result<Vec<AuditEvent>, AuditRepositoryError>;
}
