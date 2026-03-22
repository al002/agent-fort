use std::sync::Arc;

use af_audit::{AuditEventType, NewAuditEvent};
use af_task::{NewTask, Task, TaskCreatedBy, TaskStatus};
use uuid::Uuid;

use crate::errors::TaskAppError;
use crate::time::now_ms;

#[derive(Debug, Clone)]
pub struct CreateTaskInput {
    pub session_id: String,
    pub goal: Option<String>,
    pub created_by: TaskCreatedBy,
}

#[derive(Debug, Clone)]
pub struct CancelTaskInput {
    pub session_id: String,
    pub task_id: String,
}

#[derive(Debug, Clone)]
pub struct CreateTaskWrite {
    pub task: NewTask,
    pub audit_event: NewAuditEvent,
}

#[derive(Debug, Clone)]
pub struct CancelTaskWrite {
    pub session_id: String,
    pub task_id: String,
    pub cancelled_at_ms: u64,
}

pub trait TaskPort: Send + Sync {
    fn create_with_audit(&self, write: CreateTaskWrite) -> Result<Task, TaskAppError>;

    fn get_task(&self, session_id: &str, task_id: &str) -> Result<Task, TaskAppError>;

    fn cancel_with_audit(&self, write: CancelTaskWrite) -> Result<Task, TaskAppError>;
}

#[derive(Clone)]
pub struct TaskAppService {
    port: Arc<dyn TaskPort>,
}

impl std::fmt::Debug for TaskAppService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskAppService")
            .finish_non_exhaustive()
    }
}

impl TaskAppService {
    pub fn new(port: Arc<dyn TaskPort>) -> Self {
        Self { port }
    }

    pub fn create_task(&self, input: CreateTaskInput) -> Result<Task, TaskAppError> {
        validate_non_empty("session_id", &input.session_id)?;

        let now_ms = now_ms();
        let task_id = Uuid::new_v4().to_string();
        let trace_id = Uuid::new_v4().to_string();
        let write = CreateTaskWrite {
            task: NewTask {
                task_id: task_id.clone(),
                session_id: input.session_id.clone(),
                status: TaskStatus::Pending,
                goal: input.goal,
                created_by: input.created_by,
                trace_id: trace_id.clone(),
                current_step: 0,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            },
            audit_event: NewAuditEvent {
                ts_ms: now_ms,
                trace_id,
                session_id: Some(input.session_id),
                task_id: Some(task_id),
                event_type: AuditEventType::TaskCreated,
                payload_json: None,
                error_code: None,
            },
        };

        self.port.create_with_audit(write)
    }

    pub fn get_task(&self, session_id: &str, task_id: &str) -> Result<Task, TaskAppError> {
        validate_non_empty("session_id", session_id)?;
        validate_non_empty("task_id", task_id)?;
        self.port.get_task(session_id, task_id)
    }

    pub fn cancel_task(&self, input: CancelTaskInput) -> Result<Task, TaskAppError> {
        validate_non_empty("session_id", &input.session_id)?;
        validate_non_empty("task_id", &input.task_id)?;

        self.port.cancel_with_audit(CancelTaskWrite {
            session_id: input.session_id,
            task_id: input.task_id,
            cancelled_at_ms: now_ms(),
        })
    }
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), TaskAppError> {
    if value.trim().is_empty() {
        return Err(TaskAppError::Validation {
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct StubPort {
        last_create: Mutex<Option<CreateTaskWrite>>,
        last_cancel: Mutex<Option<CancelTaskWrite>>,
    }

    impl StubPort {
        fn new() -> Self {
            Self {
                last_create: Mutex::new(None),
                last_cancel: Mutex::new(None),
            }
        }
    }

    impl TaskPort for StubPort {
        fn create_with_audit(&self, write: CreateTaskWrite) -> Result<Task, TaskAppError> {
            let task = Task {
                task_id: write.task.task_id.clone(),
                session_id: write.task.session_id.clone(),
                status: write.task.status,
                goal: write.task.goal.clone(),
                created_by: write.task.created_by,
                trace_id: write.task.trace_id.clone(),
                current_step: write.task.current_step,
                error_code: None,
                error_message: None,
                created_at_ms: write.task.created_at_ms,
                updated_at_ms: write.task.updated_at_ms,
                ended_at_ms: None,
            };
            *self.last_create.lock().expect("lock create") = Some(write);
            Ok(task)
        }

        fn get_task(&self, session_id: &str, task_id: &str) -> Result<Task, TaskAppError> {
            Ok(Task {
                task_id: task_id.to_string(),
                session_id: session_id.to_string(),
                status: TaskStatus::Running,
                goal: None,
                created_by: TaskCreatedBy::Explicit,
                trace_id: "trace-1".to_string(),
                current_step: 0,
                error_code: None,
                error_message: None,
                created_at_ms: 1_000,
                updated_at_ms: 1_000,
                ended_at_ms: None,
            })
        }

        fn cancel_with_audit(&self, write: CancelTaskWrite) -> Result<Task, TaskAppError> {
            *self.last_cancel.lock().expect("lock cancel") = Some(write.clone());
            Ok(Task {
                task_id: write.task_id,
                session_id: write.session_id,
                status: TaskStatus::Cancelled,
                goal: None,
                created_by: TaskCreatedBy::Explicit,
                trace_id: "trace-1".to_string(),
                current_step: 0,
                error_code: None,
                error_message: None,
                created_at_ms: 1_000,
                updated_at_ms: write.cancelled_at_ms,
                ended_at_ms: Some(write.cancelled_at_ms),
            })
        }
    }

    #[test]
    fn create_task_writes_pending_task_and_task_created_audit() {
        let port = Arc::new(StubPort::new());
        let service = TaskAppService::new(port.clone());

        let task = service
            .create_task(CreateTaskInput {
                session_id: "s-1".to_string(),
                goal: Some("do".to_string()),
                created_by: TaskCreatedBy::Explicit,
            })
            .expect("create task");

        assert_eq!(task.status, TaskStatus::Pending);
        assert_eq!(task.created_by, TaskCreatedBy::Explicit);

        let write = port
            .last_create
            .lock()
            .expect("lock create")
            .clone()
            .expect("create write exists");
        assert_eq!(write.audit_event.event_type, AuditEventType::TaskCreated);
        assert_eq!(write.audit_event.session_id.as_deref(), Some("s-1"));
        assert_eq!(
            write.audit_event.task_id.as_deref(),
            Some(task.task_id.as_str())
        );
    }

    #[test]
    fn cancel_task_passes_write_to_port() {
        let port = Arc::new(StubPort::new());
        let service = TaskAppService::new(port.clone());

        let cancelled = service
            .cancel_task(CancelTaskInput {
                session_id: "s-1".to_string(),
                task_id: "t-1".to_string(),
            })
            .expect("cancel task");
        assert_eq!(cancelled.status, TaskStatus::Cancelled);

        let write = port
            .last_cancel
            .lock()
            .expect("lock cancel")
            .clone()
            .expect("cancel write exists");
        assert_eq!(write.session_id, "s-1");
        assert_eq!(write.task_id, "t-1");
    }
}
