use af_audit::{AuditRepository, AuditRepositoryError, NewAuditEvent};
use af_core::{TaskAppError, TaskExecutionPort};
use af_task::{
    AdvanceTaskStepCommand, Task, TaskRepository, TaskRepositoryError, UpdateTaskStatusCommand,
};

use crate::Store;

impl TaskExecutionPort for Store {
    fn update_task_status(&self, command: UpdateTaskStatusCommand) -> Result<Task, TaskAppError> {
        <Store as TaskRepository>::update_task_status(self, command).map_err(map_task_repo_error)
    }

    fn advance_task_step(&self, command: AdvanceTaskStepCommand) -> Result<Task, TaskAppError> {
        <Store as TaskRepository>::advance_task_step(self, command).map_err(map_task_repo_error)
    }

    fn append_task_audit(&self, event: NewAuditEvent) -> Result<(), TaskAppError> {
        <Store as AuditRepository>::append_event(self, event)
            .map(|_| ())
            .map_err(map_audit_repo_error)
    }
}

fn map_task_repo_error(error: TaskRepositoryError) -> TaskAppError {
    match error {
        TaskRepositoryError::NotFound {
            session_id,
            task_id,
        } => TaskAppError::NotFound {
            session_id,
            task_id,
        },
        TaskRepositoryError::Validation { message } => TaskAppError::Validation { message },
        TaskRepositoryError::InvalidState { message }
        | TaskRepositoryError::Conflict { message } => TaskAppError::InvalidState { message },
        TaskRepositoryError::AlreadyExists { .. } | TaskRepositoryError::Storage { .. } => {
            TaskAppError::Store {
                message: format!("task repository failed: {error}"),
            }
        }
    }
}

fn map_audit_repo_error(error: AuditRepositoryError) -> TaskAppError {
    TaskAppError::Audit {
        message: format!("audit repository failed: {error}"),
    }
}
