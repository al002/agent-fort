use std::sync::Arc;

use af_audit::NewAuditEvent;
use af_task::{AdvanceTaskStepCommand, Task, UpdateTaskStatusCommand};

use crate::TaskAppError;

pub trait TaskExecutionPort: Send + Sync {
    fn update_task_status(&self, command: UpdateTaskStatusCommand) -> Result<Task, TaskAppError>;

    fn advance_task_step(&self, command: AdvanceTaskStepCommand) -> Result<Task, TaskAppError>;

    fn append_task_audit(&self, event: NewAuditEvent) -> Result<(), TaskAppError>;
}

#[derive(Clone)]
pub struct TaskExecutionAppService {
    port: Arc<dyn TaskExecutionPort>,
}

impl std::fmt::Debug for TaskExecutionAppService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskExecutionAppService")
            .finish_non_exhaustive()
    }
}

impl TaskExecutionAppService {
    pub fn new(port: Arc<dyn TaskExecutionPort>) -> Self {
        Self { port }
    }

    pub fn update_task_status(
        &self,
        command: UpdateTaskStatusCommand,
    ) -> Result<Task, TaskAppError> {
        self.port.update_task_status(command)
    }

    pub fn advance_task_step(&self, command: AdvanceTaskStepCommand) -> Result<Task, TaskAppError> {
        self.port.advance_task_step(command)
    }

    pub fn append_task_audit(&self, event: NewAuditEvent) -> Result<(), TaskAppError> {
        self.port.append_task_audit(event)
    }
}
