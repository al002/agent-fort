use crate::errors::TaskRepositoryError;
use crate::model::{AdvanceTaskStepCommand, NewTask, Task, UpdateTaskStatusCommand};

pub trait TaskRepository: Send + Sync {
    fn create_task(&self, command: NewTask) -> Result<Task, TaskRepositoryError>;

    fn get_task(&self, session_id: &str, task_id: &str) -> Result<Task, TaskRepositoryError>;

    fn list_session_tasks(
        &self,
        session_id: &str,
        limit: u32,
        after_created_at_ms: Option<u64>,
        after_task_id: Option<&str>,
    ) -> Result<Vec<Task>, TaskRepositoryError>;

    fn update_task_status(
        &self,
        command: UpdateTaskStatusCommand,
    ) -> Result<Task, TaskRepositoryError>;

    fn advance_task_step(
        &self,
        command: AdvanceTaskStepCommand,
    ) -> Result<Task, TaskRepositoryError>;
}
