#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Pending,
    Running,
    Blocked,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCreatedBy {
    Explicit,
    Invoke,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub task_id: String,
    pub session_id: String,
    pub status: TaskStatus,
    pub goal: Option<String>,
    pub created_by: TaskCreatedBy,
    pub trace_id: String,
    pub limits_json: Option<String>,
    pub current_step: u32,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub ended_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTask {
    pub task_id: String,
    pub session_id: String,
    pub status: TaskStatus,
    pub goal: Option<String>,
    pub created_by: TaskCreatedBy,
    pub trace_id: String,
    pub limits_json: Option<String>,
    pub current_step: u32,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateTaskStatusCommand {
    pub session_id: String,
    pub task_id: String,
    pub expected_status: Option<TaskStatus>,
    pub new_status: TaskStatus,
    pub updated_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvanceTaskStepCommand {
    pub session_id: String,
    pub task_id: String,
    pub expected_current_step: u32,
    pub next_step: u32,
    pub updated_at_ms: u64,
}
