use af_task::{
    AdvanceTaskStepCommand, NewTask, Task, TaskCreatedBy, TaskRepository, TaskRepositoryError,
    TaskStatus, UpdateTaskStatusCommand,
};
use rusqlite::{params, Connection, OptionalExtension};

use crate::{is_dup_key, sql_err, storage_msg, to_i64, to_u64, Store, StoreError, StoreResult};

impl TaskRepository for Store {
    fn create_task(&self, command: NewTask) -> Result<Task, TaskRepositoryError> {
        let session_id = command.session_id.clone();
        let task_id = command.task_id.clone();
        self.execute(move |connection| insert_task(connection, command))
            .map_err(|error| on_create_err(error, &session_id, &task_id))
    }

    fn get_task(&self, session_id: &str, task_id: &str) -> Result<Task, TaskRepositoryError> {
        let session_id = session_id.to_string();
        let task_id = task_id.to_string();
        let lookup_session_id = session_id.clone();
        let lookup_task_id = task_id.clone();
        self.execute(move |connection| {
            load_task(connection, &lookup_session_id, &lookup_task_id)?.ok_or_else(|| {
                StoreError::NotFound(format!(
                    "task not found: session_id={lookup_session_id}, task_id={lookup_task_id}"
                ))
            })
        })
        .map_err(|error| on_lookup_err(error, &session_id, &task_id))
    }

    fn list_session_tasks(
        &self,
        session_id: &str,
        limit: u32,
        after_created_at_ms: Option<u64>,
        after_task_id: Option<&str>,
    ) -> Result<Vec<Task>, TaskRepositoryError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let session_id = session_id.to_string();
        let after_task_id = after_task_id.map(ToString::to_string);
        self.execute(move |connection| {
            list_tasks(
                connection,
                &session_id,
                limit,
                after_created_at_ms,
                after_task_id,
            )
        })
        .map_err(on_store_err)
    }

    fn update_task_status(
        &self,
        command: UpdateTaskStatusCommand,
    ) -> Result<Task, TaskRepositoryError> {
        let session_id = command.session_id.clone();
        let task_id = command.task_id.clone();
        self.execute(move |connection| set_status(connection, command))
            .map_err(|error| on_update_err(error, &session_id, &task_id))
    }

    fn advance_task_step(
        &self,
        command: AdvanceTaskStepCommand,
    ) -> Result<Task, TaskRepositoryError> {
        let session_id = command.session_id.clone();
        let task_id = command.task_id.clone();
        self.execute(move |connection| set_step(connection, command))
            .map_err(|error| on_update_err(error, &session_id, &task_id))
    }
}

fn insert_task(connection: &mut Connection, command: NewTask) -> StoreResult<Task> {
    connection
        .execute(
            "INSERT INTO tasks (
               task_id, session_id, status, goal, created_by, trace_id, limits_json,
               current_step, error_code, error_message, created_at_ms, updated_at_ms, ended_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, ?9, ?10, NULL)",
            params![
                command.task_id,
                command.session_id,
                task_status_to_db(command.status),
                command.goal,
                task_created_by_to_db(command.created_by),
                command.trace_id,
                command.limits_json,
                i64::from(command.current_step),
                to_i64(command.created_at_ms, "created_at_ms")?,
                to_i64(command.updated_at_ms, "updated_at_ms")?,
            ],
        )
        .map_err(|error| sql_err("insert task", error))?;

    load_task(connection, &command.session_id, &command.task_id)?
        .ok_or_else(|| StoreError::Internal("inserted task missing after insert".to_string()))
}

fn list_tasks(
    connection: &mut Connection,
    session_id: &str,
    limit: u32,
    after_created_at_ms: Option<u64>,
    after_task_id: Option<String>,
) -> StoreResult<Vec<Task>> {
    let (query, params): (&str, Vec<rusqlite::types::Value>) =
        match (after_created_at_ms, after_task_id) {
            (Some(after_created_at_ms), Some(after_task_id)) => (
                "SELECT
               task_id, session_id, status, goal, created_by, trace_id, limits_json,
               current_step, error_code, error_message, created_at_ms, updated_at_ms, ended_at_ms
             FROM tasks
             WHERE session_id = ?1
               AND (created_at_ms < ?2 OR (created_at_ms = ?2 AND task_id < ?3))
             ORDER BY created_at_ms DESC, task_id DESC
             LIMIT ?4",
                vec![
                    session_id.to_string().into(),
                    to_i64(after_created_at_ms, "after_created_at_ms")?.into(),
                    after_task_id.into(),
                    i64::from(limit).into(),
                ],
            ),
            _ => (
                "SELECT
               task_id, session_id, status, goal, created_by, trace_id, limits_json,
               current_step, error_code, error_message, created_at_ms, updated_at_ms, ended_at_ms
             FROM tasks
             WHERE session_id = ?1
             ORDER BY created_at_ms DESC, task_id DESC
             LIMIT ?2",
                vec![session_id.to_string().into(), i64::from(limit).into()],
            ),
        };

    let mut statement = connection
        .prepare(query)
        .map_err(|error| sql_err("prepare list session tasks", error))?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(params), row_to_raw_task)
        .map_err(|error| sql_err("query list session tasks", error))?;
    let raw = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sql_err("collect list session tasks", error))?;
    raw.into_iter().map(RawTask::into_domain).collect()
}

fn set_status(connection: &mut Connection, command: UpdateTaskStatusCommand) -> StoreResult<Task> {
    let updated_rows = match command.expected_status {
        Some(expected_status) => connection
            .execute(
                "UPDATE tasks
                 SET status = ?1, updated_at_ms = ?2, ended_at_ms = ?3, error_code = ?4, error_message = ?5
                 WHERE session_id = ?6 AND task_id = ?7 AND status = ?8",
                params![
                    task_status_to_db(command.new_status),
                    to_i64(command.updated_at_ms, "updated_at_ms")?,
                    command
                        .ended_at_ms
                        .map(|value| to_i64(value, "ended_at_ms"))
                        .transpose()?,
                    command.error_code,
                    command.error_message,
                    command.session_id,
                    command.task_id,
                    task_status_to_db(expected_status),
                ],
            )
            .map_err(|error| sql_err("update task status", error))?,
        None => connection
            .execute(
                "UPDATE tasks
                 SET status = ?1, updated_at_ms = ?2, ended_at_ms = ?3, error_code = ?4, error_message = ?5
                 WHERE session_id = ?6 AND task_id = ?7",
                params![
                    task_status_to_db(command.new_status),
                    to_i64(command.updated_at_ms, "updated_at_ms")?,
                    command
                        .ended_at_ms
                        .map(|value| to_i64(value, "ended_at_ms"))
                        .transpose()?,
                    command.error_code,
                    command.error_message,
                    command.session_id,
                    command.task_id,
                ],
            )
            .map_err(|error| sql_err("update task status", error))?,
    };

    if updated_rows == 0 {
        return on_update_miss(connection, &command.session_id, &command.task_id);
    }

    load_task(connection, &command.session_id, &command.task_id)?
        .ok_or_else(|| StoreError::Internal("updated task missing after status update".to_string()))
}

fn set_step(connection: &mut Connection, command: AdvanceTaskStepCommand) -> StoreResult<Task> {
    if command.next_step <= command.expected_current_step {
        return Err(StoreError::Conflict(format!(
            "next_step must be greater than expected_current_step: {} <= {}",
            command.next_step, command.expected_current_step
        )));
    }

    let updated_rows = connection
        .execute(
            "UPDATE tasks
             SET current_step = ?1, updated_at_ms = ?2
             WHERE session_id = ?3 AND task_id = ?4 AND current_step = ?5",
            params![
                i64::from(command.next_step),
                to_i64(command.updated_at_ms, "updated_at_ms")?,
                command.session_id,
                command.task_id,
                i64::from(command.expected_current_step),
            ],
        )
        .map_err(|error| sql_err("advance task step", error))?;

    if updated_rows == 0 {
        return on_update_miss(connection, &command.session_id, &command.task_id);
    }

    load_task(connection, &command.session_id, &command.task_id)?
        .ok_or_else(|| StoreError::Internal("updated task missing after step advance".to_string()))
}

pub(crate) fn load_task(
    connection: &Connection,
    session_id: &str,
    task_id: &str,
) -> StoreResult<Option<Task>> {
    let raw = connection
        .query_row(
            "SELECT
               task_id, session_id, status, goal, created_by, trace_id, limits_json,
               current_step, error_code, error_message, created_at_ms, updated_at_ms, ended_at_ms
             FROM tasks
             WHERE session_id = ?1 AND task_id = ?2",
            params![session_id, task_id],
            row_to_raw_task,
        )
        .optional()
        .map_err(|error| sql_err("fetch task", error))?;
    raw.map(RawTask::into_domain).transpose()
}

fn on_update_miss(connection: &Connection, session_id: &str, task_id: &str) -> StoreResult<Task> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM tasks WHERE session_id = ?1 AND task_id = ?2 LIMIT 1",
            params![session_id, task_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| sql_err("check task existence", error))?
        .is_some();

    if exists {
        Err(StoreError::Conflict(format!(
            "task update conflict: session_id={session_id}, task_id={task_id}"
        )))
    } else {
        Err(StoreError::NotFound(format!(
            "task not found: session_id={session_id}, task_id={task_id}"
        )))
    }
}

#[derive(Debug)]
struct RawTask {
    task_id: String,
    session_id: String,
    status: String,
    goal: Option<String>,
    created_by: String,
    trace_id: String,
    limits_json: Option<String>,
    current_step: i64,
    error_code: Option<String>,
    error_message: Option<String>,
    created_at_ms: i64,
    updated_at_ms: i64,
    ended_at_ms: Option<i64>,
}

impl RawTask {
    fn into_domain(self) -> StoreResult<Task> {
        Ok(Task {
            task_id: self.task_id,
            session_id: self.session_id,
            status: task_status_from_db(&self.status)?,
            goal: self.goal,
            created_by: task_created_by_from_db(&self.created_by)?,
            trace_id: self.trace_id,
            limits_json: self.limits_json,
            current_step: u32::try_from(self.current_step).map_err(|_| {
                StoreError::Internal(format!("invalid current_step in db: {}", self.current_step))
            })?,
            error_code: self.error_code,
            error_message: self.error_message,
            created_at_ms: to_u64(self.created_at_ms, "created_at_ms")?,
            updated_at_ms: to_u64(self.updated_at_ms, "updated_at_ms")?,
            ended_at_ms: self
                .ended_at_ms
                .map(|value| to_u64(value, "ended_at_ms"))
                .transpose()?,
        })
    }
}

fn row_to_raw_task(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawTask> {
    Ok(RawTask {
        task_id: row.get(0)?,
        session_id: row.get(1)?,
        status: row.get(2)?,
        goal: row.get(3)?,
        created_by: row.get(4)?,
        trace_id: row.get(5)?,
        limits_json: row.get(6)?,
        current_step: row.get(7)?,
        error_code: row.get(8)?,
        error_message: row.get(9)?,
        created_at_ms: row.get(10)?,
        updated_at_ms: row.get(11)?,
        ended_at_ms: row.get(12)?,
    })
}

pub(crate) fn task_status_to_db(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Pending => "PENDING",
        TaskStatus::Running => "RUNNING",
        TaskStatus::Blocked => "BLOCKED",
        TaskStatus::Completed => "COMPLETED",
        TaskStatus::Failed => "FAILED",
        TaskStatus::Cancelled => "CANCELLED",
    }
}

pub(crate) fn task_status_from_db(status: &str) -> StoreResult<TaskStatus> {
    match status {
        "PENDING" => Ok(TaskStatus::Pending),
        "RUNNING" => Ok(TaskStatus::Running),
        "BLOCKED" => Ok(TaskStatus::Blocked),
        "COMPLETED" => Ok(TaskStatus::Completed),
        "FAILED" => Ok(TaskStatus::Failed),
        "CANCELLED" => Ok(TaskStatus::Cancelled),
        _ => Err(StoreError::Internal(format!(
            "invalid task status in db: {status}"
        ))),
    }
}

pub(crate) fn task_created_by_to_db(created_by: TaskCreatedBy) -> &'static str {
    match created_by {
        TaskCreatedBy::Explicit => "EXPLICIT",
        TaskCreatedBy::Invoke => "INVOKE",
    }
}

pub(crate) fn task_created_by_from_db(created_by: &str) -> StoreResult<TaskCreatedBy> {
    match created_by {
        "EXPLICIT" => Ok(TaskCreatedBy::Explicit),
        "INVOKE" => Ok(TaskCreatedBy::Invoke),
        _ => Err(StoreError::Internal(format!(
            "invalid task created_by in db: {created_by}"
        ))),
    }
}

fn on_create_err(error: StoreError, session_id: &str, task_id: &str) -> TaskRepositoryError {
    match error {
        StoreError::ConstraintViolation(message) => {
            if is_dup_key(&message) {
                TaskRepositoryError::AlreadyExists {
                    session_id: session_id.to_string(),
                    task_id: task_id.to_string(),
                }
            } else {
                TaskRepositoryError::Storage { message }
            }
        }
        StoreError::Conflict(message) => TaskRepositoryError::Conflict { message },
        StoreError::RuleConflict { message, .. } => TaskRepositoryError::Conflict { message },
        StoreError::NotFound(_) => TaskRepositoryError::NotFound {
            session_id: session_id.to_string(),
            task_id: task_id.to_string(),
        },
        StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => TaskRepositoryError::Storage { message },
    }
}

fn on_lookup_err(error: StoreError, session_id: &str, task_id: &str) -> TaskRepositoryError {
    match error {
        StoreError::NotFound(_) => TaskRepositoryError::NotFound {
            session_id: session_id.to_string(),
            task_id: task_id.to_string(),
        },
        StoreError::ConstraintViolation(message)
        | StoreError::Conflict(message)
        | StoreError::RuleConflict { message, .. }
        | StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => TaskRepositoryError::Storage { message },
    }
}

fn on_update_err(error: StoreError, session_id: &str, task_id: &str) -> TaskRepositoryError {
    match error {
        StoreError::NotFound(_) => TaskRepositoryError::NotFound {
            session_id: session_id.to_string(),
            task_id: task_id.to_string(),
        },
        StoreError::Conflict(message) => TaskRepositoryError::Conflict { message },
        StoreError::RuleConflict { message, .. } => TaskRepositoryError::Conflict { message },
        StoreError::ConstraintViolation(message)
        | StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => TaskRepositoryError::Storage { message },
    }
}

fn on_store_err(error: StoreError) -> TaskRepositoryError {
    TaskRepositoryError::Storage {
        message: storage_msg(error),
    }
}
