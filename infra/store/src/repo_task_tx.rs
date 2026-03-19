use af_audit::{AuditEventType, NewAuditEvent};
use af_core::{CancelTaskWrite, CreateTaskWrite, TaskAppError, TaskPort};
use af_task::{Task, TaskStatus};
use rusqlite::{Connection, Transaction, params};

use crate::repo_task::{load_task, task_created_by_to_db, task_status_to_db};
use crate::sql_audit::audit_event_type_to_db;
use crate::{Store, StoreError, sql_err, storage_msg, to_i64};

impl TaskPort for Store {
    fn create_with_audit(&self, write: CreateTaskWrite) -> Result<Task, TaskAppError> {
        self.execute(move |conn| Ok(create_with_audit(conn, write)))
            .map_err(|error| TaskAppError::Store {
                message: storage_msg(error),
            })?
    }

    fn get_task(&self, session_id: &str, task_id: &str) -> Result<Task, TaskAppError> {
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

    fn cancel_with_audit(&self, write: CancelTaskWrite) -> Result<Task, TaskAppError> {
        self.execute(move |conn| Ok(cancel_with_audit(conn, write)))
            .map_err(|error| TaskAppError::Store {
                message: storage_msg(error),
            })?
    }
}

fn create_with_audit(
    connection: &mut Connection,
    write: CreateTaskWrite,
) -> Result<Task, TaskAppError> {
    let tx = connection
        .transaction()
        .map_err(|error| store_err(sql_err("begin create task tx", error)))?;

    insert_task(&tx, &write)?;
    insert_audit(&tx, &write.audit_event)?;

    let task = load_task(&tx, &write.task.session_id, &write.task.task_id)
        .map_err(store_err)?
        .ok_or_else(|| TaskAppError::Store {
            message: "task missing after create tx".to_string(),
        })?;
    tx.commit()
        .map_err(|error| store_err(sql_err("commit create task tx", error)))?;
    Ok(task)
}

fn cancel_with_audit(
    connection: &mut Connection,
    write: CancelTaskWrite,
) -> Result<Task, TaskAppError> {
    let tx = connection
        .transaction()
        .map_err(|error| store_err(sql_err("begin cancel task tx", error)))?;

    let task = load_task(&tx, &write.session_id, &write.task_id)
        .map_err(store_err)?
        .ok_or_else(|| TaskAppError::NotFound {
            session_id: write.session_id.clone(),
            task_id: write.task_id.clone(),
        })?;

    if !is_cancellable(task.status) {
        return Err(TaskAppError::InvalidState {
            message: format!(
                "task cannot be cancelled from status={}",
                task_status_to_db(task.status)
            ),
        });
    }

    let updated_rows = tx
        .execute(
            "UPDATE tasks
             SET status = ?1, updated_at_ms = ?2, ended_at_ms = ?3, error_code = NULL, error_message = NULL
             WHERE session_id = ?4 AND task_id = ?5
               AND status IN (?6, ?7, ?8)",
            params![
                task_status_to_db(TaskStatus::Cancelled),
                to_i64(write.cancelled_at_ms, "cancelled_at_ms").map_err(store_err)?,
                to_i64(write.cancelled_at_ms, "cancelled_at_ms").map_err(store_err)?,
                &write.session_id,
                &write.task_id,
                task_status_to_db(TaskStatus::Pending),
                task_status_to_db(TaskStatus::Running),
                task_status_to_db(TaskStatus::Blocked),
            ],
        )
        .map_err(|error| store_err(sql_err("update task status to cancelled in tx", error)))?;

    if updated_rows == 0 {
        return Err(TaskAppError::InvalidState {
            message: "task cancel update missed due state change".to_string(),
        });
    }

    insert_audit(
        &tx,
        &NewAuditEvent {
            ts_ms: write.cancelled_at_ms,
            trace_id: task.trace_id.clone(),
            session_id: Some(write.session_id.clone()),
            task_id: Some(write.task_id.clone()),
            event_type: AuditEventType::TaskCancelled,
            payload_json: None,
            error_code: None,
        },
    )?;

    let cancelled = load_task(&tx, &write.session_id, &write.task_id)
        .map_err(store_err)?
        .ok_or_else(|| TaskAppError::Store {
            message: "task missing after cancel tx".to_string(),
        })?;

    tx.commit()
        .map_err(|error| store_err(sql_err("commit cancel task tx", error)))?;
    Ok(cancelled)
}

fn insert_task(tx: &Transaction<'_>, write: &CreateTaskWrite) -> Result<(), TaskAppError> {
    tx.execute(
        "INSERT INTO tasks (
           task_id, session_id, status, goal, created_by, trace_id,
           current_step, error_code, error_message, created_at_ms, updated_at_ms, ended_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, ?8, ?9, NULL)",
        params![
            &write.task.task_id,
            &write.task.session_id,
            task_status_to_db(write.task.status),
            &write.task.goal,
            task_created_by_to_db(write.task.created_by),
            &write.task.trace_id,
            i64::from(write.task.current_step),
            to_i64(write.task.created_at_ms, "created_at_ms").map_err(store_err)?,
            to_i64(write.task.updated_at_ms, "updated_at_ms").map_err(store_err)?,
        ],
    )
    .map_err(|error| store_err(sql_err("insert task in create tx", error)))?;
    Ok(())
}

fn insert_audit(tx: &Transaction<'_>, event: &NewAuditEvent) -> Result<(), TaskAppError> {
    tx.execute(
        "INSERT INTO audit_events (
           ts_ms, trace_id, session_id, task_id, event_type, payload_json, error_code
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            to_i64(event.ts_ms, "ts_ms").map_err(audit_err)?,
            &event.trace_id,
            &event.session_id,
            &event.task_id,
            audit_event_type_to_db(event.event_type),
            &event.payload_json,
            &event.error_code,
        ],
    )
    .map_err(|error| audit_err(sql_err("insert task audit in tx", error)))?;
    Ok(())
}

fn on_lookup_err(error: StoreError, session_id: &str, task_id: &str) -> TaskAppError {
    match error {
        StoreError::NotFound(_) => TaskAppError::NotFound {
            session_id: session_id.to_string(),
            task_id: task_id.to_string(),
        },
        StoreError::Conflict(message)
        | StoreError::RuleConflict { message, .. }
        | StoreError::ConstraintViolation(message)
        | StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => TaskAppError::Store { message },
    }
}

fn is_cancellable(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Pending | TaskStatus::Running | TaskStatus::Blocked
    )
}

fn store_err(error: StoreError) -> TaskAppError {
    TaskAppError::Store {
        message: storage_msg(error),
    }
}

fn audit_err(error: StoreError) -> TaskAppError {
    TaskAppError::Audit {
        message: storage_msg(error),
    }
}
