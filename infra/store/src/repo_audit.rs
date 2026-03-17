use af_audit::{
    AuditCursor, AuditEvent, AuditEventType, AuditRepository, AuditRepositoryError, NewAuditEvent,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{Store, StoreError, StoreResult, sql_err, storage_msg, to_i64, to_u64};

impl AuditRepository for Store {
    fn append_event(&self, event: NewAuditEvent) -> Result<AuditEvent, AuditRepositoryError> {
        self.execute(move |connection| append_event(connection, event))
            .map_err(on_store_err)
    }

    fn list_by_trace(
        &self,
        trace_id: &str,
        cursor: AuditCursor,
    ) -> Result<Vec<AuditEvent>, AuditRepositoryError> {
        let trace_id = trace_id.to_string();
        self.execute(move |connection| {
            list_scoped(connection, AuditQueryScope::Trace(trace_id), cursor)
        })
        .map_err(on_store_err)
    }

    fn list_by_session(
        &self,
        session_id: &str,
        cursor: AuditCursor,
    ) -> Result<Vec<AuditEvent>, AuditRepositoryError> {
        let session_id = session_id.to_string();
        self.execute(move |connection| {
            list_scoped(connection, AuditQueryScope::Session(session_id), cursor)
        })
        .map_err(on_store_err)
    }

    fn list_by_task(
        &self,
        task_id: &str,
        cursor: AuditCursor,
    ) -> Result<Vec<AuditEvent>, AuditRepositoryError> {
        let task_id = task_id.to_string();
        self.execute(move |connection| {
            list_scoped(connection, AuditQueryScope::Task(task_id), cursor)
        })
        .map_err(on_store_err)
    }
}

fn append_event(connection: &mut Connection, event: NewAuditEvent) -> StoreResult<AuditEvent> {
    connection
        .execute(
            "INSERT INTO audit_events (
               ts_ms, trace_id, session_id, task_id, event_type, payload_json, error_code
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                to_i64(event.ts_ms, "ts_ms")?,
                event.trace_id,
                event.session_id,
                event.task_id,
                audit_event_type_to_db(event.event_type),
                event.payload_json,
                event.error_code,
            ],
        )
        .map_err(|error| sql_err("insert audit event", error))?;

    let seq = connection.last_insert_rowid();
    load_by_seq(connection, seq)?.ok_or_else(|| {
        StoreError::Internal("inserted audit event missing after insert".to_string())
    })
}

fn list_scoped(
    connection: &mut Connection,
    scope: AuditQueryScope,
    cursor: AuditCursor,
) -> StoreResult<Vec<AuditEvent>> {
    let scope_column = scope.column_name();
    let scope_value = scope.value();
    let sql = match cursor.after_seq {
        Some(_) => format!(
            "SELECT seq, ts_ms, trace_id, session_id, task_id, event_type, payload_json, error_code
             FROM audit_events
             WHERE {scope_column} = ?1 AND seq > ?2
             ORDER BY seq ASC
             LIMIT ?3"
        ),
        None => format!(
            "SELECT seq, ts_ms, trace_id, session_id, task_id, event_type, payload_json, error_code
             FROM audit_events
             WHERE {scope_column} = ?1
             ORDER BY seq ASC
             LIMIT ?2"
        ),
    };
    let values = match cursor.after_seq {
        Some(after_seq) => vec![
            scope_value.into(),
            to_i64(after_seq, "after_seq")?.into(),
            i64::from(cursor.limit).into(),
        ],
        None => vec![scope_value.into(), i64::from(cursor.limit).into()],
    };

    query(connection, &sql, values)
}

fn query(
    connection: &Connection,
    sql: &str,
    values: Vec<rusqlite::types::Value>,
) -> StoreResult<Vec<AuditEvent>> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|error| sql_err("prepare audit event query", error))?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(values), row_to_raw_event)
        .map_err(|error| sql_err("query audit events", error))?;
    let raw = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sql_err("collect audit events", error))?;
    raw.into_iter().map(RawAuditEvent::into_domain).collect()
}

fn load_by_seq(connection: &Connection, seq: i64) -> StoreResult<Option<AuditEvent>> {
    let event = connection
        .query_row(
            "SELECT seq, ts_ms, trace_id, session_id, task_id, event_type, payload_json, error_code
             FROM audit_events
             WHERE seq = ?1",
            [seq],
            row_to_raw_event,
        )
        .optional()
        .map_err(|error| sql_err("fetch audit event by seq", error))?;
    event.map(RawAuditEvent::into_domain).transpose()
}

#[derive(Debug)]
struct RawAuditEvent {
    seq: i64,
    ts_ms: i64,
    trace_id: String,
    session_id: Option<String>,
    task_id: Option<String>,
    event_type: String,
    payload_json: Option<String>,
    error_code: Option<String>,
}

impl RawAuditEvent {
    fn into_domain(self) -> StoreResult<AuditEvent> {
        Ok(AuditEvent {
            seq: to_u64(self.seq, "seq")?,
            ts_ms: to_u64(self.ts_ms, "ts_ms")?,
            trace_id: self.trace_id,
            session_id: self.session_id,
            task_id: self.task_id,
            event_type: audit_event_type_from_db(&self.event_type)?,
            payload_json: self.payload_json,
            error_code: self.error_code,
        })
    }
}

fn row_to_raw_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawAuditEvent> {
    Ok(RawAuditEvent {
        seq: row.get(0)?,
        ts_ms: row.get(1)?,
        trace_id: row.get(2)?,
        session_id: row.get(3)?,
        task_id: row.get(4)?,
        event_type: row.get(5)?,
        payload_json: row.get(6)?,
        error_code: row.get(7)?,
    })
}

fn audit_event_type_to_db(event_type: AuditEventType) -> &'static str {
    match event_type {
        AuditEventType::IpcPeerUnauthorized => "IPC_PEER_UNAUTHORIZED",
        AuditEventType::SessionCreated => "SESSION_CREATED",
        AuditEventType::SessionTerminated => "SESSION_TERMINATED",
        AuditEventType::TaskCreated => "TASK_CREATED",
        AuditEventType::TaskStarted => "TASK_STARTED",
        AuditEventType::TaskCompleted => "TASK_COMPLETED",
        AuditEventType::TaskFailed => "TASK_FAILED",
        AuditEventType::TaskCancelled => "TASK_CANCELLED",
        AuditEventType::ApprovalCreated => "APPROVAL_CREATED",
        AuditEventType::ApprovalApproved => "APPROVAL_APPROVED",
        AuditEventType::ApprovalDenied => "APPROVAL_DENIED",
        AuditEventType::ApprovalExpired => "APPROVAL_EXPIRED",
        AuditEventType::ApprovalCancelled => "APPROVAL_CANCELLED",
        AuditEventType::PolicyDenied => "POLICY_DENIED",
        AuditEventType::InvocationStarted => "INVOCATION_STARTED",
        AuditEventType::InvocationAwaitingApproval => "INVOCATION_AWAITING_APPROVAL",
        AuditEventType::InvocationResumedAfterApproval => "INVOCATION_RESUMED_AFTER_APPROVAL",
        AuditEventType::InvocationCompleted => "INVOCATION_COMPLETED",
        AuditEventType::InvocationDenied => "INVOCATION_DENIED",
        AuditEventType::InvocationCancelled => "INVOCATION_CANCELLED",
        AuditEventType::InvocationFailed => "INVOCATION_FAILED",
    }
}

fn audit_event_type_from_db(event_type: &str) -> StoreResult<AuditEventType> {
    match event_type {
        "IPC_PEER_UNAUTHORIZED" => Ok(AuditEventType::IpcPeerUnauthorized),
        "SESSION_CREATED" => Ok(AuditEventType::SessionCreated),
        "SESSION_TERMINATED" => Ok(AuditEventType::SessionTerminated),
        "TASK_CREATED" => Ok(AuditEventType::TaskCreated),
        "TASK_STARTED" => Ok(AuditEventType::TaskStarted),
        "TASK_COMPLETED" => Ok(AuditEventType::TaskCompleted),
        "TASK_FAILED" => Ok(AuditEventType::TaskFailed),
        "TASK_CANCELLED" => Ok(AuditEventType::TaskCancelled),
        "APPROVAL_CREATED" => Ok(AuditEventType::ApprovalCreated),
        "APPROVAL_APPROVED" => Ok(AuditEventType::ApprovalApproved),
        "APPROVAL_DENIED" => Ok(AuditEventType::ApprovalDenied),
        "APPROVAL_EXPIRED" => Ok(AuditEventType::ApprovalExpired),
        "APPROVAL_CANCELLED" => Ok(AuditEventType::ApprovalCancelled),
        "POLICY_DENIED" => Ok(AuditEventType::PolicyDenied),
        "INVOCATION_STARTED" => Ok(AuditEventType::InvocationStarted),
        "INVOCATION_AWAITING_APPROVAL" => Ok(AuditEventType::InvocationAwaitingApproval),
        "INVOCATION_RESUMED_AFTER_APPROVAL" => Ok(AuditEventType::InvocationResumedAfterApproval),
        "INVOCATION_COMPLETED" => Ok(AuditEventType::InvocationCompleted),
        "INVOCATION_DENIED" => Ok(AuditEventType::InvocationDenied),
        "INVOCATION_CANCELLED" => Ok(AuditEventType::InvocationCancelled),
        "INVOCATION_FAILED" => Ok(AuditEventType::InvocationFailed),
        _ => Err(StoreError::Internal(format!(
            "invalid audit event type in db: {event_type}"
        ))),
    }
}

fn on_store_err(error: StoreError) -> AuditRepositoryError {
    AuditRepositoryError::Storage {
        message: storage_msg(error),
    }
}

enum AuditQueryScope {
    Trace(String),
    Session(String),
    Task(String),
}

impl AuditQueryScope {
    fn column_name(&self) -> &'static str {
        match self {
            Self::Trace(_) => "trace_id",
            Self::Session(_) => "session_id",
            Self::Task(_) => "task_id",
        }
    }

    fn value(self) -> String {
        match self {
            Self::Trace(value) | Self::Session(value) | Self::Task(value) => value,
        }
    }
}
