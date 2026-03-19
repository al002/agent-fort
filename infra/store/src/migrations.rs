use rusqlite::{Connection, OptionalExtension};

use crate::{StoreResult, sql_err};

pub const LATEST_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationReport {
    pub current_version: u64,
    pub applied_count: u64,
    pub skipped_count: u64,
}

const INIT_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  agent_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'EXPIRED', 'TERMINATED')),
  client_instance_id TEXT NOT NULL,
  rebind_token TEXT NOT NULL,
  lease_expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  terminated_at_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_status_expires
  ON sessions(status, lease_expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_sessions_agent_name_status
  ON sessions(agent_name, status);

CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'BLOCKED', 'COMPLETED', 'FAILED', 'CANCELLED')),
  goal TEXT,
  created_by TEXT NOT NULL CHECK (created_by IN ('EXPLICIT')),
  trace_id TEXT NOT NULL,
  current_step INTEGER NOT NULL,
  error_code TEXT,
  error_message TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  ended_at_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_tasks_session_created_desc
  ON tasks(session_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_status_updated_desc
  ON tasks(status, updated_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_trace
  ON tasks(trace_id);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
  trace_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED')),
  summary TEXT NOT NULL,
  details TEXT,
  items_json TEXT NOT NULL CHECK (json_valid(items_json)),
  policy_reason TEXT NOT NULL,
  policy_revision INTEGER NOT NULL,
  execution_contract_json TEXT NOT NULL CHECK (json_valid(execution_contract_json)),
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  responded_at_ms INTEGER,
  response_reason TEXT,
  response_idempotency_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_session_status_created_desc
  ON approvals(session_id, status, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_status_expires
  ON approvals(status, expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_approvals_task
  ON approvals(task_id);

CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ms INTEGER NOT NULL,
  trace_id TEXT NOT NULL,
  session_id TEXT,
  task_id TEXT,
  event_type TEXT NOT NULL,
  payload_json TEXT CHECK (payload_json IS NULL OR json_valid(payload_json)),
  error_code TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_trace_seq
  ON audit_events(trace_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_session_seq
  ON audit_events(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_task_seq
  ON audit_events(task_id, seq);

CREATE TABLE IF NOT EXISTS capability_grants (
  session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
  revision INTEGER NOT NULL,
  expires_at INTEGER,
  capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_capability_grants_updated_at
  ON capability_grants(updated_at);

CREATE TABLE IF NOT EXISTS capability_grant_events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  from_revision INTEGER NOT NULL,
  to_revision INTEGER NOT NULL,
  delta_json TEXT NOT NULL CHECK (json_valid(delta_json)),
  actor TEXT NOT NULL CHECK (actor IN ('system', 'user', 'policy')),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_capability_grant_events_session_created
  ON capability_grant_events(session_id, created_at);
"#;

pub(crate) fn apply_all(connection: &mut Connection) -> StoreResult<MigrationReport> {
    let existed = schema_exists(connection)?;

    connection
        .execute_batch(INIT_SCHEMA_SQL)
        .map_err(|error| sql_err("apply init schema", error))?;

    Ok(MigrationReport {
        current_version: LATEST_SCHEMA_VERSION,
        applied_count: if existed { 0 } else { 1 },
        skipped_count: if existed { 1 } else { 0 },
    })
}

pub(crate) fn current_version(connection: &mut Connection) -> StoreResult<u64> {
    if schema_exists(connection)? {
        Ok(LATEST_SCHEMA_VERSION)
    } else {
        Ok(0)
    }
}

fn schema_exists(connection: &Connection) -> StoreResult<bool> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sessions' LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| sql_err("query schema existence", error))?
        .is_some();
    Ok(exists)
}
