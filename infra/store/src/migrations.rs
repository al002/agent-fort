use rusqlite::{Connection, OptionalExtension, params};

use crate::{StoreError, StoreResult, db, sql_err};

pub const LATEST_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationReport {
    pub current_version: u64,
    pub applied_count: u64,
    pub skipped_count: u64,
}

#[derive(Debug, Clone, Copy)]
struct Migration {
    version: u64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "init_store_schema",
    sql: r#"
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
  created_by TEXT NOT NULL CHECK (created_by IN ('EXPLICIT', 'INVOKE')),
  trace_id TEXT NOT NULL,
  limits_json TEXT CHECK (limits_json IS NULL OR json_valid(limits_json)),
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
  capability TEXT NOT NULL,
  operation TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED')),
  policy_reason TEXT NOT NULL,
  risk_class TEXT NOT NULL,
  command_class TEXT NOT NULL,
  input_brief_json TEXT NOT NULL CHECK (json_valid(input_brief_json)),
  requested_runtime_class TEXT NOT NULL,
  resolved_runtime_class TEXT NOT NULL,
  requires_network INTEGER NOT NULL CHECK (requires_network IN (0, 1)),
  requires_pty INTEGER NOT NULL CHECK (requires_pty IN (0, 1)),
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
"#,
}];

pub(crate) fn apply_all(connection: &mut Connection) -> StoreResult<MigrationReport> {
    create_migration_meta_table(connection)?;

    let mut applied_count = 0_u64;
    let mut skipped_count = 0_u64;

    for migration in MIGRATIONS {
        let checksum = checksum_hex(migration.sql);
        let version_i64 = i64::try_from(migration.version).expect("migration version fits in i64");
        let existing_checksum: Option<String> = connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = ?1",
                [version_i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| sql_err("read migration checksum", error))?;

        if let Some(existing_checksum) = existing_checksum {
            if existing_checksum != checksum {
                return Err(StoreError::MigrationFailed(format!(
                    "migration {} checksum mismatch: expected {}, got {}",
                    migration.version, existing_checksum, checksum
                )));
            }
            skipped_count += 1;
            continue;
        }

        let transaction = connection
            .transaction()
            .map_err(|error| sql_err("begin migration transaction", error))?;
        transaction
            .execute_batch(migration.sql)
            .map_err(|error| StoreError::MigrationFailed(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO schema_migrations (version, name, checksum, applied_at_ms) VALUES (?1, ?2, ?3, ?4)",
                params![
                    version_i64,
                    migration.name,
                    checksum,
                    i64::try_from(db::now_ms()).expect("timestamp fits in i64")
                ],
            )
            .map_err(|error| sql_err("insert migration record", error))?;
        transaction
            .commit()
            .map_err(|error| sql_err("commit migration transaction", error))?;
        applied_count += 1;
    }

    Ok(MigrationReport {
        current_version: current_version(connection)?,
        applied_count,
        skipped_count,
    })
}

pub(crate) fn current_version(connection: &mut Connection) -> StoreResult<u64> {
    let version_i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| sql_err("read schema version", error))?;
    u64::try_from(version_i64).map_err(|_| {
        StoreError::MigrationFailed(format!("invalid schema version value: {version_i64}"))
    })
}

fn create_migration_meta_table(connection: &mut Connection) -> StoreResult<()> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
               version INTEGER PRIMARY KEY,
               name TEXT NOT NULL UNIQUE,
               checksum TEXT NOT NULL,
               applied_at_ms INTEGER NOT NULL
             );",
        )
        .map_err(|error| sql_err("create schema_migrations table", error))
}

fn checksum_hex(text: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{hash:016x}")
}
