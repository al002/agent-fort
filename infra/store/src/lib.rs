mod db;
mod migrations;
mod repo_approval;
mod repo_approval_tx;
mod repo_audit;
mod repo_capability_grant;
mod repo_session;
mod repo_session_tx;
mod repo_task;
mod repo_task_tx;
mod sql_audit;
mod sql_session;
mod worker;

#[cfg(test)]
mod repository_tests;

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, Error as SqliteError, ErrorCode};
use thiserror::Error;

pub use migrations::{LATEST_SCHEMA_VERSION, MigrationReport};
pub use repo_capability_grant::{CapabilityGrantEventRecord, CapabilityGrantRecord};

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalMode {
    Wal,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynchronousMode {
    Off,
    Normal,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOptions {
    pub path: PathBuf,
    pub journal_mode: JournalMode,
    pub synchronous: SynchronousMode,
    pub busy_timeout: Duration,
    pub enforce_foreign_keys: bool,
}

impl StoreOptions {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            journal_mode: JournalMode::Wal,
            synchronous: SynchronousMode::Normal,
            busy_timeout: Duration::from_secs(5),
            enforce_foreign_keys: true,
        }
    }

    pub fn in_memory() -> Self {
        Self::new(":memory:")
    }
}

#[derive(Debug)]
pub struct Store {
    options: StoreOptions,
    startup_migration_report: MigrationReport,
    worker: worker::StoreWorker,
}

impl Store {
    pub fn open(options: StoreOptions) -> StoreResult<Self> {
        let (worker, startup_migration_report) = worker::StoreWorker::start(options.clone())?;
        Ok(Self {
            options,
            startup_migration_report,
            worker,
        })
    }

    pub fn open_path(path: impl AsRef<Path>) -> StoreResult<Self> {
        Self::open(StoreOptions::new(path.as_ref().to_path_buf()))
    }

    pub fn options(&self) -> &StoreOptions {
        &self.options
    }

    pub fn startup_migration_report(&self) -> &MigrationReport {
        &self.startup_migration_report
    }

    pub fn ping(&self) -> StoreResult<()> {
        self.worker.execute(|connection| {
            connection
                .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .map(|_| ())
                .map_err(|error| sql_err("ping", error))
        })
    }

    pub fn schema_version(&self) -> StoreResult<u64> {
        self.worker.execute(migrations::current_version)
    }

    #[allow(dead_code)]
    pub(crate) fn execute<F, R>(&self, operation: F) -> StoreResult<R>
    where
        F: FnOnce(&mut Connection) -> StoreResult<R> + Send + 'static,
        R: Send + 'static,
    {
        self.worker.execute(operation)
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite open failed: {0}")]
    OpenFailed(String),
    #[error("migration failed: {0}")]
    MigrationFailed(String),
    #[error("sqlite constraint violation: {0}")]
    ConstraintViolation(String),
    #[error("store item not found: {0}")]
    NotFound(String),
    #[error("store conflict: {0}")]
    Conflict(String),
    #[error("store rule conflict ({code}): {message}")]
    RuleConflict { code: &'static str, message: String },
    #[error("sqlite busy timeout: {0}")]
    BusyTimeout(String),
    #[error("store internal error: {0}")]
    Internal(String),
}

pub(crate) fn sql_err(operation: &str, error: SqliteError) -> StoreError {
    match error {
        SqliteError::QueryReturnedNoRows => {
            StoreError::NotFound(format!("{operation}: query returned no rows"))
        }
        SqliteError::SqliteFailure(sqlite_error, detail) => {
            let detail = detail.unwrap_or_else(|| sqlite_error.to_string());
            match sqlite_error.code {
                ErrorCode::ConstraintViolation => {
                    StoreError::ConstraintViolation(format!("{operation}: {detail}"))
                }
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => {
                    StoreError::BusyTimeout(format!("{operation}: {detail}"))
                }
                _ => StoreError::Internal(format!("{operation}: {detail}")),
            }
        }
        _ => StoreError::Internal(format!("{operation}: {error}")),
    }
}

pub(crate) fn to_i64(value: u64, field: &str) -> StoreResult<i64> {
    i64::try_from(value)
        .map_err(|_| StoreError::Internal(format!("{field} value out of i64 range: {value}")))
}

pub(crate) fn to_u64(value: i64, field: &str) -> StoreResult<u64> {
    u64::try_from(value)
        .map_err(|_| StoreError::Internal(format!("{field} value cannot be negative: {value}")))
}

pub(crate) fn storage_msg(error: StoreError) -> String {
    match error {
        StoreError::ConstraintViolation(message)
        | StoreError::NotFound(message)
        | StoreError::Conflict(message)
        | StoreError::RuleConflict { message, .. }
        | StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => message,
    }
}

pub(crate) fn is_dup_key(message: &str) -> bool {
    message.contains("UNIQUE") || message.contains("PRIMARY KEY")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn opens_in_memory_store_and_reports_schema_version() {
        let store = Store::open(StoreOptions::in_memory()).expect("open in-memory store");
        store.ping().expect("store ping should succeed");
        assert_eq!(store.schema_version().expect("schema version query"), 1);
        assert_eq!(store.startup_migration_report().current_version, 1);
        assert_eq!(store.startup_migration_report().applied_count, 1);
    }

    #[test]
    fn migration_is_idempotent_for_file_store() {
        let path = unique_temp_store_path();
        let first = Store::open_path(&path).expect("open file store first time");
        assert_eq!(first.startup_migration_report().applied_count, 1);
        drop(first);

        let second = Store::open_path(&path).expect("open file store second time");
        assert_eq!(second.startup_migration_report().applied_count, 0);
        assert_eq!(second.startup_migration_report().skipped_count, 1);
        assert_eq!(second.schema_version().expect("schema version query"), 1);
        drop(second);

        let _ = fs::remove_file(path);
    }

    fn unique_temp_store_path() -> PathBuf {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("af-store-test-{since_epoch}.sqlite3"))
    }
}
