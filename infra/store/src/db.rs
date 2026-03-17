use std::fs;
use std::path::Path;

use rusqlite::Connection;

use crate::{JournalMode, StoreError, StoreOptions, StoreResult, SynchronousMode, sql_err};

pub(crate) fn open_connection(options: &StoreOptions) -> StoreResult<Connection> {
    ensure_parent_dir_exists(&options.path)?;

    let connection = Connection::open(&options.path)
        .map_err(|error| StoreError::OpenFailed(error.to_string()))?;
    configure_connection(&connection, options)?;
    Ok(connection)
}

pub(crate) fn configure_connection(
    connection: &Connection,
    options: &StoreOptions,
) -> StoreResult<()> {
    let journal_mode = match options.journal_mode {
        JournalMode::Wal => "WAL",
        JournalMode::Delete => "DELETE",
    };
    let synchronous = match options.synchronous {
        SynchronousMode::Off => "OFF",
        SynchronousMode::Normal => "NORMAL",
        SynchronousMode::Full => "FULL",
    };
    let foreign_keys = if options.enforce_foreign_keys {
        "ON"
    } else {
        "OFF"
    };
    let pragma_sql = format!(
        "PRAGMA journal_mode={journal_mode};\
         PRAGMA foreign_keys={foreign_keys};\
         PRAGMA synchronous={synchronous};"
    );

    connection
        .execute_batch(&pragma_sql)
        .map_err(|error| sql_err("configure sqlite pragmas", error))?;
    connection
        .busy_timeout(options.busy_timeout)
        .map_err(|error| sql_err("set sqlite busy timeout", error))?;
    Ok(())
}

pub(crate) fn now_ms() -> u64 {
    let now = std::time::SystemTime::now();
    let elapsed = now
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after unix epoch");
    elapsed
        .as_millis()
        .try_into()
        .expect("timestamp fits into u64")
}

fn ensure_parent_dir_exists(path: &Path) -> StoreResult<()> {
    if is_memory_path(path) {
        return Ok(());
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| {
            StoreError::OpenFailed(format!(
                "create store parent dir `{}`: {error}",
                parent.display()
            ))
        })?;
    }
    Ok(())
}

fn is_memory_path(path: &Path) -> bool {
    path.as_os_str() == ":memory:"
}
