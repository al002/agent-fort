use af_session::{
    NewSession, RenewLeaseCommand, Session, SessionRepository, SessionRepositoryError,
    SessionStatus, TerminateSessionCommand,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::sql_session::{RawSession, row_to_raw_session, session_status_to_db};
use crate::{Store, StoreError, StoreResult, is_dup_key, sql_err, storage_msg, to_i64};

impl SessionRepository for Store {
    fn create_session(&self, command: NewSession) -> Result<Session, SessionRepositoryError> {
        let session_id = command.session_id.clone();
        self.execute(move |connection| insert_session(connection, command))
            .map_err(|error| on_create_err(error, &session_id))
    }

    fn get_session(&self, session_id: &str) -> Result<Session, SessionRepositoryError> {
        let session_id = session_id.to_string();
        let lookup_id = session_id.clone();
        self.execute(move |connection| {
            load_session(connection, &lookup_id)?.ok_or_else(|| {
                StoreError::NotFound(format!("session not found: session_id={lookup_id}"))
            })
        })
        .map_err(|error| on_get_err(error, &session_id))
    }

    fn renew_lease(&self, command: RenewLeaseCommand) -> Result<Session, SessionRepositoryError> {
        let session_id = command.session_id.clone();
        self.execute(move |connection| renew_session(connection, command))
            .map_err(|error| on_update_err(error, &session_id))
    }

    fn terminate_session(
        &self,
        command: TerminateSessionCommand,
    ) -> Result<Session, SessionRepositoryError> {
        let session_id = command.session_id.clone();
        self.execute(move |connection| terminate(connection, command))
            .map_err(|error| on_update_err(error, &session_id))
    }

    fn list_expired_sessions(
        &self,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<Session>, SessionRepositoryError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        self.execute(move |connection| list_expired(connection, now_ms, limit))
            .map_err(on_store_err)
    }
}

fn insert_session(connection: &mut Connection, command: NewSession) -> StoreResult<Session> {
    connection
        .execute(
            "INSERT INTO sessions (
               session_id, agent_name, policy_profile, status,
               client_instance_id, rebind_token, lease_expires_at_ms,
               created_at_ms, updated_at_ms, terminated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            params![
                command.session_id,
                command.agent_name,
                command.policy_profile,
                session_status_to_db(SessionStatus::Active),
                command.lease.client_instance_id,
                command.lease.rebind_token,
                to_i64(command.lease.expires_at_ms, "lease_expires_at_ms")?,
                to_i64(command.created_at_ms, "created_at_ms")?,
                to_i64(command.updated_at_ms, "updated_at_ms")?,
            ],
        )
        .map_err(|error| sql_err("insert session", error))?;

    load_session(connection, &command.session_id)?
        .ok_or_else(|| StoreError::Internal("inserted session missing after insert".to_string()))
}

fn renew_session(connection: &mut Connection, command: RenewLeaseCommand) -> StoreResult<Session> {
    let rebind_token = command
        .new_rebind_token
        .unwrap_or_else(|| command.rebind_token.clone());

    let updated_rows = connection
        .execute(
            "UPDATE sessions
             SET rebind_token = ?1, lease_expires_at_ms = ?2, updated_at_ms = ?3
             WHERE session_id = ?4
               AND client_instance_id = ?5
               AND rebind_token = ?6
               AND status = ?7",
            params![
                rebind_token,
                to_i64(command.new_expires_at_ms, "new_expires_at_ms")?,
                to_i64(command.updated_at_ms, "updated_at_ms")?,
                command.session_id,
                command.client_instance_id,
                command.rebind_token,
                session_status_to_db(SessionStatus::Active),
            ],
        )
        .map_err(|error| sql_err("renew session lease", error))?;

    if updated_rows == 0 {
        return on_update_miss(connection, &command.session_id);
    }

    load_session(connection, &command.session_id)?
        .ok_or_else(|| StoreError::Internal("updated session missing after renew".to_string()))
}

fn terminate(
    connection: &mut Connection,
    command: TerminateSessionCommand,
) -> StoreResult<Session> {
    let updated_rows = connection
        .execute(
            "UPDATE sessions
             SET status = ?1, updated_at_ms = ?2, terminated_at_ms = ?3
             WHERE session_id = ?4
               AND client_instance_id = ?5
               AND rebind_token = ?6
               AND status <> ?7",
            params![
                session_status_to_db(SessionStatus::Terminated),
                to_i64(command.terminated_at_ms, "terminated_at_ms")?,
                to_i64(command.terminated_at_ms, "terminated_at_ms")?,
                command.session_id,
                command.client_instance_id,
                command.rebind_token,
                session_status_to_db(SessionStatus::Terminated),
            ],
        )
        .map_err(|error| sql_err("terminate session", error))?;

    if updated_rows == 0 {
        return on_update_miss(connection, &command.session_id);
    }

    load_session(connection, &command.session_id)?
        .ok_or_else(|| StoreError::Internal("updated session missing after terminate".to_string()))
}

fn list_expired(connection: &mut Connection, now_ms: u64, limit: u32) -> StoreResult<Vec<Session>> {
    let mut statement = connection
        .prepare(
            "SELECT
               session_id,
               agent_name,
               policy_profile,
               status,
               client_instance_id,
               rebind_token,
               lease_expires_at_ms,
               created_at_ms,
               updated_at_ms,
               terminated_at_ms
             FROM sessions
             WHERE status = ?1
               AND lease_expires_at_ms <= ?2
             ORDER BY lease_expires_at_ms ASC, session_id ASC
             LIMIT ?3",
        )
        .map_err(|error| sql_err("prepare list expired sessions", error))?;
    let rows = statement
        .query_map(
            params![
                session_status_to_db(SessionStatus::Active),
                to_i64(now_ms, "now_ms")?,
                i64::from(limit)
            ],
            row_to_raw_session,
        )
        .map_err(|error| sql_err("query list expired sessions", error))?;

    let raw: Vec<RawSession> = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sql_err("collect list expired sessions", error))?;
    raw.into_iter().map(RawSession::into_domain).collect()
}

fn load_session(connection: &Connection, session_id: &str) -> StoreResult<Option<Session>> {
    let raw = connection
        .query_row(
            "SELECT
               session_id,
               agent_name,
               policy_profile,
               status,
               client_instance_id,
               rebind_token,
               lease_expires_at_ms,
               created_at_ms,
               updated_at_ms,
               terminated_at_ms
             FROM sessions
             WHERE session_id = ?1",
            [session_id],
            row_to_raw_session,
        )
        .optional()
        .map_err(|error| sql_err("fetch session", error))?;

    raw.map(RawSession::into_domain).transpose()
}

fn on_update_miss(connection: &Connection, session_id: &str) -> StoreResult<Session> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM sessions WHERE session_id = ?1 LIMIT 1",
            [session_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| sql_err("check session existence", error))?
        .is_some();

    if exists {
        Err(StoreError::Conflict(format!(
            "session update conflict: session_id={session_id}"
        )))
    } else {
        Err(StoreError::NotFound(format!(
            "session not found: session_id={session_id}"
        )))
    }
}

fn on_create_err(error: StoreError, session_id: &str) -> SessionRepositoryError {
    match error {
        StoreError::ConstraintViolation(message) => {
            if is_dup_key(&message) {
                SessionRepositoryError::AlreadyExists {
                    session_id: session_id.to_string(),
                }
            } else {
                SessionRepositoryError::Storage { message }
            }
        }
        StoreError::Conflict(message) => SessionRepositoryError::Conflict { message },
        StoreError::RuleConflict { message, .. } => SessionRepositoryError::Conflict { message },
        StoreError::NotFound(_) => SessionRepositoryError::NotFound {
            session_id: session_id.to_string(),
        },
        StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => SessionRepositoryError::Storage { message },
    }
}

fn on_get_err(error: StoreError, session_id: &str) -> SessionRepositoryError {
    match error {
        StoreError::NotFound(_) => SessionRepositoryError::NotFound {
            session_id: session_id.to_string(),
        },
        StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::ConstraintViolation(message)
        | StoreError::Conflict(message)
        | StoreError::RuleConflict { message, .. }
        | StoreError::OpenFailed(message) => SessionRepositoryError::Storage { message },
    }
}

fn on_update_err(error: StoreError, session_id: &str) -> SessionRepositoryError {
    match error {
        StoreError::NotFound(_) => SessionRepositoryError::NotFound {
            session_id: session_id.to_string(),
        },
        StoreError::Conflict(message) => SessionRepositoryError::Conflict { message },
        StoreError::RuleConflict { message, .. } => SessionRepositoryError::Conflict { message },
        StoreError::ConstraintViolation(message)
        | StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => SessionRepositoryError::Storage { message },
    }
}

fn on_store_err(error: StoreError) -> SessionRepositoryError {
    SessionRepositoryError::Storage {
        message: storage_msg(error),
    }
}
