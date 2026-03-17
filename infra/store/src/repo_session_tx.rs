use af_audit::NewAuditEvent;
use af_core::{CreateSessionWrite, SessionAppError, SessionWritePort};
use af_session::{Session, SessionStatus};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::sql_audit::audit_event_type_to_db;
use crate::sql_session::{row_to_raw_session, session_status_to_db};
use crate::{Store, StoreError, sql_err, storage_msg, to_i64};

impl SessionWritePort for Store {
    fn create_with_audit(&self, write: CreateSessionWrite) -> Result<Session, SessionAppError> {
        self.execute(move |conn| Ok(create_with_audit(conn, write)))
            .map_err(|error| SessionAppError::Store {
                message: storage_msg(error),
            })?
    }
}

fn create_with_audit(
    connection: &mut Connection,
    write: CreateSessionWrite,
) -> Result<Session, SessionAppError> {
    let tx = connection
        .transaction()
        .map_err(|error| store_err(sql_err("begin create session tx", error)))?;

    insert_session(&tx, &write)?;
    insert_audit(&tx, &write.audit_event)?;
    let session =
        load_session(&tx, &write.session.session_id)?.ok_or_else(|| SessionAppError::Store {
            message: "session missing after create tx".to_string(),
        })?;

    tx.commit()
        .map_err(|error| store_err(sql_err("commit create session tx", error)))?;
    Ok(session)
}

fn insert_session(tx: &Transaction<'_>, write: &CreateSessionWrite) -> Result<(), SessionAppError> {
    tx.execute(
        "INSERT INTO sessions (
           session_id, agent_name, status,
           client_instance_id, rebind_token, lease_expires_at_ms,
           created_at_ms, updated_at_ms, terminated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
        params![
            &write.session.session_id,
            &write.session.agent_name,
            session_status_to_db(SessionStatus::Active),
            &write.session.lease.client_instance_id,
            &write.session.lease.rebind_token,
            to_i64(write.session.lease.expires_at_ms, "lease_expires_at_ms").map_err(store_err)?,
            to_i64(write.session.created_at_ms, "created_at_ms").map_err(store_err)?,
            to_i64(write.session.updated_at_ms, "updated_at_ms").map_err(store_err)?,
        ],
    )
    .map_err(|error| store_err(sql_err("insert session in create tx", error)))?;
    Ok(())
}

fn insert_audit(tx: &Transaction<'_>, event: &NewAuditEvent) -> Result<(), SessionAppError> {
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
    .map_err(|error| audit_err(sql_err("insert session audit in create tx", error)))?;
    Ok(())
}

fn load_session(
    tx: &Transaction<'_>,
    session_id: &str,
) -> Result<Option<Session>, SessionAppError> {
    let raw = tx
        .query_row(
            "SELECT
               session_id,
               agent_name,
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
        .map_err(|error| store_err(sql_err("fetch session in create tx", error)))?;

    match raw {
        Some(raw) => Ok(Some(raw.into_domain().map_err(store_err)?)),
        None => Ok(None),
    }
}

fn store_err(error: StoreError) -> SessionAppError {
    SessionAppError::Store {
        message: storage_msg(error),
    }
}

fn audit_err(error: StoreError) -> SessionAppError {
    SessionAppError::Audit {
        message: storage_msg(error),
    }
}
