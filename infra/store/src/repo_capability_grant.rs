use rusqlite::{Connection, OptionalExtension, params};

use crate::{Store, StoreError, StoreResult, sql_err, to_i64, to_u64};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrantRecord {
    pub session_id: String,
    pub revision: u64,
    pub expires_at: Option<u64>,
    pub capabilities_json: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrantEventRecord {
    pub event_id: String,
    pub session_id: String,
    pub from_revision: u64,
    pub to_revision: u64,
    pub delta_json: String,
    pub actor: String,
    pub created_at: u64,
}

impl Store {
    pub fn get_capability_grant(
        &self,
        session_id: &str,
    ) -> StoreResult<Option<CapabilityGrantRecord>> {
        let session_id = session_id.to_string();
        self.execute(move |connection| load_capability_grant(connection, &session_id))
    }

    pub fn create_capability_grant_if_absent(
        &self,
        session_id: &str,
        capabilities_json: &str,
        expires_at: Option<u64>,
        now_ms: u64,
    ) -> StoreResult<CapabilityGrantRecord> {
        let session_id = session_id.to_string();
        let capabilities_json = capabilities_json.to_string();
        self.execute(move |connection| {
            create_capability_grant_if_absent(
                connection,
                &session_id,
                &capabilities_json,
                expires_at,
                now_ms,
            )
        })
    }

    pub fn update_capability_grant_with_revision(
        &self,
        session_id: &str,
        expected_revision: u64,
        capabilities_json: &str,
        delta_json: &str,
        actor: &str,
        now_ms: u64,
    ) -> StoreResult<CapabilityGrantRecord> {
        let session_id = session_id.to_string();
        let capabilities_json = capabilities_json.to_string();
        let delta_json = delta_json.to_string();
        let actor = actor.to_string();
        self.execute(move |connection| {
            update_capability_grant_with_revision(
                connection,
                &session_id,
                expected_revision,
                &capabilities_json,
                &delta_json,
                &actor,
                now_ms,
            )
        })
    }
}

fn create_capability_grant_if_absent(
    connection: &mut Connection,
    session_id: &str,
    capabilities_json: &str,
    expires_at: Option<u64>,
    now_ms: u64,
) -> StoreResult<CapabilityGrantRecord> {
    connection
        .execute(
            "INSERT OR IGNORE INTO capability_grants (
               session_id, revision, expires_at, capabilities_json, created_at, updated_at
             ) VALUES (?1, 1, ?2, ?3, ?4, ?5)",
            params![
                session_id,
                expires_at
                    .map(|value| to_i64(value, "expires_at"))
                    .transpose()?,
                capabilities_json,
                to_i64(now_ms, "created_at")?,
                to_i64(now_ms, "updated_at")?,
            ],
        )
        .map_err(|error| sql_err("insert capability_grant", error))?;

    load_capability_grant(connection, session_id)?.ok_or_else(|| {
        StoreError::Internal(format!(
            "capability_grant not found after upsert: session_id={session_id}"
        ))
    })
}

fn update_capability_grant_with_revision(
    connection: &mut Connection,
    session_id: &str,
    expected_revision: u64,
    capabilities_json: &str,
    delta_json: &str,
    actor: &str,
    now_ms: u64,
) -> StoreResult<CapabilityGrantRecord> {
    let tx = connection
        .transaction()
        .map_err(|error| sql_err("begin capability_grant update tx", error))?;

    let existing = load_capability_grant_tx(&tx, session_id)?.ok_or_else(|| {
        StoreError::NotFound(format!("capability_grant missing: session_id={session_id}"))
    })?;

    if existing.revision != expected_revision {
        return Err(StoreError::Conflict(format!(
            "capability_grant revision mismatch: session_id={session_id}, expected={expected_revision}, actual={}",
            existing.revision
        )));
    }

    let next_revision = expected_revision + 1;
    tx.execute(
        "UPDATE capability_grants
         SET revision = ?1, capabilities_json = ?2, updated_at = ?3
         WHERE session_id = ?4 AND revision = ?5",
        params![
            to_i64(next_revision, "revision")?,
            capabilities_json,
            to_i64(now_ms, "updated_at")?,
            session_id,
            to_i64(expected_revision, "expected_revision")?,
        ],
    )
    .map_err(|error| sql_err("update capability_grant", error))?;

    let event_id = format!("{session_id}:{next_revision}:{now_ms}");
    tx.execute(
        "INSERT INTO capability_grant_events (
           event_id, session_id, from_revision, to_revision, delta_json, actor, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &event_id,
            session_id,
            to_i64(expected_revision, "from_revision")?,
            to_i64(next_revision, "to_revision")?,
            delta_json,
            actor,
            to_i64(now_ms, "created_at")?,
        ],
    )
    .map_err(|error| sql_err("insert capability_grant_event", error))?;

    let updated = load_capability_grant_tx(&tx, session_id)?.ok_or_else(|| {
        StoreError::Internal(format!(
            "capability_grant missing after update: session_id={session_id}"
        ))
    })?;

    tx.commit()
        .map_err(|error| sql_err("commit capability_grant update tx", error))?;

    Ok(updated)
}

fn load_capability_grant(
    connection: &Connection,
    session_id: &str,
) -> StoreResult<Option<CapabilityGrantRecord>> {
    connection
        .query_row(
            "SELECT session_id, revision, expires_at, capabilities_json, created_at, updated_at
             FROM capability_grants
             WHERE session_id = ?1",
            [session_id],
            row_to_capability_grant,
        )
        .optional()
        .map_err(|error| sql_err("load capability_grant", error))
}

fn load_capability_grant_tx(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
) -> StoreResult<Option<CapabilityGrantRecord>> {
    tx.query_row(
        "SELECT session_id, revision, expires_at, capabilities_json, created_at, updated_at
         FROM capability_grants
         WHERE session_id = ?1",
        [session_id],
        row_to_capability_grant,
    )
    .optional()
    .map_err(|error| sql_err("load capability_grant in tx", error))
}

fn row_to_capability_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<CapabilityGrantRecord> {
    Ok(CapabilityGrantRecord {
        session_id: row.get(0)?,
        revision: to_u64(row.get(1)?, "revision").map_err(to_sql_err)?,
        expires_at: row
            .get::<_, Option<i64>>(2)?
            .map(|value| to_u64(value, "expires_at"))
            .transpose()
            .map_err(to_sql_err)?,
        capabilities_json: row.get(3)?,
        created_at: to_u64(row.get(4)?, "created_at").map_err(to_sql_err)?,
        updated_at: to_u64(row.get(5)?, "updated_at").map_err(to_sql_err)?,
    })
}

fn to_sql_err(error: StoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Integer,
        Box::new(std::io::Error::other(error.to_string())),
    )
}
