use af_session::{Session, SessionLease, SessionStatus};

use crate::{StoreError, StoreResult, to_u64};

#[derive(Debug)]
pub(crate) struct RawSession {
    pub session_id: String,
    pub agent_name: String,
    pub policy_profile: String,
    pub status: String,
    pub client_instance_id: String,
    pub rebind_token: String,
    pub lease_expires_at_ms: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub terminated_at_ms: Option<i64>,
}

impl RawSession {
    pub(crate) fn into_domain(self) -> StoreResult<Session> {
        Ok(Session {
            session_id: self.session_id,
            agent_name: self.agent_name,
            policy_profile: self.policy_profile,
            status: session_status_from_db(&self.status)?,
            lease: SessionLease {
                client_instance_id: self.client_instance_id,
                rebind_token: self.rebind_token,
                expires_at_ms: to_u64(self.lease_expires_at_ms, "lease_expires_at_ms")?,
            },
            created_at_ms: to_u64(self.created_at_ms, "created_at_ms")?,
            updated_at_ms: to_u64(self.updated_at_ms, "updated_at_ms")?,
            terminated_at_ms: self
                .terminated_at_ms
                .map(|value| to_u64(value, "terminated_at_ms"))
                .transpose()?,
        })
    }
}

pub(crate) fn row_to_raw_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawSession> {
    Ok(RawSession {
        session_id: row.get(0)?,
        agent_name: row.get(1)?,
        policy_profile: row.get(2)?,
        status: row.get(3)?,
        client_instance_id: row.get(4)?,
        rebind_token: row.get(5)?,
        lease_expires_at_ms: row.get(6)?,
        created_at_ms: row.get(7)?,
        updated_at_ms: row.get(8)?,
        terminated_at_ms: row.get(9)?,
    })
}

pub(crate) fn session_status_to_db(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Active => "ACTIVE",
        SessionStatus::Expired => "EXPIRED",
        SessionStatus::Terminated => "TERMINATED",
    }
}

pub(crate) fn session_status_from_db(status: &str) -> StoreResult<SessionStatus> {
    match status {
        "ACTIVE" => Ok(SessionStatus::Active),
        "EXPIRED" => Ok(SessionStatus::Expired),
        "TERMINATED" => Ok(SessionStatus::Terminated),
        _ => Err(StoreError::Internal(format!(
            "invalid session status in db: {status}"
        ))),
    }
}
