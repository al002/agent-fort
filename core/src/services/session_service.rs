use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use af_audit::{AuditEventType, NewAuditEvent};
use af_session::{NewSession, Session, SessionLease};
use uuid::Uuid;

use crate::errors::SessionAppError;

const DEFAULT_LEASE_TTL_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub default_lease_ttl_secs: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_lease_ttl_secs: DEFAULT_LEASE_TTL_SECS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateSessionInput {
    pub agent_name: String,
    pub policy_profile: String,
    pub client_instance_id: String,
    pub lease_ttl_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CreateSessionWrite {
    pub session: NewSession,
    pub audit_event: NewAuditEvent,
}

pub trait SessionWritePort: Send + Sync {
    fn create_with_audit(&self, write: CreateSessionWrite) -> Result<Session, SessionAppError>;
}

#[derive(Clone)]
pub struct SessionAppService {
    port: Arc<dyn SessionWritePort>,
    config: SessionConfig,
}

impl std::fmt::Debug for SessionAppService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionAppService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SessionAppService {
    pub fn new(port: Arc<dyn SessionWritePort>, config: SessionConfig) -> Self {
        Self { port, config }
    }

    pub fn create_session(&self, input: CreateSessionInput) -> Result<Session, SessionAppError> {
        validate_non_empty("agent_name", &input.agent_name)?;
        validate_non_empty("policy_profile", &input.policy_profile)?;
        validate_non_empty("client_instance_id", &input.client_instance_id)?;

        let ttl_secs = input
            .lease_ttl_secs
            .unwrap_or(self.config.default_lease_ttl_secs);
        if ttl_secs == 0 {
            return Err(SessionAppError::Validation {
                message: "lease_ttl_secs must be greater than 0".to_string(),
            });
        }

        let now_ms = now_ms();
        let ttl_ms = ttl_secs
            .checked_mul(1_000)
            .ok_or_else(|| SessionAppError::Validation {
                message: format!("lease_ttl_secs too large: {ttl_secs}"),
            })?;
        let expires_at_ms =
            now_ms
                .checked_add(ttl_ms)
                .ok_or_else(|| SessionAppError::Validation {
                    message: "session lease expiration overflows u64".to_string(),
                })?;

        let session_id = Uuid::new_v4().to_string();
        let write = CreateSessionWrite {
            session: NewSession {
                session_id: session_id.clone(),
                agent_name: input.agent_name,
                policy_profile: input.policy_profile,
                lease: SessionLease {
                    client_instance_id: input.client_instance_id,
                    rebind_token: Uuid::new_v4().to_string(),
                    expires_at_ms,
                },
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            },
            audit_event: NewAuditEvent {
                ts_ms: now_ms,
                trace_id: Uuid::new_v4().to_string(),
                session_id: Some(session_id),
                task_id: None,
                event_type: AuditEventType::SessionCreated,
                payload_json: None,
                error_code: None,
            },
        };

        self.port.create_with_audit(write)
    }
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), SessionAppError> {
    if value.trim().is_empty() {
        return Err(SessionAppError::Validation {
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn now_ms() -> u64 {
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after unix epoch");
    elapsed
        .as_millis()
        .try_into()
        .expect("timestamp fits into u64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_session::SessionStatus;

    struct StubPort;

    impl SessionWritePort for StubPort {
        fn create_with_audit(&self, write: CreateSessionWrite) -> Result<Session, SessionAppError> {
            Ok(Session {
                session_id: write.session.session_id,
                agent_name: write.session.agent_name,
                policy_profile: write.session.policy_profile,
                status: SessionStatus::Active,
                lease: write.session.lease,
                created_at_ms: write.session.created_at_ms,
                updated_at_ms: write.session.updated_at_ms,
                terminated_at_ms: None,
            })
        }
    }

    #[test]
    fn rejects_empty_agent_name() {
        let service = SessionAppService::new(
            Arc::new(StubPort),
            SessionConfig {
                default_lease_ttl_secs: 60,
            },
        );
        let result = service.create_session(CreateSessionInput {
            agent_name: " ".to_string(),
            policy_profile: "default".to_string(),
            client_instance_id: "client".to_string(),
            lease_ttl_secs: Some(10),
        });
        assert!(matches!(result, Err(SessionAppError::Validation { .. })));
    }

    #[test]
    fn applies_default_ttl_when_missing() {
        let service = SessionAppService::new(
            Arc::new(StubPort),
            SessionConfig {
                default_lease_ttl_secs: 60,
            },
        );
        let session = service
            .create_session(CreateSessionInput {
                agent_name: "agent".to_string(),
                policy_profile: "default".to_string(),
                client_instance_id: "client".to_string(),
                lease_ttl_secs: None,
            })
            .expect("create session");
        assert!(session.lease.expires_at_ms >= session.created_at_ms + 60_000);
    }

    #[test]
    fn rejects_zero_ttl() {
        let service = SessionAppService::new(Arc::new(StubPort), SessionConfig::default());
        let result = service.create_session(CreateSessionInput {
            agent_name: "agent".to_string(),
            policy_profile: "default".to_string(),
            client_instance_id: "client".to_string(),
            lease_ttl_secs: Some(0),
        });
        assert!(matches!(result, Err(SessionAppError::Validation { .. })));
    }
}
