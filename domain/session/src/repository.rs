use crate::errors::SessionRepositoryError;
use crate::model::{NewSession, RenewLeaseCommand, Session, TerminateSessionCommand};

pub trait SessionRepository: Send + Sync {
    fn create_session(&self, command: NewSession) -> Result<Session, SessionRepositoryError>;

    fn get_session(&self, session_id: &str) -> Result<Session, SessionRepositoryError>;

    fn renew_lease(&self, command: RenewLeaseCommand) -> Result<Session, SessionRepositoryError>;

    fn terminate_session(
        &self,
        command: TerminateSessionCommand,
    ) -> Result<Session, SessionRepositoryError>;

    fn list_expired_sessions(
        &self,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<Session>, SessionRepositoryError>;
}
