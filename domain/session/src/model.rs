#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Expired,
    Terminated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLease {
    pub client_instance_id: String,
    pub rebind_token: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub session_id: String,
    pub agent_name: String,
    pub policy_profile: String,
    pub status: SessionStatus,
    pub lease: SessionLease,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub terminated_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSession {
    pub session_id: String,
    pub agent_name: String,
    pub policy_profile: String,
    pub lease: SessionLease,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewLeaseCommand {
    pub session_id: String,
    pub client_instance_id: String,
    pub rebind_token: String,
    pub new_rebind_token: Option<String>,
    pub new_expires_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminateSessionCommand {
    pub session_id: String,
    pub client_instance_id: String,
    pub rebind_token: String,
    pub terminated_at_ms: u64,
}
