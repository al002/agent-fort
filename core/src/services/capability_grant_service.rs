use std::sync::Arc;

use af_policy::CapabilitySet;

use crate::{
    CapabilityDelta, CapabilityGrantAppError, apply_delta_to_capability_set,
    capability_set_within_policy,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrantState {
    pub revision: u64,
    pub capabilities: CapabilitySet,
}

pub trait CapabilityGrantPort: Send + Sync {
    fn get_capability_grant(
        &self,
        session_id: &str,
    ) -> Result<Option<CapabilityGrantState>, CapabilityGrantAppError>;

    fn create_capability_grant_if_absent(
        &self,
        session_id: &str,
        capabilities: &CapabilitySet,
        now_ms: u64,
    ) -> Result<CapabilityGrantState, CapabilityGrantAppError>;

    fn update_capability_grant_with_revision(
        &self,
        session_id: &str,
        expected_revision: u64,
        capabilities: &CapabilitySet,
        delta: &CapabilityDelta,
        actor: &str,
        now_ms: u64,
    ) -> Result<CapabilityGrantState, CapabilityGrantAppError>;
}

#[derive(Clone)]
pub struct CapabilityGrantAppService {
    port: Arc<dyn CapabilityGrantPort>,
}

impl std::fmt::Debug for CapabilityGrantAppService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CapabilityGrantAppService")
            .finish_non_exhaustive()
    }
}

impl CapabilityGrantAppService {
    pub fn new(port: Arc<dyn CapabilityGrantPort>) -> Self {
        Self { port }
    }

    pub fn ensure_session_grant(
        &self,
        session_id: &str,
        policy_capabilities: &CapabilitySet,
        now_ms: u64,
    ) -> Result<CapabilityGrantState, CapabilityGrantAppError> {
        validate_non_empty("session_id", session_id)?;

        if let Some(grant) = self.port.get_capability_grant(session_id)? {
            return Ok(grant);
        }

        self.port.create_capability_grant_if_absent(
            session_id,
            &initial_session_grant(policy_capabilities),
            now_ms,
        )
    }

    pub fn apply_delta_with_revision(
        &self,
        session_id: &str,
        expected_revision: u64,
        delta: &CapabilityDelta,
        policy_capabilities: &CapabilitySet,
        actor: &str,
        now_ms: u64,
    ) -> Result<CapabilityGrantState, CapabilityGrantAppError> {
        validate_non_empty("session_id", session_id)?;
        validate_non_empty("actor", actor)?;

        let current = self.ensure_session_grant(session_id, policy_capabilities, now_ms)?;

        if current.revision != expected_revision {
            return Err(CapabilityGrantAppError::Conflict {
                message: format!(
                    "capability_grant revision mismatch: expected={expected_revision}, actual={}",
                    current.revision
                ),
            });
        }

        if delta.is_empty() {
            return Ok(current);
        }

        let next = apply_delta_to_capability_set(&current.capabilities, delta);
        if !capability_set_within_policy(&next, policy_capabilities) {
            return Err(CapabilityGrantAppError::PolicyDenied {
                message: "approved delta exceeds policy".to_string(),
            });
        }

        self.port.update_capability_grant_with_revision(
            session_id,
            expected_revision,
            &next,
            delta,
            actor,
            now_ms,
        )
    }
}

fn initial_session_grant(static_capabilities: &CapabilitySet) -> CapabilitySet {
    CapabilitySet {
        fs_read: static_capabilities.fs_read.clone(),
        fs_write: static_capabilities.fs_write.clone(),
        fs_delete: static_capabilities.fs_delete.clone(),
        net_connect: Vec::new(),
        allow_host_exec: false,
        allow_process_control: false,
        allow_privilege: false,
        allow_credential_access: false,
    }
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), CapabilityGrantAppError> {
    if value.trim().is_empty() {
        return Err(CapabilityGrantAppError::Validation {
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}
