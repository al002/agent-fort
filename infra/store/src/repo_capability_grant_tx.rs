use af_core::{
    CapabilityDelta, CapabilityGrantAppError, CapabilityGrantPort, CapabilityGrantState,
};
use af_policy::CapabilitySet;
use serde_json::json;

use crate::{CapabilityGrantRecord, Store, StoreError};

impl CapabilityGrantPort for Store {
    fn get_capability_grant(
        &self,
        session_id: &str,
    ) -> Result<Option<CapabilityGrantState>, CapabilityGrantAppError> {
        let record = Store::get_capability_grant(self, session_id).map_err(map_store_error)?;
        record.map(record_to_state).transpose()
    }

    fn create_capability_grant_if_absent(
        &self,
        session_id: &str,
        capabilities: &CapabilitySet,
        now_ms: u64,
    ) -> Result<CapabilityGrantState, CapabilityGrantAppError> {
        let capabilities_json = serde_json::to_string(capabilities).map_err(|error| {
            CapabilityGrantAppError::Internal {
                message: format!("serialize capability_grant JSON failed: {error}"),
            }
        })?;

        let record = Store::create_capability_grant_if_absent(
            self,
            session_id,
            &capabilities_json,
            None,
            now_ms,
        )
        .map_err(map_store_error)?;

        record_to_state(record)
    }

    fn update_capability_grant_with_revision(
        &self,
        session_id: &str,
        expected_revision: u64,
        capabilities: &CapabilitySet,
        delta: &CapabilityDelta,
        actor: &str,
        now_ms: u64,
    ) -> Result<CapabilityGrantState, CapabilityGrantAppError> {
        let capabilities_json = serde_json::to_string(capabilities).map_err(|error| {
            CapabilityGrantAppError::Internal {
                message: format!("serialize capability_grant JSON failed: {error}"),
            }
        })?;
        let delta_json = capability_delta_json(delta);

        let record = Store::update_capability_grant_with_revision(
            self,
            session_id,
            expected_revision,
            &capabilities_json,
            &delta_json,
            actor,
            now_ms,
        )
        .map_err(map_store_error)?;

        record_to_state(record)
    }
}

fn record_to_state(
    record: CapabilityGrantRecord,
) -> Result<CapabilityGrantState, CapabilityGrantAppError> {
    let capabilities =
        serde_json::from_str::<CapabilitySet>(&record.capabilities_json).map_err(|error| {
            CapabilityGrantAppError::Internal {
                message: format!(
                    "parse capability_grant JSON failed: session_id={}, error={error}",
                    record.session_id
                ),
            }
        })?;

    Ok(CapabilityGrantState {
        revision: record.revision,
        capabilities,
    })
}

fn map_store_error(error: StoreError) -> CapabilityGrantAppError {
    match error {
        StoreError::Conflict(message) | StoreError::RuleConflict { message, .. } => {
            CapabilityGrantAppError::Conflict { message }
        }
        StoreError::ConstraintViolation(message)
        | StoreError::NotFound(message)
        | StoreError::BusyTimeout(message) => CapabilityGrantAppError::Store { message },
        StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => CapabilityGrantAppError::Internal { message },
    }
}

fn capability_delta_json(delta: &CapabilityDelta) -> String {
    json!({
        "fs_read": delta.fs_read.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "fs_write": delta.fs_write.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "fs_delete": delta.fs_delete.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "net_connect": delta.net_connect.iter().map(|endpoint| json!({
            "host": endpoint.host,
            "port": endpoint.port,
            "protocol": endpoint.protocol,
        })).collect::<Vec<_>>(),
        "host_exec": delta.host_exec,
        "process_control": delta.process_control,
        "privilege": delta.privilege,
        "credential_access": delta.credential_access,
    })
    .to_string()
}
