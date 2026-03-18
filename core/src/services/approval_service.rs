use std::sync::Arc;

use af_approval::{Approval, ApprovalDecision, RespondApprovalCommand};
use af_task::Task;

use crate::errors::ApprovalAppError;

#[derive(Debug, Clone)]
pub struct GetApprovalInput {
    pub session_id: String,
    pub approval_id: String,
}

#[derive(Debug, Clone)]
pub struct RespondApprovalInput {
    pub session_id: String,
    pub approval_id: String,
    pub decision: ApprovalDecision,
    pub idempotency_key: String,
    pub reason: Option<String>,
    pub responded_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RespondApprovalResult {
    pub approval: Approval,
    pub task: Task,
    pub transition_applied: bool,
}

pub trait ApprovalPort: Send + Sync {
    fn get_approval(
        &self,
        session_id: &str,
        approval_id: &str,
    ) -> Result<Approval, ApprovalAppError>;

    fn respond_approval_with_effect(
        &self,
        command: RespondApprovalCommand,
    ) -> Result<RespondApprovalResult, ApprovalAppError>;
}

#[derive(Clone)]
pub struct ApprovalAppService {
    port: Arc<dyn ApprovalPort>,
}

impl std::fmt::Debug for ApprovalAppService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovalAppService")
            .finish_non_exhaustive()
    }
}

impl ApprovalAppService {
    pub fn new(port: Arc<dyn ApprovalPort>) -> Self {
        Self { port }
    }

    pub fn get_approval(&self, input: GetApprovalInput) -> Result<Approval, ApprovalAppError> {
        validate_non_empty("session_id", &input.session_id)?;
        validate_non_empty("approval_id", &input.approval_id)?;
        self.port
            .get_approval(&input.session_id, &input.approval_id)
    }

    pub fn respond_approval(
        &self,
        input: RespondApprovalInput,
    ) -> Result<RespondApprovalResult, ApprovalAppError> {
        validate_non_empty("session_id", &input.session_id)?;
        validate_non_empty("approval_id", &input.approval_id)?;
        validate_non_empty("idempotency_key", &input.idempotency_key)?;
        if input.responded_at_ms == 0 {
            return Err(ApprovalAppError::Validation {
                message: "responded_at_ms must be greater than 0".to_string(),
            });
        }
        self.port
            .respond_approval_with_effect(RespondApprovalCommand {
                session_id: input.session_id,
                approval_id: input.approval_id,
                decision: input.decision,
                idempotency_key: input.idempotency_key,
                reason: input.reason,
                responded_at_ms: input.responded_at_ms,
            })
    }
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), ApprovalAppError> {
    if value.trim().is_empty() {
        return Err(ApprovalAppError::Validation {
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use af_approval::{ApprovalItem, ApprovalStatus, NewApproval};

    use super::*;

    #[derive(Default)]
    struct StubPort;

    impl ApprovalPort for StubPort {
        fn get_approval(
            &self,
            _session_id: &str,
            _approval_id: &str,
        ) -> Result<Approval, ApprovalAppError> {
            Ok(sample_approval())
        }

        fn respond_approval_with_effect(
            &self,
            _command: RespondApprovalCommand,
        ) -> Result<RespondApprovalResult, ApprovalAppError> {
            Ok(RespondApprovalResult {
                approval: sample_approval(),
                task: af_task::Task {
                    task_id: "task-1".to_string(),
                    session_id: "session-1".to_string(),
                    status: af_task::TaskStatus::Pending,
                    goal: None,
                    created_by: af_task::TaskCreatedBy::Invoke,
                    trace_id: "trace-1".to_string(),
                    limits_json: None,
                    current_step: 0,
                    error_code: None,
                    error_message: None,
                    created_at_ms: 1_000,
                    updated_at_ms: 1_100,
                    ended_at_ms: None,
                },
                transition_applied: true,
            })
        }
    }

    #[test]
    fn respond_rejects_empty_idempotency_key() {
        let service = ApprovalAppService::new(Arc::new(StubPort));
        let error = service
            .respond_approval(RespondApprovalInput {
                session_id: "session-1".to_string(),
                approval_id: "approval-1".to_string(),
                decision: ApprovalDecision::Approve,
                idempotency_key: " ".to_string(),
                reason: None,
                responded_at_ms: 1_000,
            })
            .expect_err("empty key must fail");

        assert!(matches!(error, ApprovalAppError::Validation { .. }));
    }

    fn sample_approval() -> Approval {
        let new = NewApproval {
            approval_id: "approval-1".to_string(),
            session_id: "session-1".to_string(),
            task_id: "task-1".to_string(),
            trace_id: "trace-1".to_string(),
            status: ApprovalStatus::Pending,
            summary: "network access requires approval".to_string(),
            details: Some("outbound request to example.com".to_string()),
            items: vec![ApprovalItem {
                kind: "network".to_string(),
                target: Some("example.com".to_string()),
                summary: "outbound network".to_string(),
            }],
            policy_reason: "needs approval".to_string(),
            policy_revision: 1,
            execution_contract_json: "{\"decision\":\"ask\"}".to_string(),
            created_at_ms: 1_000,
            expires_at_ms: 2_000,
        };
        Approval {
            approval_id: new.approval_id,
            session_id: new.session_id,
            task_id: new.task_id,
            trace_id: new.trace_id,
            status: new.status,
            summary: new.summary,
            details: new.details,
            items: new.items,
            policy_reason: new.policy_reason,
            policy_revision: new.policy_revision,
            execution_contract_json: new.execution_contract_json,
            created_at_ms: new.created_at_ms,
            expires_at_ms: new.expires_at_ms,
            responded_at_ms: None,
            response_reason: None,
            response_idempotency_key: None,
        }
    }
}
