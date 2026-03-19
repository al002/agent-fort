use af_approval::{
    Approval, ApprovalDecision, ApprovalRepository, ApprovalRepositoryError, RespondApprovalCommand,
};
use af_audit::AuditEventType;
use af_core::{ApprovalAppError, ApprovalPort, RespondApprovalResult};
use af_task::{Task, TaskStatus};
use rusqlite::{Connection, params};

use crate::repo_approval::{
    RULE_APPROVAL_EXPIRED, RULE_APPROVAL_IDEMPOTENCY_CONFLICT, RULE_APPROVAL_INVALID_STATE,
    approval_status_to_db, decision_to_status, fetch_approval_raw,
};
use crate::repo_task::{load_task, task_status_to_db};
use crate::sql_audit::audit_event_type_to_db;
use crate::{Store, StoreError, StoreResult, sql_err, to_i64, to_u64};

impl ApprovalPort for Store {
    fn get_approval(
        &self,
        session_id: &str,
        approval_id: &str,
    ) -> Result<Approval, ApprovalAppError> {
        <Store as ApprovalRepository>::get_approval(self, session_id, approval_id)
            .map_err(on_repo_err)
    }

    fn respond_approval_with_effect(
        &self,
        command: RespondApprovalCommand,
    ) -> Result<RespondApprovalResult, ApprovalAppError> {
        let session_id = command.session_id.clone();
        let approval_id = command.approval_id.clone();
        self.execute(move |connection| respond_with_effect(connection, command))
            .map_err(|error| on_respond_store_err(error, &session_id, &approval_id))
    }
}

fn respond_with_effect(
    connection: &mut Connection,
    command: RespondApprovalCommand,
) -> StoreResult<RespondApprovalResult> {
    let tx = connection
        .transaction()
        .map_err(|error| sql_err("begin respond approval with effect tx", error))?;

    let existing =
        fetch_approval_raw(&tx, &command.session_id, &command.approval_id)?.ok_or_else(|| {
            StoreError::NotFound(format!(
                "approval not found: session_id={}, approval_id={}",
                command.session_id, command.approval_id
            ))
        })?;

    let current_status = crate::repo_approval::approval_status_from_db(&existing.status)?;
    let mut transition_applied = false;
    if current_status == af_approval::ApprovalStatus::Pending {
        if command.responded_at_ms > to_u64(existing.expires_at_ms, "expires_at_ms")? {
            return Err(StoreError::RuleConflict {
                code: RULE_APPROVAL_EXPIRED,
                message: format!("approval expired: approval_id={}", command.approval_id),
            });
        }
        tx.execute(
            "UPDATE approvals
             SET status = ?1, responded_at_ms = ?2, response_reason = ?3, response_idempotency_key = ?4
             WHERE session_id = ?5 AND approval_id = ?6 AND status = ?7",
            params![
                approval_status_to_db(decision_to_status(command.decision)),
                to_i64(command.responded_at_ms, "responded_at_ms")?,
                command.reason.as_deref(),
                &command.idempotency_key,
                &command.session_id,
                &command.approval_id,
                approval_status_to_db(af_approval::ApprovalStatus::Pending),
            ],
        )
        .map_err(|error| sql_err("update approval in respond approval with effect tx", error))?;
        transition_applied = true;
    } else if let Some(existing_key) = existing.response_idempotency_key.as_deref() {
        if existing_key != command.idempotency_key {
            return Err(StoreError::RuleConflict {
                code: RULE_APPROVAL_IDEMPOTENCY_CONFLICT,
                message: format!("idempotency conflict: approval_id={}", command.approval_id),
            });
        }
    } else {
        return Err(StoreError::RuleConflict {
            code: RULE_APPROVAL_INVALID_STATE,
            message: format!("approval not pending: approval_id={}", command.approval_id),
        });
    }

    let approval = fetch_approval_raw(&tx, &command.session_id, &command.approval_id)?
        .ok_or_else(|| {
            StoreError::Internal("updated approval missing after respond transaction".to_string())
        })?
        .into_domain()?;

    let task = load_task(&tx, &command.session_id, &approval.task_id)?.ok_or_else(|| {
        StoreError::Internal(format!(
            "approval task missing after respond transaction: session_id={}, task_id={}",
            command.session_id, approval.task_id
        ))
    })?;

    let task = if transition_applied {
        let next_task = transition_task_for_approval(&tx, &task, &approval, &command)?;
        append_approval_audit_event(&tx, &approval, &command)?;
        if next_task.status != task.status {
            append_task_approval_audit_event(
                &tx,
                &approval,
                command.decision,
                command.responded_at_ms,
            )?;
        }
        next_task
    } else {
        task
    };

    tx.commit()
        .map_err(|error| sql_err("commit respond approval with effect tx", error))?;

    Ok(RespondApprovalResult {
        approval,
        task,
        transition_applied,
    })
}

fn transition_task_for_approval(
    tx: &rusqlite::Transaction<'_>,
    task: &Task,
    approval: &Approval,
    command: &RespondApprovalCommand,
) -> StoreResult<Task> {
    match approval.status {
        af_approval::ApprovalStatus::Approved => {
            if task.status == TaskStatus::Blocked {
                tx.execute(
                    "UPDATE tasks
                     SET status = ?1, updated_at_ms = ?2, ended_at_ms = NULL, error_code = NULL, error_message = NULL
                     WHERE session_id = ?3 AND task_id = ?4 AND status = ?5",
                    params![
                        task_status_to_db(TaskStatus::Pending),
                        to_i64(command.responded_at_ms, "responded_at_ms")?,
                        &task.session_id,
                        &task.task_id,
                        task_status_to_db(TaskStatus::Blocked),
                    ],
                )
                .map_err(|error| {
                    sql_err("update task status for approved approval in tx", error)
                })?;

                load_task(tx, &task.session_id, &task.task_id)?.ok_or_else(|| {
                    StoreError::Internal(
                        "task missing after approval approved transition".to_string(),
                    )
                })
            } else {
                Ok(task.clone())
            }
        }
        af_approval::ApprovalStatus::Denied => {
            if matches!(
                task.status,
                TaskStatus::Pending | TaskStatus::Running | TaskStatus::Blocked
            ) {
                let error_message = command
                    .reason
                    .clone()
                    .unwrap_or_else(|| approval.policy_reason.clone());
                tx.execute(
                    "UPDATE tasks
                     SET status = ?1, updated_at_ms = ?2, ended_at_ms = ?3, error_code = ?4, error_message = ?5
                     WHERE session_id = ?6 AND task_id = ?7",
                    params![
                        task_status_to_db(TaskStatus::Failed),
                        to_i64(command.responded_at_ms, "responded_at_ms")?,
                        to_i64(command.responded_at_ms, "responded_at_ms")?,
                        "APPROVAL_DENIED",
                        error_message,
                        &task.session_id,
                        &task.task_id,
                    ],
                )
                .map_err(|error| sql_err("update task status for denied approval in tx", error))?;

                load_task(tx, &task.session_id, &task.task_id)?.ok_or_else(|| {
                    StoreError::Internal(
                        "task missing after approval denied transition".to_string(),
                    )
                })
            } else {
                Ok(task.clone())
            }
        }
        af_approval::ApprovalStatus::Pending
        | af_approval::ApprovalStatus::Expired
        | af_approval::ApprovalStatus::Cancelled => Ok(task.clone()),
    }
}

fn append_approval_audit_event(
    tx: &rusqlite::Transaction<'_>,
    approval: &Approval,
    command: &RespondApprovalCommand,
) -> StoreResult<()> {
    let event_type = match command.decision {
        ApprovalDecision::Approve => AuditEventType::ApprovalApproved,
        ApprovalDecision::Deny => AuditEventType::ApprovalDenied,
    };
    tx.execute(
        "INSERT INTO audit_events (
           ts_ms, trace_id, session_id, task_id, event_type, payload_json, error_code
         ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
        params![
            to_i64(command.responded_at_ms, "responded_at_ms")?,
            &approval.trace_id,
            &approval.session_id,
            &approval.task_id,
            audit_event_type_to_db(event_type),
        ],
    )
    .map_err(|error| sql_err("insert approval audit event in tx", error))?;
    Ok(())
}

fn append_task_approval_audit_event(
    tx: &rusqlite::Transaction<'_>,
    approval: &Approval,
    decision: ApprovalDecision,
    responded_at_ms: u64,
) -> StoreResult<()> {
    let event_type = match decision {
        ApprovalDecision::Approve => AuditEventType::TaskResumedAfterApproval,
        ApprovalDecision::Deny => AuditEventType::TaskDeniedByApproval,
    };
    tx.execute(
        "INSERT INTO audit_events (
           ts_ms, trace_id, session_id, task_id, event_type, payload_json, error_code
         ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
        params![
            to_i64(responded_at_ms, "responded_at_ms")?,
            &approval.trace_id,
            &approval.session_id,
            &approval.task_id,
            audit_event_type_to_db(event_type),
        ],
    )
    .map_err(|error| sql_err("insert task approval audit event in tx", error))?;
    Ok(())
}

fn on_repo_err(error: ApprovalRepositoryError) -> ApprovalAppError {
    match error {
        ApprovalRepositoryError::NotFound {
            session_id,
            approval_id,
        } => ApprovalAppError::NotFound {
            session_id,
            approval_id,
        },
        ApprovalRepositoryError::Expired { approval_id } => {
            ApprovalAppError::Expired { approval_id }
        }
        ApprovalRepositoryError::IdempotencyConflict { approval_id } => {
            ApprovalAppError::IdempotencyConflict { approval_id }
        }
        ApprovalRepositoryError::InvalidState { message } => {
            ApprovalAppError::InvalidState { message }
        }
        ApprovalRepositoryError::Validation { message } => ApprovalAppError::Validation { message },
        ApprovalRepositoryError::AlreadyExists { approval_id } => ApprovalAppError::Store {
            message: format!("approval already exists: approval_id={approval_id}"),
        },
        ApprovalRepositoryError::Conflict { message }
        | ApprovalRepositoryError::Storage { message } => ApprovalAppError::Store { message },
    }
}

fn on_respond_store_err(
    error: StoreError,
    session_id: &str,
    approval_id: &str,
) -> ApprovalAppError {
    match error {
        StoreError::NotFound(_) => ApprovalAppError::NotFound {
            session_id: session_id.to_string(),
            approval_id: approval_id.to_string(),
        },
        StoreError::RuleConflict { code, message } => match code {
            RULE_APPROVAL_EXPIRED => ApprovalAppError::Expired {
                approval_id: approval_id.to_string(),
            },
            RULE_APPROVAL_IDEMPOTENCY_CONFLICT => ApprovalAppError::IdempotencyConflict {
                approval_id: approval_id.to_string(),
            },
            RULE_APPROVAL_INVALID_STATE => ApprovalAppError::InvalidState { message },
            _ => ApprovalAppError::Store { message },
        },
        StoreError::ConstraintViolation(message)
        | StoreError::Conflict(message)
        | StoreError::BusyTimeout(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => ApprovalAppError::Store { message },
        StoreError::Internal(message) => ApprovalAppError::Internal { message },
    }
}
