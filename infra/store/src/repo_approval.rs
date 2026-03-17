use af_approval::{
    Approval, ApprovalDecision, ApprovalRepository, ApprovalRepositoryError, ApprovalStatus,
    ApprovalSummary, ListPendingApprovalsQuery, NewApproval, RespondApprovalCommand,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{Store, StoreError, StoreResult, is_dup_key, sql_err, storage_msg, to_i64, to_u64};

impl ApprovalRepository for Store {
    fn create_approval(&self, command: NewApproval) -> Result<Approval, ApprovalRepositoryError> {
        let approval_id = command.approval_id.clone();
        self.execute(move |connection| create_approval(connection, command))
            .map_err(|error| on_create_err(error, &approval_id))
    }

    fn get_approval(
        &self,
        session_id: &str,
        approval_id: &str,
    ) -> Result<Approval, ApprovalRepositoryError> {
        let session_id = session_id.to_string();
        let approval_id = approval_id.to_string();
        let lookup_session_id = session_id.clone();
        let lookup_approval_id = approval_id.clone();
        self.execute(move |connection| {
            fetch_approval(connection, &lookup_session_id, &lookup_approval_id)?.ok_or_else(|| {
                StoreError::NotFound(format!(
                    "approval not found: session_id={lookup_session_id}, approval_id={lookup_approval_id}"
                ))
            })
        })
        .map_err(|error| on_lookup_err(error, &session_id, &approval_id))
    }

    fn list_pending_approvals(
        &self,
        query: ListPendingApprovalsQuery,
    ) -> Result<Vec<ApprovalSummary>, ApprovalRepositoryError> {
        if query.limit == 0 {
            return Ok(Vec::new());
        }
        self.execute(move |connection| list_pending_approvals(connection, query))
            .map_err(on_store_err)
    }

    fn respond_approval(
        &self,
        command: RespondApprovalCommand,
    ) -> Result<Approval, ApprovalRepositoryError> {
        let session_id = command.session_id.clone();
        let approval_id = command.approval_id.clone();
        self.execute(move |connection| respond_approval(connection, command))
            .map_err(|error| on_respond_err(error, &session_id, &approval_id))
    }

    fn expire_pending_approvals(
        &self,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<Approval>, ApprovalRepositoryError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.execute(move |connection| expire_pending_approvals(connection, now_ms, limit))
            .map_err(on_store_err)
    }
}

fn create_approval(connection: &mut Connection, command: NewApproval) -> StoreResult<Approval> {
    connection
        .execute(
            "INSERT INTO approvals (
               approval_id, session_id, task_id, trace_id, capability, operation, status, policy_reason,
               risk_class, command_class, input_brief_json, requested_runtime_class, resolved_runtime_class,
               requires_network, requires_pty, created_at_ms, expires_at_ms, responded_at_ms,
               response_reason, response_idempotency_key
             ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, NULL, NULL, NULL
             )",
            params![
                command.approval_id,
                command.session_id,
                command.task_id,
                command.trace_id,
                command.capability,
                command.operation,
                approval_status_to_db(command.status),
                command.policy_reason,
                command.risk_class,
                command.command_class,
                command.input_brief_json,
                command.requested_runtime_class,
                command.resolved_runtime_class,
                bool_to_i64(command.requires_network),
                bool_to_i64(command.requires_pty),
                to_i64(command.created_at_ms, "created_at_ms")?,
                to_i64(command.expires_at_ms, "expires_at_ms")?,
            ],
        )
        .map_err(|error| sql_err("insert approval", error))?;

    fetch_approval(connection, &command.session_id, &command.approval_id)?
        .ok_or_else(|| StoreError::Internal("inserted approval missing after insert".to_string()))
}

fn list_pending_approvals(
    connection: &mut Connection,
    query: ListPendingApprovalsQuery,
) -> StoreResult<Vec<ApprovalSummary>> {
    let (sql, values): (&str, Vec<rusqlite::types::Value>) = match query.after_approval_id {
        Some(after_approval_id) => (
            "SELECT approval_id, status, expires_at_ms, task_id, capability, operation, policy_reason
             FROM approvals
             WHERE session_id = ?1
               AND status = ?2
               AND approval_id > ?3
             ORDER BY approval_id ASC
             LIMIT ?4",
            vec![
                query.session_id.into(),
                approval_status_to_db(ApprovalStatus::Pending)
                    .to_string()
                    .into(),
                after_approval_id.into(),
                i64::from(query.limit).into(),
            ],
        ),
        None => (
            "SELECT approval_id, status, expires_at_ms, task_id, capability, operation, policy_reason
             FROM approvals
             WHERE session_id = ?1
               AND status = ?2
             ORDER BY approval_id ASC
             LIMIT ?3",
            vec![
                query.session_id.into(),
                approval_status_to_db(ApprovalStatus::Pending)
                    .to_string()
                    .into(),
                i64::from(query.limit).into(),
            ],
        ),
    };

    let mut statement = connection
        .prepare(sql)
        .map_err(|error| sql_err("prepare list pending approvals", error))?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(values), |row| {
            let status: String = row.get(1)?;
            let expires_at_ms: i64 = row.get(2)?;
            Ok((
                row.get(0)?,
                status,
                expires_at_ms,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .map_err(|error| sql_err("query list pending approvals", error))?;

    let mut list = Vec::new();
    for row in rows {
        let (approval_id, status, expires_at_ms, task_id, capability, operation, policy_reason) =
            row.map_err(|error| sql_err("read list pending approvals row", error))?;
        list.push(ApprovalSummary {
            approval_id,
            status: approval_status_from_db(&status)?,
            expires_at_ms: to_u64(expires_at_ms, "expires_at_ms")?,
            task_id,
            capability,
            operation,
            policy_reason,
        });
    }
    Ok(list)
}

fn respond_approval(
    connection: &mut Connection,
    command: RespondApprovalCommand,
) -> StoreResult<Approval> {
    let transaction = connection
        .transaction()
        .map_err(|error| sql_err("begin respond approval transaction", error))?;

    let existing = fetch_approval_raw(&transaction, &command.session_id, &command.approval_id)?
        .ok_or_else(|| {
            StoreError::NotFound(format!(
                "approval not found: session_id={}, approval_id={}",
                command.session_id, command.approval_id
            ))
        })?;

    let current_status = approval_status_from_db(&existing.status)?;
    match current_status {
        ApprovalStatus::Pending => {
            if command.responded_at_ms > to_u64(existing.expires_at_ms, "expires_at_ms")? {
                return Err(StoreError::Conflict(format!(
                    "approval expired: approval_id={}",
                    command.approval_id
                )));
            }

            let new_status = approval_status_to_db(decision_to_status(command.decision));
            transaction
                .execute(
                    "UPDATE approvals
                     SET status = ?1, responded_at_ms = ?2, response_reason = ?3, response_idempotency_key = ?4
                     WHERE session_id = ?5 AND approval_id = ?6 AND status = ?7",
                    params![
                        new_status,
                        to_i64(command.responded_at_ms, "responded_at_ms")?,
                        command.reason,
                        command.idempotency_key,
                        command.session_id,
                        command.approval_id,
                        approval_status_to_db(ApprovalStatus::Pending),
                    ],
                )
                .map_err(|error| sql_err("update respond approval", error))?;
        }
        _ => {
            if let Some(existing_key) = existing.response_idempotency_key.as_deref() {
                if existing_key == command.idempotency_key {
                    return existing.into_domain();
                }
                return Err(StoreError::Conflict(format!(
                    "idempotency_conflict: approval_id={}",
                    command.approval_id
                )));
            }
            return Err(StoreError::Conflict(format!(
                "approval not pending: approval_id={}",
                command.approval_id
            )));
        }
    }

    let updated = fetch_approval_raw(&transaction, &command.session_id, &command.approval_id)?
        .ok_or_else(|| {
            StoreError::Internal("updated approval missing after respond".to_string())
        })?;
    transaction
        .commit()
        .map_err(|error| sql_err("commit respond approval transaction", error))?;
    updated.into_domain()
}

fn expire_pending_approvals(
    connection: &mut Connection,
    now_ms: u64,
    limit: u32,
) -> StoreResult<Vec<Approval>> {
    let transaction = connection
        .transaction()
        .map_err(|error| sql_err("begin expire approvals transaction", error))?;

    let expiring = {
        let mut statement = transaction
            .prepare(
                "SELECT session_id, approval_id
                 FROM approvals
                 WHERE status = ?1
                   AND expires_at_ms <= ?2
                 ORDER BY expires_at_ms ASC, approval_id ASC
                 LIMIT ?3",
            )
            .map_err(|error| sql_err("prepare select expiring approvals", error))?;
        let expiring_rows = statement
            .query_map(
                params![
                    approval_status_to_db(ApprovalStatus::Pending),
                    to_i64(now_ms, "now_ms")?,
                    i64::from(limit),
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|error| sql_err("query expiring approvals", error))?;
        expiring_rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| sql_err("collect expiring approvals", error))?
    };

    if expiring.is_empty() {
        transaction
            .commit()
            .map_err(|error| sql_err("commit empty expire approvals transaction", error))?;
        return Ok(Vec::new());
    }

    for (session_id, approval_id) in &expiring {
        transaction
            .execute(
                "UPDATE approvals
                 SET status = ?1
                 WHERE session_id = ?2
                   AND approval_id = ?3
                   AND status = ?4",
                params![
                    approval_status_to_db(ApprovalStatus::Expired),
                    session_id,
                    approval_id,
                    approval_status_to_db(ApprovalStatus::Pending)
                ],
            )
            .map_err(|error| sql_err("update expired approval", error))?;
    }

    let mut approvals = Vec::new();
    for (session_id, approval_id) in &expiring {
        if let Some(raw) = fetch_approval_raw(&transaction, session_id, approval_id)? {
            approvals.push(raw.into_domain()?);
        }
    }
    transaction
        .commit()
        .map_err(|error| sql_err("commit expire approvals transaction", error))?;
    Ok(approvals)
}

fn fetch_approval(
    connection: &Connection,
    session_id: &str,
    approval_id: &str,
) -> StoreResult<Option<Approval>> {
    fetch_approval_raw(connection, session_id, approval_id)?
        .map(RawApproval::into_domain)
        .transpose()
}

fn fetch_approval_raw(
    connection: &Connection,
    session_id: &str,
    approval_id: &str,
) -> StoreResult<Option<RawApproval>> {
    connection
        .query_row(
            "SELECT
               approval_id, session_id, task_id, trace_id, capability, operation, status,
               policy_reason, risk_class, command_class, input_brief_json, requested_runtime_class,
               resolved_runtime_class, requires_network, requires_pty, created_at_ms, expires_at_ms,
               responded_at_ms, response_reason, response_idempotency_key
             FROM approvals
             WHERE session_id = ?1 AND approval_id = ?2",
            params![session_id, approval_id],
            row_to_raw_approval,
        )
        .optional()
        .map_err(|error| sql_err("fetch approval", error))
}

#[derive(Debug)]
struct RawApproval {
    approval_id: String,
    session_id: String,
    task_id: String,
    trace_id: String,
    capability: String,
    operation: String,
    status: String,
    policy_reason: String,
    risk_class: String,
    command_class: String,
    input_brief_json: String,
    requested_runtime_class: String,
    resolved_runtime_class: String,
    requires_network: i64,
    requires_pty: i64,
    created_at_ms: i64,
    expires_at_ms: i64,
    responded_at_ms: Option<i64>,
    response_reason: Option<String>,
    response_idempotency_key: Option<String>,
}

impl RawApproval {
    fn into_domain(self) -> StoreResult<Approval> {
        Ok(Approval {
            approval_id: self.approval_id,
            session_id: self.session_id,
            task_id: self.task_id,
            trace_id: self.trace_id,
            capability: self.capability,
            operation: self.operation,
            status: approval_status_from_db(&self.status)?,
            policy_reason: self.policy_reason,
            risk_class: self.risk_class,
            command_class: self.command_class,
            input_brief_json: self.input_brief_json,
            requested_runtime_class: self.requested_runtime_class,
            resolved_runtime_class: self.resolved_runtime_class,
            requires_network: self.requires_network != 0,
            requires_pty: self.requires_pty != 0,
            created_at_ms: to_u64(self.created_at_ms, "created_at_ms")?,
            expires_at_ms: to_u64(self.expires_at_ms, "expires_at_ms")?,
            responded_at_ms: self
                .responded_at_ms
                .map(|value| to_u64(value, "responded_at_ms"))
                .transpose()?,
            response_reason: self.response_reason,
            response_idempotency_key: self.response_idempotency_key,
        })
    }
}

fn row_to_raw_approval(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawApproval> {
    Ok(RawApproval {
        approval_id: row.get(0)?,
        session_id: row.get(1)?,
        task_id: row.get(2)?,
        trace_id: row.get(3)?,
        capability: row.get(4)?,
        operation: row.get(5)?,
        status: row.get(6)?,
        policy_reason: row.get(7)?,
        risk_class: row.get(8)?,
        command_class: row.get(9)?,
        input_brief_json: row.get(10)?,
        requested_runtime_class: row.get(11)?,
        resolved_runtime_class: row.get(12)?,
        requires_network: row.get(13)?,
        requires_pty: row.get(14)?,
        created_at_ms: row.get(15)?,
        expires_at_ms: row.get(16)?,
        responded_at_ms: row.get(17)?,
        response_reason: row.get(18)?,
        response_idempotency_key: row.get(19)?,
    })
}

fn decision_to_status(decision: ApprovalDecision) -> ApprovalStatus {
    match decision {
        ApprovalDecision::Approve => ApprovalStatus::Approved,
        ApprovalDecision::Deny => ApprovalStatus::Denied,
    }
}

fn approval_status_to_db(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "PENDING",
        ApprovalStatus::Approved => "APPROVED",
        ApprovalStatus::Denied => "DENIED",
        ApprovalStatus::Expired => "EXPIRED",
        ApprovalStatus::Cancelled => "CANCELLED",
    }
}

fn approval_status_from_db(status: &str) -> StoreResult<ApprovalStatus> {
    match status {
        "PENDING" => Ok(ApprovalStatus::Pending),
        "APPROVED" => Ok(ApprovalStatus::Approved),
        "DENIED" => Ok(ApprovalStatus::Denied),
        "EXPIRED" => Ok(ApprovalStatus::Expired),
        "CANCELLED" => Ok(ApprovalStatus::Cancelled),
        _ => Err(StoreError::Internal(format!(
            "invalid approval status in db: {status}"
        ))),
    }
}

fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn on_create_err(error: StoreError, approval_id: &str) -> ApprovalRepositoryError {
    match error {
        StoreError::ConstraintViolation(message) => {
            if is_dup_key(&message) {
                ApprovalRepositoryError::AlreadyExists {
                    approval_id: approval_id.to_string(),
                }
            } else {
                ApprovalRepositoryError::Storage { message }
            }
        }
        StoreError::Conflict(message) => ApprovalRepositoryError::Conflict { message },
        StoreError::NotFound(message) => ApprovalRepositoryError::Storage { message },
        StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => ApprovalRepositoryError::Storage { message },
    }
}

fn on_lookup_err(
    error: StoreError,
    session_id: &str,
    approval_id: &str,
) -> ApprovalRepositoryError {
    match error {
        StoreError::NotFound(_) => ApprovalRepositoryError::NotFound {
            session_id: session_id.to_string(),
            approval_id: approval_id.to_string(),
        },
        StoreError::ConstraintViolation(message)
        | StoreError::Conflict(message)
        | StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => ApprovalRepositoryError::Storage { message },
    }
}

fn on_respond_err(
    error: StoreError,
    session_id: &str,
    approval_id: &str,
) -> ApprovalRepositoryError {
    match error {
        StoreError::NotFound(_) => ApprovalRepositoryError::NotFound {
            session_id: session_id.to_string(),
            approval_id: approval_id.to_string(),
        },
        StoreError::Conflict(message) => {
            if message.contains("idempotency_conflict") {
                ApprovalRepositoryError::IdempotencyConflict {
                    approval_id: approval_id.to_string(),
                }
            } else if message.contains("expired") {
                ApprovalRepositoryError::Expired {
                    approval_id: approval_id.to_string(),
                }
            } else {
                ApprovalRepositoryError::InvalidState { message }
            }
        }
        StoreError::ConstraintViolation(message)
        | StoreError::BusyTimeout(message)
        | StoreError::Internal(message)
        | StoreError::MigrationFailed(message)
        | StoreError::OpenFailed(message) => ApprovalRepositoryError::Storage { message },
    }
}

fn on_store_err(error: StoreError) -> ApprovalRepositoryError {
    ApprovalRepositoryError::Storage {
        message: storage_msg(error),
    }
}
