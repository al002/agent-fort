use std::sync::Arc;

use af_approval::{
    ApprovalDecision, ApprovalRepository, ApprovalRepositoryError, ApprovalStatus,
    ListPendingApprovalsQuery, NewApproval, RespondApprovalCommand,
};
use af_audit::{AuditCursor, AuditEventType, AuditRepository, NewAuditEvent};
use af_core::{
    CancelTaskInput, CreateSessionInput, CreateTaskInput, SessionAppService, SessionConfig,
    TaskAppService,
};
use af_session::{
    NewSession, RenewLeaseCommand, SessionLease, SessionRepository, SessionStatus,
    TerminateSessionCommand,
};
use af_task::{
    AdvanceTaskStepCommand, NewTask, TaskCreatedBy, TaskRepository, TaskStatus,
    UpdateTaskStatusCommand,
};

use crate::{Store, StoreOptions};

#[test]
fn session_repository_round_trip() {
    let store = Store::open(StoreOptions::in_memory()).expect("open in-memory store");
    create_base_session(&store, "session-1");

    let fetched = store.get_session("session-1").expect("get session");
    assert_eq!(fetched.status, SessionStatus::Active);
    assert_eq!(fetched.lease.rebind_token, "token-1");

    let renewed = store
        .renew_lease(RenewLeaseCommand {
            session_id: "session-1".to_string(),
            client_instance_id: "client-1".to_string(),
            rebind_token: "token-1".to_string(),
            new_rebind_token: Some("token-2".to_string()),
            new_expires_at_ms: 2_000,
            updated_at_ms: 1_100,
        })
        .expect("renew lease");
    assert_eq!(renewed.lease.rebind_token, "token-2");
    assert_eq!(renewed.lease.expires_at_ms, 2_000);

    let expired = store
        .list_expired_sessions(3_000, 100)
        .expect("list expired sessions");
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].session_id, "session-1");

    let terminated = store
        .terminate_session(TerminateSessionCommand {
            session_id: "session-1".to_string(),
            client_instance_id: "client-1".to_string(),
            rebind_token: "token-2".to_string(),
            terminated_at_ms: 1_200,
        })
        .expect("terminate session");
    assert_eq!(terminated.status, SessionStatus::Terminated);
    assert_eq!(terminated.terminated_at_ms, Some(1_200));
}

#[test]
fn task_repository_round_trip() {
    let store = Store::open(StoreOptions::in_memory()).expect("open in-memory store");
    create_base_session(&store, "session-1");

    let created = store
        .create_task(NewTask {
            task_id: "task-1".to_string(),
            session_id: "session-1".to_string(),
            status: TaskStatus::Pending,
            goal: Some("build repo".to_string()),
            created_by: TaskCreatedBy::Explicit,
            trace_id: "trace-1".to_string(),
            limits_json: Some("{\"max_steps\":10}".to_string()),
            current_step: 0,
            created_at_ms: 1_000,
            updated_at_ms: 1_000,
        })
        .expect("create task");
    assert_eq!(created.status, TaskStatus::Pending);

    let running = store
        .update_task_status(UpdateTaskStatusCommand {
            session_id: "session-1".to_string(),
            task_id: "task-1".to_string(),
            expected_status: Some(TaskStatus::Pending),
            new_status: TaskStatus::Running,
            updated_at_ms: 1_100,
            ended_at_ms: None,
            error_code: None,
            error_message: None,
        })
        .expect("update task status to running");
    assert_eq!(running.status, TaskStatus::Running);

    let advanced = store
        .advance_task_step(AdvanceTaskStepCommand {
            session_id: "session-1".to_string(),
            task_id: "task-1".to_string(),
            expected_current_step: 0,
            next_step: 1,
            updated_at_ms: 1_200,
        })
        .expect("advance task step");
    assert_eq!(advanced.current_step, 1);

    let completed = store
        .update_task_status(UpdateTaskStatusCommand {
            session_id: "session-1".to_string(),
            task_id: "task-1".to_string(),
            expected_status: Some(TaskStatus::Running),
            new_status: TaskStatus::Completed,
            updated_at_ms: 1_300,
            ended_at_ms: Some(1_300),
            error_code: None,
            error_message: None,
        })
        .expect("update task status to completed");
    assert_eq!(completed.status, TaskStatus::Completed);
    assert_eq!(completed.ended_at_ms, Some(1_300));
}

#[test]
fn approval_repository_idempotency_and_expire_flow() {
    let store = Store::open(StoreOptions::in_memory()).expect("open in-memory store");
    create_base_session(&store, "session-1");
    create_base_task(&store, "session-1", "task-1", "trace-1");

    let created = store
        .create_approval(NewApproval {
            approval_id: "approval-1".to_string(),
            session_id: "session-1".to_string(),
            task_id: "task-1".to_string(),
            trace_id: "trace-1".to_string(),
            capability: "shell.exec".to_string(),
            operation: "run".to_string(),
            status: ApprovalStatus::Pending,
            policy_reason: "needs approval".to_string(),
            risk_class: "high".to_string(),
            command_class: "shell".to_string(),
            input_brief_json: "{\"cmd\":\"rm -rf\"}".to_string(),
            requested_runtime_class: "workspace_write".to_string(),
            resolved_runtime_class: "workspace_write".to_string(),
            requires_network: false,
            requires_pty: false,
            created_at_ms: 1_000,
            expires_at_ms: 5_000,
        })
        .expect("create approval");
    assert_eq!(created.status, ApprovalStatus::Pending);

    let pending = store
        .list_pending_approvals(ListPendingApprovalsQuery {
            session_id: "session-1".to_string(),
            limit: 10,
            after_approval_id: None,
        })
        .expect("list pending approvals");
    assert_eq!(pending.len(), 1);

    let approved = store
        .respond_approval(RespondApprovalCommand {
            session_id: "session-1".to_string(),
            approval_id: "approval-1".to_string(),
            decision: ApprovalDecision::Approve,
            idempotency_key: "idem-1".to_string(),
            reason: Some("looks good".to_string()),
            responded_at_ms: 1_500,
        })
        .expect("respond approval first call");
    assert_eq!(approved.status, ApprovalStatus::Approved);

    let idempotent = store
        .respond_approval(RespondApprovalCommand {
            session_id: "session-1".to_string(),
            approval_id: "approval-1".to_string(),
            decision: ApprovalDecision::Approve,
            idempotency_key: "idem-1".to_string(),
            reason: Some("same key".to_string()),
            responded_at_ms: 1_600,
        })
        .expect("respond approval same idempotency key");
    assert_eq!(idempotent.status, ApprovalStatus::Approved);

    let conflict = store.respond_approval(RespondApprovalCommand {
        session_id: "session-1".to_string(),
        approval_id: "approval-1".to_string(),
        decision: ApprovalDecision::Approve,
        idempotency_key: "idem-2".to_string(),
        reason: Some("different key".to_string()),
        responded_at_ms: 1_700,
    });
    match conflict {
        Err(ApprovalRepositoryError::IdempotencyConflict { approval_id }) => {
            assert_eq!(approval_id, "approval-1")
        }
        other => panic!("expected idempotency conflict, got {other:?}"),
    }

    store
        .create_approval(NewApproval {
            approval_id: "approval-2".to_string(),
            session_id: "session-1".to_string(),
            task_id: "task-1".to_string(),
            trace_id: "trace-1".to_string(),
            capability: "shell.exec".to_string(),
            operation: "run".to_string(),
            status: ApprovalStatus::Pending,
            policy_reason: "will expire".to_string(),
            risk_class: "high".to_string(),
            command_class: "shell".to_string(),
            input_brief_json: "{\"cmd\":\"ls\"}".to_string(),
            requested_runtime_class: "workspace_write".to_string(),
            resolved_runtime_class: "workspace_write".to_string(),
            requires_network: false,
            requires_pty: false,
            created_at_ms: 1_000,
            expires_at_ms: 1_200,
        })
        .expect("create expiring approval");

    let expired = store
        .expire_pending_approvals(2_000, 10)
        .expect("expire pending approvals");
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].approval_id, "approval-2");
    assert_eq!(expired[0].status, ApprovalStatus::Expired);
}

#[test]
fn audit_repository_append_and_query() {
    let store = Store::open(StoreOptions::in_memory()).expect("open in-memory store");

    let first = store
        .append_event(NewAuditEvent {
            ts_ms: 1_000,
            trace_id: "trace-1".to_string(),
            session_id: Some("session-1".to_string()),
            task_id: Some("task-1".to_string()),
            event_type: AuditEventType::TaskCreated,
            payload_json: Some("{\"step\":1}".to_string()),
            error_code: None,
        })
        .expect("append first audit event");
    let second = store
        .append_event(NewAuditEvent {
            ts_ms: 1_100,
            trace_id: "trace-1".to_string(),
            session_id: Some("session-1".to_string()),
            task_id: Some("task-1".to_string()),
            event_type: AuditEventType::TaskCompleted,
            payload_json: Some("{\"step\":2}".to_string()),
            error_code: None,
        })
        .expect("append second audit event");
    assert!(second.seq > first.seq);

    let by_trace = store
        .list_by_trace(
            "trace-1",
            AuditCursor {
                after_seq: None,
                limit: 10,
            },
        )
        .expect("list audit by trace");
    assert_eq!(by_trace.len(), 2);
    assert_eq!(by_trace[0].seq, first.seq);
    assert_eq!(by_trace[1].seq, second.seq);

    let by_trace_after_first = store
        .list_by_trace(
            "trace-1",
            AuditCursor {
                after_seq: Some(first.seq),
                limit: 10,
            },
        )
        .expect("list audit by trace after cursor");
    assert_eq!(by_trace_after_first.len(), 1);
    assert_eq!(by_trace_after_first[0].seq, second.seq);

    let by_session = store
        .list_by_session(
            "session-1",
            AuditCursor {
                after_seq: None,
                limit: 10,
            },
        )
        .expect("list audit by session");
    assert_eq!(by_session.len(), 2);

    let by_task = store
        .list_by_task(
            "task-1",
            AuditCursor {
                after_seq: None,
                limit: 10,
            },
        )
        .expect("list audit by task");
    assert_eq!(by_task.len(), 2);
}

#[test]
fn create_session_service_writes_session_and_audit_atomically() {
    let store = Arc::new(Store::open(StoreOptions::in_memory()).expect("open in-memory store"));
    let service = SessionAppService::new(
        store.clone(),
        SessionConfig {
            default_lease_ttl_secs: 120,
        },
    );

    let created = service
        .create_session(CreateSessionInput {
            agent_name: "agent-1".to_string(),
            client_instance_id: "client-1".to_string(),
            lease_ttl_secs: Some(30),
        })
        .expect("create session");
    assert_eq!(created.status, SessionStatus::Active);

    let fetched = store
        .get_session(&created.session_id)
        .expect("fetch created session");
    assert_eq!(fetched.session_id, created.session_id);

    let events = store
        .list_by_session(
            &created.session_id,
            AuditCursor {
                after_seq: None,
                limit: 10,
            },
        )
        .expect("list session audit events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, AuditEventType::SessionCreated);
}

#[test]
fn task_service_writes_task_and_audit_atomically() {
    let store = Arc::new(Store::open(StoreOptions::in_memory()).expect("open in-memory store"));
    create_base_session(&store, "session-1");
    let service = TaskAppService::new(store.clone());

    let created = service
        .create_task(CreateTaskInput {
            session_id: "session-1".to_string(),
            goal: Some("ship".to_string()),
            limits_json: Some("{\"max_steps\":1}".to_string()),
            created_by: TaskCreatedBy::Explicit,
        })
        .expect("create task");
    assert_eq!(created.status, TaskStatus::Pending);

    let after_create = store
        .list_by_task(
            &created.task_id,
            AuditCursor {
                after_seq: None,
                limit: 10,
            },
        )
        .expect("list task audit after create");
    assert_eq!(after_create.len(), 1);
    assert_eq!(after_create[0].event_type, AuditEventType::TaskCreated);

    let cancelled = service
        .cancel_task(CancelTaskInput {
            session_id: created.session_id.clone(),
            task_id: created.task_id.clone(),
        })
        .expect("cancel task");
    assert_eq!(cancelled.status, TaskStatus::Cancelled);

    let after_cancel = store
        .list_by_task(
            &created.task_id,
            AuditCursor {
                after_seq: None,
                limit: 10,
            },
        )
        .expect("list task audit after cancel");
    assert_eq!(after_cancel.len(), 2);
    assert_eq!(after_cancel[1].event_type, AuditEventType::TaskCancelled);
}

fn create_base_session(store: &Store, session_id: &str) {
    store
        .create_session(NewSession {
            session_id: session_id.to_string(),
            agent_name: "agent-1".to_string(),
            lease: SessionLease {
                client_instance_id: "client-1".to_string(),
                rebind_token: "token-1".to_string(),
                expires_at_ms: 1_500,
            },
            created_at_ms: 1_000,
            updated_at_ms: 1_000,
        })
        .expect("create base session");
}

fn create_base_task(store: &Store, session_id: &str, task_id: &str, trace_id: &str) {
    store
        .create_task(NewTask {
            task_id: task_id.to_string(),
            session_id: session_id.to_string(),
            status: TaskStatus::Pending,
            goal: None,
            created_by: TaskCreatedBy::Invoke,
            trace_id: trace_id.to_string(),
            limits_json: None,
            current_step: 0,
            created_at_ms: 1_000,
            updated_at_ms: 1_000,
        })
        .expect("create base task");
}
