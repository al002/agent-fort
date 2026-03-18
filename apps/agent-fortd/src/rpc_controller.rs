use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use af_core::{
    ApprovalAppError, ApprovalAppService, CancelTaskInput, CreateSessionInput, CreateTaskInput,
    GetApprovalInput, RespondApprovalInput, SessionAppError, SessionAppService, SessionConfig,
    TaskAppError, TaskAppService,
};
use af_rpc_proto::codec::{decode_message, encode_message};
use af_rpc_proto::{
    Approval as RpcApproval, ApprovalDecision as RpcApprovalDecision,
    ApprovalItem as RpcApprovalItem, ApprovalStatus as RpcApprovalStatus, CancelTaskRequest,
    CancelTaskResponse, CreateSessionRequest, CreateSessionResponse, CreateTaskRequest,
    CreateTaskResponse, DaemonInfo, GetApprovalRequest, GetApprovalResponse, GetDaemonInfoRequest,
    GetDaemonInfoResponse, GetTaskRequest, GetTaskResponse, PingRequest, PingResponse,
    RespondApprovalRequest, RespondApprovalResponse, RpcError, RpcErrorCode, RpcMethod, RpcRequest,
    RpcResponse, Session, SessionLease, SessionStatus, Task, TaskCreatedBy, TaskStatus,
    rpc_response,
};
use af_rpc_transport::RpcConnection;
use af_session::{SessionRepository, SessionRepositoryError, SessionStatus as DomainSessionStatus};
use af_store::Store;
use af_task::TaskCreatedBy as DomainTaskCreatedBy;
use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct RpcController {
    state: Arc<ControllerState>,
}

#[derive(Debug)]
struct ControllerState {
    daemon_instance_id: String,
    store: Arc<Store>,
    session_service: SessionAppService,
    task_service: TaskAppService,
    approval_service: ApprovalAppService,
}

impl RpcController {
    pub fn new(daemon_instance_id: String, store: Arc<Store>) -> Self {
        let session_service = SessionAppService::new(store.clone(), SessionConfig::default());
        let task_service = TaskAppService::new(store.clone());
        let approval_service = ApprovalAppService::new(store.clone());
        Self {
            state: Arc::new(ControllerState {
                daemon_instance_id,
                store,
                session_service,
                task_service,
                approval_service,
            }),
        }
    }

    pub fn daemon_info(&self) -> GetDaemonInfoResponse {
        GetDaemonInfoResponse {
            info: Some(DaemonInfo {
                daemon_instance_id: self.state.daemon_instance_id.clone(),
                protocol: "rpc-transport.v1".to_string(),
                routes: vec![
                    "Ping".to_string(),
                    "GetDaemonInfo".to_string(),
                    "CreateSession".to_string(),
                    "CreateTask".to_string(),
                    "GetTask".to_string(),
                    "CancelTask".to_string(),
                    "GetApproval".to_string(),
                    "RespondApproval".to_string(),
                ],
            }),
        }
    }

    pub async fn handle_connection(&self, mut connection: RpcConnection) -> Result<()> {
        let request: RpcRequest = connection.read_message().await?;
        let controller = self.clone();
        let response = tokio::task::spawn_blocking(move || -> Result<RpcResponse> {
            controller.state.store.ping()?;
            Ok(controller.dispatch(request))
        })
        .await
        .context("join rpc dispatch task")??;
        connection.write_message(&response).await?;
        Ok(())
    }

    fn dispatch(&self, request: RpcRequest) -> RpcResponse {
        let method = match RpcMethod::try_from(request.method) {
            Ok(method) => method,
            Err(_) => {
                return err(
                    RpcErrorCode::BadRequest,
                    format!("unknown rpc method value: {}", request.method),
                );
            }
        };

        match method {
            RpcMethod::Ping => self.handle_ping(request.payload),
            RpcMethod::GetDaemonInfo => self.handle_daemon_info(request.payload),
            RpcMethod::CreateSession => self.handle_create_session(request.payload),
            RpcMethod::CreateTask => self.handle_create_task(request.payload),
            RpcMethod::GetTask => self.handle_get_task(request.payload),
            RpcMethod::CancelTask => self.handle_cancel_task(request.payload),
            RpcMethod::GetApproval => self.handle_get_approval(request.payload),
            RpcMethod::RespondApproval => self.handle_respond_approval(request.payload),
            _ => err(
                RpcErrorCode::MethodNotSupported,
                format!("method not supported: {:?}", method),
            ),
        }
    }

    fn handle_ping(&self, payload: Vec<u8>) -> RpcResponse {
        if let Err(error) = decode_message::<PingRequest>(&payload) {
            return err(
                RpcErrorCode::BadRequest,
                format!("decode PingRequest failed: {error}"),
            );
        }

        ok(encode_message(&PingResponse {
            status: "ok".to_string(),
            daemon_instance_id: self.state.daemon_instance_id.clone(),
        }))
    }

    fn handle_daemon_info(&self, payload: Vec<u8>) -> RpcResponse {
        if let Err(error) = decode_message::<GetDaemonInfoRequest>(&payload) {
            return err(
                RpcErrorCode::BadRequest,
                format!("decode GetDaemonInfoRequest failed: {error}"),
            );
        }

        ok(encode_message(&self.daemon_info()))
    }

    fn handle_create_session(&self, payload: Vec<u8>) -> RpcResponse {
        let request = match decode_message::<CreateSessionRequest>(&payload) {
            Ok(request) => request,
            Err(error) => {
                return err(
                    RpcErrorCode::BadRequest,
                    format!("decode CreateSessionRequest failed: {error}"),
                );
            }
        };

        let created = self
            .state
            .session_service
            .create_session(CreateSessionInput {
                agent_name: request.agent_name,
                client_instance_id: request.client_instance_id,
                lease_ttl_secs: request.lease_ttl_secs,
            });
        match created {
            Ok(session) => ok(encode_message(&CreateSessionResponse {
                session: Some(to_proto_session(session)),
            })),
            Err(error) => map_session_error(error),
        }
    }

    fn handle_create_task(&self, payload: Vec<u8>) -> RpcResponse {
        let request = match decode_message::<CreateTaskRequest>(&payload) {
            Ok(request) => request,
            Err(error) => {
                return err(
                    RpcErrorCode::BadRequest,
                    format!("decode CreateTaskRequest failed: {error}"),
                );
            }
        };

        if let Some(response) = self.ensure_session_access(
            &request.session_id,
            &request.client_instance_id,
            &request.rebind_token,
        ) {
            return response;
        }

        let created = self.state.task_service.create_task(CreateTaskInput {
            session_id: request.session_id,
            goal: request.goal,
            limits_json: request.limits_json,
            created_by: DomainTaskCreatedBy::Explicit,
        });
        match created {
            Ok(task) => ok(encode_message(&CreateTaskResponse {
                task: Some(to_proto_task(task)),
            })),
            Err(error) => map_task_error(error),
        }
    }

    fn handle_get_task(&self, payload: Vec<u8>) -> RpcResponse {
        let request = match decode_message::<GetTaskRequest>(&payload) {
            Ok(request) => request,
            Err(error) => {
                return err(
                    RpcErrorCode::BadRequest,
                    format!("decode GetTaskRequest failed: {error}"),
                );
            }
        };

        if let Some(response) = self.ensure_session_access(
            &request.session_id,
            &request.client_instance_id,
            &request.rebind_token,
        ) {
            return response;
        }

        match self
            .state
            .task_service
            .get_task(&request.session_id, &request.task_id)
        {
            Ok(task) => ok(encode_message(&GetTaskResponse {
                task: Some(to_proto_task(task)),
            })),
            Err(error) => map_task_error(error),
        }
    }

    fn handle_cancel_task(&self, payload: Vec<u8>) -> RpcResponse {
        let request = match decode_message::<CancelTaskRequest>(&payload) {
            Ok(request) => request,
            Err(error) => {
                return err(
                    RpcErrorCode::BadRequest,
                    format!("decode CancelTaskRequest failed: {error}"),
                );
            }
        };

        if let Some(response) = self.ensure_session_access(
            &request.session_id,
            &request.client_instance_id,
            &request.rebind_token,
        ) {
            return response;
        }

        match self.state.task_service.cancel_task(CancelTaskInput {
            session_id: request.session_id,
            task_id: request.task_id,
        }) {
            Ok(task) => ok(encode_message(&CancelTaskResponse {
                task: Some(to_proto_task(task)),
            })),
            Err(error) => map_task_error(error),
        }
    }

    fn handle_get_approval(&self, payload: Vec<u8>) -> RpcResponse {
        let request = match decode_message::<GetApprovalRequest>(&payload) {
            Ok(request) => request,
            Err(error) => {
                return err(
                    RpcErrorCode::BadRequest,
                    format!("decode GetApprovalRequest failed: {error}"),
                );
            }
        };

        if let Some(response) = self.ensure_session_access(
            &request.session_id,
            &request.client_instance_id,
            &request.rebind_token,
        ) {
            return response;
        }

        match self.state.approval_service.get_approval(GetApprovalInput {
            session_id: request.session_id,
            approval_id: request.approval_id,
        }) {
            Ok(approval) => ok(encode_message(&GetApprovalResponse {
                approval: Some(to_proto_approval(approval)),
            })),
            Err(error) => map_approval_error(error),
        }
    }

    fn handle_respond_approval(&self, payload: Vec<u8>) -> RpcResponse {
        let request = match decode_message::<RespondApprovalRequest>(&payload) {
            Ok(request) => request,
            Err(error) => {
                return err(
                    RpcErrorCode::BadRequest,
                    format!("decode RespondApprovalRequest failed: {error}"),
                );
            }
        };

        if let Some(response) = self.ensure_session_access(
            &request.session_id,
            &request.client_instance_id,
            &request.rebind_token,
        ) {
            return response;
        }

        let decision = match rpc_approval_decision_to_domain(request.decision) {
            Ok(decision) => decision,
            Err(response) => return response,
        };

        let responded = match self
            .state
            .approval_service
            .respond_approval(RespondApprovalInput {
                session_id: request.session_id.clone(),
                approval_id: request.approval_id.clone(),
                decision,
                idempotency_key: request.idempotency_key,
                reason: request.reason,
                responded_at_ms: now_ms(),
            }) {
            Ok(result) => result,
            Err(error) => return map_approval_error(error),
        };

        let task = if responded.transition_applied {
            responded.task
        } else {
            match self
                .state
                .task_service
                .get_task(&request.session_id, &responded.task.task_id)
            {
                Ok(task) => task,
                Err(error) => return map_task_error(error),
            }
        };

        ok(encode_message(&RespondApprovalResponse {
            approval: Some(to_proto_approval(responded.approval)),
            task: Some(to_proto_task(task)),
            invoke_result: None,
        }))
    }

    fn ensure_session_access(
        &self,
        session_id: &str,
        client_instance_id: &str,
        rebind_token: &str,
    ) -> Option<RpcResponse> {
        let session = match self.state.store.get_session(session_id) {
            Ok(session) => session,
            Err(error) => {
                return Some(map_session_lookup_error(error));
            }
        };

        if session.status != DomainSessionStatus::Active {
            return Some(err(
                RpcErrorCode::InvalidSessionState,
                format!("session is not active: session_id={session_id}"),
            ));
        }
        if session.lease.expires_at_ms <= now_ms() {
            return Some(err(
                RpcErrorCode::InvalidSessionState,
                format!("session lease expired: session_id={session_id}"),
            ));
        }
        if session.lease.client_instance_id != client_instance_id
            || session.lease.rebind_token != rebind_token
        {
            return Some(err(
                RpcErrorCode::SessionRebindDenied,
                format!("session rebind denied: session_id={session_id}"),
            ));
        }
        None
    }
}

fn ok(payload: Vec<u8>) -> RpcResponse {
    RpcResponse {
        outcome: Some(rpc_response::Outcome::Payload(payload)),
    }
}

fn err(code: RpcErrorCode, message: impl Into<String>) -> RpcResponse {
    RpcResponse {
        outcome: Some(rpc_response::Outcome::Error(RpcError {
            code: code as i32,
            message: message.into(),
        })),
    }
}

fn map_session_error(error: SessionAppError) -> RpcResponse {
    match error {
        SessionAppError::Validation { message } => err(RpcErrorCode::BadRequest, message),
        SessionAppError::Store { message } => err(RpcErrorCode::StoreError, message),
        SessionAppError::Audit { message } => err(RpcErrorCode::AuditWriteFailed, message),
        SessionAppError::Internal { message } => err(RpcErrorCode::InternalError, message),
    }
}

fn map_session_lookup_error(error: SessionRepositoryError) -> RpcResponse {
    match error {
        SessionRepositoryError::NotFound { .. } => {
            err(RpcErrorCode::SessionNotFound, "session not found")
        }
        SessionRepositoryError::AlreadyExists { .. }
        | SessionRepositoryError::Conflict { .. }
        | SessionRepositoryError::Validation { .. }
        | SessionRepositoryError::Storage { .. } => err(
            RpcErrorCode::StoreError,
            format!("session lookup failed: {error}"),
        ),
    }
}

fn map_task_error(error: TaskAppError) -> RpcResponse {
    match error {
        TaskAppError::Validation { message } => err(RpcErrorCode::BadRequest, message),
        TaskAppError::NotFound { .. } => err(RpcErrorCode::TaskNotFound, "task not found"),
        TaskAppError::InvalidState { message } => err(RpcErrorCode::InvalidTaskState, message),
        TaskAppError::Store { message } => err(RpcErrorCode::StoreError, message),
        TaskAppError::Audit { message } => err(RpcErrorCode::AuditWriteFailed, message),
        TaskAppError::Internal { message } => err(RpcErrorCode::InternalError, message),
    }
}

fn map_approval_error(error: ApprovalAppError) -> RpcResponse {
    match error {
        ApprovalAppError::Validation { message } => err(RpcErrorCode::BadRequest, message),
        ApprovalAppError::NotFound { .. } => {
            err(RpcErrorCode::ApprovalNotFound, "approval not found")
        }
        ApprovalAppError::Expired { .. } => err(RpcErrorCode::ApprovalExpired, "approval expired"),
        ApprovalAppError::IdempotencyConflict { .. } => err(
            RpcErrorCode::ApprovalIdempotencyConflict,
            "approval idempotency conflict",
        ),
        ApprovalAppError::InvalidState { message } => {
            err(RpcErrorCode::ApprovalInvalidState, message)
        }
        ApprovalAppError::Store { message } => err(RpcErrorCode::StoreError, message),
        ApprovalAppError::Audit { message } => err(RpcErrorCode::AuditWriteFailed, message),
        ApprovalAppError::Internal { message } => err(RpcErrorCode::InternalError, message),
    }
}

fn rpc_approval_decision_to_domain(
    raw_decision: i32,
) -> Result<af_approval::ApprovalDecision, RpcResponse> {
    let decision = RpcApprovalDecision::try_from(raw_decision).map_err(|_| {
        err(
            RpcErrorCode::BadRequest,
            format!("unknown ApprovalDecision value: {raw_decision}"),
        )
    })?;
    match decision {
        RpcApprovalDecision::Unspecified => Err(err(
            RpcErrorCode::BadRequest,
            "approval decision must not be unspecified",
        )),
        RpcApprovalDecision::Approve => Ok(af_approval::ApprovalDecision::Approve),
        RpcApprovalDecision::Deny => Ok(af_approval::ApprovalDecision::Deny),
    }
}

fn to_proto_approval(approval: af_approval::Approval) -> RpcApproval {
    let items = approval
        .items
        .into_iter()
        .map(|item| RpcApprovalItem {
            kind: item.kind,
            target: item.target.unwrap_or_default(),
            summary: item.summary,
        })
        .collect();

    RpcApproval {
        approval_id: approval.approval_id,
        session_id: approval.session_id,
        task_id: approval.task_id,
        trace_id: approval.trace_id,
        status: to_proto_approval_status(approval.status) as i32,
        summary: approval.summary,
        items,
        details: approval.details,
        created_at_ms: approval.created_at_ms,
        expires_at_ms: approval.expires_at_ms,
        responded_at_ms: approval.responded_at_ms,
        response_reason: approval.response_reason,
        response_idempotency_key: approval.response_idempotency_key,
    }
}

fn to_proto_approval_status(status: af_approval::ApprovalStatus) -> RpcApprovalStatus {
    match status {
        af_approval::ApprovalStatus::Pending => RpcApprovalStatus::Pending,
        af_approval::ApprovalStatus::Approved => RpcApprovalStatus::Approved,
        af_approval::ApprovalStatus::Denied => RpcApprovalStatus::Denied,
        af_approval::ApprovalStatus::Expired => RpcApprovalStatus::Expired,
        af_approval::ApprovalStatus::Cancelled => RpcApprovalStatus::Cancelled,
    }
}

fn to_proto_session(session: af_session::Session) -> Session {
    Session {
        session_id: session.session_id,
        agent_name: session.agent_name,
        status: match session.status {
            af_session::SessionStatus::Active => SessionStatus::Active as i32,
            af_session::SessionStatus::Expired => SessionStatus::Expired as i32,
            af_session::SessionStatus::Terminated => SessionStatus::Terminated as i32,
        },
        lease: Some(SessionLease {
            client_instance_id: session.lease.client_instance_id,
            rebind_token: session.lease.rebind_token,
            expires_at_ms: session.lease.expires_at_ms,
        }),
        created_at_ms: session.created_at_ms,
        updated_at_ms: session.updated_at_ms,
    }
}

fn to_proto_task(task: af_task::Task) -> Task {
    Task {
        task_id: task.task_id,
        session_id: task.session_id,
        status: match task.status {
            af_task::TaskStatus::Pending => TaskStatus::Pending as i32,
            af_task::TaskStatus::Running => TaskStatus::Running as i32,
            af_task::TaskStatus::Blocked => TaskStatus::Blocked as i32,
            af_task::TaskStatus::Completed => TaskStatus::Completed as i32,
            af_task::TaskStatus::Failed => TaskStatus::Failed as i32,
            af_task::TaskStatus::Cancelled => TaskStatus::Cancelled as i32,
        },
        goal: task.goal,
        created_by: match task.created_by {
            af_task::TaskCreatedBy::Explicit => TaskCreatedBy::Explicit as i32,
            af_task::TaskCreatedBy::Invoke => TaskCreatedBy::Invoke as i32,
        },
        trace_id: task.trace_id,
        limits_json: task.limits_json,
        current_step: task.current_step,
        error_code: task.error_code,
        error_message: task.error_message,
        created_at_ms: task.created_at_ms,
        updated_at_ms: task.updated_at_ms,
        ended_at_ms: task.ended_at_ms,
    }
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
    use af_approval::{ApprovalItem, ApprovalRepository, ApprovalStatus, NewApproval};
    use af_audit::{AuditCursor, AuditEventType, AuditRepository};
    use af_session::{NewSession, SessionLease, SessionRepository};
    use af_store::StoreOptions;
    use af_task::{NewTask, TaskCreatedBy, TaskRepository, TaskStatus as DomainTaskStatus};

    #[test]
    fn create_session_dispatch_returns_session_and_audit() {
        let store = Arc::new(Store::open(StoreOptions::in_memory()).expect("open store"));
        let controller = RpcController::new("daemon-1".to_string(), store.clone());
        let request = CreateSessionRequest {
            agent_name: "agent-1".to_string(),
            client_instance_id: "client-1".to_string(),
            lease_ttl_secs: Some(30),
        };
        let rpc_request = RpcRequest {
            method: RpcMethod::CreateSession as i32,
            payload: encode_message(&request),
        };

        let response = controller.dispatch(rpc_request);
        let payload = match response.outcome {
            Some(rpc_response::Outcome::Payload(payload)) => payload,
            other => panic!("expected payload response, got {other:?}"),
        };
        let created = decode_message::<CreateSessionResponse>(&payload)
            .expect("decode create session response");
        let session = created.session.expect("session must exist");
        assert_eq!(session.agent_name, "agent-1");
        assert_eq!(session.status, SessionStatus::Active as i32);

        store
            .get_session(&session.session_id)
            .expect("session persisted");
        let events = store
            .list_by_session(
                &session.session_id,
                AuditCursor {
                    after_seq: None,
                    limit: 10,
                },
            )
            .expect("list audit");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::SessionCreated);
    }

    #[test]
    fn create_get_cancel_task_dispatch_round_trip() {
        let store = Arc::new(Store::open(StoreOptions::in_memory()).expect("open store"));
        let controller = RpcController::new("daemon-1".to_string(), store.clone());

        let create_session = RpcRequest {
            method: RpcMethod::CreateSession as i32,
            payload: encode_message(&CreateSessionRequest {
                agent_name: "agent-1".to_string(),
                client_instance_id: "client-1".to_string(),
                lease_ttl_secs: Some(30),
            }),
        };
        let session_response = controller.dispatch(create_session);
        let session_payload = match session_response.outcome {
            Some(rpc_response::Outcome::Payload(payload)) => payload,
            other => panic!("expected payload response, got {other:?}"),
        };
        let created_session = decode_message::<CreateSessionResponse>(&session_payload)
            .expect("decode create session response")
            .session
            .expect("session must exist");

        let create_task_response = controller.dispatch(RpcRequest {
            method: RpcMethod::CreateTask as i32,
            payload: encode_message(&CreateTaskRequest {
                session_id: created_session.session_id.clone(),
                client_instance_id: created_session
                    .lease
                    .as_ref()
                    .expect("lease")
                    .client_instance_id
                    .clone(),
                rebind_token: created_session
                    .lease
                    .as_ref()
                    .expect("lease")
                    .rebind_token
                    .clone(),
                goal: Some("work".to_string()),
                limits_json: Some("{\"max_steps\":1}".to_string()),
            }),
        });
        let create_task_payload = match create_task_response.outcome {
            Some(rpc_response::Outcome::Payload(payload)) => payload,
            other => panic!("expected payload response, got {other:?}"),
        };
        let created_task = decode_message::<CreateTaskResponse>(&create_task_payload)
            .expect("decode create task response")
            .task
            .expect("task must exist");
        assert_eq!(created_task.status, TaskStatus::Pending as i32);

        let get_task_response = controller.dispatch(RpcRequest {
            method: RpcMethod::GetTask as i32,
            payload: encode_message(&GetTaskRequest {
                session_id: created_session.session_id.clone(),
                task_id: created_task.task_id.clone(),
                client_instance_id: created_session
                    .lease
                    .as_ref()
                    .expect("lease")
                    .client_instance_id
                    .clone(),
                rebind_token: created_session
                    .lease
                    .as_ref()
                    .expect("lease")
                    .rebind_token
                    .clone(),
            }),
        });
        let get_task_payload = match get_task_response.outcome {
            Some(rpc_response::Outcome::Payload(payload)) => payload,
            other => panic!("expected payload response, got {other:?}"),
        };
        let fetched_task = decode_message::<GetTaskResponse>(&get_task_payload)
            .expect("decode get task response")
            .task
            .expect("task must exist");
        assert_eq!(fetched_task.task_id, created_task.task_id);

        let cancel_task_response = controller.dispatch(RpcRequest {
            method: RpcMethod::CancelTask as i32,
            payload: encode_message(&CancelTaskRequest {
                session_id: created_session.session_id.clone(),
                task_id: created_task.task_id.clone(),
                client_instance_id: created_session
                    .lease
                    .as_ref()
                    .expect("lease")
                    .client_instance_id
                    .clone(),
                rebind_token: created_session
                    .lease
                    .as_ref()
                    .expect("lease")
                    .rebind_token
                    .clone(),
            }),
        });
        let cancel_task_payload = match cancel_task_response.outcome {
            Some(rpc_response::Outcome::Payload(payload)) => payload,
            other => panic!("expected payload response, got {other:?}"),
        };
        let cancelled_task = decode_message::<CancelTaskResponse>(&cancel_task_payload)
            .expect("decode cancel task response")
            .task
            .expect("task must exist");
        assert_eq!(cancelled_task.status, TaskStatus::Cancelled as i32);

        store
            .get_task(&created_session.session_id, &created_task.task_id)
            .expect("task persisted");
        let events = store
            .list_by_task(
                &created_task.task_id,
                AuditCursor {
                    after_seq: None,
                    limit: 10,
                },
            )
            .expect("list task audit");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, AuditEventType::TaskCreated);
        assert_eq!(events[1].event_type, AuditEventType::TaskCancelled);
    }

    #[test]
    fn create_task_rejects_expired_session_lease() {
        let store = Arc::new(Store::open(StoreOptions::in_memory()).expect("open store"));
        let controller = RpcController::new("daemon-1".to_string(), store.clone());

        store
            .create_session(NewSession {
                session_id: "session-expired".to_string(),
                agent_name: "agent-1".to_string(),
                lease: SessionLease {
                    client_instance_id: "client-1".to_string(),
                    rebind_token: "token-1".to_string(),
                    expires_at_ms: 1,
                },
                created_at_ms: 1,
                updated_at_ms: 1,
            })
            .expect("create expired session");

        let response = controller.dispatch(RpcRequest {
            method: RpcMethod::CreateTask as i32,
            payload: encode_message(&CreateTaskRequest {
                session_id: "session-expired".to_string(),
                client_instance_id: "client-1".to_string(),
                rebind_token: "token-1".to_string(),
                goal: None,
                limits_json: None,
            }),
        });

        let error = match response.outcome {
            Some(rpc_response::Outcome::Error(error)) => error,
            other => panic!("expected error response, got {other:?}"),
        };
        assert_eq!(error.code, RpcErrorCode::InvalidSessionState as i32);
        assert!(error.message.contains("expired"));
    }

    #[test]
    fn approval_routes_round_trip_and_resume_blocked_task() {
        let store = Arc::new(Store::open(StoreOptions::in_memory()).expect("open store"));
        let controller = RpcController::new("daemon-1".to_string(), store.clone());

        let session_response = controller.dispatch(RpcRequest {
            method: RpcMethod::CreateSession as i32,
            payload: encode_message(&CreateSessionRequest {
                agent_name: "agent-1".to_string(),
                client_instance_id: "client-1".to_string(),
                lease_ttl_secs: Some(30),
            }),
        });
        let session_payload = match session_response.outcome {
            Some(rpc_response::Outcome::Payload(payload)) => payload,
            other => panic!("expected payload response, got {other:?}"),
        };
        let created_session = decode_message::<CreateSessionResponse>(&session_payload)
            .expect("decode create session response")
            .session
            .expect("session must exist");
        let lease = created_session.lease.clone().expect("lease must exist");

        store
            .create_task(NewTask {
                task_id: "task-approval-1".to_string(),
                session_id: created_session.session_id.clone(),
                status: DomainTaskStatus::Blocked,
                goal: Some("wait approval".to_string()),
                created_by: TaskCreatedBy::Invoke,
                trace_id: "trace-approval-1".to_string(),
                limits_json: None,
                current_step: 0,
                created_at_ms: 1_000,
                updated_at_ms: 1_000,
            })
            .expect("create blocked task");
        store
            .create_approval(NewApproval {
                approval_id: "approval-1".to_string(),
                session_id: created_session.session_id.clone(),
                task_id: "task-approval-1".to_string(),
                trace_id: "trace-approval-1".to_string(),
                status: ApprovalStatus::Pending,
                summary: "network access requires approval".to_string(),
                details: Some("outbound request to example.com".to_string()),
                items: vec![ApprovalItem {
                    kind: "network".to_string(),
                    target: Some("example.com".to_string()),
                    summary: "outbound network".to_string(),
                }],
                policy_reason: "needs manual approval".to_string(),
                policy_revision: 1,
                execution_contract_json: "{\"decision\":\"ask\"}".to_string(),
                created_at_ms: 1_000,
                expires_at_ms: now_ms() + 60_000,
            })
            .expect("create approval");

        let get_response = controller.dispatch(RpcRequest {
            method: RpcMethod::GetApproval as i32,
            payload: encode_message(&GetApprovalRequest {
                session_id: created_session.session_id.clone(),
                approval_id: "approval-1".to_string(),
                client_instance_id: lease.client_instance_id.clone(),
                rebind_token: lease.rebind_token.clone(),
            }),
        });
        let get_payload = match get_response.outcome {
            Some(rpc_response::Outcome::Payload(payload)) => payload,
            other => panic!("expected payload response, got {other:?}"),
        };
        let fetched = decode_message::<GetApprovalResponse>(&get_payload)
            .expect("decode get approval response")
            .approval
            .expect("approval must exist");
        assert_eq!(fetched.status, RpcApprovalStatus::Pending as i32);
        assert_eq!(fetched.summary, "network access requires approval");
        assert!(!fetched.items.is_empty());

        let respond_response = controller.dispatch(RpcRequest {
            method: RpcMethod::RespondApproval as i32,
            payload: encode_message(&RespondApprovalRequest {
                session_id: created_session.session_id.clone(),
                approval_id: "approval-1".to_string(),
                decision: RpcApprovalDecision::Approve as i32,
                idempotency_key: "idem-approval-1".to_string(),
                reason: Some("approved".to_string()),
                client_instance_id: lease.client_instance_id,
                rebind_token: lease.rebind_token,
            }),
        });
        let respond_payload = match respond_response.outcome {
            Some(rpc_response::Outcome::Payload(payload)) => payload,
            other => panic!("expected payload response, got {other:?}"),
        };
        let responded = decode_message::<RespondApprovalResponse>(&respond_payload)
            .expect("decode respond approval response");
        assert_eq!(
            responded
                .approval
                .as_ref()
                .expect("approval must exist")
                .status,
            RpcApprovalStatus::Approved as i32
        );
        assert_eq!(
            responded.task.as_ref().expect("task must exist").status,
            TaskStatus::Pending as i32
        );

        let task = store
            .get_task(&created_session.session_id, "task-approval-1")
            .expect("task should exist");
        assert_eq!(task.status, DomainTaskStatus::Pending);

        let events = store
            .list_by_task(
                "task-approval-1",
                AuditCursor {
                    after_seq: None,
                    limit: 20,
                },
            )
            .expect("list task audit");
        assert!(
            events
                .iter()
                .any(|event| event.event_type == AuditEventType::ApprovalApproved)
        );
        assert!(
            events
                .iter()
                .any(|event| event.event_type == AuditEventType::InvocationResumedAfterApproval)
        );
    }

    #[test]
    fn unknown_method_returns_bad_request_error() {
        let store = Arc::new(Store::open(StoreOptions::in_memory()).expect("open store"));
        let controller = RpcController::new("daemon-1".to_string(), store);
        let response = controller.dispatch(RpcRequest {
            method: 9_999,
            payload: Vec::new(),
        });
        let error = match response.outcome {
            Some(rpc_response::Outcome::Error(error)) => error,
            other => panic!("expected error response, got {other:?}"),
        };
        assert_eq!(error.code, RpcErrorCode::BadRequest as i32);
    }
}
