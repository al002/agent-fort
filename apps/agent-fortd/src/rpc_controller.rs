use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use af_core::{
    CancelTaskInput, CreateSessionInput, CreateTaskInput, SessionAppError, SessionAppService,
    SessionConfig, TaskAppError, TaskAppService,
};
use af_rpc_proto::codec::{decode_message, encode_message};
use af_rpc_proto::{
    CancelTaskRequest, CancelTaskResponse, CreateSessionRequest, CreateSessionResponse,
    CreateTaskRequest, CreateTaskResponse, DaemonInfo, GetDaemonInfoRequest, GetDaemonInfoResponse,
    GetTaskRequest, GetTaskResponse, PingRequest, PingResponse, RpcError, RpcErrorCode, RpcMethod,
    RpcRequest, RpcResponse, Session, SessionLease, SessionStatus, Task, TaskCreatedBy, TaskStatus,
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
}

impl RpcController {
    pub fn new(daemon_instance_id: String, store: Arc<Store>) -> Self {
        let session_service = SessionAppService::new(store.clone(), SessionConfig::default());
        let task_service = TaskAppService::new(store.clone());
        Self {
            state: Arc::new(ControllerState {
                daemon_instance_id,
                store,
                session_service,
                task_service,
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
    use af_audit::{AuditCursor, AuditEventType, AuditRepository};
    use af_session::{NewSession, SessionLease, SessionRepository};
    use af_store::StoreOptions;
    use af_task::TaskRepository;

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
