use std::sync::Arc;

use af_core::{CreateSessionInput, SessionAppError, SessionAppService, SessionConfig};
use af_rpc_proto::codec::{decode_message, encode_message};
use af_rpc_proto::{
    CreateSessionRequest, CreateSessionResponse, DaemonInfo, GetDaemonInfoRequest,
    GetDaemonInfoResponse, PingRequest, PingResponse, RpcError, RpcErrorCode, RpcMethod,
    RpcRequest, RpcResponse, Session, SessionLease, SessionStatus, rpc_response,
};
use af_rpc_transport::RpcConnection;
use af_store::Store;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct RpcController {
    state: Arc<ControllerState>,
}

#[derive(Debug)]
struct ControllerState {
    daemon_instance_id: String,
    store: Arc<Store>,
    session_service: SessionAppService,
}

impl RpcController {
    pub fn new(daemon_instance_id: String, store: Arc<Store>) -> Self {
        let session_service = SessionAppService::new(store.clone(), SessionConfig::default());
        Self {
            state: Arc::new(ControllerState {
                daemon_instance_id,
                store,
                session_service,
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
                ],
            }),
        }
    }

    pub async fn handle_connection(&self, mut connection: RpcConnection) -> Result<()> {
        let request: RpcRequest = connection.read_message().await?;
        self.state.store.ping()?;
        let response = self.dispatch(request);
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

#[cfg(test)]
mod tests {
    use super::*;
    use af_audit::{AuditCursor, AuditEventType, AuditRepository};
    use af_session::SessionRepository;
    use af_store::StoreOptions;

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
