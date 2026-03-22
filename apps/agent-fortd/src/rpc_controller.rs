use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use af_approval::ApprovalItem as DomainApprovalItem;
use af_audit::{AuditEventType, NewAuditEvent};
use af_core::{
    ApprovalAppError, ApprovalAppService, BackendSelector, CancelTaskInput, CapabilityDecision,
    CapabilityDelta, CapabilityExtractor, CapabilityGrantAppService, CapabilityPolicyEvaluator,
    CommandRuleEngine, CreateApprovalInput, CreateSessionInput, CreateTaskInput, EvaluationMode,
    GetApprovalInput, NormalizedCommand, OperationNormalizer, RawOperation, RequestedCapabilities,
    RespondApprovalInput, RuntimeCompiler, RuntimeContext, RuntimePlatform, SessionAppError,
    SessionAppService, SessionConfig, TaskAppError, TaskAppService, TaskExecutionAppService,
    capability_set_within_policy, intersect_requested_with_capabilities,
    requested_within_capabilities,
};
use af_policy::CapabilitySet;
use af_policy_infra::{ActivePolicy, SharedPolicyRuntime};
use af_rpc_proto::codec::{decode_message, encode_message};
use af_rpc_proto::task_outcome::Outcome as RpcTaskOutcome;
use af_rpc_proto::{
    Approval as RpcApproval, ApprovalDecision as RpcApprovalDecision,
    ApprovalItem as RpcApprovalItem, ApprovalStatus as RpcApprovalStatus, CancelTaskRequest,
    CancelTaskResponse, CreateSessionRequest, CreateSessionResponse, CreateTaskRequest,
    CreateTaskResponse, DaemonInfo, ExecutionEffect, ExecutionEffectKind, ExecutionResult,
    GetApprovalRequest, GetApprovalResponse, GetDaemonInfoRequest, GetDaemonInfoResponse,
    GetTaskRequest, GetTaskResponse, PendingApproval, PingRequest, PingResponse,
    RespondApprovalRequest, RespondApprovalResponse, RpcError, RpcErrorCode, RpcMethod, RpcRequest,
    RpcResponse, Session, SessionLease, SessionStatus, Task, TaskCreatedBy, TaskDenied,
    TaskOperation, TaskOutcome, TaskStatus, rpc_response,
};
use af_rpc_transport::{RpcConnection, TransportError};
use af_sandbox::{
    FilesystemMode, FilesystemPolicy, NetworkPolicy, OutputCapturePolicy, PtyPolicy,
    ResourceGovernanceMode, ResourceLimits, SandboxExecRequest, SandboxExecResult,
    SandboxExitStatus, SyscallPolicy, TraceContext, WritableRoot,
};
use af_session::{SessionRepository, SessionRepositoryError, SessionStatus as DomainSessionStatus};
use af_store::Store;
use af_task::{
    AdvanceTaskStepCommand, TaskCreatedBy as DomainTaskCreatedBy, TaskStatus as DomainTaskStatus,
    UpdateTaskStatusCommand,
};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::helper_client::HelperClient;

const APPROVAL_SNAPSHOT_SCHEMA_V2: &str = "task_approval_snapshot.v2";

mod authorization;
mod controller_exec;
mod conversion;
mod execution;
mod operation_codec;
mod response;
mod snapshot;
#[cfg(test)]
mod tests;

use self::authorization::*;
use self::conversion::*;
use self::execution::*;
use self::operation_codec::*;
use self::response::*;
use self::snapshot::*;

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
    task_execution_service: TaskExecutionAppService,
    approval_service: ApprovalAppService,
    capability_grant_service: CapabilityGrantAppService,
    execution_runtime: Option<ExecutionRuntime>,
}

#[derive(Debug, Clone)]
struct ExecutionRuntime {
    helper_client: HelperClient,
    policy_runtime: SharedPolicyRuntime,
    policy_dir: PathBuf,
    workspace_root: Option<PathBuf>,
    resource_governance_mode: ResourceGovernanceMode,
}

#[derive(Debug, Clone)]
struct SessionGrantState {
    revision: u64,
    capabilities: CapabilitySet,
}

#[derive(Debug, Clone)]
struct AllowExecutionPlan {
    normalized: af_core::NormalizedOperation,
    requested: RequestedCapabilities,
    effective: RequestedCapabilities,
    runtime_plan: af_core::RuntimeExecPlan,
    session_grant_revision: u64,
    policy_revision: u64,
}

#[derive(Debug, Clone)]
struct AskExecutionPlan {
    requested: RequestedCapabilities,
    delta: CapabilityDelta,
    reason: String,
    session_grant_revision: u64,
    policy_revision: u64,
}

#[derive(Debug, Clone)]
struct ApprovalSnapshot {
    operation: TaskOperation,
    session_grant_revision_before: u64,
    policy_revision: u64,
    delta: CapabilityDelta,
}

#[derive(Debug, Clone)]
enum AuthorizationResult {
    Allow(Box<AllowExecutionPlan>),
    Ask(Box<AskExecutionPlan>),
    Deny { reason: String, code: &'static str },
}

impl RpcController {
    pub fn new_with_execution(
        daemon_instance_id: String,
        store: Arc<Store>,
        helper_client: HelperClient,
        policy_runtime: SharedPolicyRuntime,
        policy_dir: PathBuf,
        workspace_root: Option<PathBuf>,
        resource_governance_mode: ResourceGovernanceMode,
    ) -> Self {
        Self::new_internal(
            daemon_instance_id,
            store,
            Some(ExecutionRuntime {
                helper_client,
                policy_runtime,
                policy_dir,
                workspace_root,
                resource_governance_mode,
            }),
        )
    }

    fn new_internal(
        daemon_instance_id: String,
        store: Arc<Store>,
        execution_runtime: Option<ExecutionRuntime>,
    ) -> Self {
        let session_service = SessionAppService::new(store.clone(), SessionConfig::default());
        let task_service = TaskAppService::new(store.clone());
        let task_execution_service = TaskExecutionAppService::new(store.clone());
        let approval_service = ApprovalAppService::new(store.clone());
        let capability_grant_service = CapabilityGrantAppService::new(store.clone());
        Self {
            state: Arc::new(ControllerState {
                daemon_instance_id,
                store,
                session_service,
                task_service,
                task_execution_service,
                approval_service,
                capability_grant_service,
                execution_runtime,
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
        loop {
            let request: RpcRequest = match connection.read_message().await {
                Ok(request) => request,
                Err(TransportError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            };

            let controller = self.clone();
            let response = tokio::task::spawn_blocking(move || -> Result<RpcResponse> {
                controller.state.store.ping()?;
                Ok(controller.dispatch(request))
            })
            .await
            .context("join rpc dispatch task")??;

            if let Err(error) = connection.write_message(&response).await {
                match error {
                    TransportError::Io(io_error)
                        if matches!(
                            io_error.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        return Ok(());
                    }
                    other => return Err(other.into()),
                }
            }
        }
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

        if let Some(response) = validate_task_operation(request.operation.as_ref()) {
            return response;
        }

        let CreateTaskRequest {
            session_id,
            client_instance_id,
            rebind_token,
            goal,
            operation,
        } = request;
        let Some(operation) = operation else {
            return err(
                RpcErrorCode::BadRequest,
                "create_task operation is required",
            );
        };

        if let Some(response) =
            self.ensure_session_access(&session_id, &client_instance_id, &rebind_token)
        {
            return response;
        }

        let created = self.state.task_service.create_task(CreateTaskInput {
            session_id,
            goal,
            created_by: DomainTaskCreatedBy::Explicit,
        });

        match created {
            Ok(task) => {
                let mut response_task = task;
                let mut outcome = None;
                if self.state.execution_runtime.is_some() {
                    match self.execute_single_step_task(response_task.clone(), operation) {
                        Ok((updated_task, task_outcome)) => {
                            response_task = updated_task;
                            outcome = Some(task_outcome);
                        }
                        Err(error_response) => return error_response,
                    }
                }

                ok(encode_message(&CreateTaskResponse {
                    task: Some(to_proto_task(response_task)),
                    outcome,
                }))
            }
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

        let mut task = task;
        let mut outcome = None;

        if responded.transition_applied {
            match responded.approval.status {
                af_approval::ApprovalStatus::Approved => {
                    if self.state.execution_runtime.is_some()
                        && task.status == af_task::TaskStatus::Pending
                    {
                        match self
                            .execute_approved_single_step_task(task.clone(), &responded.approval)
                        {
                            Ok((updated_task, task_outcome)) => {
                                task = updated_task;
                                outcome = Some(task_outcome);
                            }
                            Err(error_response) => return error_response,
                        }
                    }
                }
                af_approval::ApprovalStatus::Denied => {
                    outcome = Some(TaskOutcome {
                        outcome: Some(RpcTaskOutcome::Denied(TaskDenied {
                            code: Some("APPROVAL_DENIED".to_string()),
                            message: task.error_message.clone(),
                        })),
                    });
                }
                _ => {}
            }
        }

        ok(encode_message(&RespondApprovalResponse {
            approval: Some(to_proto_approval(responded.approval)),
            task: Some(to_proto_task(task)),
            outcome,
        }))
    }
}
