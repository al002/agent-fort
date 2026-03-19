use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use af_approval::{
    ApprovalItem as DomainApprovalItem, ApprovalRepository, ApprovalStatus, NewApproval,
};
use af_audit::{AuditEventType, AuditRepository, NewAuditEvent};
use af_core::{
    ApprovalAppError, ApprovalAppService, CancelTaskInput, CreateSessionInput, CreateTaskInput,
    ExecutionContract, Fact, GetApprovalInput, OperationKind, OperationNormalizer,
    PolicyEvaluationTrace, PolicyEvaluator, RawOperation, RespondApprovalInput, RuntimeContext,
    RuntimePlatform, SessionAppError, SessionAppService, SessionConfig, TargetKind, TaskAppError,
    TaskAppService,
};
use af_policy::PolicyDecision;
use af_policy_infra::{CompiledPolicies, PolicyRuntime};
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
    BindMount, FilesystemMode, FilesystemPolicy, NetworkPolicy, OutputCapturePolicy, PtyPolicy,
    ResourceGovernanceMode, ResourceLimits, SandboxExecRequest, SandboxExecResult,
    SandboxExitStatus, SyscallPolicy, TraceContext, WritableRoot,
};
use af_session::{SessionRepository, SessionRepositoryError, SessionStatus as DomainSessionStatus};
use af_store::Store;
use af_task::{
    AdvanceTaskStepCommand, TaskCreatedBy as DomainTaskCreatedBy, TaskRepository,
    TaskStatus as DomainTaskStatus, UpdateTaskStatusCommand,
};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::helper_client::HelperClient;

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
    execution_runtime: Option<ExecutionRuntime>,
}

#[derive(Debug, Clone)]
struct ExecutionRuntime {
    helper_client: HelperClient,
    policy_runtime: Arc<Mutex<PolicyRuntime>>,
    policy_dir: PathBuf,
    workspace_root: Option<PathBuf>,
}

impl RpcController {
    pub fn new(daemon_instance_id: String, store: Arc<Store>) -> Self {
        Self::new_internal(daemon_instance_id, store, None)
    }

    pub fn new_with_execution(
        daemon_instance_id: String,
        store: Arc<Store>,
        helper_client: HelperClient,
        policy_runtime: Arc<Mutex<PolicyRuntime>>,
        policy_dir: PathBuf,
        workspace_root: Option<PathBuf>,
    ) -> Self {
        Self::new_internal(
            daemon_instance_id,
            store,
            Some(ExecutionRuntime {
                helper_client,
                policy_runtime,
                policy_dir,
                workspace_root,
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
        let approval_service = ApprovalAppService::new(store.clone());
        Self {
            state: Arc::new(ControllerState {
                daemon_instance_id,
                store,
                session_service,
                task_service,
                approval_service,
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
            limits_json,
            operation,
        } = request;
        let operation = operation.expect("operation validated above");

        if let Some(response) =
            self.ensure_session_access(&session_id, &client_instance_id, &rebind_token)
        {
            return response;
        }

        let created = self.state.task_service.create_task(CreateTaskInput {
            session_id,
            goal,
            limits_json,
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
                        let operation = match task_operation_from_approval_snapshot(
                            &responded.approval.execution_contract_json,
                        ) {
                            Ok(operation) => operation,
                            Err(error_response) => return error_response,
                        };
                        match self.execute_approved_single_step_task(
                            task.clone(),
                            operation,
                            &responded.approval,
                        ) {
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

    fn execute_single_step_task(
        &self,
        task: af_task::Task,
        operation: TaskOperation,
    ) -> Result<(af_task::Task, TaskOutcome), RpcResponse> {
        let runtime = self.state.execution_runtime.as_ref().ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "execution runtime not configured",
            )
        })?;

        let normalized =
            normalize_task_operation(&operation, runtime, &self.state.daemon_instance_id)?;
        let compiled = load_compiled_policies(runtime)?;
        let contract = PolicyEvaluator::default().evaluate(compiled.as_ref(), &normalized);

        match contract.decision {
            PolicyDecision::Allow => execute_allow_path(
                &self.state.store,
                runtime,
                task,
                &normalized,
                &operation,
                &contract,
            ),
            PolicyDecision::Ask => execute_ask_path(&self.state.store, task, &operation, &contract),
            PolicyDecision::Deny | PolicyDecision::Forbid => {
                execute_deny_path(&self.state.store, task, &contract)
            }
        }
    }

    fn execute_approved_single_step_task(
        &self,
        task: af_task::Task,
        operation: TaskOperation,
        approval: &af_approval::Approval,
    ) -> Result<(af_task::Task, TaskOutcome), RpcResponse> {
        let runtime = self.state.execution_runtime.as_ref().ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "execution runtime not configured",
            )
        })?;
        let normalized =
            normalize_task_operation(&operation, runtime, &self.state.daemon_instance_id)?;
        let contract = approved_execution_contract(approval);
        execute_allow_path(
            &self.state.store,
            runtime,
            task,
            &normalized,
            &operation,
            &contract,
        )
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

fn validate_task_operation(operation: Option<&af_rpc_proto::TaskOperation>) -> Option<RpcResponse> {
    let operation = match operation {
        Some(operation) => operation,
        None => {
            return Some(err(
                RpcErrorCode::BadRequest,
                "create_task operation is required",
            ));
        }
    };
    if operation.kind.trim().is_empty() {
        return Some(err(
            RpcErrorCode::BadRequest,
            "create_task operation.kind must not be empty",
        ));
    }
    None
}

fn normalize_task_operation(
    operation: &TaskOperation,
    runtime: &ExecutionRuntime,
    daemon_instance_id: &str,
) -> Result<af_core::NormalizedOperation, RpcResponse> {
    let labels = operation
        .labels
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let raw = RawOperation {
        kind: operation.kind.clone(),
        payload: struct_to_json(operation.payload.as_ref()),
        options: struct_to_json(operation.options.as_ref()),
        labels,
    };
    let runtime_context = RuntimeContext {
        platform: RuntimePlatform::Linux,
        daemon_instance_id: daemon_instance_id.to_string(),
        policy_dir: runtime.policy_dir.clone(),
        workspace_root: runtime.workspace_root.clone(),
    };
    OperationNormalizer
        .normalize(raw, runtime_context)
        .map_err(|error| {
            err(
                RpcErrorCode::BadRequest,
                format!("normalize operation failed: {error}"),
            )
        })
}

fn load_compiled_policies(
    runtime: &ExecutionRuntime,
) -> Result<Arc<CompiledPolicies>, RpcResponse> {
    let policy_runtime = runtime.policy_runtime.lock().map_err(|_| {
        err(
            RpcErrorCode::PolicyLoadFailed,
            "policy runtime lock poisoned",
        )
    })?;
    policy_runtime.compiled().map_err(|error| {
        err(
            RpcErrorCode::PolicyLoadFailed,
            format!("load policy failed: {error}"),
        )
    })
}

fn execute_allow_path(
    store: &Store,
    runtime: &ExecutionRuntime,
    task: af_task::Task,
    normalized: &af_core::NormalizedOperation,
    operation: &TaskOperation,
    contract: &af_core::ExecutionContract,
) -> Result<(af_task::Task, TaskOutcome), RpcResponse> {
    let running = transition_task_status(
        store,
        &task,
        Some(DomainTaskStatus::Pending),
        DomainTaskStatus::Running,
        None,
        None,
    )?;
    append_task_audit(
        store,
        AuditEventType::TaskStarted,
        &running,
        contract.policy_audit_payload_json().ok(),
        None,
    )?;

    let request = build_sandbox_request(runtime, &running, normalized, operation)?;
    let effects = build_execution_effects(normalized, &request.command);
    let mut execution = match runtime.helper_client.execute(request) {
        Ok(result) => execution_result_from_sandbox(result),
        Err(error) => failure_execution_result(error.to_string()),
    };
    execution.effects = effects;
    let finished_status = if execution.state == "completed" {
        DomainTaskStatus::Completed
    } else {
        DomainTaskStatus::Failed
    };
    let error_code = if finished_status == DomainTaskStatus::Failed {
        Some(if execution.timed_out {
            "EXEC_TIMEOUT".to_string()
        } else {
            "EXEC_FAILED".to_string()
        })
    } else {
        None
    };
    let error_message = if finished_status == DomainTaskStatus::Failed {
        Some(if execution.stderr.trim().is_empty() {
            "task execution failed".to_string()
        } else {
            execution.stderr.clone()
        })
    } else {
        None
    };

    let finished = transition_task_status(
        store,
        &running,
        Some(DomainTaskStatus::Running),
        finished_status,
        error_code.clone(),
        error_message,
    )?;
    let stepped = finalize_task_step(store, &finished)?;
    let event_type = if finished_status == DomainTaskStatus::Completed {
        AuditEventType::TaskCompleted
    } else {
        AuditEventType::TaskFailed
    };
    append_task_audit(
        store,
        event_type,
        &stepped,
        Some(execution_payload_json(&execution)),
        error_code,
    )?;

    Ok((
        stepped,
        TaskOutcome {
            outcome: Some(RpcTaskOutcome::Execution(execution)),
        },
    ))
}

fn execute_ask_path(
    store: &Store,
    task: af_task::Task,
    operation: &TaskOperation,
    contract: &af_core::ExecutionContract,
) -> Result<(af_task::Task, TaskOutcome), RpcResponse> {
    let blocked = transition_task_status(
        store,
        &task,
        Some(DomainTaskStatus::Pending),
        DomainTaskStatus::Blocked,
        None,
        None,
    )?;
    let now = now_ms();
    let approval_id = Uuid::new_v4().to_string();
    let expires_at_ms = now.saturating_add(5 * 60 * 1000);
    let summary = contract
        .approval
        .as_ref()
        .map(|approval| approval.summary.clone())
        .or_else(|| contract.reason.clone())
        .unwrap_or_else(|| "approval required".to_string());
    let details = contract
        .approval
        .as_ref()
        .and_then(|approval| approval.details.clone());
    let items = contract
        .approval
        .as_ref()
        .map(|approval| {
            approval
                .items
                .iter()
                .map(|item| DomainApprovalItem {
                    kind: item.kind.clone(),
                    target: item.target.clone(),
                    summary: item.summary.clone(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let policy_reason = contract
        .reason
        .clone()
        .unwrap_or_else(|| "policy requires approval".to_string());
    let execution_contract_json = approval_snapshot_json(contract, operation);

    let created_approval = store
        .create_approval(NewApproval {
            approval_id: approval_id.clone(),
            session_id: blocked.session_id.clone(),
            task_id: blocked.task_id.clone(),
            trace_id: blocked.trace_id.clone(),
            status: ApprovalStatus::Pending,
            summary: summary.clone(),
            details: details.clone(),
            items,
            policy_reason,
            policy_revision: contract.policy_revision,
            execution_contract_json,
            created_at_ms: now,
            expires_at_ms,
        })
        .map_err(map_approval_repo_error)?;

    append_task_audit(
        store,
        AuditEventType::ApprovalCreated,
        &blocked,
        Some(
            json!({
                "approval_id": created_approval.approval_id,
                "summary": created_approval.summary,
                "expires_at_ms": created_approval.expires_at_ms
            })
            .to_string(),
        ),
        None,
    )?;
    append_task_audit(
        store,
        AuditEventType::TaskAwaitingApproval,
        &blocked,
        contract.policy_audit_payload_json().ok(),
        None,
    )?;

    Ok((
        blocked,
        TaskOutcome {
            outcome: Some(RpcTaskOutcome::Approval(PendingApproval {
                approval_id,
                status: to_proto_approval_status(created_approval.status) as i32,
                expires_at_ms,
                task_id: created_approval.task_id,
                summary,
            })),
        },
    ))
}

fn execute_deny_path(
    store: &Store,
    task: af_task::Task,
    contract: &af_core::ExecutionContract,
) -> Result<(af_task::Task, TaskOutcome), RpcResponse> {
    let message = contract
        .reason
        .clone()
        .unwrap_or_else(|| "policy denied task".to_string());
    let failed = transition_task_status(
        store,
        &task,
        Some(DomainTaskStatus::Pending),
        DomainTaskStatus::Failed,
        Some("POLICY_DENIED".to_string()),
        Some(message.clone()),
    )?;
    let stepped = finalize_task_step(store, &failed)?;
    append_task_audit(
        store,
        AuditEventType::PolicyDenied,
        &stepped,
        contract.policy_audit_payload_json().ok(),
        Some("POLICY_DENIED".to_string()),
    )?;
    append_task_audit(
        store,
        AuditEventType::TaskFailed,
        &stepped,
        Some(json!({ "reason": message }).to_string()),
        Some("POLICY_DENIED".to_string()),
    )?;

    Ok((
        stepped,
        TaskOutcome {
            outcome: Some(RpcTaskOutcome::Denied(TaskDenied {
                code: Some("POLICY_DENIED".to_string()),
                message: contract.reason.clone(),
            })),
        },
    ))
}

fn transition_task_status(
    store: &Store,
    task: &af_task::Task,
    expected_status: Option<DomainTaskStatus>,
    next_status: DomainTaskStatus,
    error_code: Option<String>,
    error_message: Option<String>,
) -> Result<af_task::Task, RpcResponse> {
    let terminal = matches!(
        next_status,
        DomainTaskStatus::Completed | DomainTaskStatus::Failed | DomainTaskStatus::Cancelled
    );
    store
        .update_task_status(UpdateTaskStatusCommand {
            session_id: task.session_id.clone(),
            task_id: task.task_id.clone(),
            expected_status,
            new_status: next_status,
            updated_at_ms: now_ms(),
            ended_at_ms: terminal.then(now_ms),
            error_code,
            error_message,
        })
        .map_err(map_task_repo_error)
}

fn finalize_task_step(store: &Store, task: &af_task::Task) -> Result<af_task::Task, RpcResponse> {
    if task.current_step >= 1 {
        return Ok(task.clone());
    }
    store
        .advance_task_step(AdvanceTaskStepCommand {
            session_id: task.session_id.clone(),
            task_id: task.task_id.clone(),
            expected_current_step: task.current_step,
            next_step: 1,
            updated_at_ms: now_ms(),
        })
        .map_err(map_task_repo_error)
}

fn append_task_audit(
    store: &Store,
    event_type: AuditEventType,
    task: &af_task::Task,
    payload_json: Option<String>,
    error_code: Option<String>,
) -> Result<(), RpcResponse> {
    store
        .append_event(NewAuditEvent {
            ts_ms: now_ms(),
            trace_id: task.trace_id.clone(),
            session_id: Some(task.session_id.clone()),
            task_id: Some(task.task_id.clone()),
            event_type,
            payload_json,
            error_code,
        })
        .map_err(map_audit_repo_error)?;
    Ok(())
}

fn build_sandbox_request(
    runtime: &ExecutionRuntime,
    task: &af_task::Task,
    normalized: &af_core::NormalizedOperation,
    operation: &TaskOperation,
) -> Result<SandboxExecRequest, RpcResponse> {
    let payload = struct_to_json(operation.payload.as_ref());
    let options = struct_to_json(operation.options.as_ref());
    let sandbox_root = default_sandbox_root(runtime.workspace_root.as_deref())?;
    let command = extract_command(&payload, &options)?;
    let cwd = extract_cwd(&payload, &options, sandbox_root.as_path())?;
    let env = extract_env(&payload, &options)?;
    let parsed_limits = parse_limits_json_value(task.limits_json.as_deref())?;
    let limits = parse_resource_limits(parsed_limits.as_ref());
    let capture = parse_capture_policy(parsed_limits.as_ref());
    let sandbox_overrides = parse_sandbox_overrides(parsed_limits.as_ref())?;
    let default_network = default_network_policy_for_operation(normalized);
    let network = sandbox_overrides.network.unwrap_or(default_network);
    let filesystem_mode = sandbox_overrides
        .filesystem_mode
        .unwrap_or(FilesystemMode::Restricted);
    let include_platform_defaults = sandbox_overrides.include_platform_defaults.unwrap_or(true);
    let mount_proc = sandbox_overrides.mount_proc.unwrap_or(true);
    let governance_mode = sandbox_overrides
        .governance_mode
        .unwrap_or(ResourceGovernanceMode::BestEffort);
    let syscall_policy = sandbox_overrides
        .syscall_policy
        .unwrap_or(SyscallPolicy::Baseline);

    Ok(SandboxExecRequest {
        command,
        cwd,
        env,
        filesystem: FilesystemPolicy {
            mode: filesystem_mode,
            include_platform_defaults,
            mount_proc,
            readable_roots: Vec::new(),
            writable_roots: vec![WritableRoot {
                root: sandbox_root,
                read_only_subpaths: Vec::new(),
            }],
            mounts: sandbox_overrides.mounts,
            unreadable_roots: Vec::new(),
        },
        network,
        pty: PtyPolicy::Disabled,
        limits,
        governance_mode,
        syscall_policy,
        capture,
        trace: TraceContext {
            session_id: Some(task.session_id.clone()),
            task_id: Some(task.task_id.clone()),
            trace_id: Some(task.trace_id.clone()),
        },
    })
}

fn default_network_policy_for_operation(
    normalized: &af_core::NormalizedOperation,
) -> NetworkPolicy {
    if matches!(normalized.facts.network_access, Fact::Known(true)) {
        NetworkPolicy::Full
    } else {
        NetworkPolicy::Disabled
    }
}

fn parse_limits_json_value(raw: Option<&str>) -> Result<Option<Value>, RpcResponse> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let parsed = serde_json::from_str::<Value>(raw).map_err(|error| {
        err(
            RpcErrorCode::BadRequest,
            format!("limits_json parse failed: {error}"),
        )
    })?;
    Ok(Some(parsed))
}

fn parse_resource_limits(parsed: Option<&Value>) -> ResourceLimits {
    let mut limits = ResourceLimits::default();
    let Some(parsed) = parsed else {
        return limits;
    };
    if let Some(value) = find_u64(&parsed, "wall_timeout_secs") {
        limits.wall_timeout = Duration::from_secs(value.max(1));
    }
    if let Some(value) = find_u64(&parsed, "wall_timeout_ms") {
        limits.wall_timeout = Duration::from_millis(value.max(1));
    }
    limits.cpu_time_limit_seconds = find_u64(&parsed, "cpu_time_limit_seconds");
    limits.max_memory_bytes = find_u64(&parsed, "max_memory_bytes");
    limits.max_processes = find_u64(&parsed, "max_processes");
    limits.max_file_size_bytes = find_u64(&parsed, "max_file_size_bytes");
    limits.cpu_max_percent =
        find_u64(&parsed, "cpu_max_percent").and_then(|value| u32::try_from(value).ok());
    limits
}

fn parse_capture_policy(parsed: Option<&Value>) -> OutputCapturePolicy {
    let mut capture = OutputCapturePolicy::default();
    let Some(parsed) = parsed else {
        return capture;
    };
    if let Some(value) =
        find_u64(&parsed, "stdout_max_bytes").and_then(|value| usize::try_from(value).ok())
    {
        capture.stdout_max_bytes = value.max(1);
    }
    if let Some(value) =
        find_u64(&parsed, "stderr_max_bytes").and_then(|value| usize::try_from(value).ok())
    {
        capture.stderr_max_bytes = value.max(1);
    }
    capture
}

#[derive(Debug, Clone, Default)]
struct SandboxOverrides {
    network: Option<NetworkPolicy>,
    filesystem_mode: Option<FilesystemMode>,
    include_platform_defaults: Option<bool>,
    mount_proc: Option<bool>,
    mounts: Vec<BindMount>,
    governance_mode: Option<ResourceGovernanceMode>,
    syscall_policy: Option<SyscallPolicy>,
}

fn parse_sandbox_overrides(parsed: Option<&Value>) -> Result<SandboxOverrides, RpcResponse> {
    let Some(root) = parsed else {
        return Ok(SandboxOverrides::default());
    };
    let Some(root_object) = root.as_object() else {
        return Err(err(
            RpcErrorCode::BadRequest,
            "limits_json must be a JSON object",
        ));
    };

    let Some(sandbox) = root_object.get("sandbox") else {
        return Ok(SandboxOverrides::default());
    };
    let Some(sandbox_object) = sandbox.as_object() else {
        return Err(err(
            RpcErrorCode::BadRequest,
            "limits_json.sandbox must be a JSON object",
        ));
    };

    let mut overrides = SandboxOverrides::default();
    if let Some(value) = sandbox_object.get("network") {
        let text = value.as_str().ok_or_else(|| {
            err(
                RpcErrorCode::BadRequest,
                "limits_json.sandbox.network must be a string",
            )
        })?;
        overrides.network = Some(parse_network_policy(text)?);
    }
    if let Some(value) = sandbox_object.get("filesystem_mode") {
        let text = value.as_str().ok_or_else(|| {
            err(
                RpcErrorCode::BadRequest,
                "limits_json.sandbox.filesystem_mode must be a string",
            )
        })?;
        overrides.filesystem_mode = Some(parse_filesystem_mode(text)?);
    }
    if let Some(value) = sandbox_object.get("include_platform_defaults") {
        let flag = value.as_bool().ok_or_else(|| {
            err(
                RpcErrorCode::BadRequest,
                "limits_json.sandbox.include_platform_defaults must be a boolean",
            )
        })?;
        overrides.include_platform_defaults = Some(flag);
    }
    if let Some(value) = sandbox_object.get("mount_proc") {
        let flag = value.as_bool().ok_or_else(|| {
            err(
                RpcErrorCode::BadRequest,
                "limits_json.sandbox.mount_proc must be a boolean",
            )
        })?;
        overrides.mount_proc = Some(flag);
    }
    if let Some(value) = sandbox_object.get("mounts") {
        overrides.mounts = parse_sandbox_mounts(value)?;
    }
    if let Some(value) = sandbox_object.get("governance_mode") {
        let text = value.as_str().ok_or_else(|| {
            err(
                RpcErrorCode::BadRequest,
                "limits_json.sandbox.governance_mode must be a string",
            )
        })?;
        overrides.governance_mode = Some(parse_governance_mode(text)?);
    }
    if let Some(value) = sandbox_object.get("syscall_policy") {
        let text = value.as_str().ok_or_else(|| {
            err(
                RpcErrorCode::BadRequest,
                "limits_json.sandbox.syscall_policy must be a string",
            )
        })?;
        overrides.syscall_policy = Some(parse_syscall_policy(text)?);
    }

    Ok(overrides)
}

fn parse_sandbox_mounts(value: &Value) -> Result<Vec<BindMount>, RpcResponse> {
    let mounts = value.as_array().ok_or_else(|| {
        err(
            RpcErrorCode::BadRequest,
            "limits_json.sandbox.mounts must be an array",
        )
    })?;
    let mut parsed = Vec::with_capacity(mounts.len());
    for (index, mount) in mounts.iter().enumerate() {
        let mount_obj = mount.as_object().ok_or_else(|| {
            err(
                RpcErrorCode::BadRequest,
                format!("limits_json.sandbox.mounts[{index}] must be an object"),
            )
        })?;
        let source = mount_obj
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                err(
                    RpcErrorCode::BadRequest,
                    format!(
                        "limits_json.sandbox.mounts[{index}].source must be a non-empty string"
                    ),
                )
            })?;
        if source.trim().is_empty() {
            return Err(err(
                RpcErrorCode::BadRequest,
                format!("limits_json.sandbox.mounts[{index}].source must not be empty"),
            ));
        }
        if !Path::new(source).is_absolute() {
            return Err(err(
                RpcErrorCode::BadRequest,
                format!("limits_json.sandbox.mounts[{index}].source must be an absolute path"),
            ));
        }
        let target = mount_obj
            .get("target")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                err(
                    RpcErrorCode::BadRequest,
                    format!(
                        "limits_json.sandbox.mounts[{index}].target must be a non-empty string"
                    ),
                )
            })?;
        if target.trim().is_empty() {
            return Err(err(
                RpcErrorCode::BadRequest,
                format!("limits_json.sandbox.mounts[{index}].target must not be empty"),
            ));
        }
        if !Path::new(target).is_absolute() {
            return Err(err(
                RpcErrorCode::BadRequest,
                format!("limits_json.sandbox.mounts[{index}].target must be an absolute path"),
            ));
        }
        let read_only = match mount_obj.get("read_only") {
            Some(raw) => raw.as_bool().ok_or_else(|| {
                err(
                    RpcErrorCode::BadRequest,
                    format!("limits_json.sandbox.mounts[{index}].read_only must be a boolean"),
                )
            })?,
            None => true,
        };
        parsed.push(BindMount {
            source: PathBuf::from(source),
            target: PathBuf::from(target),
            read_only,
        });
    }
    Ok(parsed)
}

fn parse_network_policy(value: &str) -> Result<NetworkPolicy, RpcResponse> {
    match value.trim().to_ascii_lowercase().as_str() {
        "disabled" => Ok(NetworkPolicy::Disabled),
        "full" => Ok(NetworkPolicy::Full),
        _ => Err(err(
            RpcErrorCode::BadRequest,
            format!("unsupported limits_json.sandbox.network `{value}`; expected disabled|full"),
        )),
    }
}

fn parse_filesystem_mode(value: &str) -> Result<FilesystemMode, RpcResponse> {
    match value.trim().to_ascii_lowercase().as_str() {
        "restricted" => Ok(FilesystemMode::Restricted),
        "read_only" | "readonly" | "read-only" => Ok(FilesystemMode::ReadOnly),
        "full_access" | "full-access" => Ok(FilesystemMode::FullAccess),
        _ => Err(err(
            RpcErrorCode::BadRequest,
            format!(
                "unsupported limits_json.sandbox.filesystem_mode `{value}`; expected restricted|read_only|full_access"
            ),
        )),
    }
}

fn parse_governance_mode(value: &str) -> Result<ResourceGovernanceMode, RpcResponse> {
    match value.trim().to_ascii_lowercase().as_str() {
        "required" => Ok(ResourceGovernanceMode::Required),
        "best_effort" | "best-effort" => Ok(ResourceGovernanceMode::BestEffort),
        "disabled" => Ok(ResourceGovernanceMode::Disabled),
        _ => Err(err(
            RpcErrorCode::BadRequest,
            format!(
                "unsupported limits_json.sandbox.governance_mode `{value}`; expected required|best_effort|disabled"
            ),
        )),
    }
}

fn parse_syscall_policy(value: &str) -> Result<SyscallPolicy, RpcResponse> {
    match value.trim().to_ascii_lowercase().as_str() {
        "baseline" => Ok(SyscallPolicy::Baseline),
        "unconfined" => Ok(SyscallPolicy::Unconfined),
        _ => Err(err(
            RpcErrorCode::BadRequest,
            format!(
                "unsupported limits_json.sandbox.syscall_policy `{value}`; expected baseline|unconfined"
            ),
        )),
    }
}

fn extract_command(payload: &Value, options: &Value) -> Result<Vec<String>, RpcResponse> {
    let value = payload
        .as_object()
        .and_then(|object| object.get("command"))
        .or_else(|| options.as_object().and_then(|object| object.get("command")));

    let Some(value) = value else {
        return Err(err(
            RpcErrorCode::BadRequest,
            "task operation payload/options.command is required",
        ));
    };
    match value {
        Value::String(command) => {
            if command.trim().is_empty() {
                return Err(err(
                    RpcErrorCode::BadRequest,
                    "task operation command string must not be empty",
                ));
            }
            Ok(vec![
                "/bin/sh".to_string(),
                "-lc".to_string(),
                command.to_string(),
            ])
        }
        Value::Array(parts) => {
            let command = parts
                .iter()
                .map(|part| {
                    part.as_str().map(ToString::to_string).ok_or_else(|| {
                        err(
                            RpcErrorCode::BadRequest,
                            "task operation command array must contain only strings",
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if command.is_empty() || command[0].trim().is_empty() {
                return Err(err(
                    RpcErrorCode::BadRequest,
                    "task operation command array must contain a non-empty command[0]",
                ));
            }
            Ok(command)
        }
        _ => Err(err(
            RpcErrorCode::BadRequest,
            "task operation command must be string or string[]",
        )),
    }
}

fn extract_cwd(
    payload: &Value,
    options: &Value,
    default_cwd: &Path,
) -> Result<PathBuf, RpcResponse> {
    let cwd = payload
        .as_object()
        .and_then(|object| object.get("cwd"))
        .and_then(Value::as_str)
        .or_else(|| {
            options
                .as_object()
                .and_then(|object| object.get("cwd"))
                .and_then(Value::as_str)
        })
        .map(PathBuf::from)
        .unwrap_or_else(|| default_cwd.to_path_buf());

    let resolved = if cwd.is_absolute() {
        cwd
    } else {
        default_cwd.join(cwd)
    };
    if !resolved.is_absolute() {
        return Err(err(
            RpcErrorCode::BadRequest,
            format!("resolved cwd must be absolute: {}", resolved.display()),
        ));
    }
    Ok(resolved)
}

fn default_sandbox_root(workspace_root: Option<&Path>) -> Result<PathBuf, RpcResponse> {
    let candidate = workspace_root
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("/"));

    let resolved = if candidate.is_absolute() {
        candidate
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(candidate)
    };

    if !resolved.is_absolute() {
        return Err(err(
            RpcErrorCode::BadRequest,
            format!(
                "default sandbox root must be absolute: {}",
                resolved.display()
            ),
        ));
    }

    Ok(resolved)
}

fn extract_env(payload: &Value, options: &Value) -> Result<BTreeMap<String, String>, RpcResponse> {
    let env_value = payload
        .as_object()
        .and_then(|object| object.get("env"))
        .or_else(|| options.as_object().and_then(|object| object.get("env")));
    let Some(env_value) = env_value else {
        return Ok(BTreeMap::new());
    };
    let object = env_value.as_object().ok_or_else(|| {
        err(
            RpcErrorCode::BadRequest,
            "task operation env must be an object of string values",
        )
    })?;
    object
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_string()))
                .ok_or_else(|| {
                    err(
                        RpcErrorCode::BadRequest,
                        format!("task operation env value must be string: key={key}"),
                    )
                })
        })
        .collect()
}

fn build_execution_effects(
    normalized: &af_core::NormalizedOperation,
    command: &[String],
) -> Vec<ExecutionEffect> {
    let mut effects = Vec::new();
    let mut seen = BTreeSet::<(i32, String)>::new();

    let write_from_paths = matches!(
        normalized.intent.kind,
        OperationKind::FileWrite | OperationKind::FilePatch
    ) || (matches!(normalized.intent.kind, OperationKind::Fetch)
        && any_file_write(normalized));

    if matches!(normalized.intent.kind, OperationKind::FileRead) {
        for path in &normalized.facts.affected_paths {
            push_execution_effect(
                &mut effects,
                &mut seen,
                ExecutionEffectKind::FileRead,
                path.display().to_string(),
            );
        }
    } else if write_from_paths {
        for path in &normalized.facts.affected_paths {
            push_execution_effect(
                &mut effects,
                &mut seen,
                ExecutionEffectKind::FileWrite,
                path.display().to_string(),
            );
        }
    }

    if matches!(normalized.facts.network_access, Fact::Known(true)) {
        let mut hosts = normalized
            .intent
            .targets
            .iter()
            .filter(|target| target.kind == TargetKind::Host)
            .map(|target| target.value.clone())
            .collect::<Vec<_>>();
        if let Fact::Known(host) = normalized.facts.primary_host.as_ref() {
            hosts.push(host.to_string());
        }
        if hosts.is_empty() {
            push_execution_effect(
                &mut effects,
                &mut seen,
                ExecutionEffectKind::NetworkEgress,
                "*".to_string(),
            );
        } else {
            for host in hosts {
                push_execution_effect(
                    &mut effects,
                    &mut seen,
                    ExecutionEffectKind::NetworkEgress,
                    host,
                );
            }
        }
    }

    let command_target = normalized
        .intent
        .targets
        .iter()
        .find(|target| target.kind == TargetKind::Path)
        .map(|target| target.value.clone())
        .or_else(|| command.first().cloned());
    if let Some(command_target) = command_target {
        push_execution_effect(
            &mut effects,
            &mut seen,
            ExecutionEffectKind::ProcessExec,
            command_target,
        );
    }

    effects
}

fn push_execution_effect(
    effects: &mut Vec<ExecutionEffect>,
    seen: &mut BTreeSet<(i32, String)>,
    kind: ExecutionEffectKind,
    target: String,
) {
    if target.trim().is_empty() {
        return;
    }
    let key = (kind as i32, target.clone());
    if seen.insert(key) {
        effects.push(ExecutionEffect {
            kind: kind as i32,
            target,
        });
    }
}

fn any_file_write(normalized: &af_core::NormalizedOperation) -> bool {
    matches!(normalized.facts.safe_file_write, Fact::Known(true))
        || matches!(normalized.facts.system_file_write, Fact::Known(true))
}

fn execution_result_from_sandbox(result: SandboxExecResult) -> ExecutionResult {
    let state = if result.timed_out {
        "timed_out".to_string()
    } else if matches!(result.status, SandboxExitStatus::Exited) && result.exit_code == Some(0) {
        "completed".to_string()
    } else {
        "failed".to_string()
    };
    ExecutionResult {
        state,
        exit_code: result.exit_code,
        timed_out: result.timed_out,
        stdout: result.stdout,
        stderr: result.stderr,
        stdout_truncated: result.stdout_truncated,
        stderr_truncated: result.stderr_truncated,
        effects: Vec::new(),
    }
}

fn failure_execution_result(message: String) -> ExecutionResult {
    ExecutionResult {
        state: "failed".to_string(),
        exit_code: None,
        timed_out: false,
        stdout: String::new(),
        stderr: message,
        stdout_truncated: false,
        stderr_truncated: false,
        effects: Vec::new(),
    }
}

fn execution_payload_json(result: &ExecutionResult) -> String {
    json!({
        "state": result.state,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
    })
    .to_string()
}

fn approval_snapshot_json(
    contract: &af_core::ExecutionContract,
    operation: &TaskOperation,
) -> String {
    json!({
        "schema": "task_approval_snapshot.v1",
        "contract": contract.policy_audit_payload(),
        "operation": task_operation_to_json(operation),
    })
    .to_string()
}

fn approved_execution_contract(approval: &af_approval::Approval) -> ExecutionContract {
    let (candidate_rule_count, matched_rule_ids) =
        approval_snapshot_trace(&approval.execution_contract_json);

    ExecutionContract {
        decision: PolicyDecision::Allow,
        reason: Some("approved by user response".to_string()),
        runtime_backend: Some("sandbox".to_string()),
        requirements: Vec::new(),
        approval: None,
        policy_revision: approval.policy_revision,
        matched_rule: None,
        evaluation_trace: PolicyEvaluationTrace::new(candidate_rule_count, matched_rule_ids),
        fail_closed: false,
    }
}

fn approval_snapshot_trace(raw: &str) -> (usize, Vec<String>) {
    let Ok(parsed) = serde_json::from_str::<Value>(raw) else {
        return (0, Vec::new());
    };
    let contract = parsed
        .as_object()
        .and_then(|obj| obj.get("contract"))
        .and_then(Value::as_object);
    let Some(contract) = contract else {
        return (0, Vec::new());
    };

    let candidate_rule_count = contract
        .get("candidate_rule_count")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(0);

    let matched_rule_ids = contract
        .get("matched_rule_ids")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    (candidate_rule_count, matched_rule_ids)
}

fn task_operation_from_approval_snapshot(raw: &str) -> Result<TaskOperation, RpcResponse> {
    let parsed = serde_json::from_str::<Value>(raw).map_err(|error| {
        err(
            RpcErrorCode::InternalError,
            format!("approval snapshot parse failed: {error}"),
        )
    })?;
    let object = parsed.as_object().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot must be a JSON object",
        )
    })?;
    let schema = object
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot missing schema",
            )
        })?;
    if schema != "task_approval_snapshot.v1" {
        return Err(err(
            RpcErrorCode::InternalError,
            format!("unsupported approval snapshot schema: {schema}"),
        ));
    }
    let operation_value = object.get("operation").ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot missing operation payload",
        )
    })?;
    task_operation_from_json(operation_value)
}

fn task_operation_to_json(operation: &TaskOperation) -> Value {
    json!({
        "kind": operation.kind,
        "payload": struct_to_json(operation.payload.as_ref()),
        "options": struct_to_json(operation.options.as_ref()),
        "labels": operation.labels,
    })
}

fn task_operation_from_json(value: &Value) -> Result<TaskOperation, RpcResponse> {
    let object = value.as_object().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot operation must be object",
        )
    })?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
        .ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot operation.kind must not be empty",
            )
        })?;

    let payload = maybe_json_to_prost_struct(object.get("payload"))?;
    let options = maybe_json_to_prost_struct(object.get("options"))?;
    let labels = object
        .get("labels")
        .and_then(Value::as_object)
        .map(|labels| {
            labels
                .iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|value| (key.clone(), value.to_string()))
                        .ok_or_else(|| {
                            err(
                                RpcErrorCode::InternalError,
                                format!(
                                    "approval snapshot operation.labels must be string map: key={key}"
                                ),
                            )
                        })
                })
                .collect::<Result<HashMap<_, _>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(TaskOperation {
        kind: kind.to_string(),
        payload,
        options,
        labels,
    })
}

fn maybe_json_to_prost_struct(
    value: Option<&Value>,
) -> Result<Option<prost_types::Struct>, RpcResponse> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(json_to_prost_struct(value)?)),
    }
}

fn json_to_prost_struct(value: &Value) -> Result<prost_types::Struct, RpcResponse> {
    let object = value.as_object().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "operation payload/options must be object",
        )
    })?;
    let fields = object
        .iter()
        .map(|(key, value)| (key.clone(), json_to_proto_value(value)))
        .collect::<BTreeMap<_, _>>();
    Ok(prost_types::Struct { fields })
}

fn json_to_proto_value(value: &Value) -> prost_types::Value {
    match value {
        Value::Null => prost_types::Value {
            kind: Some(prost_types::value::Kind::NullValue(0)),
        },
        Value::Bool(flag) => prost_types::Value {
            kind: Some(prost_types::value::Kind::BoolValue(*flag)),
        },
        Value::Number(number) => prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(
                number.as_f64().unwrap_or_default(),
            )),
        },
        Value::String(text) => prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(text.clone())),
        },
        Value::Array(list) => prost_types::Value {
            kind: Some(prost_types::value::Kind::ListValue(
                prost_types::ListValue {
                    values: list.iter().map(json_to_proto_value).collect(),
                },
            )),
        },
        Value::Object(object) => prost_types::Value {
            kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                fields: object
                    .iter()
                    .map(|(key, value)| (key.clone(), json_to_proto_value(value)))
                    .collect(),
            })),
        },
    }
}

fn struct_to_json(value: Option<&prost_types::Struct>) -> Value {
    let Some(value) = value else {
        return Value::Object(Default::default());
    };
    let map = value
        .fields
        .iter()
        .map(|(key, value)| (key.clone(), proto_value_to_json(value)))
        .collect::<serde_json::Map<String, Value>>();
    Value::Object(map)
}

fn proto_value_to_json(value: &prost_types::Value) -> Value {
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::NullValue(_)) | None => Value::Null,
        Some(prost_types::value::Kind::NumberValue(number)) => json!(number),
        Some(prost_types::value::Kind::StringValue(text)) => Value::String(text.clone()),
        Some(prost_types::value::Kind::BoolValue(flag)) => Value::Bool(*flag),
        Some(prost_types::value::Kind::StructValue(object)) => {
            let map = object
                .fields
                .iter()
                .map(|(key, value)| (key.clone(), proto_value_to_json(value)))
                .collect::<serde_json::Map<String, Value>>();
            Value::Object(map)
        }
        Some(prost_types::value::Kind::ListValue(list)) => Value::Array(
            list.values
                .iter()
                .map(proto_value_to_json)
                .collect::<Vec<_>>(),
        ),
    }
}

fn find_u64(value: &Value, key: &str) -> Option<u64> {
    value
        .as_object()
        .and_then(|object| object.get(key))
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.parse::<u64>().ok(),
            _ => None,
        })
}

fn map_task_repo_error(error: af_task::TaskRepositoryError) -> RpcResponse {
    match error {
        af_task::TaskRepositoryError::NotFound { .. } => {
            err(RpcErrorCode::TaskNotFound, "task not found")
        }
        af_task::TaskRepositoryError::Validation { message } => {
            err(RpcErrorCode::BadRequest, message)
        }
        af_task::TaskRepositoryError::InvalidState { message }
        | af_task::TaskRepositoryError::Conflict { message } => {
            err(RpcErrorCode::InvalidTaskState, message)
        }
        af_task::TaskRepositoryError::AlreadyExists { .. }
        | af_task::TaskRepositoryError::Storage { .. } => err(
            RpcErrorCode::StoreError,
            format!("task repository failed: {error}"),
        ),
    }
}

fn map_approval_repo_error(error: af_approval::ApprovalRepositoryError) -> RpcResponse {
    match error {
        af_approval::ApprovalRepositoryError::Validation { message } => {
            err(RpcErrorCode::BadRequest, message)
        }
        af_approval::ApprovalRepositoryError::AlreadyExists { .. }
        | af_approval::ApprovalRepositoryError::Conflict { .. }
        | af_approval::ApprovalRepositoryError::Storage { .. }
        | af_approval::ApprovalRepositoryError::NotFound { .. }
        | af_approval::ApprovalRepositoryError::Expired { .. }
        | af_approval::ApprovalRepositoryError::IdempotencyConflict { .. }
        | af_approval::ApprovalRepositoryError::InvalidState { .. } => err(
            RpcErrorCode::StoreError,
            format!("approval repository failed: {error}"),
        ),
    }
}

fn map_audit_repo_error(error: af_audit::AuditRepositoryError) -> RpcResponse {
    err(
        RpcErrorCode::AuditWriteFailed,
        format!("audit repository failed: {error}"),
    )
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
    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;

    use super::*;
    use af_approval::{ApprovalItem, ApprovalRepository, ApprovalStatus, NewApproval};
    use af_audit::{AuditCursor, AuditEventType, AuditRepository};
    use af_core::{
        Facts, Intent, NormalizedOperation, OperationKind, RuntimeContext, Target, TargetKind,
    };
    use af_rpc_transport::{Endpoint, RpcClient, RpcServer};
    use af_session::{NewSession, SessionLease, SessionRepository};
    use af_store::StoreOptions;
    use af_task::{NewTask, TaskCreatedBy, TaskRepository, TaskStatus as DomainTaskStatus};
    use tempfile::TempDir;

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
                operation: Some(test_task_operation()),
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
                operation: Some(test_task_operation()),
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
    fn create_task_rejects_missing_operation() {
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
        let lease = created_session.lease.expect("lease must exist");

        let response = controller.dispatch(RpcRequest {
            method: RpcMethod::CreateTask as i32,
            payload: encode_message(&CreateTaskRequest {
                session_id: created_session.session_id,
                client_instance_id: lease.client_instance_id,
                rebind_token: lease.rebind_token,
                goal: None,
                limits_json: None,
                operation: None,
            }),
        });

        let error = match response.outcome {
            Some(rpc_response::Outcome::Error(error)) => error,
            other => panic!("expected error response, got {other:?}"),
        };
        assert_eq!(error.code, RpcErrorCode::BadRequest as i32);
        assert!(error.message.contains("operation"));
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
                created_by: TaskCreatedBy::Explicit,
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
                execution_contract_json: test_approval_snapshot_json(),
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
        assert!(responded.outcome.is_none());

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
                .any(|event| event.event_type == AuditEventType::TaskResumedAfterApproval)
        );
    }

    #[test]
    fn respond_approval_deny_returns_denied_outcome() {
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
                task_id: "task-approval-deny".to_string(),
                session_id: created_session.session_id.clone(),
                status: DomainTaskStatus::Blocked,
                goal: Some("wait approval".to_string()),
                created_by: TaskCreatedBy::Explicit,
                trace_id: "trace-approval-deny".to_string(),
                limits_json: None,
                current_step: 0,
                created_at_ms: 1_000,
                updated_at_ms: 1_000,
            })
            .expect("create blocked task");
        store
            .create_approval(NewApproval {
                approval_id: "approval-deny".to_string(),
                session_id: created_session.session_id.clone(),
                task_id: "task-approval-deny".to_string(),
                trace_id: "trace-approval-deny".to_string(),
                status: ApprovalStatus::Pending,
                summary: "network access requires approval".to_string(),
                details: None,
                items: vec![],
                policy_reason: "needs manual approval".to_string(),
                policy_revision: 1,
                execution_contract_json: test_approval_snapshot_json(),
                created_at_ms: 1_000,
                expires_at_ms: now_ms() + 60_000,
            })
            .expect("create approval");

        let respond_response = controller.dispatch(RpcRequest {
            method: RpcMethod::RespondApproval as i32,
            payload: encode_message(&RespondApprovalRequest {
                session_id: created_session.session_id.clone(),
                approval_id: "approval-deny".to_string(),
                decision: RpcApprovalDecision::Deny as i32,
                idempotency_key: "idem-approval-deny".to_string(),
                reason: Some("denied".to_string()),
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
            responded.task.as_ref().expect("task must exist").status,
            TaskStatus::Failed as i32
        );
        let outcome = responded
            .outcome
            .as_ref()
            .and_then(|outcome| outcome.outcome.as_ref())
            .expect("denied outcome must exist");
        match outcome {
            RpcTaskOutcome::Denied(denied) => {
                assert_eq!(denied.code.as_deref(), Some("APPROVAL_DENIED"));
            }
            other => panic!("expected denied outcome, got {other:?}"),
        }
    }

    #[test]
    fn build_execution_effects_projects_write_network_and_process_effects() {
        let normalized = NormalizedOperation {
            intent: Intent {
                kind: OperationKind::Fetch,
                labels: Default::default(),
                tags: Default::default(),
                targets: vec![Target {
                    kind: TargetKind::Host,
                    value: "example.com".to_string(),
                }],
            },
            facts: Facts {
                interactive: Fact::Known(false),
                safe_file_read: Fact::Known(false),
                safe_file_write: Fact::Known(true),
                system_file_read: Fact::Known(false),
                system_file_write: Fact::Known(false),
                network_access: Fact::Known(true),
                system_admin: Fact::Known(false),
                process_control: Fact::Known(false),
                credential_access: Fact::Known(false),
                unknown_intent: Fact::Known(false),
                touches_policy_dir: Fact::Known(false),
                primary_host: Fact::Known("example.com".to_string()),
                command_text: Fact::Unknown,
                affected_paths: vec![PathBuf::from("/tmp/out.txt")],
                reason_codes: Vec::new(),
            },
            runtime: RuntimeContext {
                platform: RuntimePlatform::Linux,
                daemon_instance_id: "daemon-1".to_string(),
                policy_dir: PathBuf::from("/tmp/policies"),
                workspace_root: Some(PathBuf::from("/tmp")),
            },
        };

        let effects = build_execution_effects(&normalized, &["curl".to_string()]);

        assert!(has_effect(
            &effects,
            ExecutionEffectKind::FileWrite,
            "/tmp/out.txt"
        ));
        assert!(has_effect(
            &effects,
            ExecutionEffectKind::NetworkEgress,
            "example.com"
        ));
        assert!(has_effect(
            &effects,
            ExecutionEffectKind::ProcessExec,
            "curl"
        ));
        assert_eq!(
            effects
                .iter()
                .filter(|effect| effect.kind == ExecutionEffectKind::NetworkEgress as i32)
                .count(),
            1
        );
    }

    #[test]
    fn build_execution_effects_network_unknown_host_uses_wildcard() {
        let normalized = NormalizedOperation {
            intent: Intent {
                kind: OperationKind::Exec,
                labels: Default::default(),
                tags: Default::default(),
                targets: Vec::new(),
            },
            facts: Facts {
                interactive: Fact::Known(false),
                safe_file_read: Fact::Unknown,
                safe_file_write: Fact::Unknown,
                system_file_read: Fact::Unknown,
                system_file_write: Fact::Unknown,
                network_access: Fact::Known(true),
                system_admin: Fact::Unknown,
                process_control: Fact::Unknown,
                credential_access: Fact::Unknown,
                unknown_intent: Fact::Unknown,
                touches_policy_dir: Fact::Known(false),
                primary_host: Fact::Unknown,
                command_text: Fact::Known("/bin/sh -lc echo hi".to_string()),
                affected_paths: Vec::new(),
                reason_codes: Vec::new(),
            },
            runtime: RuntimeContext {
                platform: RuntimePlatform::Linux,
                daemon_instance_id: "daemon-1".to_string(),
                policy_dir: PathBuf::from("/tmp/policies"),
                workspace_root: Some(PathBuf::from("/tmp")),
            },
        };

        let effects = build_execution_effects(&normalized, &["/bin/sh".to_string()]);
        assert!(has_effect(
            &effects,
            ExecutionEffectKind::NetworkEgress,
            "*"
        ));
    }

    #[test]
    fn default_network_policy_disables_when_network_fact_is_unknown() {
        let normalized = NormalizedOperation {
            intent: Intent {
                kind: OperationKind::Exec,
                labels: Default::default(),
                tags: Default::default(),
                targets: Vec::new(),
            },
            facts: Facts {
                interactive: Fact::Known(false),
                safe_file_read: Fact::Unknown,
                safe_file_write: Fact::Unknown,
                system_file_read: Fact::Unknown,
                system_file_write: Fact::Unknown,
                network_access: Fact::Unknown,
                system_admin: Fact::Unknown,
                process_control: Fact::Unknown,
                credential_access: Fact::Unknown,
                unknown_intent: Fact::Unknown,
                touches_policy_dir: Fact::Known(false),
                primary_host: Fact::Unknown,
                command_text: Fact::Unknown,
                affected_paths: Vec::new(),
                reason_codes: Vec::new(),
            },
            runtime: RuntimeContext {
                platform: RuntimePlatform::Linux,
                daemon_instance_id: "daemon-1".to_string(),
                policy_dir: PathBuf::from("/tmp/policies"),
                workspace_root: Some(PathBuf::from("/tmp")),
            },
        };

        assert_eq!(
            default_network_policy_for_operation(&normalized),
            NetworkPolicy::Disabled
        );
    }

    #[test]
    fn parse_sandbox_overrides_accepts_explicit_settings() {
        let parsed = json!({
            "sandbox": {
                "network": "full",
                "filesystem_mode": "read_only",
                "include_platform_defaults": false,
                "mount_proc": false,
                "mounts": [
                    {
                        "source": "/opt/models",
                        "target": "/mnt/models",
                        "read_only": false
                    }
                ],
                "governance_mode": "required",
                "syscall_policy": "unconfined"
            }
        });
        let overrides = parse_sandbox_overrides(Some(&parsed)).expect("parse sandbox overrides");

        assert_eq!(overrides.network, Some(NetworkPolicy::Full));
        assert_eq!(overrides.filesystem_mode, Some(FilesystemMode::ReadOnly));
        assert_eq!(overrides.include_platform_defaults, Some(false));
        assert_eq!(overrides.mount_proc, Some(false));
        assert_eq!(
            overrides.mounts,
            vec![BindMount {
                source: PathBuf::from("/opt/models"),
                target: PathBuf::from("/mnt/models"),
                read_only: false,
            }]
        );
        assert_eq!(
            overrides.governance_mode,
            Some(ResourceGovernanceMode::Required)
        );
        assert_eq!(overrides.syscall_policy, Some(SyscallPolicy::Unconfined));
    }

    #[test]
    fn parse_sandbox_overrides_rejects_invalid_network_value() {
        let parsed = json!({
            "sandbox": {
                "network": "all"
            }
        });
        let response = parse_sandbox_overrides(Some(&parsed)).expect_err("network=all must fail");
        let rpc_error = match response.outcome {
            Some(rpc_response::Outcome::Error(error)) => error,
            other => panic!("expected rpc error response, got {other:?}"),
        };
        assert_eq!(rpc_error.code, RpcErrorCode::BadRequest as i32);
        assert!(rpc_error.message.contains("sandbox.network"));
    }

    #[test]
    fn parse_sandbox_overrides_rejects_invalid_mounts_shape() {
        let parsed = json!({
            "sandbox": {
                "mounts": {
                    "source": "/opt/models",
                    "target": "/mnt/models"
                }
            }
        });
        let response = parse_sandbox_overrides(Some(&parsed)).expect_err("mounts object must fail");
        let rpc_error = match response.outcome {
            Some(rpc_response::Outcome::Error(error)) => error,
            other => panic!("expected rpc error response, got {other:?}"),
        };
        assert_eq!(rpc_error.code, RpcErrorCode::BadRequest as i32);
        assert!(rpc_error.message.contains("sandbox.mounts"));
    }

    #[test]
    fn approval_snapshot_round_trip_recovers_task_operation() {
        let operation = TaskOperation {
            kind: "exec".to_string(),
            payload: Some(prost_types::Struct {
                fields: BTreeMap::from([(
                    "command".to_string(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue(
                            "echo hello".to_string(),
                        )),
                    },
                )]),
            }),
            options: None,
            labels: HashMap::from([("k".to_string(), "v".to_string())]),
        };
        let snapshot = approval_snapshot_json(
            &af_core::ExecutionContract {
                decision: PolicyDecision::Ask,
                reason: Some("approval".to_string()),
                runtime_backend: None,
                requirements: Vec::new(),
                approval: None,
                policy_revision: 1,
                matched_rule: None,
                evaluation_trace: af_core::PolicyEvaluationTrace::new(1, vec!["r1".to_string()]),
                fail_closed: false,
            },
            &operation,
        );

        let recovered = task_operation_from_approval_snapshot(&snapshot).expect("parse snapshot");
        assert_eq!(recovered.kind, operation.kind);
        assert_eq!(recovered.labels, operation.labels);
        assert!(recovered.payload.is_some());
    }

    #[test]
    fn approval_snapshot_rejects_missing_operation() {
        let error =
            task_operation_from_approval_snapshot("{\"schema\":\"task_approval_snapshot.v1\"}")
                .expect_err("missing operation must fail");
        let rpc_error = match error.outcome {
            Some(rpc_response::Outcome::Error(error)) => error,
            other => panic!("expected rpc error response, got {other:?}"),
        };
        assert_eq!(rpc_error.code, RpcErrorCode::InternalError as i32);
    }

    #[test]
    fn approval_snapshot_trace_extracts_rule_info() {
        let snapshot = json!({
            "schema": "task_approval_snapshot.v1",
            "contract": {
                "candidate_rule_count": 3,
                "matched_rule_ids": ["r-deny", "r-ask"]
            },
            "operation": {
                "kind": "exec",
                "payload": {},
                "options": {},
                "labels": {}
            }
        })
        .to_string();

        let (candidate_rule_count, matched_rule_ids) = approval_snapshot_trace(&snapshot);
        assert_eq!(candidate_rule_count, 3);
        assert_eq!(
            matched_rule_ids,
            vec!["r-deny".to_string(), "r-ask".to_string()]
        );
    }

    #[test]
    fn approved_execution_contract_always_allows() {
        let approval = af_approval::Approval {
            approval_id: "approval-1".to_string(),
            session_id: "session-1".to_string(),
            task_id: "task-1".to_string(),
            trace_id: "trace-1".to_string(),
            status: ApprovalStatus::Approved,
            summary: "approval required".to_string(),
            details: None,
            items: Vec::new(),
            policy_reason: "manual approval".to_string(),
            policy_revision: 42,
            execution_contract_json: json!({
                "schema": "task_approval_snapshot.v1",
                "contract": {
                    "candidate_rule_count": 2,
                    "matched_rule_ids": ["r-ask"],
                    "final_decision": "ask"
                },
                "operation": {
                    "kind": "exec",
                    "payload": {},
                    "options": {},
                    "labels": {}
                }
            })
            .to_string(),
            created_at_ms: 1_000,
            expires_at_ms: 2_000,
            responded_at_ms: Some(1_200),
            response_reason: Some("approved".to_string()),
            response_idempotency_key: Some("idem-1".to_string()),
        };

        let contract = approved_execution_contract(&approval);
        assert_eq!(contract.decision, PolicyDecision::Allow);
        assert_eq!(contract.policy_revision, 42);
        assert_eq!(contract.evaluation_trace.candidate_rule_count, 2);
        assert_eq!(contract.evaluation_trace.matched_rule_ids, vec!["r-ask"]);
    }

    fn has_effect(effects: &[ExecutionEffect], kind: ExecutionEffectKind, target: &str) -> bool {
        effects
            .iter()
            .any(|effect| effect.kind == kind as i32 && effect.target == target)
    }

    fn test_task_operation() -> af_rpc_proto::TaskOperation {
        af_rpc_proto::TaskOperation {
            kind: "exec".to_string(),
            payload: None,
            options: None,
            labels: Default::default(),
        }
    }

    fn test_approval_snapshot_json() -> String {
        json!({
            "schema": "task_approval_snapshot.v1",
            "contract": {
                "final_decision": "ask"
            },
            "operation": {
                "kind": "exec",
                "payload": {},
                "options": {},
                "labels": {}
            }
        })
        .to_string()
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

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires unix socket bind capability"]
    async fn handles_multiple_requests_over_single_connection() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let socket_path = temp_dir.path().join("rpc.sock");
        let endpoint = Endpoint::parse(&format!("unix://{}", socket_path.display()))
            .expect("parse unix endpoint");

        let store = Arc::new(Store::open(StoreOptions::in_memory()).expect("open store"));
        let controller = RpcController::new("daemon-1".to_string(), store);
        let server = RpcServer::bind(endpoint.clone()).expect("bind rpc server");

        let server_task = tokio::spawn(async move {
            let connection = server.accept().await.expect("accept connection");
            controller
                .handle_connection(connection)
                .await
                .expect("handle connection");
        });

        let mut client = RpcClient::connect(endpoint)
            .await
            .expect("connect rpc client");
        let request = RpcRequest {
            method: RpcMethod::Ping as i32,
            payload: encode_message(&PingRequest {}),
        };

        for _ in 0..2 {
            let response: RpcResponse = client.roundtrip(&request).await.expect("ping roundtrip");
            let payload = match response.outcome {
                Some(rpc_response::Outcome::Payload(payload)) => payload,
                other => panic!("expected payload response, got {other:?}"),
            };
            let ping = decode_message::<PingResponse>(&payload).expect("decode ping response");
            assert_eq!(ping.status, "ok");
            assert_eq!(ping.daemon_instance_id, "daemon-1");
        }

        drop(client);
        server_task.await.expect("server task should finish");
    }
}
