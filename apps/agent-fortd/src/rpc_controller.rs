use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use af_approval::{
    ApprovalItem as DomainApprovalItem, ApprovalRepository, ApprovalStatus, NewApproval,
};
use af_audit::{AuditEventType, AuditRepository, NewAuditEvent};
use af_core::{
    ApprovalAppError, ApprovalAppService, BackendSelector, CancelTaskInput, CapabilityDecision,
    CapabilityDelta, CapabilityExtractor, CapabilityPolicyEvaluator, CreateSessionInput,
    CreateTaskInput, EvaluationMode, GetApprovalInput, NormalizedCommand, OperationNormalizer,
    RawOperation, RequestedCapabilities, RespondApprovalInput, RuntimeCompiler, RuntimeContext,
    RuntimePlatform, SessionAppError, SessionAppService, SessionConfig, TaskAppError,
    TaskAppService, apply_delta_to_capability_set, intersect_requested_with_capabilities,
    subset_capability_set_within_static, subset_requested_vs_capabilities,
};
use af_policy::CapabilitySet;
use af_policy_infra::{ActiveStaticPolicy, PolicyRuntime};
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
use af_store::{Store, StoreError};
use af_task::{
    AdvanceTaskStepCommand, TaskCreatedBy as DomainTaskCreatedBy, TaskRepository,
    TaskStatus as DomainTaskStatus, UpdateTaskStatusCommand,
};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::helper_client::HelperClient;

const APPROVAL_SNAPSHOT_SCHEMA_V2: &str = "task_approval_snapshot.v2";

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
    static_policy_revision: u64,
}

#[derive(Debug, Clone)]
struct AskExecutionPlan {
    requested: RequestedCapabilities,
    delta: CapabilityDelta,
    reason: String,
    session_grant_revision: u64,
    static_policy_revision: u64,
}

#[derive(Debug, Clone)]
struct ApprovalSnapshot {
    operation: TaskOperation,
    session_grant_revision_before: u64,
    static_policy_revision: u64,
    delta: CapabilityDelta,
}

#[derive(Debug, Clone)]
enum AuthorizationResult {
    Allow(AllowExecutionPlan),
    Ask(AskExecutionPlan),
    Deny { reason: String, code: &'static str },
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
        let active_policy = load_active_static_policy(runtime)?;
        let session_grant = ensure_session_grant(
            &self.state.store,
            &task.session_id,
            &active_policy.document.capabilities,
        )?;

        match authorize_interactive(normalized, &active_policy, &session_grant)? {
            AuthorizationResult::Allow(plan) => {
                execute_allow_path(&self.state.store, runtime, task, &plan)
            }
            AuthorizationResult::Ask(plan) => {
                execute_ask_path(&self.state.store, task, &operation, &plan)
            }
            AuthorizationResult::Deny { reason, code } => {
                execute_deny_path(&self.state.store, task, reason, code)
            }
        }
    }

    fn execute_approved_single_step_task(
        &self,
        task: af_task::Task,
        approval: &af_approval::Approval,
    ) -> Result<(af_task::Task, TaskOutcome), RpcResponse> {
        let runtime = self.state.execution_runtime.as_ref().ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "execution runtime not configured",
            )
        })?;

        let snapshot = approval_snapshot_from_json(&approval.execution_contract_json)?;
        let active_policy = load_active_static_policy(runtime)?;
        if snapshot.static_policy_revision != active_policy.document.revision {
            return Err(err(
                RpcErrorCode::InvalidTaskState,
                format!(
                    "static policy revision changed: approval={}, active={}",
                    snapshot.static_policy_revision, active_policy.document.revision
                ),
            ));
        }

        let session_grant = match apply_approval_delta_with_cas(
            &self.state.store,
            &task.session_id,
            &snapshot,
            &active_policy,
        ) {
            Ok(grant) => grant,
            Err(response) => {
                if let Some((code, message)) = rpc_error_details(&response)
                    && matches!(
                        code,
                        RpcErrorCode::PolicyDenied | RpcErrorCode::InvalidTaskState
                    )
                {
                    return execute_deny_path(&self.state.store, task, message, "POLICY_DENIED");
                }
                return Err(response);
            }
        };

        let normalized =
            normalize_task_operation(&snapshot.operation, runtime, &self.state.daemon_instance_id)?;
        let requested = requested_from_normalized(&normalized);

        if !subset_requested_vs_capabilities(&requested, &session_grant.capabilities) {
            return execute_deny_path(
                &self.state.store,
                task,
                "approved grant no longer satisfies requested capabilities".to_string(),
                "POLICY_DENIED",
            );
        }

        match compile_allow_plan(normalized, requested, &active_policy, &session_grant) {
            Ok(plan) => execute_allow_path(&self.state.store, runtime, task, &plan),
            Err(reason) => execute_deny_path(&self.state.store, task, reason, "POLICY_DENIED"),
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

fn authorize_interactive(
    normalized: af_core::NormalizedOperation,
    active_policy: &ActiveStaticPolicy,
    session_grant: &SessionGrantState,
) -> Result<AuthorizationResult, RpcResponse> {
    let requested = requested_from_normalized(&normalized);
    let evaluator = CapabilityPolicyEvaluator;
    match evaluator.decide(
        &requested,
        &session_grant.capabilities,
        &active_policy.document,
        EvaluationMode::INTERACTIVE,
    ) {
        CapabilityDecision::Allow => {
            match compile_allow_plan(normalized, requested, active_policy, session_grant) {
                Ok(plan) => Ok(AuthorizationResult::Allow(plan)),
                Err(reason) => Ok(AuthorizationResult::Deny {
                    reason,
                    code: "POLICY_DENIED",
                }),
            }
        }
        CapabilityDecision::Ask { delta, reason } => {
            Ok(AuthorizationResult::Ask(AskExecutionPlan {
                requested,
                delta,
                reason,
                session_grant_revision: session_grant.revision,
                static_policy_revision: active_policy.document.revision,
            }))
        }
        CapabilityDecision::Deny { reason } => Ok(AuthorizationResult::Deny {
            reason,
            code: "POLICY_DENIED",
        }),
        CapabilityDecision::Forbid { reason } => Ok(AuthorizationResult::Deny {
            reason,
            code: "POLICY_FORBID",
        }),
    }
}

fn compile_allow_plan(
    normalized: af_core::NormalizedOperation,
    requested: RequestedCapabilities,
    active_policy: &ActiveStaticPolicy,
    session_grant: &SessionGrantState,
) -> Result<AllowExecutionPlan, String> {
    if !subset_capability_set_within_static(
        &session_grant.capabilities,
        &active_policy.document.capabilities,
    ) {
        return Err("session_grant exceeds static_policy".to_string());
    }

    let by_session = intersect_requested_with_capabilities(&requested, &session_grant.capabilities);
    let effective =
        intersect_requested_with_capabilities(&by_session, &active_policy.document.capabilities);

    let selected = BackendSelector
        .select(&effective, &active_policy.document)
        .map_err(|error| format!("backend selection failed: {error}"))?;

    let runtime_plan = RuntimeCompiler
        .compile(&selected, &effective, &active_policy.document)
        .map_err(|error| format!("runtime compile failed: {error}"))?;

    Ok(AllowExecutionPlan {
        normalized,
        requested,
        effective,
        runtime_plan,
        session_grant_revision: session_grant.revision,
        static_policy_revision: active_policy.document.revision,
    })
}

fn requested_from_normalized(normalized: &af_core::NormalizedOperation) -> RequestedCapabilities {
    let extractor = CapabilityExtractor::default();
    let mut requested = extractor.from_operation(normalized);
    if normalized.unknown {
        requested.unknown = true;
    }
    requested
        .reason_codes
        .extend(normalized.reason_codes.iter().cloned());
    requested.reason_codes.sort();
    requested.reason_codes.dedup();
    requested
}

fn execute_allow_path(
    store: &Store,
    runtime: &ExecutionRuntime,
    task: af_task::Task,
    plan: &AllowExecutionPlan,
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
        Some(policy_execution_payload_json(plan)),
        None,
    )?;

    let mut execution =
        match build_sandbox_request(runtime, &running, &plan.normalized, &plan.runtime_plan) {
            Ok(request) => {
                let command = request.command.clone();
                let mut result = match runtime.helper_client.execute(request) {
                    Ok(result) => execution_result_from_sandbox(result),
                    Err(error) => failure_execution_result(error.to_string()),
                };
                result.effects = build_execution_effects(&plan.effective, &command);
                result
            }
            Err(error_message) => {
                let mut result = failure_execution_result(error_message);
                result.effects = build_execution_effects(
                    &plan.effective,
                    &command_from_normalized(plan.normalized.command.as_ref()).unwrap_or_default(),
                );
                result
            }
        };

    execution.effects.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.target.cmp(&right.target))
    });

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
        Some(execution_payload_json(&execution, plan)),
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
    plan: &AskExecutionPlan,
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

    let items = approval_items_from_delta(&plan.delta);
    let summary = "capability escalation requires approval".to_string();
    let details = Some(
        json!({
            "reason": plan.reason,
            "delta_capabilities": capability_delta_to_json(&plan.delta),
            "requested_capabilities": requested_capabilities_to_json(&plan.requested)
        })
        .to_string(),
    );

    let execution_contract_json = approval_snapshot_json(
        operation,
        &plan.requested,
        &plan.delta,
        plan.session_grant_revision,
        plan.static_policy_revision,
        &plan.reason,
    );

    let created_approval = store
        .create_approval(NewApproval {
            approval_id: approval_id.clone(),
            session_id: blocked.session_id.clone(),
            task_id: blocked.task_id.clone(),
            trace_id: blocked.trace_id.clone(),
            status: ApprovalStatus::Pending,
            summary: summary.clone(),
            details,
            items,
            policy_reason: plan.reason.clone(),
            policy_revision: plan.static_policy_revision,
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
        Some(
            json!({
                "reason": plan.reason,
                "requested_capabilities": requested_capabilities_to_json(&plan.requested),
                "delta_capabilities": capability_delta_to_json(&plan.delta),
                "session_grant_revision": plan.session_grant_revision,
                "static_policy_revision": plan.static_policy_revision,
            })
            .to_string(),
        ),
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
    reason: String,
    policy_code: &'static str,
) -> Result<(af_task::Task, TaskOutcome), RpcResponse> {
    let failed = transition_task_status(
        store,
        &task,
        Some(DomainTaskStatus::Pending),
        DomainTaskStatus::Failed,
        Some(policy_code.to_string()),
        Some(reason.clone()),
    )?;

    let stepped = finalize_task_step(store, &failed)?;

    append_task_audit(
        store,
        AuditEventType::PolicyDenied,
        &stepped,
        Some(json!({ "reason": reason }).to_string()),
        Some(policy_code.to_string()),
    )?;
    append_task_audit(
        store,
        AuditEventType::TaskFailed,
        &stepped,
        Some(json!({ "reason": reason }).to_string()),
        Some(policy_code.to_string()),
    )?;

    Ok((
        stepped,
        TaskOutcome {
            outcome: Some(RpcTaskOutcome::Denied(TaskDenied {
                code: Some(policy_code.to_string()),
                message: Some(reason),
            })),
        },
    ))
}

fn ensure_session_grant(
    store: &Store,
    session_id: &str,
    static_capabilities: &CapabilitySet,
) -> Result<SessionGrantState, RpcResponse> {
    if let Some(record) = store
        .get_capability_grant(session_id)
        .map_err(|error| map_store_error(error, "get capability_grant"))?
    {
        return Ok(SessionGrantState {
            revision: record.revision,
            capabilities: parse_capability_set_json(&record.capabilities_json)?,
        });
    }

    let initial = initial_session_grant(static_capabilities);
    let initial_json = serde_json::to_string(&initial).map_err(|error| {
        err(
            RpcErrorCode::InternalError,
            format!("serialize initial capability_grant failed: {error}"),
        )
    })?;

    let created = store
        .create_capability_grant_if_absent(session_id, &initial_json, None, now_ms())
        .map_err(|error| map_store_error(error, "create capability_grant"))?;

    Ok(SessionGrantState {
        revision: created.revision,
        capabilities: parse_capability_set_json(&created.capabilities_json)?,
    })
}

fn initial_session_grant(static_capabilities: &CapabilitySet) -> CapabilitySet {
    CapabilitySet {
        fs_read: static_capabilities.fs_read.clone(),
        fs_write: static_capabilities.fs_write.clone(),
        fs_delete: static_capabilities.fs_delete.clone(),
        net_connect: Vec::new(),
        allow_host_exec: false,
        allow_process_control: false,
        allow_privilege: false,
        allow_credential_access: false,
    }
}

fn apply_approval_delta_with_cas(
    store: &Store,
    session_id: &str,
    snapshot: &ApprovalSnapshot,
    active_policy: &ActiveStaticPolicy,
) -> Result<SessionGrantState, RpcResponse> {
    let current = ensure_session_grant(store, session_id, &active_policy.document.capabilities)?;

    if current.revision != snapshot.session_grant_revision_before {
        return Err(err(
            RpcErrorCode::InvalidTaskState,
            format!(
                "capability_grant revision mismatch: expected={}, actual={}",
                snapshot.session_grant_revision_before, current.revision
            ),
        ));
    }

    if snapshot.delta.is_empty() {
        return Ok(current);
    }

    let next = apply_delta_to_capability_set(&current.capabilities, &snapshot.delta);
    if !subset_capability_set_within_static(&next, &active_policy.document.capabilities) {
        return Err(err(
            RpcErrorCode::PolicyDenied,
            "approved delta exceeds static policy",
        ));
    }

    let next_json = serde_json::to_string(&next).map_err(|error| {
        err(
            RpcErrorCode::InternalError,
            format!("serialize updated capability_grant failed: {error}"),
        )
    })?;
    let delta_json = capability_delta_to_json(&snapshot.delta).to_string();

    let updated = store
        .update_capability_grant_with_revision(
            session_id,
            snapshot.session_grant_revision_before,
            &next_json,
            &delta_json,
            "user",
            now_ms(),
        )
        .map_err(|error| map_store_error(error, "update capability_grant"))?;

    Ok(SessionGrantState {
        revision: updated.revision,
        capabilities: parse_capability_set_json(&updated.capabilities_json)?,
    })
}

fn parse_capability_set_json(raw: &str) -> Result<CapabilitySet, RpcResponse> {
    serde_json::from_str(raw).map_err(|error| {
        err(
            RpcErrorCode::InternalError,
            format!("parse capability_grant JSON failed: {error}"),
        )
    })
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

fn load_active_static_policy(
    runtime: &ExecutionRuntime,
) -> Result<ActiveStaticPolicy, RpcResponse> {
    let policy_runtime = runtime.policy_runtime.lock().map_err(|_| {
        err(
            RpcErrorCode::PolicyLoadFailed,
            "policy runtime lock poisoned",
        )
    })?;

    policy_runtime.active_static_policy().map_err(|error| {
        err(
            RpcErrorCode::PolicyLoadFailed,
            format!("load static policy failed: {error}"),
        )
    })
}

fn build_sandbox_request(
    runtime: &ExecutionRuntime,
    task: &af_task::Task,
    normalized: &af_core::NormalizedOperation,
    runtime_plan: &af_core::RuntimeExecPlan,
) -> Result<SandboxExecRequest, String> {
    let plan = match runtime_plan {
        af_core::RuntimeExecPlan::Sandbox(plan) => plan,
        _ => {
            return Err(format!(
                "runtime backend `{}` is not executable on this daemon",
                runtime_plan.backend().as_str()
            ));
        }
    };

    let command = command_from_normalized(normalized.command.as_ref())
        .ok_or_else(|| "task operation command is required for execution".to_string())?;

    let cwd = normalized
        .cwd
        .clone()
        .or_else(|| normalized.runtime.workspace_root.clone())
        .or_else(|| runtime.workspace_root.clone())
        .unwrap_or_else(|| PathBuf::from("/"));

    if !cwd.is_absolute() {
        return Err(format!("execution cwd must be absolute: {}", cwd.display()));
    }

    let mut writable_roots = roots_from_patterns(&plan.writable_roots)
        .into_iter()
        .map(|root| WritableRoot {
            root,
            read_only_subpaths: Vec::new(),
        })
        .collect::<Vec<_>>();

    if writable_roots.is_empty() {
        writable_roots.push(WritableRoot {
            root: runtime
                .workspace_root
                .clone()
                .unwrap_or_else(|| PathBuf::from("/tmp")),
            read_only_subpaths: Vec::new(),
        });
    }

    let request = SandboxExecRequest {
        command,
        cwd,
        env: normalized.env.clone(),
        filesystem: FilesystemPolicy {
            mode: FilesystemMode::Restricted,
            include_platform_defaults: true,
            mount_proc: true,
            readable_roots: roots_from_patterns(&plan.readonly_roots),
            writable_roots,
            mounts: Vec::new(),
            unreadable_roots: Vec::new(),
        },
        network: network_policy_from_plan(&plan.network_mode, plan.allowed_network.is_empty()),
        pty: PtyPolicy::Disabled,
        limits: sandbox_limits_from_plan(&plan.limits),
        governance_mode: runtime.resource_governance_mode,
        syscall_policy: syscall_policy_from_plan(&plan.syscall_policy),
        capture: OutputCapturePolicy::default(),
        trace: TraceContext {
            session_id: Some(task.session_id.clone()),
            task_id: Some(task.task_id.clone()),
            trace_id: Some(task.trace_id.clone()),
        },
    };

    request
        .validate()
        .map_err(|error| format!("invalid sandbox request: {error}"))?;
    Ok(request)
}

fn network_policy_from_plan(network_mode: &str, no_network_endpoints: bool) -> NetworkPolicy {
    let mode = network_mode.trim().to_ascii_lowercase();
    if mode.contains("proxy") {
        return NetworkPolicy::ProxyOnly;
    }
    if no_network_endpoints || mode == "deny" || mode == "disabled" {
        NetworkPolicy::Disabled
    } else {
        NetworkPolicy::Full
    }
}

fn syscall_policy_from_plan(syscall_policy: &str) -> SyscallPolicy {
    if syscall_policy.eq_ignore_ascii_case("unconfined") {
        SyscallPolicy::Unconfined
    } else {
        SyscallPolicy::Baseline
    }
}

fn sandbox_limits_from_plan(limits: &af_policy::BackendResourceLimits) -> ResourceLimits {
    let timeout_ms = limits.timeout_ms.max(1);
    let cpu_secs = (limits.cpu_ms.max(1) as f64 / 1000.0).ceil() as u64;

    ResourceLimits {
        elapsed_timeout: Duration::from_millis(timeout_ms),
        cpu_time_limit_seconds: Some(cpu_secs.max(1)),
        max_memory_bytes: Some(limits.memory_mb.saturating_mul(1024 * 1024)),
        max_processes: Some(u64::from(limits.pids)),
        max_file_size_bytes: Some(limits.disk_mb.saturating_mul(1024 * 1024)),
        cpu_max_percent: None,
    }
}

fn roots_from_patterns(patterns: &[String]) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    for pattern in patterns {
        if let Some(root) = pattern_to_root(pattern) {
            roots.insert(root);
        }
    }
    roots.into_iter().collect()
}

fn pattern_to_root(pattern: &str) -> Option<PathBuf> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return None;
    }

    let base = trimmed
        .split('*')
        .next()
        .unwrap_or(trimmed)
        .trim_end_matches('/');

    let normalized = if base.is_empty() { "/" } else { base };
    let path = PathBuf::from(normalized);
    if path.is_absolute() { Some(path) } else { None }
}

fn command_from_normalized(command: Option<&NormalizedCommand>) -> Option<Vec<String>> {
    match command {
        Some(NormalizedCommand::Shell(command)) => Some(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            command.clone(),
        ]),
        Some(NormalizedCommand::Argv(argv)) if !argv.is_empty() => Some(argv.clone()),
        _ => None,
    }
}

fn build_execution_effects(
    requested: &RequestedCapabilities,
    command: &[String],
) -> Vec<ExecutionEffect> {
    let mut effects = Vec::new();
    let mut seen = BTreeSet::<(i32, String)>::new();

    for path in &requested.fs_read {
        push_execution_effect(
            &mut effects,
            &mut seen,
            ExecutionEffectKind::FileRead,
            path.display().to_string(),
        );
    }
    for path in &requested.fs_write {
        push_execution_effect(
            &mut effects,
            &mut seen,
            ExecutionEffectKind::FileWrite,
            path.display().to_string(),
        );
    }
    for path in &requested.fs_delete {
        push_execution_effect(
            &mut effects,
            &mut seen,
            ExecutionEffectKind::FileWrite,
            path.display().to_string(),
        );
    }
    for endpoint in &requested.net_connect {
        let target = match endpoint.port {
            Some(port) => format!("{}:{port}", endpoint.host),
            None => endpoint.host.clone(),
        };
        push_execution_effect(
            &mut effects,
            &mut seen,
            ExecutionEffectKind::NetworkEgress,
            target,
        );
    }

    if let Some(binary) = command.first() {
        push_execution_effect(
            &mut effects,
            &mut seen,
            ExecutionEffectKind::ProcessExec,
            binary.clone(),
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

fn policy_execution_payload_json(plan: &AllowExecutionPlan) -> String {
    json!({
        "session_grant_revision": plan.session_grant_revision,
        "static_policy_revision": plan.static_policy_revision,
        "selected_backend": plan.runtime_plan.backend().as_str(),
        "backend_profile_id": plan.runtime_plan.profile_id(),
        "requested_capabilities": requested_capabilities_to_json(&plan.requested),
        "effective_capabilities": requested_capabilities_to_json(&plan.effective),
    })
    .to_string()
}

fn execution_payload_json(result: &ExecutionResult, plan: &AllowExecutionPlan) -> String {
    json!({
        "state": result.state,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
        "selected_backend": plan.runtime_plan.backend().as_str(),
        "backend_profile_id": plan.runtime_plan.profile_id(),
        "session_grant_revision": plan.session_grant_revision,
        "static_policy_revision": plan.static_policy_revision,
    })
    .to_string()
}

fn requested_capabilities_to_json(requested: &RequestedCapabilities) -> Value {
    json!({
        "fs_read": requested.fs_read.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "fs_write": requested.fs_write.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "fs_delete": requested.fs_delete.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "net_connect": requested.net_connect.iter().map(|endpoint| json!({
            "host": endpoint.host,
            "port": endpoint.port,
            "protocol": endpoint.protocol,
        })).collect::<Vec<_>>(),
        "host_exec": requested.host_exec,
        "process_control": requested.process_control,
        "privilege": requested.privilege,
        "credential_access": requested.credential_access,
        "unknown": requested.unknown,
        "reason_codes": requested.reason_codes,
    })
}

fn capability_delta_to_json(delta: &CapabilityDelta) -> Value {
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
}

fn capability_delta_from_json(value: &Value) -> Result<CapabilityDelta, RpcResponse> {
    let object = value.as_object().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot delta_capabilities must be object",
        )
    })?;

    Ok(CapabilityDelta {
        fs_read: parse_path_array(object.get("fs_read"))?,
        fs_write: parse_path_array(object.get("fs_write"))?,
        fs_delete: parse_path_array(object.get("fs_delete"))?,
        net_connect: parse_net_endpoints(object.get("net_connect"))?,
        host_exec: object
            .get("host_exec")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        process_control: object
            .get("process_control")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        privilege: object
            .get("privilege")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        credential_access: object
            .get("credential_access")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn parse_path_array(value: Option<&Value>) -> Result<Vec<PathBuf>, RpcResponse> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let items = value.as_array().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot path capability must be array",
        )
    })?;

    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let raw = item.as_str().ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot path capability item must be string",
            )
        })?;
        output.push(PathBuf::from(raw));
    }
    Ok(output)
}

fn parse_net_endpoints(value: Option<&Value>) -> Result<Vec<af_core::NetEndpoint>, RpcResponse> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let items = value.as_array().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot net_connect must be array",
        )
    })?;

    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let object = item.as_object().ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot net endpoint must be object",
            )
        })?;

        let host = object
            .get("host")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                err(
                    RpcErrorCode::InternalError,
                    "approval snapshot net endpoint.host is required",
                )
            })?;

        let port = object
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok());

        let protocol = object
            .get("protocol")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        output.push(af_core::NetEndpoint::new(host.to_string(), port, protocol));
    }

    Ok(output)
}

fn approval_items_from_delta(delta: &CapabilityDelta) -> Vec<DomainApprovalItem> {
    let mut items = Vec::new();

    for path in &delta.fs_read {
        items.push(DomainApprovalItem {
            kind: "fs.read".to_string(),
            target: Some(path.display().to_string()),
            summary: "read path outside granted capability".to_string(),
        });
    }
    for path in &delta.fs_write {
        items.push(DomainApprovalItem {
            kind: "fs.write".to_string(),
            target: Some(path.display().to_string()),
            summary: "write path outside granted capability".to_string(),
        });
    }
    for path in &delta.fs_delete {
        items.push(DomainApprovalItem {
            kind: "fs.delete".to_string(),
            target: Some(path.display().to_string()),
            summary: "delete path outside granted capability".to_string(),
        });
    }
    for endpoint in &delta.net_connect {
        let target = match endpoint.port {
            Some(port) => format!("{}:{port}", endpoint.host),
            None => endpoint.host.clone(),
        };
        items.push(DomainApprovalItem {
            kind: "net.connect".to_string(),
            target: Some(target),
            summary: "network endpoint outside granted capability".to_string(),
        });
    }

    if delta.host_exec {
        items.push(DomainApprovalItem {
            kind: "host.exec".to_string(),
            target: None,
            summary: "host execution capability escalation".to_string(),
        });
    }
    if delta.process_control {
        items.push(DomainApprovalItem {
            kind: "process.control".to_string(),
            target: None,
            summary: "process control capability escalation".to_string(),
        });
    }
    if delta.privilege {
        items.push(DomainApprovalItem {
            kind: "privilege".to_string(),
            target: None,
            summary: "privilege capability escalation".to_string(),
        });
    }
    if delta.credential_access {
        items.push(DomainApprovalItem {
            kind: "credential.access".to_string(),
            target: None,
            summary: "credential access capability escalation".to_string(),
        });
    }

    items
}

fn approval_snapshot_json(
    operation: &TaskOperation,
    requested: &RequestedCapabilities,
    delta: &CapabilityDelta,
    session_grant_revision_before: u64,
    static_policy_revision: u64,
    reason: &str,
) -> String {
    json!({
        "schema": APPROVAL_SNAPSHOT_SCHEMA_V2,
        "operation": task_operation_to_json(operation),
        "requested_capabilities": requested_capabilities_to_json(requested),
        "delta_capabilities": capability_delta_to_json(delta),
        "session_grant_revision_before": session_grant_revision_before,
        "static_policy_revision": static_policy_revision,
        "reason": reason,
        "reason_codes": requested.reason_codes,
    })
    .to_string()
}

fn approval_snapshot_from_json(raw: &str) -> Result<ApprovalSnapshot, RpcResponse> {
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

    if schema != APPROVAL_SNAPSHOT_SCHEMA_V2 {
        return Err(err(
            RpcErrorCode::InternalError,
            format!("unsupported approval snapshot schema: {schema}"),
        ));
    }

    let operation = object.get("operation").ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot missing operation",
        )
    })?;

    let session_grant_revision_before = object
        .get("session_grant_revision_before")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot missing session_grant_revision_before",
            )
        })?;

    let static_policy_revision = object
        .get("static_policy_revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot missing static_policy_revision",
            )
        })?;

    let delta = object.get("delta_capabilities").ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot missing delta_capabilities",
        )
    })?;

    Ok(ApprovalSnapshot {
        operation: task_operation_from_json(operation)?,
        session_grant_revision_before,
        static_policy_revision,
        delta: capability_delta_from_json(delta)?,
    })
}

fn validate_task_operation(operation: Option<&TaskOperation>) -> Option<RpcResponse> {
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

    let payload = struct_to_json(operation.payload.as_ref());
    let options = struct_to_json(operation.options.as_ref());

    if let Some(path) = find_forbidden_runtime_override_key(&payload, "payload") {
        return Some(err(
            RpcErrorCode::BadRequest,
            format!("runtime override is not allowed in task operation: {path}"),
        ));
    }
    if let Some(path) = find_forbidden_runtime_override_key(&options, "options") {
        return Some(err(
            RpcErrorCode::BadRequest,
            format!("runtime override is not allowed in task operation: {path}"),
        ));
    }

    for key in operation.labels.keys() {
        let lower = key.trim().to_ascii_lowercase();
        if lower == "backend"
            || lower == "runtime_backend"
            || lower.starts_with("sandbox.")
            || lower.starts_with("runtime.")
            || lower.starts_with("backend.")
        {
            return Some(err(
                RpcErrorCode::BadRequest,
                format!("runtime override label is not allowed: {key}"),
            ));
        }
    }

    None
}

fn find_forbidden_runtime_override_key(value: &Value, prefix: &str) -> Option<String> {
    const FORBIDDEN: [&str; 9] = [
        "sandbox",
        "sandbox_overrides",
        "backend",
        "runtime_backend",
        "backend_override",
        "filesystem_mode",
        "governance_mode",
        "syscall_policy",
        "mounts",
    ];

    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let lower = key.to_ascii_lowercase();
                if FORBIDDEN.contains(&lower.as_str()) {
                    return Some(format!("{prefix}.{key}"));
                }
                if let Some(found) =
                    find_forbidden_runtime_override_key(value, &format!("{prefix}.{key}"))
                {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(list) => list.iter().enumerate().find_map(|(index, item)| {
            find_forbidden_runtime_override_key(item, &format!("{prefix}[{index}]"))
        }),
        _ => None,
    }
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

fn rpc_error_details(response: &RpcResponse) -> Option<(RpcErrorCode, String)> {
    let rpc_response::Outcome::Error(error) = response.outcome.as_ref()? else {
        return None;
    };
    let code = RpcErrorCode::try_from(error.code).ok()?;
    Some((code, error.message.clone()))
}

fn map_store_error(error: StoreError, context: &str) -> RpcResponse {
    match error {
        StoreError::Conflict(message) => err(
            RpcErrorCode::InvalidTaskState,
            format!("{context} conflict: {message}"),
        ),
        StoreError::NotFound(message) => err(
            RpcErrorCode::StoreError,
            format!("{context} not found: {message}"),
        ),
        other => err(
            RpcErrorCode::StoreError,
            format!("{context} failed: {other}"),
        ),
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
