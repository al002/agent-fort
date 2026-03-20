use super::*;

pub(super) fn execute_allow_path(
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

pub(super) fn execute_ask_path(
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
        plan.policy_revision,
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
            policy_revision: plan.policy_revision,
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
                "policy_revision": plan.policy_revision,
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

pub(super) fn execute_deny_path(
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

pub(super) fn ensure_session_grant(
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

pub(super) fn apply_approval_delta_with_cas(
    store: &Store,
    session_id: &str,
    snapshot: &ApprovalSnapshot,
    active_policy: &ActivePolicy,
) -> Result<SessionGrantState, RpcResponse> {
    let current = ensure_session_grant(store, session_id, &active_policy.policy.capabilities)?;

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
    if !capability_set_within_policy(&next, &active_policy.policy.capabilities) {
        return Err(err(
            RpcErrorCode::PolicyDenied,
            "approved delta exceeds policy",
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

pub(super) fn normalize_task_operation(
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

pub(super) fn load_active_policy(runtime: &ExecutionRuntime) -> Result<ActivePolicy, RpcResponse> {
    let policy_runtime = runtime.policy_runtime.lock().map_err(|_| {
        err(
            RpcErrorCode::PolicyLoadFailed,
            "policy runtime lock poisoned",
        )
    })?;

    policy_runtime.active_policy().map_err(|error| {
        err(
            RpcErrorCode::PolicyLoadFailed,
            format!("load static policy failed: {error}"),
        )
    })
}

pub(super) fn network_policy_from_plan(
    network_mode: &str,
    no_network_endpoints: bool,
) -> NetworkPolicy {
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

pub(super) fn now_ms() -> u64 {
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after unix epoch");
    elapsed
        .as_millis()
        .try_into()
        .expect("timestamp fits into u64")
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

fn parse_capability_set_json(raw: &str) -> Result<CapabilitySet, RpcResponse> {
    serde_json::from_str(raw).map_err(|error| {
        err(
            RpcErrorCode::InternalError,
            format!("parse capability_grant JSON failed: {error}"),
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
        "policy_revision": plan.policy_revision,
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
        "policy_revision": plan.policy_revision,
    })
    .to_string()
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
