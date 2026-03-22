use super::*;

impl RpcController {
    pub(super) fn execute_single_step_task(
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
        let active_policy = load_active_policy(runtime)?;
        let session_grant = ensure_session_grant(
            &self.state.capability_grant_service,
            &task.session_id,
            &active_policy.policy.capabilities,
        )?;

        match authorize_interactive(normalized, &active_policy, &session_grant)? {
            AuthorizationResult::Allow(plan) => execute_allow_path(
                &self.state.task_execution_service,
                runtime,
                task,
                plan.as_ref(),
            ),
            AuthorizationResult::Ask(plan) => execute_ask_path(
                &self.state.task_execution_service,
                &self.state.approval_service,
                task,
                &operation,
                plan.as_ref(),
            ),
            AuthorizationResult::Deny { reason, code } => {
                execute_deny_path(&self.state.task_execution_service, task, reason, code)
            }
        }
    }

    pub(super) fn execute_approved_single_step_task(
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
        let active_policy = load_active_policy(runtime)?;
        if snapshot.policy_revision != active_policy.policy.revision {
            return Err(err(
                RpcErrorCode::InvalidTaskState,
                format!(
                    "policy revision changed: approval={}, active={}",
                    snapshot.policy_revision, active_policy.policy.revision
                ),
            ));
        }

        let session_grant = match apply_approval_delta_with_cas(
            &self.state.capability_grant_service,
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
                    return execute_deny_path(
                        &self.state.task_execution_service,
                        task,
                        message,
                        "POLICY_DENIED",
                    );
                }
                return Err(response);
            }
        };

        let normalized =
            normalize_task_operation(&snapshot.operation, runtime, &self.state.daemon_instance_id)?;
        let requested = requested_from_normalized(&normalized, &active_policy);

        if !requested_within_capabilities(&requested, &session_grant.capabilities) {
            return execute_deny_path(
                &self.state.task_execution_service,
                task,
                "approved grant no longer satisfies requested capabilities".to_string(),
                "POLICY_DENIED",
            );
        }

        match compile_allow_plan(normalized, requested, &active_policy, &session_grant) {
            Ok(plan) => {
                execute_allow_path(&self.state.task_execution_service, runtime, task, &plan)
            }
            Err(reason) => execute_deny_path(
                &self.state.task_execution_service,
                task,
                reason,
                "POLICY_DENIED",
            ),
        }
    }

    pub(super) fn ensure_session_access(
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
