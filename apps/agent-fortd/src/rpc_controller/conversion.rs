use super::*;

pub(super) fn rpc_approval_decision_to_domain(
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

pub(super) fn to_proto_approval(approval: af_approval::Approval) -> RpcApproval {
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

pub(super) fn to_proto_approval_status(status: af_approval::ApprovalStatus) -> RpcApprovalStatus {
    match status {
        af_approval::ApprovalStatus::Pending => RpcApprovalStatus::Pending,
        af_approval::ApprovalStatus::Approved => RpcApprovalStatus::Approved,
        af_approval::ApprovalStatus::Denied => RpcApprovalStatus::Denied,
        af_approval::ApprovalStatus::Expired => RpcApprovalStatus::Expired,
        af_approval::ApprovalStatus::Cancelled => RpcApprovalStatus::Cancelled,
    }
}

pub(super) fn to_proto_session(session: af_session::Session) -> Session {
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

pub(super) fn to_proto_task(task: af_task::Task) -> Task {
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
