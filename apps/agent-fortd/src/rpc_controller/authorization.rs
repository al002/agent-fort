use std::collections::HashSet;
use std::sync::Arc;

use super::*;

pub(super) fn authorize_interactive(
    normalized: af_core::NormalizedOperation,
    active_policy: &ActivePolicy,
    session_grant: &SessionGrantState,
) -> Result<AuthorizationResult, RpcResponse> {
    let requested = requested_from_normalized(&normalized, active_policy);
    let evaluator = CapabilityPolicyEvaluator;
    match evaluator.decide(
        &requested,
        &session_grant.capabilities,
        &active_policy.policy,
        EvaluationMode::INTERACTIVE,
    ) {
        CapabilityDecision::Allow => {
            match compile_allow_plan(normalized, requested, active_policy, session_grant) {
                Ok(plan) => Ok(AuthorizationResult::Allow(Box::new(plan))),
                Err(reason) => Ok(AuthorizationResult::Deny {
                    reason,
                    code: "POLICY_DENIED",
                }),
            }
        }
        CapabilityDecision::Ask { delta, reason } => {
            Ok(AuthorizationResult::Ask(Box::new(AskExecutionPlan {
                requested,
                delta,
                reason,
                session_grant_revision: session_grant.revision,
                policy_revision: active_policy.policy.revision,
            })))
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

pub(super) fn compile_allow_plan(
    normalized: af_core::NormalizedOperation,
    requested: RequestedCapabilities,
    active_policy: &ActivePolicy,
    session_grant: &SessionGrantState,
) -> Result<AllowExecutionPlan, String> {
    if !capability_set_within_policy(
        &session_grant.capabilities,
        &active_policy.policy.capabilities,
    ) {
        return Err("session_grant exceeds policy".to_string());
    }

    let by_session = intersect_requested_with_capabilities(&requested, &session_grant.capabilities);
    let effective =
        intersect_requested_with_capabilities(&by_session, &active_policy.policy.capabilities);

    let selected = BackendSelector
        .select(&effective, &active_policy.policy)
        .map_err(|error| format!("backend selection failed: {error}"))?;

    let runtime_plan = RuntimeCompiler
        .compile(&selected, &effective, &active_policy.policy)
        .map_err(|error| format!("runtime compile failed: {error}"))?;

    Ok(AllowExecutionPlan {
        normalized,
        requested,
        effective,
        runtime_plan,
        session_grant_revision: session_grant.revision,
        policy_revision: active_policy.policy.revision,
    })
}

pub(super) fn requested_from_normalized(
    normalized: &af_core::NormalizedOperation,
    active_policy: &ActivePolicy,
) -> RequestedCapabilities {
    let extractor = CapabilityExtractor::default();
    let mut requested = extractor.from_operation(normalized);
    if !active_policy.command_rules.rules.is_empty() {
        let rule_engine = CommandRuleEngine::new(Arc::clone(&active_policy.command_rules));
        requested.merge(rule_engine.from_operation(normalized));
        clear_unclassified_unknown_covered_by_rules(&mut requested);
    }
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

pub(super) fn clear_unclassified_unknown_covered_by_rules(requested: &mut RequestedCapabilities) {
    let covered_commands: HashSet<String> = requested
        .reason_codes
        .iter()
        .filter_map(|code| {
            code.strip_prefix("rule.command:")
                .map(std::string::ToString::to_string)
        })
        .collect();
    if covered_commands.is_empty() {
        return;
    }

    let mut removed_unclassified = false;
    requested.reason_codes.retain(|code| {
        if code.starts_with("rule.command:") {
            return false;
        }
        if let Some(command_raw) = code.strip_prefix("command.unclassified:")
            && covered_commands.contains(command_raw)
        {
            removed_unclassified = true;
            return false;
        }
        true
    });

    if !removed_unclassified {
        return;
    }

    let has_remaining_unclassified = requested
        .reason_codes
        .iter()
        .any(|code| code.starts_with("command.unclassified:"));
    let has_other_unknown_reason = requested
        .reason_codes
        .iter()
        .any(|code| reason_implies_unknown_except_unclassified(code));

    if !has_remaining_unclassified && !has_other_unknown_reason {
        requested.unknown = false;
    }
}

fn reason_implies_unknown_except_unclassified(code: &str) -> bool {
    code == "net.endpoint_unknown"
        || code == "operation.unknown_kind"
        || code == "redirect.unknown"
        || code == "redirect.target_missing"
        || code == "parser.has_error"
        || code == "parser.failed"
        || code == "exec.argv_empty"
        || code == "exec.command_missing"
        || code == "command.binary_missing"
        || code.starts_with("dynamic.script:")
        || code == "dynamic.script.inline"
        || code.starts_with("command.dangerous:")
        || code.starts_with("command.risky:")
        || code.starts_with("rule.mark_unknown:")
        || code.starts_with("rule.net_host_missing:")
        || code.starts_with("rule.net_host_invalid:")
}
