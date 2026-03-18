use af_policy::{PolicyApproval, PolicyDecision, PolicyRuleKind};
use af_policy_infra::CompiledRule;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionContract {
    pub decision: PolicyDecision,
    pub reason: Option<String>,
    pub runtime_backend: Option<String>,
    pub requirements: Vec<String>,
    pub approval: Option<PolicyApproval>,
    pub policy_revision: u64,
    pub matched_rule: Option<MatchedRuleInfo>,
    pub evaluation_trace: PolicyEvaluationTrace,
    pub fail_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRuleInfo {
    pub id: String,
    pub kind: PolicyRuleKind,
    pub priority: i64,
    pub relative_path: String,
    pub rule_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationTrace {
    pub candidate_rule_count: usize,
    pub matched_rule_ids: Vec<String>,
}

impl PolicyEvaluationTrace {
    pub fn new(candidate_rule_count: usize, matched_rule_ids: Vec<String>) -> Self {
        Self {
            candidate_rule_count,
            matched_rule_ids,
        }
    }
}

impl ExecutionContract {
    pub fn policy_audit_payload(&self) -> Value {
        json!({
            "candidate_rule_count": self.evaluation_trace.candidate_rule_count,
            "matched_rule_ids": self.evaluation_trace.matched_rule_ids,
            "final_decision": decision_to_str(self.decision),
            "reason": self.reason,
            "approval_summary": self.approval.as_ref().map(|approval| approval.summary.clone()),
            "policy_revision": self.policy_revision,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn policy_audit_payload_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.policy_audit_payload())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DecisionMapper;

impl DecisionMapper {
    pub fn map_matched_rule(
        &self,
        compiled_rule: &CompiledRule,
        revision: u64,
        trace: PolicyEvaluationTrace,
    ) -> ExecutionContract {
        ExecutionContract {
            decision: compiled_rule.rule.effect.decision,
            reason: compiled_rule.rule.effect.reason.clone(),
            runtime_backend: compiled_rule.rule.effect.runtime_backend.clone(),
            requirements: compiled_rule.rule.effect.requirements.clone(),
            approval: compiled_rule.rule.effect.approval.clone(),
            policy_revision: revision,
            matched_rule: Some(MatchedRuleInfo {
                id: compiled_rule.rule.id.clone(),
                kind: compiled_rule.rule.kind,
                priority: compiled_rule.rule.priority,
                relative_path: compiled_rule.source.relative_path.clone(),
                rule_index: compiled_rule.source.rule_index,
            }),
            evaluation_trace: trace,
            fail_closed: false,
        }
    }

    pub fn map_no_match(&self, revision: u64, trace: PolicyEvaluationTrace) -> ExecutionContract {
        ExecutionContract {
            decision: PolicyDecision::Allow,
            reason: Some("no policy rule matched".to_string()),
            runtime_backend: None,
            requirements: Vec::new(),
            approval: None,
            policy_revision: revision,
            matched_rule: None,
            evaluation_trace: trace,
            fail_closed: false,
        }
    }

    pub fn map_fail_closed(
        &self,
        revision: u64,
        reason: impl Into<String>,
        trace: PolicyEvaluationTrace,
    ) -> ExecutionContract {
        ExecutionContract {
            decision: PolicyDecision::Forbid,
            reason: Some(reason.into()),
            runtime_backend: None,
            requirements: Vec::new(),
            approval: None,
            policy_revision: revision,
            matched_rule: None,
            evaluation_trace: trace,
            fail_closed: true,
        }
    }
}

fn decision_to_str(decision: PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => "allow",
        PolicyDecision::Ask => "ask",
        PolicyDecision::Deny => "deny",
        PolicyDecision::Forbid => "forbid",
    }
}
