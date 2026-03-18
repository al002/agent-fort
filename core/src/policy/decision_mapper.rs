use af_policy::{PolicyApproval, PolicyDecision, PolicyRuleKind};
use af_policy_infra::CompiledRule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionContract {
    pub decision: PolicyDecision,
    pub reason: Option<String>,
    pub execution_profile: Option<String>,
    pub requirements: Vec<String>,
    pub approval: Option<PolicyApproval>,
    pub policy_revision: u64,
    pub matched_rule: Option<MatchedRuleInfo>,
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

#[derive(Debug, Clone, Copy, Default)]
pub struct DecisionMapper;

impl DecisionMapper {
    pub fn map_matched_rule(
        &self,
        compiled_rule: &CompiledRule,
        revision: u64,
    ) -> ExecutionContract {
        ExecutionContract {
            decision: compiled_rule.rule.effect.decision,
            reason: compiled_rule.rule.effect.reason.clone(),
            execution_profile: compiled_rule.rule.effect.execution_profile.clone(),
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
            fail_closed: false,
        }
    }

    pub fn map_no_match(&self, revision: u64) -> ExecutionContract {
        ExecutionContract {
            decision: PolicyDecision::Allow,
            reason: Some("no policy rule matched".to_string()),
            execution_profile: None,
            requirements: Vec::new(),
            approval: None,
            policy_revision: revision,
            matched_rule: None,
            fail_closed: false,
        }
    }

    pub fn map_fail_closed(&self, revision: u64, reason: impl Into<String>) -> ExecutionContract {
        ExecutionContract {
            decision: PolicyDecision::Forbid,
            reason: Some(reason.into()),
            execution_profile: None,
            requirements: Vec::new(),
            approval: None,
            policy_revision: revision,
            matched_rule: None,
            fail_closed: true,
        }
    }
}
