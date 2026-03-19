use std::cmp::Ordering;

use af_policy::PolicyDecision;
use af_policy_infra::{CompiledPolicies, CompiledRule};
use thiserror::Error;

use crate::operation::NormalizedOperation;

use super::{
    CelContextBuilder, DecisionMapper, ExecutionContract, PolicyEvaluationTrace, RuleMatchFilter,
    RuleSorter,
};

#[derive(Debug, Clone)]
pub struct PolicyEvaluator {
    context_builder: CelContextBuilder,
    rule_match_filter: RuleMatchFilter,
    rule_sorter: RuleSorter,
    decision_mapper: DecisionMapper,
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self {
            context_builder: CelContextBuilder,
            rule_match_filter: RuleMatchFilter,
            rule_sorter: RuleSorter,
            decision_mapper: DecisionMapper,
        }
    }
}

impl PolicyEvaluator {
    pub fn evaluate(
        &self,
        compiled: &CompiledPolicies,
        operation: &NormalizedOperation,
    ) -> ExecutionContract {
        match self.try_evaluate_with_trace(compiled, operation) {
            Ok(contract) => contract,
            Err(error) => self.decision_mapper.map_fail_closed(
                compiled.revision,
                error.error.to_string(),
                error.trace,
            ),
        }
    }

    pub fn try_evaluate(
        &self,
        compiled: &CompiledPolicies,
        operation: &NormalizedOperation,
    ) -> Result<ExecutionContract, PolicyEvaluationError> {
        self.try_evaluate_with_trace(compiled, operation)
            .map_err(|error| error.error)
    }

    fn try_evaluate_with_trace(
        &self,
        compiled: &CompiledPolicies,
        operation: &NormalizedOperation,
    ) -> Result<ExecutionContract, PolicyEvaluationFailure> {
        let force_unknown_intent_ask = requires_unknown_intent_approval(operation);
        let mut candidates = compiled
            .rules
            .iter()
            .filter(|rule| self.rule_match_filter.matches_rule(&rule.rule, operation))
            .collect::<Vec<_>>();

        let candidate_rule_count = candidates.len();
        candidates.sort_by(|left, right| self.compare_compiled_rules(left, right));

        let context = self.context_builder.build(operation);
        let mut matched_rule_ids = Vec::new();
        for rule in candidates {
            let matched = rule
                .evaluate(&context)
                .map_err(|error| PolicyEvaluationFailure {
                    error: PolicyEvaluationError::CelEvaluation {
                        rule_id: rule.rule.id.clone(),
                        message: error.to_string(),
                    },
                    trace: PolicyEvaluationTrace::new(
                        candidate_rule_count,
                        matched_rule_ids.clone(),
                    ),
                })?;
            if matched {
                matched_rule_ids.push(rule.rule.id.clone());
                let mut contract = self.decision_mapper.map_matched_rule(
                    rule,
                    compiled.revision,
                    PolicyEvaluationTrace::new(candidate_rule_count, matched_rule_ids),
                );
                if force_unknown_intent_ask && contract.decision == PolicyDecision::Allow {
                    contract.decision = PolicyDecision::Ask;
                    contract.reason = Some("unknown command intent requires approval".to_string());
                }
                return Ok(contract);
            }
        }

        let mut contract = self.decision_mapper.map_no_match(
            compiled.revision,
            PolicyEvaluationTrace::new(candidate_rule_count, matched_rule_ids),
        );
        if force_unknown_intent_ask {
            contract.reason = Some("unknown command intent requires approval".to_string());
        }
        Ok(contract)
    }

    fn compare_compiled_rules(&self, left: &CompiledRule, right: &CompiledRule) -> Ordering {
        self.rule_sorter
            .compare_rules(&left.rule, &left.source, &right.rule, &right.source)
    }
}

fn requires_unknown_intent_approval(operation: &NormalizedOperation) -> bool {
    matches!(
        operation.facts.unknown_intent,
        crate::operation::Fact::Known(true)
    )
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyEvaluationError {
    #[error("policy CEL evaluation failed at rule `{rule_id}`: {message}")]
    CelEvaluation { rule_id: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyEvaluationFailure {
    error: PolicyEvaluationError,
    trace: PolicyEvaluationTrace,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use af_policy::{
        LoadedPolicies, LoadedRule, PolicyApproval, PolicyApprovalItem, PolicyDecision,
        PolicyDirectorySnapshot, PolicyEffect, PolicyFile, PolicyMatch, PolicyRule, PolicyRuleKind,
        RuleSource,
    };
    use af_policy_infra::CelCompiler;

    use super::*;
    use crate::operation::{
        Fact, Facts, Intent, OperationKind, RuntimeContext, RuntimePlatform, Target, TargetKind,
    };

    #[test]
    fn applies_sorted_rule_and_projects_effect() {
        let compiled = compiled(vec![
            rule(
                "allow",
                PolicyRuleKind::Allow,
                100,
                PolicyMatch {
                    operation_kinds: vec!["fetch".to_string()],
                    interactive: None,
                    requires_network: Some(true),
                    requires_write: None,
                    tags: vec![],
                },
                "true",
                PolicyEffect {
                    decision: PolicyDecision::Allow,
                    reason: Some("allow network".to_string()),
                    runtime_backend: Some("sandbox".to_string()),
                    requirements: vec!["audit".to_string()],
                    approval: None,
                },
            ),
            rule(
                "ask",
                PolicyRuleKind::Approval,
                200,
                PolicyMatch {
                    operation_kinds: vec!["fetch".to_string()],
                    interactive: None,
                    requires_network: Some(true),
                    requires_write: None,
                    tags: vec![],
                },
                "true",
                PolicyEffect {
                    decision: PolicyDecision::Ask,
                    reason: Some("needs approval".to_string()),
                    runtime_backend: None,
                    requirements: Vec::new(),
                    approval: Some(PolicyApproval {
                        summary: "Need approval".to_string(),
                        details: None,
                        items: vec![PolicyApprovalItem {
                            kind: "network".to_string(),
                            target: Some("example.com".to_string()),
                            summary: "outbound request".to_string(),
                        }],
                    }),
                },
            ),
        ]);

        let contract = PolicyEvaluator::default().evaluate(&compiled, &fetch_operation());

        assert_eq!(contract.decision, PolicyDecision::Ask);
        assert_eq!(contract.policy_revision, 1);
        assert_eq!(
            contract.matched_rule.as_ref().map(|rule| rule.id.as_str()),
            Some("ask")
        );
        assert_eq!(contract.evaluation_trace.candidate_rule_count, 2);
        assert_eq!(
            contract.evaluation_trace.matched_rule_ids,
            vec!["ask".to_string()]
        );
        let payload = contract.policy_audit_payload();
        assert_eq!(payload["candidate_rule_count"], 2);
        assert_eq!(payload["matched_rule_ids"][0], "ask");
        assert_eq!(payload["final_decision"], "ask");
        assert_eq!(payload["policy_revision"], 1);
        assert!(!contract.fail_closed);
    }

    #[test]
    fn defaults_to_ask_when_no_rule_matches() {
        let compiled = compiled(vec![rule(
            "write-only",
            PolicyRuleKind::Deny,
            100,
            PolicyMatch {
                operation_kinds: vec!["file.write".to_string()],
                interactive: None,
                requires_network: None,
                requires_write: Some(true),
                tags: vec![],
            },
            "true",
            PolicyEffect {
                decision: PolicyDecision::Deny,
                reason: Some("write blocked".to_string()),
                runtime_backend: None,
                requirements: Vec::new(),
                approval: None,
            },
        )]);

        let contract = PolicyEvaluator::default().evaluate(&compiled, &fetch_operation());
        assert_eq!(contract.decision, PolicyDecision::Ask);
        assert!(contract.matched_rule.is_none());
        assert_eq!(contract.evaluation_trace.candidate_rule_count, 0);
        assert!(contract.evaluation_trace.matched_rule_ids.is_empty());
        assert!(!contract.fail_closed);
    }

    #[test]
    fn forces_ask_when_unknown_intent_matches_allow_rule() {
        let compiled = compiled(vec![rule(
            "allow-all-fetch",
            PolicyRuleKind::Allow,
            100,
            PolicyMatch {
                operation_kinds: vec!["fetch".to_string()],
                interactive: None,
                requires_network: None,
                requires_write: None,
                tags: vec![],
            },
            "true",
            PolicyEffect {
                decision: PolicyDecision::Allow,
                reason: Some("allow fetch".to_string()),
                runtime_backend: None,
                requirements: Vec::new(),
                approval: None,
            },
        )]);

        let mut operation = fetch_operation();
        operation.facts.unknown_intent = Fact::Known(true);

        let contract = PolicyEvaluator::default().evaluate(&compiled, &operation);
        assert_eq!(contract.decision, PolicyDecision::Ask);
        assert_eq!(
            contract.reason.as_deref(),
            Some("unknown command intent requires approval")
        );
        assert_eq!(
            contract.matched_rule.as_ref().map(|rule| rule.id.as_str()),
            Some("allow-all-fetch")
        );
    }

    #[test]
    fn fail_closed_on_cel_error() {
        let compiled = compiled(vec![rule(
            "broken",
            PolicyRuleKind::Guardrail,
            1000,
            PolicyMatch {
                operation_kinds: vec!["fetch".to_string()],
                interactive: None,
                requires_network: None,
                requires_write: None,
                tags: vec![],
            },
            "facts.network_access + 1",
            PolicyEffect {
                decision: PolicyDecision::Allow,
                reason: None,
                runtime_backend: None,
                requirements: Vec::new(),
                approval: None,
            },
        )]);

        let contract = PolicyEvaluator::default().evaluate(&compiled, &fetch_operation());
        assert_eq!(contract.decision, PolicyDecision::Forbid);
        assert_eq!(contract.evaluation_trace.candidate_rule_count, 1);
        assert!(contract.evaluation_trace.matched_rule_ids.is_empty());
        assert!(contract.fail_closed);
        assert!(
            contract
                .reason
                .as_ref()
                .is_some_and(|reason| reason.contains("broken"))
        );
    }

    fn compiled(rules: Vec<LoadedRule>) -> CompiledPolicies {
        let loaded = LoadedPolicies {
            snapshot: PolicyDirectorySnapshot {
                root: PathBuf::from("/work/policies"),
                files: vec![PolicyFile {
                    absolute_path: PathBuf::from("/work/policies/base.yaml"),
                    relative_path: "base.yaml".to_string(),
                }],
            },
            rules,
        };
        CelCompiler
            .compile(loaded, 1)
            .expect("compile test policy rules")
    }

    fn rule(
        id: &str,
        kind: PolicyRuleKind,
        priority: i64,
        match_selector: PolicyMatch,
        when: &str,
        effect: PolicyEffect,
    ) -> LoadedRule {
        LoadedRule {
            source: RuleSource {
                relative_path: "base.yaml".to_string(),
                rule_index: 0,
            },
            rule: PolicyRule {
                id: id.to_string(),
                kind,
                priority,
                enabled: true,
                match_selector,
                when: when.to_string(),
                effect,
            },
        }
    }

    fn fetch_operation() -> NormalizedOperation {
        NormalizedOperation {
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
                safe_file_write: Fact::Known(false),
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
                affected_paths: Vec::new(),
                reason_codes: Vec::new(),
            },
            runtime: RuntimeContext {
                platform: RuntimePlatform::Linux,
                daemon_instance_id: "daemon-1".to_string(),
                policy_dir: PathBuf::from("/work/policies"),
                workspace_root: Some(PathBuf::from("/work")),
            },
        }
    }
}
