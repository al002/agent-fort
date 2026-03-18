use std::cmp::Ordering;

use af_policy_infra::{CompiledPolicies, CompiledRule};
use thiserror::Error;

use crate::operation::NormalizedOperation;

use super::{CelContextBuilder, DecisionMapper, ExecutionContract, RuleMatchFilter, RuleSorter};

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
        match self.try_evaluate(compiled, operation) {
            Ok(contract) => contract,
            Err(error) => self
                .decision_mapper
                .map_fail_closed(compiled.revision, error.to_string()),
        }
    }

    pub fn try_evaluate(
        &self,
        compiled: &CompiledPolicies,
        operation: &NormalizedOperation,
    ) -> Result<ExecutionContract, PolicyEvaluationError> {
        let mut candidates = compiled
            .rules
            .iter()
            .filter(|rule| self.rule_match_filter.matches_rule(&rule.rule, operation))
            .collect::<Vec<_>>();

        candidates.sort_by(|left, right| self.compare_compiled_rules(left, right));

        let context = self.context_builder.build(operation);
        for rule in candidates {
            let matched = rule
                .evaluate(&context)
                .map_err(|error| PolicyEvaluationError::CelEvaluation {
                    rule_id: rule.rule.id.clone(),
                    message: error.to_string(),
                })?;
            if matched {
                return Ok(self.decision_mapper.map_matched_rule(rule, compiled.revision));
            }
        }

        Ok(self.decision_mapper.map_no_match(compiled.revision))
    }

    fn compare_compiled_rules(&self, left: &CompiledRule, right: &CompiledRule) -> Ordering {
        self.rule_sorter
            .compare_rules(&left.rule, &left.source, &right.rule, &right.source)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyEvaluationError {
    #[error("policy CEL evaluation failed at rule `{rule_id}`: {message}")]
    CelEvaluation { rule_id: String, message: String },
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use af_policy::{
        LoadedPolicies, LoadedRule, PolicyApproval, PolicyApprovalItem, PolicyDecision, PolicyDirectorySnapshot,
        PolicyEffect, PolicyFile, PolicyMatch, PolicyRule, PolicyRuleKind, RuleSource,
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
                    execution_profile: Some("workspace_write_with_network".to_string()),
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
                    execution_profile: None,
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
        assert!(!contract.fail_closed);
    }

    #[test]
    fn defaults_to_allow_when_no_rule_matches() {
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
                execution_profile: None,
                requirements: Vec::new(),
                approval: None,
            },
        )]);

        let contract = PolicyEvaluator::default().evaluate(&compiled, &fetch_operation());
        assert_eq!(contract.decision, PolicyDecision::Allow);
        assert!(contract.matched_rule.is_none());
        assert!(!contract.fail_closed);
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
            "facts.requires_network + 1",
            PolicyEffect {
                decision: PolicyDecision::Allow,
                reason: None,
                execution_profile: None,
                requirements: Vec::new(),
                approval: None,
            },
        )]);

        let contract = PolicyEvaluator::default().evaluate(&compiled, &fetch_operation());
        assert_eq!(contract.decision, PolicyDecision::Forbid);
        assert!(contract.fail_closed);
        assert!(contract
            .reason
            .as_ref()
            .is_some_and(|reason| reason.contains("broken")));
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
                requires_network: Fact::Known(true),
                requires_write: Fact::Known(false),
                touches_policy_dir: Fact::Known(false),
                primary_host: Fact::Known("example.com".to_string()),
                affected_paths: Vec::new(),
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
