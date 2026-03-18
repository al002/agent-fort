use af_policy::{LoadedRule, PolicyMatch, PolicyRule};

use crate::operation::{Fact, NormalizedOperation};

#[derive(Debug, Clone, Copy, Default)]
pub struct RuleMatchFilter;

impl RuleMatchFilter {
    pub fn matches_rule(&self, rule: &PolicyRule, operation: &NormalizedOperation) -> bool {
        rule.enabled && matches_selector(&rule.match_selector, operation)
    }

    pub fn select_loaded<'a>(
        &self,
        rules: &'a [LoadedRule],
        operation: &NormalizedOperation,
    ) -> Vec<&'a LoadedRule> {
        rules.iter()
            .filter(|loaded| self.matches_rule(&loaded.rule, operation))
            .collect()
    }
}

fn matches_selector(selector: &PolicyMatch, operation: &NormalizedOperation) -> bool {
    if !selector.operation_kinds.is_empty()
        && !selector
            .operation_kinds
            .iter()
            .any(|kind| kind.eq_ignore_ascii_case(operation.intent.operation_kind()))
    {
        return false;
    }

    if !matches_bool(selector.interactive, operation.facts.interactive.as_ref()) {
        return false;
    }
    if !matches_bool(
        selector.requires_network,
        operation.facts.requires_network.as_ref(),
    ) {
        return false;
    }
    if !matches_bool(selector.requires_write, operation.facts.requires_write.as_ref()) {
        return false;
    }

    if !selector.tags.is_empty()
        && !selector.tags.iter().all(|required_tag| {
            operation
                .intent
                .tags
                .iter()
                .any(|tag| tag.eq_ignore_ascii_case(required_tag))
        })
    {
        return false;
    }

    true
}

fn matches_bool(expected: Option<bool>, actual: Fact<&bool>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    match actual {
        Fact::Known(value) => *value == expected,
        Fact::Unknown => true,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use af_policy::{PolicyDecision, PolicyEffect, PolicyMatch, PolicyRule, PolicyRuleKind};

    use super::*;
    use crate::operation::{Facts, Intent, OperationKind, RuntimeContext, RuntimePlatform};

    fn operation() -> NormalizedOperation {
        NormalizedOperation {
            intent: Intent {
                kind: OperationKind::Fetch,
                labels: BTreeMap::new(),
                tags: BTreeSet::from([String::from("network"), String::from("http")]),
                targets: Vec::new(),
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

    fn rule(match_selector: PolicyMatch) -> PolicyRule {
        PolicyRule {
            id: "r1".to_string(),
            kind: PolicyRuleKind::Approval,
            priority: 100,
            enabled: true,
            match_selector,
            when: "true".to_string(),
            effect: PolicyEffect {
                decision: PolicyDecision::Ask,
                reason: None,
                execution_profile: None,
                requirements: Vec::new(),
                approval: None,
            },
        }
    }

    #[test]
    fn filters_by_operation_kind_and_tags() {
        let op = operation();
        let rule = rule(PolicyMatch {
            operation_kinds: vec!["fetch".to_string()],
            interactive: None,
            requires_network: None,
            requires_write: None,
            tags: vec!["network".to_string()],
        });
        assert!(RuleMatchFilter.matches_rule(&rule, &op));
    }

    #[test]
    fn rejects_rule_on_known_boolean_mismatch() {
        let op = operation();
        let rule = rule(PolicyMatch {
            operation_kinds: vec!["fetch".to_string()],
            interactive: None,
            requires_network: Some(false),
            requires_write: None,
            tags: Vec::new(),
        });
        assert!(!RuleMatchFilter.matches_rule(&rule, &op));
    }

    #[test]
    fn keeps_rule_when_fact_is_unknown() {
        let mut op = operation();
        op.facts.requires_network = Fact::Unknown;
        let rule = rule(PolicyMatch {
            operation_kinds: vec!["fetch".to_string()],
            interactive: None,
            requires_network: Some(true),
            requires_write: None,
            tags: Vec::new(),
        });
        assert!(RuleMatchFilter.matches_rule(&rule, &op));
    }
}
