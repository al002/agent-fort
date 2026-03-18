use std::cmp::Ordering;

use af_policy::{LoadedRule, PolicyRule, PolicyRuleKind, RuleSource};

#[derive(Debug, Clone, Copy, Default)]
pub struct RuleSorter;

impl RuleSorter {
    pub fn sort_loaded_rules(&self, rules: &mut [LoadedRule]) {
        rules.sort_by(compare_loaded_rules);
    }

    pub fn compare_rules(
        &self,
        left_rule: &PolicyRule,
        left_source: &RuleSource,
        right_rule: &PolicyRule,
        right_source: &RuleSource,
    ) -> Ordering {
        compare_rule_keys(left_rule, left_source, right_rule, right_source)
    }
}

fn compare_loaded_rules(left: &LoadedRule, right: &LoadedRule) -> Ordering {
    compare_rule_keys(&left.rule, &left.source, &right.rule, &right.source)
}

fn compare_rule_keys(
    left_rule: &PolicyRule,
    left_source: &RuleSource,
    right_rule: &PolicyRule,
    right_source: &RuleSource,
    ) -> Ordering {
    right_rule
        .priority
        .cmp(&left_rule.priority)
        .then_with(|| kind_rank(left_rule.kind).cmp(&kind_rank(right_rule.kind)))
        .then_with(|| left_source.relative_path.cmp(&right_source.relative_path))
        .then_with(|| left_source.rule_index.cmp(&right_source.rule_index))
        .then_with(|| left_rule.id.cmp(&right_rule.id))
}

fn kind_rank(kind: PolicyRuleKind) -> u8 {
    match kind {
        PolicyRuleKind::Guardrail => 0,
        PolicyRuleKind::Deny => 1,
        PolicyRuleKind::Approval => 2,
        PolicyRuleKind::Allow => 3,
    }
}

#[cfg(test)]
mod tests {
    use af_policy::{PolicyDecision, PolicyEffect, PolicyMatch};

    use super::*;

    #[test]
    fn sorts_by_priority_kind_then_source() {
        let mut rules = vec![
            loaded("allow-low", PolicyRuleKind::Allow, 100, "z.yaml", 1),
            loaded("deny-low", PolicyRuleKind::Deny, 100, "a.yaml", 3),
            loaded("guardrail", PolicyRuleKind::Guardrail, 900, "b.yaml", 0),
            loaded("approval-low", PolicyRuleKind::Approval, 100, "a.yaml", 1),
        ];

        RuleSorter.sort_loaded_rules(&mut rules);
        let ordered_ids = rules.iter().map(|rule| rule.rule.id.as_str()).collect::<Vec<_>>();
        assert_eq!(
            ordered_ids,
            vec!["guardrail", "deny-low", "approval-low", "allow-low"]
        );
    }

    #[test]
    fn uses_path_and_index_as_stable_tie_break() {
        let mut rules = vec![
            loaded("r2", PolicyRuleKind::Allow, 10, "b.yaml", 0),
            loaded("r1", PolicyRuleKind::Allow, 10, "a.yaml", 1),
            loaded("r0", PolicyRuleKind::Allow, 10, "a.yaml", 0),
        ];
        RuleSorter.sort_loaded_rules(&mut rules);
        let ordered_ids = rules.iter().map(|rule| rule.rule.id.as_str()).collect::<Vec<_>>();
        assert_eq!(ordered_ids, vec!["r0", "r1", "r2"]);
    }

    fn loaded(
        id: &str,
        kind: PolicyRuleKind,
        priority: i64,
        path: &str,
        index: usize,
    ) -> LoadedRule {
        LoadedRule {
            source: RuleSource {
                relative_path: path.to_string(),
                rule_index: index,
            },
            rule: PolicyRule {
                id: id.to_string(),
                kind,
                priority,
                enabled: true,
                match_selector: PolicyMatch::default(),
                when: "true".to_string(),
                effect: PolicyEffect {
                    decision: PolicyDecision::Allow,
                    reason: None,
                    execution_profile: None,
                    requirements: Vec::new(),
                    approval: None,
                },
            },
        }
    }
}
