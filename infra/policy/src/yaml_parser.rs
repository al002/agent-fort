use std::collections::BTreeMap;
use std::fs;

use af_policy::{LoadedPolicies, LoadedRule, PolicyDirectorySnapshot, PolicyDocument, RuleSource};

use crate::{PolicyInfraError, PolicyInfraResult};

#[derive(Debug, Default, Clone, Copy)]
pub struct YamlParser;

impl YamlParser {
    pub fn parse(&self, snapshot: PolicyDirectorySnapshot) -> PolicyInfraResult<LoadedPolicies> {
        let mut rules = Vec::new();
        let mut seen_rule_ids = BTreeMap::<String, String>::new();

        for file in &snapshot.files {
            let raw = fs::read_to_string(&file.absolute_path)?;
            let document: PolicyDocument =
                serde_yaml::from_str(&raw).map_err(|error| PolicyInfraError::YamlParse {
                    path: file.relative_path.clone(),
                    message: error.to_string(),
                })?;

            if document.version != 1 {
                return Err(PolicyInfraError::InvalidDocument {
                    path: file.relative_path.clone(),
                    message: format!("unsupported policy document version: {}", document.version),
                });
            }

            for (rule_index, rule) in document.rules.into_iter().enumerate() {
                validate_rule(&file.relative_path, &rule.id, &rule.when)?;

                if let Some(first_path) =
                    seen_rule_ids.insert(rule.id.clone(), file.relative_path.clone())
                {
                    return Err(PolicyInfraError::DuplicateRuleId {
                        rule_id: rule.id,
                        first_path,
                        second_path: file.relative_path.clone(),
                    });
                }

                rules.push(LoadedRule {
                    source: RuleSource {
                        relative_path: file.relative_path.clone(),
                        rule_index,
                    },
                    rule,
                });
            }
        }

        Ok(LoadedPolicies { snapshot, rules })
    }
}

fn validate_rule(path: &str, rule_id: &str, when: &str) -> PolicyInfraResult<()> {
    if rule_id.trim().is_empty() {
        return Err(PolicyInfraError::InvalidDocument {
            path: path.to_string(),
            message: "rule id must not be empty".to_string(),
        });
    }
    if when.trim().is_empty() {
        return Err(PolicyInfraError::InvalidDocument {
            path: path.to_string(),
            message: format!("rule `{rule_id}` has empty when expression"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use crate::PolicyDirectoryLoader;

    use super::*;

    #[test]
    fn parses_policy_rules_in_snapshot_order() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(root.join("nested")).expect("create dirs");
        fs::write(
            root.join("a.yaml"),
            r#"
version: 1
rules:
  - id: allow-a
    kind: allow
    when: true
    effect:
      decision: allow
"#,
        )
        .expect("write first policy file");
        fs::write(
            root.join("nested/b.yaml"),
            r#"
version: 1
rules:
  - id: allow-b
    kind: allow
    when: false
    effect:
      decision: deny
"#,
        )
        .expect("write second policy file");

        let snapshot = PolicyDirectoryLoader::new(&root)
            .load()
            .expect("load directory snapshot");
        let loaded = YamlParser.parse(snapshot).expect("parse policy documents");

        let ids = loaded
            .rules
            .iter()
            .map(|loaded_rule| loaded_rule.rule.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["allow-a", "allow-b"]);
    }

    #[test]
    fn rejects_duplicate_rule_ids_across_files() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");

        for file_name in ["a.yaml", "b.yaml"] {
            fs::write(
                root.join(file_name),
                r#"
version: 1
rules:
  - id: duplicate
    kind: allow
    when: true
    effect:
      decision: allow
"#,
            )
            .expect("write duplicate rule file");
        }

        let snapshot = PolicyDirectoryLoader::new(&root)
            .load()
            .expect("load directory snapshot");
        let error = YamlParser
            .parse(snapshot)
            .expect_err("duplicate rule ids should fail");
        assert!(matches!(error, PolicyInfraError::DuplicateRuleId { .. }));
    }
}
