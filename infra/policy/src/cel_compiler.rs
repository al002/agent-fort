use af_policy::{LoadedPolicies, LoadedRule, PolicyRule, RuleSource};
use cel::{Context, Program, Value};
use serde::Serialize;

use crate::{PolicyInfraError, PolicyInfraResult};

pub struct CompiledPolicies {
    pub revision: u64,
    pub loaded: LoadedPolicies,
    pub rules: Vec<CompiledRule>,
}

impl std::fmt::Debug for CompiledPolicies {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledPolicies")
            .field("revision", &self.revision)
            .field("loaded", &self.loaded)
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

impl CompiledPolicies {
    pub fn file_count(&self) -> usize {
        self.loaded.snapshot.file_count()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

pub struct CompiledRule {
    pub source: RuleSource,
    pub rule: PolicyRule,
    pub referenced_variables: Vec<String>,
    pub referenced_functions: Vec<String>,
    program: Program,
}

impl std::fmt::Debug for CompiledRule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledRule")
            .field("source", &self.source)
            .field("rule", &self.rule)
            .field("referenced_variables", &self.referenced_variables)
            .field("referenced_functions", &self.referenced_functions)
            .finish_non_exhaustive()
    }
}

impl CompiledRule {
    pub fn evaluate<T>(&self, activation: &T) -> PolicyInfraResult<bool>
    where
        T: Serialize,
    {
        let value = cel::to_value(activation)?;
        let context = context_from_root_value(value)?;
        let result =
            self.program
                .execute(&context)
                .map_err(|error| PolicyInfraError::CelExecution {
                    rule_id: self.rule.id.clone(),
                    message: error.to_string(),
                })?;
        match result {
            Value::Bool(value) => Ok(value),
            other => Err(PolicyInfraError::NonBooleanResult {
                rule_id: self.rule.id.clone(),
                actual_type: format!("{:?}", other.type_of()),
            }),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CelCompiler;

impl CelCompiler {
    pub fn compile(
        &self,
        loaded: LoadedPolicies,
        revision: u64,
    ) -> PolicyInfraResult<CompiledPolicies> {
        let rules = loaded
            .rules
            .iter()
            .map(|rule| self.compile_rule(rule))
            .collect::<PolicyInfraResult<Vec<_>>>()?;

        Ok(CompiledPolicies {
            revision,
            loaded,
            rules,
        })
    }

    fn compile_rule(&self, loaded_rule: &LoadedRule) -> PolicyInfraResult<CompiledRule> {
        let program = Program::compile(loaded_rule.rule.when.as_str()).map_err(|error| {
            PolicyInfraError::CelCompile {
                rule_id: loaded_rule.rule.id.clone(),
                path: loaded_rule.source.relative_path.clone(),
                message: error.to_string(),
            }
        })?;
        let references = program.references();
        let mut referenced_variables = references
            .variables()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        referenced_variables.sort();
        let mut referenced_functions = references
            .functions()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        referenced_functions.sort();

        Ok(CompiledRule {
            source: loaded_rule.source.clone(),
            rule: loaded_rule.rule.clone(),
            referenced_variables,
            referenced_functions,
            program,
        })
    }
}

fn context_from_root_value(value: Value) -> PolicyInfraResult<Context<'static>> {
    let mut context = Context::default();
    match value {
        Value::Map(map) => {
            for (key, value) in map.map.iter() {
                let cel::objects::Key::String(name) = key else {
                    return Err(PolicyInfraError::InvalidEvaluationContext);
                };
                context.add_variable_from_value(name.as_str(), value.clone());
            }
            Ok(context)
        }
        _ => Err(PolicyInfraError::InvalidEvaluationContext),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;

    use tempfile::TempDir;

    use crate::{PolicyDirectoryLoader, YamlParser};

    use super::*;

    #[test]
    fn compiles_and_evaluates_rule_against_serialized_context() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(
            root.join("base.yaml"),
            r#"
version: 1
rules:
  - id: check-network
    kind: approval
    when: facts.requires_network
    effect:
      decision: ask
"#,
        )
        .expect("write policy file");

        let snapshot = PolicyDirectoryLoader::new(&root)
            .load()
            .expect("load directory");
        let loaded = YamlParser.parse(snapshot).expect("parse policy file");
        let compiled = CelCompiler
            .compile(loaded, 1)
            .expect("compile policy rules");

        let activation = HashMap::from([("facts", HashMap::from([("requires_network", true)]))]);
        assert!(
            compiled.rules[0]
                .evaluate(&activation)
                .expect("evaluate rule")
        );
    }
}
