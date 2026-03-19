use serde_json::{Value, json};

use crate::operation::{Fact, NormalizedOperation};

#[derive(Debug, Clone, Copy, Default)]
pub struct CelContextBuilder;

impl CelContextBuilder {
    pub fn build(&self, operation: &NormalizedOperation) -> Value {
        let targets = operation
            .intent
            .targets
            .iter()
            .map(|target| {
                json!({
                    "kind": target.kind.as_str(),
                    "value": target.value,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "request": {
                "kind": operation.intent.kind.as_str(),
                "labels": operation.intent.labels,
                "tags": operation.intent.tags,
                "targets": targets,
            },
            "facts": {
                "interactive": fact_to_value(operation.facts.interactive.as_ref()),
                "safe_file_read": fact_to_value(operation.facts.safe_file_read.as_ref()),
                "safe_file_write": fact_to_value(operation.facts.safe_file_write.as_ref()),
                "system_file_read": fact_to_value(operation.facts.system_file_read.as_ref()),
                "system_file_write": fact_to_value(operation.facts.system_file_write.as_ref()),
                "network_access": fact_to_value(operation.facts.network_access.as_ref()),
                "system_admin": fact_to_value(operation.facts.system_admin.as_ref()),
                "process_control": fact_to_value(operation.facts.process_control.as_ref()),
                "credential_access": fact_to_value(operation.facts.credential_access.as_ref()),
                "unknown_intent": fact_to_value(operation.facts.unknown_intent.as_ref()),
                "touches_policy_dir": fact_to_value(operation.facts.touches_policy_dir.as_ref()),
                "primary_host": fact_to_value(operation.facts.primary_host.as_ref()),
                "command_text": fact_to_value(operation.facts.command_text.as_ref()),
                "affected_paths": operation
                    .facts
                    .affected_paths
                    .iter()
                    .map(|path| Value::String(path.display().to_string()))
                    .collect::<Vec<_>>(),
                "reason_codes": operation
                    .facts
                    .reason_codes
                    .iter()
                    .map(|code| Value::String(code.clone()))
                    .collect::<Vec<_>>(),
            },
            "runtime": {
                "platform": operation.runtime.platform.as_str(),
                "daemon_instance_id": operation.runtime.daemon_instance_id,
                "policy_dir": operation.runtime.policy_dir.display().to_string(),
                "workspace_root": operation
                    .runtime
                    .workspace_root
                    .as_ref()
                    .map(|path| path.display().to_string()),
            },
        })
    }
}

fn fact_to_value<T>(fact: Fact<&T>) -> Value
where
    T: Clone + Into<Value>,
{
    match fact {
        Fact::Known(value) => value.clone().into(),
        Fact::Unknown => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use super::*;
    use crate::operation::{
        Facts, Intent, OperationKind, RuntimeContext, RuntimePlatform, Target, TargetKind,
    };

    #[test]
    fn builds_stable_context_shape_for_cel() {
        let operation = NormalizedOperation {
            intent: Intent {
                kind: OperationKind::Fetch,
                labels: BTreeMap::from([(String::from("risk"), String::from("high"))]),
                tags: BTreeSet::from([String::from("network")]),
                targets: vec![Target {
                    kind: TargetKind::Host,
                    value: "example.com".to_string(),
                }],
            },
            facts: Facts {
                interactive: Fact::Known(false),
                safe_file_read: Fact::Known(false),
                safe_file_write: Fact::Unknown,
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
                affected_paths: vec![PathBuf::from("/work/downloads/out.txt")],
                reason_codes: vec!["exec.network_command".to_string()],
            },
            runtime: RuntimeContext {
                platform: RuntimePlatform::Linux,
                daemon_instance_id: "daemon-1".to_string(),
                policy_dir: PathBuf::from("/work/policies"),
                workspace_root: Some(PathBuf::from("/work")),
            },
        };

        let context = CelContextBuilder.build(&operation);
        let object = context.as_object().expect("context must be object");

        assert_eq!(
            object["request"]["kind"],
            Value::String("fetch".to_string())
        );
        assert_eq!(object["facts"]["network_access"], Value::Bool(true));
        assert_eq!(object["facts"]["safe_file_write"], Value::Null);
        assert_eq!(object["facts"]["system_admin"], Value::Bool(false));
        assert_eq!(
            object["runtime"]["platform"],
            Value::String("linux".to_string())
        );
    }

    #[test]
    fn maps_unknown_fact_to_null() {
        let operation = NormalizedOperation {
            intent: Intent {
                kind: OperationKind::Unknown,
                labels: BTreeMap::new(),
                tags: BTreeSet::new(),
                targets: Vec::new(),
            },
            facts: Facts {
                interactive: Fact::Unknown,
                safe_file_read: Fact::Unknown,
                safe_file_write: Fact::Unknown,
                system_file_read: Fact::Unknown,
                system_file_write: Fact::Unknown,
                network_access: Fact::Unknown,
                system_admin: Fact::Unknown,
                process_control: Fact::Unknown,
                credential_access: Fact::Unknown,
                unknown_intent: Fact::Unknown,
                touches_policy_dir: Fact::Unknown,
                primary_host: Fact::Unknown,
                command_text: Fact::Unknown,
                affected_paths: Vec::new(),
                reason_codes: Vec::new(),
            },
            runtime: RuntimeContext {
                platform: RuntimePlatform::Unknown,
                daemon_instance_id: "daemon-1".to_string(),
                policy_dir: PathBuf::from("/work/policies"),
                workspace_root: None,
            },
        };

        let context = CelContextBuilder.build(&operation);
        let facts = context
            .as_object()
            .and_then(|obj| obj.get("facts"))
            .and_then(Value::as_object)
            .expect("facts object");
        assert_eq!(facts.get("interactive"), Some(&Value::Null));
        assert_eq!(facts.get("network_access"), Some(&Value::Null));
        assert_eq!(facts.get("primary_host"), Some(&Value::Null));
        assert_eq!(facts.get("system_admin"), Some(&Value::Null));
    }
}
