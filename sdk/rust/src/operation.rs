use std::collections::{BTreeMap, HashMap};

use af_rpc_proto::TaskOperation;
use prost_types::{Struct as ProstStruct, Value as ProstValue, value::Kind as ProstValueKind};
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use uuid::Uuid;

use crate::{Result, SdkError};

/// Schema identifier for untrusted action JSON accepted by the SDK converter.
pub const ACTION_SCHEMA_V1: &str = "af.action.v1";

/// Parsed and sanitized task request extracted from an untrusted action JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionTaskRequest {
    pub request_id: Option<String>,
    pub goal: Option<String>,
    pub options: ActionOptions,
    pub operation: TaskOperation,
}

/// Supported and normalized operation options for action conversion.
///
/// Unrecognized option keys from input are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionOptions {
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub stdin: Option<String>,
    pub shell: Option<String>,
}

/// Builds an `exec` task operation with a shell command string payload.
///
/// The resulting payload uses `{"command": "<your command>"}` format, which is
/// accepted by daemon task command extraction.
///
/// Valid operation kinds in capability-first mode are:
/// - `exec`
/// - `fs.read`
/// - `fs.write`
/// - `net`
/// - `tool`
///
/// This helper intentionally only builds `exec`.
///
/// # Examples
/// ```
/// use af_sdk::exec_operation;
///
/// let operation = exec_operation("echo hello");
/// assert_eq!(operation.kind, "exec");
/// ```
pub fn exec_operation(command: impl Into<String>) -> TaskOperation {
    let mut payload_fields = BTreeMap::new();
    payload_fields.insert(
        "command".to_string(),
        ProstValue {
            kind: Some(ProstValueKind::StringValue(command.into())),
        },
    );

    TaskOperation {
        kind: "exec".to_string(),
        payload: Some(ProstStruct {
            fields: payload_fields,
        }),
        options: None,
        labels: HashMap::new(),
    }
}

/// Builds a fixed action JSON for command execution.
///
/// This is intended for client flows where end users type shell commands and
/// the app wraps them into a stable JSON schema before conversion.
pub fn build_exec_action_json(command: impl AsRef<str>) -> String {
    let command = command.as_ref().trim();
    json!({
        "schema": ACTION_SCHEMA_V1,
        "request_id": Uuid::new_v4().to_string(),
        "session": {
            "mode": "create"
        },
        "task": {
            "goal": format!("exec: {command}"),
            "operation": {
                "kind": "exec",
                "payload": {
                    "command": command,
                },
                "options": {
                    "cwd": ".",
                    "env": {},
                }
            }
        }
    })
    .to_string()
}

/// Parses untrusted action JSON and extracts only supported fields.
///
/// Unknown fields are ignored instead of producing errors.
pub fn parse_action_json(input: &str) -> Result<ActionTaskRequest> {
    let value: JsonValue = serde_json::from_str(input)
        .map_err(|error| SdkError::Protocol(format!("invalid action json: {error}")))?;
    parse_action_value(&value)
}

/// Parses untrusted action value and extracts only supported fields.
///
/// Unknown fields are ignored instead of producing errors.
pub fn parse_action_value(value: &JsonValue) -> Result<ActionTaskRequest> {
    let root = value
        .as_object()
        .ok_or_else(|| SdkError::Protocol("action must be a JSON object".to_string()))?;

    let schema = root
        .get("schema")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| SdkError::Protocol("action schema is required".to_string()))?;
    if schema != ACTION_SCHEMA_V1 {
        return Err(SdkError::Protocol(format!(
            "unsupported action schema: {schema}"
        )));
    }

    let request_id = root
        .get("request_id")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(ToOwned::to_owned);

    let task = root
        .get("task")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| SdkError::Protocol("action task is required".to_string()))?;

    let goal = task
        .get("goal")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(ToOwned::to_owned);

    let operation = task
        .get("operation")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| SdkError::Protocol("action task.operation is required".to_string()))?;

    let kind = operation
        .get("kind")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| SdkError::Protocol("action task.operation.kind is required".to_string()))?
        .to_ascii_lowercase();

    let payload_object = operation
        .get("payload")
        .and_then(JsonValue::as_object)
        .cloned()
        .unwrap_or_default();
    let sanitized_payload = sanitize_payload(kind.as_str(), &payload_object)?;

    let options = parse_options(operation.get("options").and_then(JsonValue::as_object));

    let mut labels = HashMap::new();
    labels.insert("source".to_string(), "action.v1".to_string());
    if let Some(request_id) = request_id.as_ref() {
        labels.insert("request_id".to_string(), request_id.clone());
    }

    let payload = json_map_to_prost_struct(sanitized_payload).unwrap_or_else(|| ProstStruct {
        fields: BTreeMap::new(),
    });
    let operation = TaskOperation {
        kind,
        payload: Some(payload),
        options: options_to_prost_struct(&options),
        labels,
    };

    Ok(ActionTaskRequest {
        request_id,
        goal,
        options,
        operation,
    })
}

fn parse_options(options: Option<&JsonMap<String, JsonValue>>) -> ActionOptions {
    let Some(options) = options else {
        return ActionOptions::default();
    };

    let cwd = options
        .get("cwd")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(ToOwned::to_owned);

    let env = options
        .get("env")
        .and_then(JsonValue::as_object)
        .map(|env| {
            env.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|text| (key.clone(), text.to_string()))
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    let stdin = options
        .get("stdin")
        .and_then(JsonValue::as_str)
        .map(ToOwned::to_owned);

    let shell = options
        .get("shell")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(ToOwned::to_owned);

    ActionOptions {
        cwd,
        env,
        stdin,
        shell,
    }
}

fn sanitize_payload(
    kind: &str,
    payload: &JsonMap<String, JsonValue>,
) -> Result<JsonMap<String, JsonValue>> {
    match kind {
        "exec" => sanitize_exec_payload(payload),
        "fs.read" => sanitize_fs_read_payload(payload),
        "fs.write" => sanitize_fs_write_payload(payload),
        "net" => sanitize_net_payload(payload),
        "tool" => sanitize_tool_payload(payload),
        _ => Err(SdkError::Protocol(format!(
            "unsupported action operation kind: {kind}"
        ))),
    }
}

fn sanitize_exec_payload(
    payload: &JsonMap<String, JsonValue>,
) -> Result<JsonMap<String, JsonValue>> {
    let command = payload
        .get("command")
        .and_then(sanitize_command_value)
        .ok_or_else(|| SdkError::Protocol("action exec payload.command is required".to_string()))?;

    let mut sanitized = JsonMap::new();
    sanitized.insert("command".to_string(), command);
    Ok(sanitized)
}

fn sanitize_fs_read_payload(
    payload: &JsonMap<String, JsonValue>,
) -> Result<JsonMap<String, JsonValue>> {
    let mut sanitized = JsonMap::new();
    if let Some(path) = payload
        .get("path")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        sanitized.insert("path".to_string(), JsonValue::String(path.to_string()));
    }
    if let Some(paths) = payload
        .get("paths")
        .and_then(sanitize_string_array)
        .filter(|paths| !paths.is_empty())
    {
        sanitized.insert(
            "paths".to_string(),
            JsonValue::Array(paths.into_iter().map(JsonValue::String).collect()),
        );
    }
    if sanitized.is_empty() {
        return Err(SdkError::Protocol(
            "action fs.read payload.path or payload.paths is required".to_string(),
        ));
    }
    Ok(sanitized)
}

fn sanitize_fs_write_payload(
    payload: &JsonMap<String, JsonValue>,
) -> Result<JsonMap<String, JsonValue>> {
    let path = payload
        .get("path")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| {
            SdkError::Protocol("action fs.write payload.path is required".to_string())
        })?;

    let mut sanitized = JsonMap::new();
    sanitized.insert("path".to_string(), JsonValue::String(path.to_string()));

    if let Some(content) = payload.get("content").and_then(JsonValue::as_str) {
        sanitized.insert(
            "content".to_string(),
            JsonValue::String(content.to_string()),
        );
    }
    if let Some(append) = payload.get("append").and_then(JsonValue::as_bool) {
        sanitized.insert("append".to_string(), JsonValue::Bool(append));
    }

    Ok(sanitized)
}

fn sanitize_net_payload(
    payload: &JsonMap<String, JsonValue>,
) -> Result<JsonMap<String, JsonValue>> {
    let mut sanitized = JsonMap::new();

    if let Some(url) = payload
        .get("url")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        sanitized.insert("url".to_string(), JsonValue::String(url.to_string()));
    }
    if let Some(host) = payload
        .get("host")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        sanitized.insert("host".to_string(), JsonValue::String(host.to_string()));
    }
    if let Some(port) = payload.get("port").and_then(JsonValue::as_u64)
        && let Ok(port) = u16::try_from(port)
    {
        sanitized.insert("port".to_string(), JsonValue::Number(port.into()));
    }
    if let Some(protocol) = payload
        .get("protocol")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        sanitized.insert(
            "protocol".to_string(),
            JsonValue::String(protocol.to_string()),
        );
    }

    if !sanitized.contains_key("url") && !sanitized.contains_key("host") {
        return Err(SdkError::Protocol(
            "action net payload.url or payload.host is required".to_string(),
        ));
    }

    Ok(sanitized)
}

fn sanitize_tool_payload(
    payload: &JsonMap<String, JsonValue>,
) -> Result<JsonMap<String, JsonValue>> {
    let name = payload
        .get("name")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| SdkError::Protocol("action tool payload.name is required".to_string()))?;

    let mut sanitized = JsonMap::new();
    sanitized.insert("name".to_string(), JsonValue::String(name.to_string()));

    if let Some(args) = payload
        .get("args")
        .and_then(sanitize_string_array)
        .filter(|args| !args.is_empty())
    {
        sanitized.insert(
            "args".to_string(),
            JsonValue::Array(args.into_iter().map(JsonValue::String).collect()),
        );
    }
    if let Some(input) = payload.get("input").and_then(JsonValue::as_str) {
        sanitized.insert("input".to_string(), JsonValue::String(input.to_string()));
    }

    Ok(sanitized)
}

fn sanitize_command_value(value: &JsonValue) -> Option<JsonValue> {
    if let Some(command) = value.as_str().map(str::trim).filter(|raw| !raw.is_empty()) {
        return Some(JsonValue::String(command.to_string()));
    }

    sanitize_string_array(value).and_then(|parts| {
        if parts.is_empty() {
            None
        } else {
            Some(JsonValue::Array(
                parts.into_iter().map(JsonValue::String).collect(),
            ))
        }
    })
}

fn sanitize_string_array(value: &JsonValue) -> Option<Vec<String>> {
    let list = value.as_array()?;
    let sanitized = list
        .iter()
        .filter_map(|item| item.as_str().map(str::trim))
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    Some(sanitized)
}

fn options_to_prost_struct(options: &ActionOptions) -> Option<ProstStruct> {
    let mut fields = BTreeMap::new();
    if let Some(cwd) = options.cwd.as_ref() {
        fields.insert(
            "cwd".to_string(),
            ProstValue {
                kind: Some(ProstValueKind::StringValue(cwd.clone())),
            },
        );
    }
    if !options.env.is_empty() {
        let env_fields = options
            .env
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    ProstValue {
                        kind: Some(ProstValueKind::StringValue(value.clone())),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        fields.insert(
            "env".to_string(),
            ProstValue {
                kind: Some(ProstValueKind::StructValue(ProstStruct {
                    fields: env_fields,
                })),
            },
        );
    }
    if let Some(stdin) = options.stdin.as_ref() {
        fields.insert(
            "stdin".to_string(),
            ProstValue {
                kind: Some(ProstValueKind::StringValue(stdin.clone())),
            },
        );
    }
    if let Some(shell) = options.shell.as_ref() {
        fields.insert(
            "shell".to_string(),
            ProstValue {
                kind: Some(ProstValueKind::StringValue(shell.clone())),
            },
        );
    }
    if fields.is_empty() {
        None
    } else {
        Some(ProstStruct { fields })
    }
}

fn json_map_to_prost_struct(map: JsonMap<String, JsonValue>) -> Option<ProstStruct> {
    if map.is_empty() {
        return None;
    }
    Some(ProstStruct {
        fields: map
            .iter()
            .map(|(key, value)| (key.clone(), json_value_to_prost(value)))
            .collect::<BTreeMap<_, _>>(),
    })
}

fn json_value_to_prost(value: &JsonValue) -> ProstValue {
    match value {
        JsonValue::Null => ProstValue {
            kind: Some(ProstValueKind::NullValue(0)),
        },
        JsonValue::Bool(flag) => ProstValue {
            kind: Some(ProstValueKind::BoolValue(*flag)),
        },
        JsonValue::Number(number) => ProstValue {
            kind: Some(ProstValueKind::NumberValue(
                number.as_f64().unwrap_or_default(),
            )),
        },
        JsonValue::String(text) => ProstValue {
            kind: Some(ProstValueKind::StringValue(text.clone())),
        },
        JsonValue::Array(list) => ProstValue {
            kind: Some(ProstValueKind::ListValue(prost_types::ListValue {
                values: list.iter().map(json_value_to_prost).collect(),
            })),
        },
        JsonValue::Object(object) => ProstValue {
            kind: Some(ProstValueKind::StructValue(ProstStruct {
                fields: object
                    .iter()
                    .map(|(key, value)| (key.clone(), json_value_to_prost(value)))
                    .collect(),
            })),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exec_action_ignores_unknown_fields() {
        let input = json!({
            "schema": "af.action.v1",
            "request_id": "req-123",
            "ignored_root": "value",
            "task": {
                "goal": "exec: ls",
                "operation": {
                    "kind": "exec",
                    "payload": {
                        "command": "ls -la",
                        "ignored": "field"
                    },
                    "options": {
                        "cwd": "/tmp",
                        "env": {
                            "A": "B",
                            "DROP_ME": 1
                        },
                        "unknown_option": true
                    },
                    "labels": {
                        "danger": "ignored"
                    }
                }
            }
        });

        let parsed = parse_action_value(&input).expect("parse");
        assert_eq!(parsed.request_id.as_deref(), Some("req-123"));
        assert_eq!(parsed.goal.as_deref(), Some("exec: ls"));
        assert_eq!(parsed.options.cwd.as_deref(), Some("/tmp"));
        assert_eq!(parsed.options.env.get("A").map(String::as_str), Some("B"));
        assert!(!parsed.options.env.contains_key("DROP_ME"));
        assert_eq!(parsed.operation.kind, "exec");
        assert_eq!(
            parsed.operation.labels.get("source").map(String::as_str),
            Some("action.v1")
        );
        assert!(
            !parsed.operation.labels.contains_key("danger"),
            "untrusted labels should be ignored"
        );
    }

    #[test]
    fn parse_exec_action_accepts_command_argv() {
        let input = json!({
            "schema": "af.action.v1",
            "task": {
                "operation": {
                    "kind": "exec",
                    "payload": {
                        "command": ["bash", "-lc", "echo hello", 1, ""]
                    }
                }
            }
        });
        let parsed = parse_action_value(&input).expect("parse");
        let payload = parsed.operation.payload.expect("payload");
        let command = payload
            .fields
            .get("command")
            .expect("command")
            .kind
            .as_ref()
            .expect("kind");
        match command {
            ProstValueKind::ListValue(list) => {
                let values = list
                    .values
                    .iter()
                    .filter_map(|value| match value.kind.as_ref() {
                        Some(ProstValueKind::StringValue(text)) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(values, vec!["bash", "-lc", "echo hello"]);
            }
            other => panic!("unexpected command value kind: {other:?}"),
        }
    }

    #[test]
    fn parse_action_requires_supported_schema_and_kind() {
        let no_schema = json!({
            "task": { "operation": { "kind": "exec", "payload": { "command": "ls" } } }
        });
        let error = parse_action_value(&no_schema).expect_err("missing schema should fail");
        assert!(error.to_string().contains("schema is required"));

        let bad_kind = json!({
            "schema": "af.action.v1",
            "task": { "operation": { "kind": "unknown" } }
        });
        let error = parse_action_value(&bad_kind).expect_err("unknown kind should fail");
        assert!(
            error
                .to_string()
                .contains("unsupported action operation kind")
        );
    }

    #[test]
    fn parse_action_extracts_extended_options() {
        let input = json!({
            "schema": "af.action.v1",
            "task": {
                "operation": {
                    "kind": "exec",
                    "payload": {"command": "cat"},
                    "options": {
                        "cwd": "/work",
                        "env": {"A": "B"},
                        "stdin": "hello",
                        "shell": "/bin/bash",
                        "timeout_ms": 120000,
                        "pty": true,
                        "ignored": {"x": 1}
                    }
                }
            }
        });

        let parsed = parse_action_value(&input).expect("parse");
        assert_eq!(parsed.options.cwd.as_deref(), Some("/work"));
        assert_eq!(parsed.options.env.get("A").map(String::as_str), Some("B"));
        assert_eq!(parsed.options.stdin.as_deref(), Some("hello"));
        assert_eq!(parsed.options.shell.as_deref(), Some("/bin/bash"));
    }
}
