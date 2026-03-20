use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;
use thiserror::Error;

use super::{NormalizedCommand, NormalizedOperation, OperationKind, RuntimeContext};

#[derive(Debug, Clone, PartialEq)]
pub struct RawOperation {
    pub kind: String,
    pub payload: Value,
    pub options: Value,
    pub labels: BTreeMap<String, String>,
}

impl RawOperation {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            payload: Value::Object(Default::default()),
            options: Value::Object(Default::default()),
            labels: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OperationNormalizer;

impl OperationNormalizer {
    pub fn normalize(
        &self,
        raw: RawOperation,
        runtime: RuntimeContext,
    ) -> Result<NormalizedOperation, NormalizeError> {
        if raw.kind.trim().is_empty() {
            return Err(NormalizeError::EmptyKind);
        }

        let kind = normalize_kind(&raw.kind);
        let command = extract_command(&raw.payload, &raw.options)?;
        let cwd = extract_cwd(
            &raw.payload,
            &raw.options,
            runtime.workspace_root.as_deref(),
        );
        let env = extract_env(&raw.payload, &raw.options)?;
        let stdin = extract_stdin(&raw.payload, &raw.options)?;
        let shell = extract_shell(&raw.payload, &raw.options)?;

        let mut paths = extract_paths(&raw.payload, runtime.workspace_root.as_deref());
        paths.extend(extract_paths(
            &raw.options,
            runtime.workspace_root.as_deref(),
        ));
        paths = dedupe_paths(paths);

        let mut hosts = extract_hosts(&raw.payload);
        hosts.extend(extract_hosts(&raw.options));
        hosts = dedupe_strings(hosts);

        let mut reason_codes = Vec::new();
        let mut unknown = false;

        if matches!(kind, OperationKind::Unknown) {
            unknown = true;
            reason_codes.push("operation.kind_unknown".to_string());
        }
        if matches!(kind, OperationKind::Exec) && command.is_none() {
            unknown = true;
            reason_codes.push("exec.command_missing".to_string());
        }

        Ok(NormalizedOperation {
            kind,
            payload: raw.payload,
            options: raw.options,
            labels: raw.labels,
            command,
            cwd,
            env,
            stdin,
            shell,
            paths,
            hosts,
            reason_codes,
            unknown,
            runtime,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    #[error("operation kind must not be empty")]
    EmptyKind,
    #[error("operation command is invalid: {message}")]
    InvalidCommand { message: String },
    #[error("operation env is invalid: {message}")]
    InvalidEnv { message: String },
    #[error("operation stdin is invalid: {message}")]
    InvalidStdin { message: String },
    #[error("operation shell is invalid: {message}")]
    InvalidShell { message: String },
}

fn normalize_kind(kind: &str) -> OperationKind {
    let kind = kind.trim().to_ascii_lowercase();
    match kind.as_str() {
        "exec" => OperationKind::Exec,
        "fs.read" => OperationKind::FsRead,
        "fs.write" => OperationKind::FsWrite,
        "net" => OperationKind::Net,
        "tool" => OperationKind::Tool,
        _ => OperationKind::Unknown,
    }
}

fn extract_command(
    payload: &Value,
    options: &Value,
) -> Result<Option<NormalizedCommand>, NormalizeError> {
    let value = find_value(payload, "command").or_else(|| find_value(options, "command"));
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        Value::String(command) => {
            let trimmed = command.trim();
            if trimmed.is_empty() {
                return Err(NormalizeError::InvalidCommand {
                    message: "command string must not be empty".to_string(),
                });
            }
            Ok(Some(NormalizedCommand::Shell(trimmed.to_string())))
        }
        Value::Array(parts) => {
            let mut argv = Vec::with_capacity(parts.len());
            for (index, part) in parts.iter().enumerate() {
                let Some(value) = part.as_str() else {
                    return Err(NormalizeError::InvalidCommand {
                        message: format!("command[{index}] must be string"),
                    });
                };
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(NormalizeError::InvalidCommand {
                        message: format!("command[{index}] must not be empty"),
                    });
                }
                argv.push(trimmed.to_string());
            }
            if argv.is_empty() {
                return Err(NormalizeError::InvalidCommand {
                    message: "command array must not be empty".to_string(),
                });
            }
            Ok(Some(NormalizedCommand::Argv(argv)))
        }
        _ => Err(NormalizeError::InvalidCommand {
            message: "command must be string or string[]".to_string(),
        }),
    }
}

fn extract_env(
    payload: &Value,
    options: &Value,
) -> Result<BTreeMap<String, String>, NormalizeError> {
    let value = find_value(payload, "env").or_else(|| find_value(options, "env"));
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };

    let Some(object) = value.as_object() else {
        return Err(NormalizeError::InvalidEnv {
            message: "env must be an object".to_string(),
        });
    };

    let mut env = BTreeMap::new();
    for (key, value) in object {
        let Some(text) = value.as_str() else {
            return Err(NormalizeError::InvalidEnv {
                message: format!("env.{key} must be string"),
            });
        };
        env.insert(key.clone(), text.to_string());
    }
    Ok(env)
}

fn extract_stdin(payload: &Value, options: &Value) -> Result<Option<String>, NormalizeError> {
    let value = find_value(payload, "stdin").or_else(|| find_value(options, "stdin"));
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::String(text) => Ok(Some(text.clone())),
        _ => Err(NormalizeError::InvalidStdin {
            message: "stdin must be string".to_string(),
        }),
    }
}

fn extract_shell(payload: &Value, options: &Value) -> Result<Option<String>, NormalizeError> {
    let value = find_value(payload, "shell").or_else(|| find_value(options, "shell"));
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::String(shell) => {
            let trimmed = shell.trim();
            if trimmed.is_empty() {
                return Err(NormalizeError::InvalidShell {
                    message: "shell string must not be empty".to_string(),
                });
            }
            Ok(Some(trimmed.to_string()))
        }
        _ => Err(NormalizeError::InvalidShell {
            message: "shell must be string".to_string(),
        }),
    }
}

fn extract_cwd(payload: &Value, options: &Value, workspace_root: Option<&Path>) -> Option<PathBuf> {
    let cwd = find_value(payload, "cwd")
        .or_else(|| find_value(options, "cwd"))
        .and_then(Value::as_str)?;
    Some(resolve_path(cwd, workspace_root))
}

fn extract_paths(value: &Value, workspace_root: Option<&Path>) -> Vec<PathBuf> {
    let mut output = Vec::new();
    collect_paths(value, None, workspace_root, &mut output);
    output
}

fn collect_paths(
    value: &Value,
    current_key: Option<&str>,
    workspace_root: Option<&Path>,
    output: &mut Vec<PathBuf>,
) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                collect_paths(value, Some(key.as_str()), workspace_root, output);
            }
        }
        Value::Array(items) => {
            for value in items {
                collect_paths(value, current_key, workspace_root, output);
            }
        }
        Value::String(text) => {
            if is_path_key(current_key) && looks_like_path(text) {
                output.push(resolve_path(text, workspace_root));
            }
        }
        _ => {}
    }
}

fn extract_hosts(value: &Value) -> Vec<String> {
    let mut hosts = Vec::new();
    collect_hosts(value, None, &mut hosts);
    hosts
}

fn collect_hosts(value: &Value, current_key: Option<&str>, output: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                collect_hosts(value, Some(key.as_str()), output);
            }
        }
        Value::Array(items) => {
            for value in items {
                collect_hosts(value, current_key, output);
            }
        }
        Value::String(text) => {
            if is_host_key(current_key) || text.contains("://") {
                if let Some(host) = extract_host(text) {
                    output.push(host);
                }
            }
        }
        _ => {}
    }
}

fn is_path_key(key: Option<&str>) -> bool {
    key.is_some_and(|name| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "path" | "paths" | "cwd" | "file" | "files" | "output" | "target" | "destination"
        )
    })
}

fn is_host_key(key: Option<&str>) -> bool {
    key.is_some_and(|name| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "host" | "hosts" | "url" | "uri" | "endpoint"
        )
    })
}

fn looks_like_path(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with('~')
        || trimmed.contains('/')
}

fn resolve_path(raw: &str, workspace_root: Option<&Path>) -> PathBuf {
    let trimmed = raw.trim();
    let raw_path = if trimmed.starts_with('~') {
        PathBuf::from(trimmed.trim_start_matches('~'))
    } else {
        PathBuf::from(trimmed)
    };

    let joined = if raw_path.is_absolute() {
        raw_path
    } else if let Some(root) = workspace_root {
        root.join(raw_path)
    } else {
        PathBuf::from("/").join(raw_path)
    };

    normalize_lexical_path(&joined)
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized != PathBuf::from("/") {
                    normalized.pop();
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    if normalized.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        normalized
    }
}

fn extract_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let raw_host = if let Some((_, rest)) = trimmed.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let without_userinfo = authority
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(authority);
        without_userinfo
            .strip_prefix('[')
            .and_then(|value| value.split_once(']').map(|(host, _)| host))
            .unwrap_or_else(|| without_userinfo.split(':').next().unwrap_or_default())
    } else {
        trimmed
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
    };

    let host = raw_host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    if !host
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return None;
    }
    Some(host)
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut set = BTreeSet::new();
    let mut output = Vec::new();
    for path in paths {
        if set.insert(path.clone()) {
            output.push(path);
        }
    }
    output
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut set = BTreeSet::new();
    let mut output = Vec::new();
    for value in values {
        if set.insert(value.clone()) {
            output.push(value);
        }
    }
    output
}

fn find_value<'a>(root: &'a Value, key: &str) -> Option<&'a Value> {
    root.as_object().and_then(|object| object.get(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_context() -> RuntimeContext {
        RuntimeContext {
            platform: super::super::RuntimePlatform::Linux,
            daemon_instance_id: "daemon-1".to_string(),
            policy_dir: PathBuf::from("/work/policies"),
            workspace_root: Some(PathBuf::from("/work")),
        }
    }

    #[test]
    fn normalizes_exec_shell_command_and_paths() {
        let raw = RawOperation {
            kind: "exec".to_string(),
            payload: serde_json::json!({
                "command": "cat ./a.txt",
                "cwd": "project",
                "output": "./out.log",
                "url": "https://example.com/path"
            }),
            options: serde_json::json!({
                "stdin": "hello",
                "shell": "/bin/bash"
            }),
            labels: BTreeMap::new(),
        };

        let normalized = OperationNormalizer
            .normalize(raw, runtime_context())
            .expect("normalize operation");

        assert_eq!(normalized.kind, OperationKind::Exec);
        assert_eq!(
            normalized.command,
            Some(NormalizedCommand::Shell("cat ./a.txt".to_string()))
        );
        assert_eq!(normalized.cwd, Some(PathBuf::from("/work/project")));
        assert_eq!(normalized.stdin.as_deref(), Some("hello"));
        assert_eq!(normalized.shell.as_deref(), Some("/bin/bash"));
        assert!(normalized.paths.contains(&PathBuf::from("/work/out.log")));
        assert_eq!(normalized.hosts, vec!["example.com".to_string()]);
        assert!(!normalized.unknown);
    }

    #[test]
    fn rejects_invalid_command_type() {
        let raw = RawOperation {
            kind: "exec".to_string(),
            payload: serde_json::json!({"command": true}),
            options: serde_json::json!({}),
            labels: BTreeMap::new(),
        };

        let error = OperationNormalizer
            .normalize(raw, runtime_context())
            .expect_err("command bool should fail");
        assert!(matches!(error, NormalizeError::InvalidCommand { .. }));
    }

    #[test]
    fn marks_unknown_when_kind_unknown() {
        let raw = RawOperation::new("future.tool");
        let normalized = OperationNormalizer
            .normalize(raw, runtime_context())
            .expect("normalize operation");
        assert!(normalized.unknown);
        assert!(
            normalized
                .reason_codes
                .contains(&"operation.kind_unknown".to_string())
        );
    }
}
