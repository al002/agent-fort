use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;
use thiserror::Error;

use super::{
    Fact, Facts, Intent, NormalizedOperation, OperationKind, RuntimeContext, Target, TargetKind,
};

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
        let labels = raw.labels;
        let tags = collect_tags(&labels, &raw.payload, &raw.options);

        let mut targets = extract_targets(kind, &raw.payload, &raw.options);
        let mut facts = base_facts(&raw.payload, &raw.options, &labels);
        let mut affected_paths = extract_affected_paths(kind, &raw.payload, &raw.options, &runtime);

        apply_kind_defaults(kind, &mut facts, &affected_paths);

        if matches!(facts.requires_write, Fact::Unknown)
            && matches!(kind, OperationKind::FileWrite | OperationKind::FilePatch)
        {
            facts.requires_write = Fact::Known(true);
        }

        if matches!(facts.requires_network, Fact::Unknown) && matches!(kind, OperationKind::Fetch) {
            facts.requires_network = Fact::Known(true);
        }

        add_path_targets(&mut targets, &affected_paths);
        facts.touches_policy_dir = Fact::Known(touches_policy_dir(&affected_paths, &runtime.policy_dir));
        facts.affected_paths = std::mem::take(&mut affected_paths);

        Ok(NormalizedOperation {
            intent: Intent {
                kind,
                labels,
                tags,
                targets,
            },
            facts,
            runtime,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    #[error("operation kind must not be empty")]
    EmptyKind,
}

fn normalize_kind(kind: &str) -> OperationKind {
    let kind = kind.trim().to_ascii_lowercase();
    match kind.as_str() {
        "exec" | "command" | "shell.exec" => OperationKind::Exec,
        "file.read" | "read_file" | "fs.read" | "read" => OperationKind::FileRead,
        "file.write" | "write_file" | "fs.write" | "write" => OperationKind::FileWrite,
        "file.patch" | "patch_file" | "fs.patch" | "patch" => OperationKind::FilePatch,
        "fetch" | "http.fetch" | "web.fetch" | "url.fetch" => OperationKind::Fetch,
        "tool.call" | "tool" | "call_tool" => OperationKind::ToolCall,
        _ => OperationKind::Unknown,
    }
}

fn base_facts(payload: &Value, options: &Value, labels: &BTreeMap<String, String>) -> Facts {
    Facts {
        interactive: bool_fact(payload, options, labels, &["interactive"]),
        requires_network: bool_fact(
            payload,
            options,
            labels,
            &["requires_network", "network", "network_required"],
        ),
        requires_write: bool_fact(
            payload,
            options,
            labels,
            &["requires_write", "write", "write_required"],
        ),
        touches_policy_dir: Fact::Unknown,
        primary_host: host_fact(payload, options, labels),
        affected_paths: Vec::new(),
    }
}

fn apply_kind_defaults(kind: OperationKind, facts: &mut Facts, affected_paths: &[PathBuf]) {
    match kind {
        OperationKind::FileRead => {
            if matches!(facts.requires_network, Fact::Unknown) {
                facts.requires_network = Fact::Known(false);
            }
            if matches!(facts.requires_write, Fact::Unknown) {
                facts.requires_write = Fact::Known(false);
            }
            if matches!(facts.interactive, Fact::Unknown) {
                facts.interactive = Fact::Known(false);
            }
        }
        OperationKind::FileWrite | OperationKind::FilePatch => {
            if matches!(facts.requires_network, Fact::Unknown) {
                facts.requires_network = Fact::Known(false);
            }
            facts.requires_write = Fact::Known(true);
            if matches!(facts.interactive, Fact::Unknown) {
                facts.interactive = Fact::Known(false);
            }
        }
        OperationKind::Fetch => {
            facts.requires_network = Fact::Known(true);
            if !affected_paths.is_empty() {
                facts.requires_write = Fact::Known(true);
            }
            if matches!(facts.interactive, Fact::Unknown) {
                facts.interactive = Fact::Known(false);
            }
        }
        OperationKind::Exec | OperationKind::ToolCall | OperationKind::Unknown => {}
    }
}

fn bool_fact(
    payload: &Value,
    options: &Value,
    labels: &BTreeMap<String, String>,
    keys: &[&str],
) -> Fact<bool> {
    for key in keys {
        if let Some(value) = find_bool(payload, key) {
            return Fact::Known(value);
        }
        if let Some(value) = find_bool(options, key) {
            return Fact::Known(value);
        }
        if let Some(value) = labels
            .get(*key)
            .and_then(|value| parse_bool_like(value))
        {
            return Fact::Known(value);
        }
    }
    Fact::Unknown
}

fn host_fact(payload: &Value, options: &Value, labels: &BTreeMap<String, String>) -> Fact<String> {
    for key in ["url", "uri", "host", "hostname"] {
        if let Some(host) = find_host(payload, key) {
            return Fact::Known(host);
        }
        if let Some(host) = find_host(options, key) {
            return Fact::Known(host);
        }
    }
    if let Some(host) = labels.get("host").map(String::as_str) {
        return Fact::Known(host.to_string());
    }
    Fact::Unknown
}

fn collect_tags(payload_labels: &BTreeMap<String, String>, payload: &Value, options: &Value) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    collect_tags_from_value(payload, &mut tags);
    collect_tags_from_value(options, &mut tags);

    for (key, value) in payload_labels {
        if key == "tag" {
            insert_tag(value, &mut tags);
            continue;
        }
        if let Some(suffix) = key.strip_prefix("tag.") {
            insert_tag(suffix, &mut tags);
            insert_tag(value, &mut tags);
            continue;
        }
        if let Some(suffix) = key.strip_prefix("tags.") {
            insert_tag(suffix, &mut tags);
            insert_tag(value, &mut tags);
        }
    }
    tags
}

fn collect_tags_from_value(value: &Value, tags: &mut BTreeSet<String>) {
    let Some(object) = value.as_object() else {
        return;
    };
    let Some(raw_tags) = object.get("tags") else {
        return;
    };
    match raw_tags {
        Value::String(single) => insert_tag(single, tags),
        Value::Array(list) => {
            for item in list {
                if let Some(tag) = item.as_str() {
                    insert_tag(tag, tags);
                }
            }
        }
        _ => {}
    }
}

fn insert_tag(raw: &str, tags: &mut BTreeSet<String>) {
    for part in raw.split(',') {
        let tag = part.trim();
        if !tag.is_empty() {
            tags.insert(tag.to_string());
        }
    }
}

fn extract_targets(kind: OperationKind, payload: &Value, options: &Value) -> Vec<Target> {
    let mut result = Vec::new();
    let mut dedupe = BTreeSet::<(TargetKind, String)>::new();

    match kind {
        OperationKind::Exec => {
            if let Some(command) = first_command_token(payload).or_else(|| first_command_token(options)) {
                push_target(TargetKind::Path, command, &mut dedupe, &mut result);
            }
        }
        OperationKind::FileRead | OperationKind::FileWrite | OperationKind::FilePatch => {
            for path in extract_string_paths(payload, options) {
                push_target(TargetKind::Path, path, &mut dedupe, &mut result);
            }
        }
        OperationKind::Fetch => {
            if let Some(host) = find_host(payload, "url").or_else(|| find_host(options, "url")) {
                push_target(TargetKind::Host, host, &mut dedupe, &mut result);
            }
        }
        OperationKind::ToolCall => {
            if let Some(tool) = find_string(payload, "tool")
                .or_else(|| find_string(payload, "name"))
                .or_else(|| find_string(options, "tool"))
            {
                push_target(TargetKind::Tool, tool.to_string(), &mut dedupe, &mut result);
            }
        }
        OperationKind::Unknown => {}
    }

    result
}

fn extract_affected_paths(
    kind: OperationKind,
    payload: &Value,
    options: &Value,
    runtime: &RuntimeContext,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = BTreeSet::<String>::new();

    match kind {
        OperationKind::FileRead | OperationKind::FileWrite | OperationKind::FilePatch => {
            for raw in extract_string_paths(payload, options) {
                let resolved = resolve_path(raw.as_str(), runtime.workspace_root.as_deref());
                if seen.insert(resolved.display().to_string()) {
                    paths.push(resolved);
                }
            }
        }
        OperationKind::Fetch => {
            for key in ["output_path", "save_to", "path", "target_path"] {
                if let Some(raw) = find_string(payload, key).or_else(|| find_string(options, key)) {
                    let resolved = resolve_path(raw, runtime.workspace_root.as_deref());
                    if seen.insert(resolved.display().to_string()) {
                        paths.push(resolved);
                    }
                }
            }
        }
        OperationKind::Exec | OperationKind::ToolCall | OperationKind::Unknown => {}
    }

    paths
}

fn add_path_targets(targets: &mut Vec<Target>, affected_paths: &[PathBuf]) {
    let mut seen = targets
        .iter()
        .map(|target| (target.kind, target.value.clone()))
        .collect::<BTreeSet<_>>();
    for path in affected_paths {
        let value = path.display().to_string();
        if seen.insert((TargetKind::Path, value.clone())) {
            targets.push(Target {
                kind: TargetKind::Path,
                value,
            });
        }
    }
}

fn touches_policy_dir(paths: &[PathBuf], policy_dir: &Path) -> bool {
    paths.iter().any(|path| path.starts_with(policy_dir))
}

fn resolve_path(raw: &str, workspace_root: Option<&Path>) -> PathBuf {
    let candidate = PathBuf::from(raw);
    if candidate.is_absolute() {
        return candidate;
    }
    if let Some(root) = workspace_root {
        return root.join(candidate);
    }
    PathBuf::from(raw)
}

fn extract_string_paths(payload: &Value, options: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    let mut seen = BTreeSet::new();
    for key in [
        "path",
        "file_path",
        "target_path",
        "destination_path",
        "dst",
        "to",
    ] {
        if let Some(value) = find_string(payload, key).or_else(|| find_string(options, key)) {
            let owned = value.to_string();
            if seen.insert(owned.clone()) {
                paths.push(owned);
            }
        }
    }

    for value in find_string_array(payload, "paths")
        .into_iter()
        .chain(find_string_array(options, "paths"))
    {
        if seen.insert(value.clone()) {
            paths.push(value);
        }
    }
    paths
}

fn first_command_token(value: &Value) -> Option<String> {
    let command = value.as_object()?.get("command")?;
    if let Some(single) = command.as_str() {
        let token = single.split_whitespace().next()?;
        return Some(token.to_string());
    }
    if let Some(array) = command.as_array() {
        let first = array.first()?.as_str()?;
        if !first.trim().is_empty() {
            return Some(first.to_string());
        }
    }
    None
}

fn find_bool(value: &Value, key: &str) -> Option<bool> {
    let raw = value.as_object()?.get(key)?;
    if let Some(boolean) = raw.as_bool() {
        return Some(boolean);
    }
    raw.as_str().and_then(parse_bool_like)
}

fn find_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.as_object()?.get(key)?.as_str()
}

fn find_string_array(value: &Value, key: &str) -> Vec<String> {
    let Some(list) = value
        .as_object()
        .and_then(|object| object.get(key))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    list.iter()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

fn parse_bool_like(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn find_host(value: &Value, key: &str) -> Option<String> {
    let raw = find_string(value, key)?;
    host_from_url(raw).or_else(|| {
        if raw.trim().is_empty() {
            None
        } else {
            Some(raw.to_string())
        }
    })
}

fn host_from_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let separator = raw.find("://")?;
    let after_scheme = &raw[separator + 3..];
    let authority = after_scheme.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    let without_auth = authority.rsplit('@').next()?;
    if without_auth.starts_with('[') {
        let end = without_auth.find(']')?;
        return Some(without_auth[1..end].to_string());
    }
    let host = without_auth.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn push_target(
    kind: TargetKind,
    value: String,
    dedupe: &mut BTreeSet<(TargetKind, String)>,
    out: &mut Vec<Target>,
) {
    if value.trim().is_empty() {
        return;
    }
    if dedupe.insert((kind, value.clone())) {
        out.push(Target { kind, value });
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::operation::RuntimePlatform;

    fn runtime() -> RuntimeContext {
        RuntimeContext {
            platform: RuntimePlatform::Linux,
            daemon_instance_id: "daemon-1".to_string(),
            policy_dir: PathBuf::from("/work/policies"),
            workspace_root: Some(PathBuf::from("/work")),
        }
    }

    #[test]
    fn normalizes_exec_interactive_from_options() {
        let raw = RawOperation {
            kind: "exec".to_string(),
            payload: json!({ "command": ["/bin/sh", "-lc", "echo hi"] }),
            options: json!({ "interactive": true }),
            labels: BTreeMap::new(),
        };
        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize exec");

        assert_eq!(normalized.intent.kind, OperationKind::Exec);
        assert_eq!(
            normalized.intent.targets,
            vec![Target {
                kind: TargetKind::Path,
                value: "/bin/sh".to_string(),
            }]
        );
        assert_eq!(normalized.facts.interactive, Fact::Known(true));
        assert_eq!(normalized.facts.requires_network, Fact::Unknown);
        assert_eq!(normalized.facts.requires_write, Fact::Unknown);
    }

    #[test]
    fn normalizes_file_write_and_detects_policy_touch() {
        let raw = RawOperation {
            kind: "file.write".to_string(),
            payload: json!({ "path": "policies/base.yaml" }),
            options: json!({}),
            labels: BTreeMap::new(),
        };
        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize file write");

        assert_eq!(normalized.intent.kind, OperationKind::FileWrite);
        assert_eq!(normalized.facts.requires_write, Fact::Known(true));
        assert_eq!(normalized.facts.requires_network, Fact::Known(false));
        assert_eq!(normalized.facts.touches_policy_dir, Fact::Known(true));
        assert_eq!(
            normalized.facts.affected_paths,
            vec![PathBuf::from("/work/policies/base.yaml")]
        );
    }

    #[test]
    fn normalizes_fetch_with_host_and_output_path() {
        let raw = RawOperation {
            kind: "fetch".to_string(),
            payload: json!({
                "url": "https://example.com/path?q=1",
                "output_path": "downloads/example.txt"
            }),
            options: json!({}),
            labels: BTreeMap::new(),
        };
        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize fetch");

        assert_eq!(normalized.intent.kind, OperationKind::Fetch);
        assert_eq!(normalized.facts.requires_network, Fact::Known(true));
        assert_eq!(normalized.facts.requires_write, Fact::Known(true));
        assert_eq!(normalized.facts.primary_host, Fact::Known("example.com".to_string()));
        assert!(normalized.intent.targets.iter().any(|target| {
            target.kind == TargetKind::Host && target.value == "example.com"
        }));
    }

    #[test]
    fn normalizes_tool_call_name_and_tags() {
        let mut labels = BTreeMap::new();
        labels.insert("tag".to_string(), "sensitive,approval".to_string());
        let raw = RawOperation {
            kind: "tool.call".to_string(),
            payload: json!({ "name": "web.search", "tags": ["network"] }),
            options: json!({}),
            labels,
        };
        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize tool call");

        assert_eq!(normalized.intent.kind, OperationKind::ToolCall);
        assert!(normalized.intent.targets.iter().any(|target| {
            target.kind == TargetKind::Tool && target.value == "web.search"
        }));
        assert!(normalized.intent.tags.contains("network"));
        assert!(normalized.intent.tags.contains("sensitive"));
        assert!(normalized.intent.tags.contains("approval"));
    }

    #[test]
    fn normalizes_file_read_as_non_write() {
        let raw = RawOperation {
            kind: "file.read".to_string(),
            payload: json!({ "path": "/work/README.md" }),
            options: json!({}),
            labels: BTreeMap::new(),
        };
        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize file read");

        assert_eq!(normalized.intent.kind, OperationKind::FileRead);
        assert_eq!(normalized.facts.requires_write, Fact::Known(false));
        assert_eq!(normalized.facts.requires_network, Fact::Known(false));
    }

    #[test]
    fn unknown_kind_is_preserved_as_unknown() {
        let raw = RawOperation {
            kind: "git.commit".to_string(),
            payload: json!({}),
            options: json!({}),
            labels: BTreeMap::new(),
        };
        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize unknown");
        assert_eq!(normalized.intent.kind, OperationKind::Unknown);
    }

    #[test]
    fn rejects_empty_kind() {
        let error = OperationNormalizer
            .normalize(RawOperation::new(" "), runtime())
            .expect_err("empty kind must fail");
        assert_eq!(error, NormalizeError::EmptyKind);
    }
}
