use std::path::{Path, PathBuf};
use std::sync::Arc;

use af_policy::{CommandRule, CommandRuleSet, ValueRef};

use crate::operation::{NormalizedCommand, NormalizedOperation, OperationKind};

use super::command_parser::{CommandParseError, CommandParser};
use super::extractor::{
    collect_positionals, command_base_name, looks_like_credential_path, parse_endpoint,
    resolve_path,
};
use super::{CommandIR, CommandNode, RequestedCapabilities};

#[derive(Debug, Clone)]
pub struct CommandRuleEngine {
    parser: CommandParser,
    rules: Arc<CommandRuleSet>,
}

impl CommandRuleEngine {
    pub fn new(rules: Arc<CommandRuleSet>) -> Self {
        Self {
            parser: CommandParser,
            rules,
        }
    }

    pub fn from_operation(&self, operation: &NormalizedOperation) -> RequestedCapabilities {
        if operation.kind != OperationKind::Exec {
            return RequestedCapabilities::default();
        }

        let cwd = operation
            .cwd
            .as_deref()
            .or(operation.runtime.workspace_root.as_deref())
            .unwrap_or_else(|| Path::new("/"));

        match operation.command.as_ref() {
            Some(NormalizedCommand::Shell(command)) => match self.parser.parse(command) {
                Ok(ir) => self.from_command_ir(&ir, Some(cwd)),
                Err(CommandParseError::LanguageUnavailable | CommandParseError::ParseFailed) => {
                    RequestedCapabilities::default()
                }
            },
            Some(NormalizedCommand::Argv(argv)) => {
                if let Some(script) = script_from_argv(argv) {
                    match self.parser.parse(&script) {
                        Ok(ir) => self.from_command_ir(&ir, Some(cwd)),
                        Err(_) => RequestedCapabilities::default(),
                    }
                } else if !argv.is_empty() {
                    self.evaluate(
                        &CommandNode {
                            raw: argv.join(" "),
                            argv: argv.clone(),
                        },
                        cwd,
                    )
                } else {
                    RequestedCapabilities::default()
                }
            }
            None => RequestedCapabilities::default(),
        }
    }

    pub fn from_command_ir(&self, ir: &CommandIR, cwd: Option<&Path>) -> RequestedCapabilities {
        let cwd = cwd.unwrap_or_else(|| Path::new("/"));
        let mut requested = RequestedCapabilities::default();
        for command in &ir.commands {
            requested.merge(self.evaluate_command_or_inline_script(command, cwd));
        }
        requested.reason_codes.sort();
        requested.reason_codes.dedup();
        requested.matched_rules.sort();
        requested.matched_rules.dedup();
        requested.risk_tags.sort();
        requested.risk_tags.dedup();
        requested
    }

    fn evaluate_command_or_inline_script(
        &self,
        command: &CommandNode,
        cwd: &Path,
    ) -> RequestedCapabilities {
        if let Some(script) = script_from_argv(&command.argv)
            && let Ok(ir) = self.parser.parse(&script)
        {
            return self.from_command_ir(&ir, Some(cwd));
        }
        self.evaluate(command, cwd)
    }

    pub fn evaluate(&self, command: &CommandNode, cwd: &Path) -> RequestedCapabilities {
        let mut requested = RequestedCapabilities::default();
        for rule in &self.rules.rules {
            if !rule.matches(&command.argv) {
                continue;
            }
            apply_rule(rule, command, cwd, &mut requested);
        }
        requested.reason_codes.sort();
        requested.reason_codes.dedup();
        requested.matched_rules.sort();
        requested.matched_rules.dedup();
        requested.risk_tags.sort();
        requested.risk_tags.dedup();
        requested
    }
}

fn script_from_argv(argv: &[String]) -> Option<String> {
    let binary = argv
        .first()
        .map(|value| command_base_name(value))
        .unwrap_or_default();
    if !matches!(binary.as_str(), "sh" | "bash" | "zsh" | "dash" | "ksh") {
        return None;
    }

    argv.windows(2).find_map(|pair| {
        if pair[0] == "-c" || pair[0] == "-lc" {
            Some(pair[1].clone())
        } else {
            None
        }
    })
}

fn apply_rule(
    rule: &CommandRule,
    command: &CommandNode,
    cwd: &Path,
    requested: &mut RequestedCapabilities,
) {
    let rule_key = rule.source_key();
    if !command.raw.is_empty() {
        requested
            .reason_codes
            .push(format!("rule.command:{}", command.raw));
    }
    requested.matched_rules.push(rule_key.clone());
    requested
        .reason_codes
        .push(format!("rule.matched:{rule_key}"));
    if let Some(reason) = rule.reason.as_ref() {
        requested
            .reason_codes
            .push(format!("rule.reason:{rule_key}:{reason}"));
    }

    for reference in &rule.capabilities.fs_read {
        for path in evaluate_path_reference(reference, command, cwd) {
            requested.fs_read.insert(path.clone());
            if looks_like_credential_path(path.to_string_lossy().as_ref()) {
                requested.credential_access = true;
            }
        }
    }
    for reference in &rule.capabilities.fs_write {
        for path in evaluate_path_reference(reference, command, cwd) {
            requested.fs_write.insert(path.clone());
            if looks_like_credential_path(path.to_string_lossy().as_ref()) {
                requested.credential_access = true;
            }
        }
    }
    for reference in &rule.capabilities.fs_delete {
        for path in evaluate_path_reference(reference, command, cwd) {
            requested.fs_delete.insert(path.clone());
            if looks_like_credential_path(path.to_string_lossy().as_ref()) {
                requested.credential_access = true;
            }
        }
    }
    for spec in &rule.capabilities.net_connect {
        let hosts = evaluate_value_reference(&spec.host, command, cwd);
        if hosts.is_empty() {
            requested.unknown = true;
            requested
                .reason_codes
                .push(format!("rule.net_host_missing:{rule_key}"));
            continue;
        }
        for host in hosts {
            if let Some(mut endpoint) = parse_endpoint(&host) {
                if spec.port.is_some() {
                    endpoint.port = spec.port;
                }
                if spec.protocol.is_some() {
                    endpoint.protocol = spec.protocol.clone();
                }
                requested.net_connect.insert(endpoint);
            } else {
                requested.unknown = true;
                requested
                    .reason_codes
                    .push(format!("rule.net_host_invalid:{rule_key}:{host}"));
            }
        }
    }

    requested.host_exec |= rule.capabilities.host_exec;
    requested.process_control |= rule.capabilities.process_control;
    requested.privilege |= rule.capabilities.privilege;
    requested.credential_access |= rule.capabilities.credential_access;
    requested.unknown |= rule.capabilities.mark_unknown;
    if rule.capabilities.mark_unknown {
        requested
            .reason_codes
            .push(format!("rule.mark_unknown:{rule_key}"));
    }
    requested
        .risk_tags
        .extend(rule.capabilities.risk_tags.iter().cloned());
}

fn evaluate_path_reference(
    reference: &ValueRef,
    command: &CommandNode,
    cwd: &Path,
) -> Vec<PathBuf> {
    evaluate_value_reference(reference, command, cwd)
        .into_iter()
        .map(|raw| resolve_path(cwd, &raw))
        .collect()
}

fn evaluate_value_reference(
    reference: &ValueRef,
    command: &CommandNode,
    cwd: &Path,
) -> Vec<String> {
    match reference {
        ValueRef::Literal(value) => vec![value.clone()],
        ValueRef::Arg(index) => command
            .argv
            .get(index + 1)
            .cloned()
            .into_iter()
            .collect::<Vec<_>>(),
        ValueRef::ArgAfter(flag) => arg_after(command, flag).into_iter().collect(),
        ValueRef::ArgAfterAny(flags) => {
            for flag in flags {
                if let Some(value) = arg_after(command, flag) {
                    return vec![value];
                }
            }
            Vec::new()
        }
        ValueRef::Positional(index) => collect_positionals(&command.argv)
            .get(*index)
            .cloned()
            .into_iter()
            .collect::<Vec<_>>(),
        ValueRef::AllPositionals => collect_positionals(&command.argv),
        ValueRef::UrlHostFromArg(index) => command
            .argv
            .get(index + 1)
            .and_then(|value| parse_endpoint(value))
            .map(|endpoint| endpoint.host)
            .into_iter()
            .collect(),
        ValueRef::Cwd => vec![cwd.display().to_string()],
        ValueRef::ResolvePath(inner) => evaluate_value_reference(inner, command, cwd)
            .into_iter()
            .map(|raw| resolve_path(cwd, &raw).display().to_string())
            .collect(),
    }
}

fn arg_after(command: &CommandNode, flag: &str) -> Option<String> {
    let mut index = 1usize;
    while index < command.argv.len() {
        if command.argv[index] == flag && index + 1 < command.argv.len() {
            return Some(command.argv[index + 1].clone());
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use af_policy::{
        CommandRule, CommandRuleSet, NetConnectSpec, PatternToken, RuleCapabilities, RuleSource,
        ValueRef,
    };

    use super::*;
    use crate::operation::{
        NormalizedCommand, NormalizedOperation, OperationKind, RuntimeContext, RuntimePlatform,
    };

    fn runtime() -> RuntimeContext {
        RuntimeContext {
            platform: RuntimePlatform::Linux,
            daemon_instance_id: "daemon-1".to_string(),
            policy_dir: PathBuf::from("/work/policies"),
            workspace_root: Some(PathBuf::from("/work")),
        }
    }

    #[test]
    fn applies_rule_capability_delta() {
        let engine = CommandRuleEngine::new(Arc::new(CommandRuleSet {
            revision: 1,
            rules: vec![CommandRule {
                source: RuleSource {
                    file: "10.rules".to_string(),
                    line: 2,
                    ordinal: 1,
                },
                pattern: vec![PatternToken::Single("curl".to_string())],
                when: None,
                capabilities: RuleCapabilities {
                    fs_write: vec![ValueRef::ArgAfter("-o".to_string())],
                    net_connect: vec![NetConnectSpec {
                        host: ValueRef::UrlHostFromArg(0),
                        port: Some(443),
                        protocol: Some("https".to_string()),
                    }],
                    ..RuleCapabilities::default()
                },
                reason: Some("curl writes output and connects url host".to_string()),
            }],
        }));
        let command = CommandNode {
            raw: "curl https://example.com -o out.txt".to_string(),
            argv: vec![
                "curl".to_string(),
                "https://example.com".to_string(),
                "-o".to_string(),
                "out.txt".to_string(),
            ],
        };

        let requested = engine.evaluate(&command, Path::new("/work"));
        assert!(requested.fs_write.contains(&PathBuf::from("/work/out.txt")));
        assert!(
            requested
                .net_connect
                .iter()
                .any(|endpoint| endpoint.host == "example.com")
        );
        assert!(
            requested
                .matched_rules
                .iter()
                .any(|rule| rule.contains("10.rules"))
        );
    }

    #[test]
    fn collect_positionals_keeps_args_after_valueless_options() {
        let argv = vec!["jq".to_string(), "-c".to_string(), "file.json".to_string()];
        let positionals = collect_positionals(&argv);
        assert_eq!(positionals, vec!["file.json".to_string()]);
    }

    #[test]
    fn from_operation_extracts_rule_capabilities_for_exec_command() {
        let engine = CommandRuleEngine::new(Arc::new(CommandRuleSet {
            revision: 1,
            rules: vec![CommandRule {
                source: RuleSource {
                    file: "00-base.rules".to_string(),
                    line: 1,
                    ordinal: 1,
                },
                pattern: vec![
                    PatternToken::Single("git".to_string()),
                    PatternToken::Single("status".to_string()),
                ],
                when: None,
                capabilities: RuleCapabilities {
                    fs_read: vec![ValueRef::Cwd],
                    ..RuleCapabilities::default()
                },
                reason: Some("git status reads repository state".to_string()),
            }],
        }));

        let operation = NormalizedOperation {
            kind: OperationKind::Exec,
            payload: serde_json::json!({}),
            options: serde_json::json!({}),
            labels: BTreeMap::new(),
            command: Some(NormalizedCommand::Shell("git status".to_string())),
            cwd: Some(PathBuf::from("/work/repo")),
            env: BTreeMap::new(),
            stdin: None,
            shell: None,
            paths: Vec::new(),
            hosts: Vec::new(),
            reason_codes: Vec::new(),
            unknown: false,
            runtime: runtime(),
        };

        let requested = engine.from_operation(&operation);
        assert!(requested.fs_read.contains(&PathBuf::from("/work/repo")));
        assert!(
            requested
                .matched_rules
                .iter()
                .any(|rule| rule.contains("00-base.rules"))
        );
    }

    #[test]
    fn from_operation_unwraps_shell_inline_script_wrappers() {
        let engine = CommandRuleEngine::new(Arc::new(CommandRuleSet {
            revision: 1,
            rules: vec![CommandRule {
                source: RuleSource {
                    file: "00-base.rules".to_string(),
                    line: 1,
                    ordinal: 1,
                },
                pattern: vec![
                    PatternToken::Single("git".to_string()),
                    PatternToken::Single("status".to_string()),
                ],
                when: None,
                capabilities: RuleCapabilities {
                    fs_read: vec![ValueRef::Cwd],
                    ..RuleCapabilities::default()
                },
                reason: Some("git status reads repository state".to_string()),
            }],
        }));

        let operation = NormalizedOperation {
            kind: OperationKind::Exec,
            payload: serde_json::json!({}),
            options: serde_json::json!({}),
            labels: BTreeMap::new(),
            command: Some(NormalizedCommand::Shell(
                r#"bash -lc "git status""#.to_string(),
            )),
            cwd: Some(PathBuf::from("/work/repo")),
            env: BTreeMap::new(),
            stdin: None,
            shell: None,
            paths: Vec::new(),
            hosts: Vec::new(),
            reason_codes: Vec::new(),
            unknown: false,
            runtime: runtime(),
        };

        let requested = engine.from_operation(&operation);
        assert!(requested.fs_read.contains(&PathBuf::from("/work/repo")));
        assert!(
            requested
                .matched_rules
                .iter()
                .any(|rule| rule.contains("00-base.rules"))
        );
    }
}
