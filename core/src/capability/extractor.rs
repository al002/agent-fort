use std::path::{Path, PathBuf};

use crate::operation::{NormalizedCommand, NormalizedOperation, OperationKind};

use super::command_parser::{CommandParseError, CommandParser};
use super::extractor_registry::{ExtractorKind, ExtractorRegistry};
use super::{CommandIR, CommandNode, NetEndpoint, RedirectionKind, RequestedCapabilities};

#[derive(Debug, Clone)]
pub struct CapabilityExtractor {
    parser: CommandParser,
    registry: ExtractorRegistry,
}

impl Default for CapabilityExtractor {
    fn default() -> Self {
        Self {
            parser: CommandParser,
            registry: ExtractorRegistry::default(),
        }
    }
}

impl CapabilityExtractor {
    pub fn from_operation(&self, operation: &NormalizedOperation) -> RequestedCapabilities {
        let mut requested = RequestedCapabilities::default();

        match operation.kind {
            OperationKind::FsRead => {
                for path in &operation.paths {
                    requested.fs_read.insert(path.clone());
                    maybe_mark_credential(path, &mut requested);
                }
            }
            OperationKind::FsWrite => {
                for path in &operation.paths {
                    requested.fs_write.insert(path.clone());
                    maybe_mark_credential(path, &mut requested);
                }
            }
            OperationKind::Net => {
                for host in &operation.hosts {
                    requested
                        .net_connect
                        .insert(NetEndpoint::new(host.clone(), None, None));
                }
                for path in &operation.paths {
                    requested.fs_write.insert(path.clone());
                }
                if operation.hosts.is_empty() {
                    requested.unknown = true;
                    requested
                        .reason_codes
                        .push("net.endpoint_unknown".to_string());
                }
            }
            OperationKind::Exec => {
                self.extract_exec(operation, &mut requested);
            }
            OperationKind::Tool | OperationKind::Unknown => {
                requested.unknown = true;
                requested
                    .reason_codes
                    .push("operation.unknown_kind".to_string());
            }
        }

        requested.reason_codes.sort();
        requested.reason_codes.dedup();
        requested
    }

    pub fn from_command_ir(&self, ir: &CommandIR, cwd: Option<&Path>) -> RequestedCapabilities {
        let cwd = cwd.unwrap_or_else(|| Path::new("/"));
        let mut requested = RequestedCapabilities::default();

        for redirection in &ir.redirections {
            if let Some(target) = redirection.target.as_ref() {
                let path = resolve_path(cwd, target);
                match redirection.kind {
                    RedirectionKind::Read | RedirectionKind::Heredoc => {
                        requested.fs_read.insert(path.clone());
                    }
                    RedirectionKind::Write | RedirectionKind::Append => {
                        requested.fs_write.insert(path.clone());
                    }
                    RedirectionKind::Unknown => {
                        requested.unknown = true;
                        requested.reason_codes.push("redirect.unknown".to_string());
                    }
                }
                maybe_mark_credential(&path, &mut requested);
            } else {
                requested.unknown = true;
                requested
                    .reason_codes
                    .push("redirect.target_missing".to_string());
            }
        }

        if ir.is_complex_shell() {
            requested.process_control = true;
        }
        if ir.parse_error {
            requested.unknown = true;
            requested.reason_codes.push("parser.has_error".to_string());
        }

        for command in &ir.commands {
            self.extract_command_node(command, cwd, &mut requested);
        }

        requested.reason_codes.sort();
        requested.reason_codes.dedup();
        requested
    }

    fn extract_exec(&self, operation: &NormalizedOperation, requested: &mut RequestedCapabilities) {
        let cwd = operation
            .cwd
            .as_deref()
            .or(operation.runtime.workspace_root.as_deref())
            .unwrap_or_else(|| Path::new("/"));

        match operation.command.as_ref() {
            Some(NormalizedCommand::Shell(command)) => match self.parser.parse(command) {
                Ok(ir) => requested.merge(self.from_command_ir(&ir, Some(cwd))),
                Err(CommandParseError::LanguageUnavailable | CommandParseError::ParseFailed) => {
                    requested.unknown = true;
                    requested.reason_codes.push("parser.failed".to_string());
                }
            },
            Some(NormalizedCommand::Argv(argv)) => {
                if let Some(script) = script_from_argv(argv) {
                    match self.parser.parse(&script) {
                        Ok(ir) => requested.merge(self.from_command_ir(&ir, Some(cwd))),
                        Err(_) => {
                            requested.unknown = true;
                            requested.reason_codes.push("parser.failed".to_string());
                        }
                    }
                } else if !argv.is_empty() {
                    self.extract_command_node(
                        &CommandNode {
                            raw: argv.join(" "),
                            argv: argv.clone(),
                        },
                        cwd,
                        requested,
                    );
                } else {
                    requested.unknown = true;
                    requested.reason_codes.push("exec.argv_empty".to_string());
                }
            }
            None => {
                requested.unknown = true;
                requested
                    .reason_codes
                    .push("exec.command_missing".to_string());
            }
        }
    }

    fn extract_command_node(
        &self,
        command: &CommandNode,
        cwd: &Path,
        requested: &mut RequestedCapabilities,
    ) {
        if command.argv.is_empty() {
            return;
        }

        let binary = command_base_name(&command.argv[0]);
        if binary.is_empty() {
            requested.unknown = true;
            requested
                .reason_codes
                .push("command.binary_missing".to_string());
            return;
        }

        if let Some(extractor_kind) = self.registry.get(binary.as_str()) {
            apply_registered_extractor(extractor_kind, command, cwd, requested);
        } else {
            requested
                .reason_codes
                .push(format!("extractor.missing:{binary}"));
        }

        if binary == "rm" || binary == "unlink" {
            for arg in command.argv.iter().skip(1) {
                if is_option(arg) {
                    continue;
                }
                let path = resolve_path(cwd, arg);
                requested.fs_delete.insert(path.clone());
                maybe_mark_credential(&path, requested);
            }
        }

        if binary == "sudo" || binary == "su" {
            requested.privilege = true;
        }

        if is_dynamic_script(binary.as_str(), &command.argv) {
            requested.host_exec = true;
            requested.unknown = true;
            requested
                .reason_codes
                .push(format!("dynamic.script:{binary}"));
        }

        for token in &command.argv {
            if looks_like_credential_path(token) {
                requested.credential_access = true;
            }
        }

        if binary == "kill" || binary == "pkill" || binary == "killall" {
            requested.process_control = true;
        }
    }
}

fn apply_registered_extractor(
    kind: ExtractorKind,
    command: &CommandNode,
    cwd: &Path,
    requested: &mut RequestedCapabilities,
) {
    match kind {
        ExtractorKind::CurlLike => {
            let mut endpoint_found = false;
            let mut index = 1;
            while index < command.argv.len() {
                let token = command.argv[index].as_str();
                if (token == "-o" || token == "--output") && index + 1 < command.argv.len() {
                    requested
                        .fs_write
                        .insert(resolve_path(cwd, &command.argv[index + 1]));
                    index += 2;
                    continue;
                }
                if let Some(endpoint) = parse_endpoint(token) {
                    endpoint_found = true;
                    requested.net_connect.insert(endpoint);
                }
                index += 1;
            }
            if !endpoint_found {
                requested.unknown = true;
                requested
                    .reason_codes
                    .push("endpoint.unknown:curl_like".to_string());
            }
        }
        ExtractorKind::Git => {
            let sub = command
                .argv
                .get(1)
                .map(|value| value.to_ascii_lowercase())
                .unwrap_or_default();
            match sub.as_str() {
                "clone" | "fetch" | "pull" | "push" | "ls-remote" => {
                    for token in &command.argv {
                        if let Some(endpoint) = parse_endpoint(token) {
                            requested.net_connect.insert(endpoint);
                        }
                    }
                }
                "add" | "commit" | "checkout" | "reset" | "clean" | "rm" => {
                    for arg in command.argv.iter().skip(2) {
                        if is_option(arg) {
                            continue;
                        }
                        requested.fs_write.insert(resolve_path(cwd, arg));
                    }
                }
                _ => {
                    requested.unknown = true;
                    requested
                        .reason_codes
                        .push("git.subcommand_unknown".to_string());
                }
            }
        }
        ExtractorKind::PythonLike | ExtractorKind::NodeLike | ExtractorKind::GenericShell => {
            if has_inline_script_flag(&command.argv) {
                requested.host_exec = true;
                requested.unknown = true;
                requested
                    .reason_codes
                    .push("dynamic.script.inline".to_string());
            }
        }
    }
}

fn command_base_name(value: &str) -> String {
    Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(value)
        .to_ascii_lowercase()
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

fn is_dynamic_script(binary: &str, argv: &[String]) -> bool {
    if matches!(binary, "sh" | "bash" | "zsh" | "dash" | "ksh") {
        return argv.iter().any(|arg| arg == "-c" || arg == "-lc");
    }
    if matches!(
        binary,
        "python" | "python3" | "node" | "deno" | "perl" | "ruby"
    ) {
        return has_inline_script_flag(argv);
    }
    false
}

fn has_inline_script_flag(argv: &[String]) -> bool {
    argv.iter()
        .any(|arg| arg == "-c" || arg == "-e" || arg == "--eval")
}

fn is_option(value: &str) -> bool {
    value.starts_with('-')
}

fn resolve_path(cwd: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    let joined = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    crate::capability::matcher::normalize_lexical_path(&joined)
}

fn parse_endpoint(raw: &str) -> Option<NetEndpoint> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (host_raw, protocol) = if let Some((scheme, rest)) = trimmed.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let without_userinfo = authority
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(authority);
        (without_userinfo, Some(scheme.to_ascii_lowercase()))
    } else {
        (trimmed, None)
    };

    let host_port = host_raw.trim();
    if host_port.is_empty() {
        return None;
    }

    let (host, mut port) = if let Some((host, port_raw)) = host_port.rsplit_once(':') {
        if port_raw.chars().all(|ch| ch.is_ascii_digit()) {
            (host, port_raw.parse::<u16>().ok())
        } else {
            (host_port, None)
        }
    } else {
        (host_port, None)
    };

    let normalized_host = host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized_host.is_empty() {
        return None;
    }
    if !normalized_host
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_')
    {
        return None;
    }

    if port.is_none()
        && let Some(scheme) = protocol.as_deref()
    {
        port = match scheme {
            "https" => Some(443),
            "http" => Some(80),
            _ => None,
        };
    }

    Some(NetEndpoint::new(normalized_host, port, protocol))
}

fn maybe_mark_credential(path: &Path, requested: &mut RequestedCapabilities) {
    if looks_like_credential_path(path.to_string_lossy().as_ref()) {
        requested.credential_access = true;
    }
}

fn looks_like_credential_path(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains(".ssh")
        || lower.contains(".aws/credentials")
        || lower.contains("/etc/shadow")
        || lower.contains("id_rsa")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::operation::{RuntimeContext, RuntimePlatform};

    fn runtime() -> RuntimeContext {
        RuntimeContext {
            platform: RuntimePlatform::Linux,
            daemon_instance_id: "daemon-1".to_string(),
            policy_dir: PathBuf::from("/work/policies"),
            workspace_root: Some(PathBuf::from("/work")),
        }
    }

    #[test]
    fn extracts_network_and_write_from_curl_command() {
        let operation = NormalizedOperation {
            kind: OperationKind::Exec,
            payload: json!({}),
            options: json!({}),
            labels: BTreeMap::new(),
            command: Some(NormalizedCommand::Shell(
                "curl https://example.com -o out.txt".to_string(),
            )),
            cwd: Some(PathBuf::from("/work")),
            env: BTreeMap::new(),
            paths: Vec::new(),
            hosts: Vec::new(),
            reason_codes: Vec::new(),
            unknown: false,
            runtime: runtime(),
        };

        let requested = CapabilityExtractor::default().from_operation(&operation);
        assert!(
            requested
                .net_connect
                .iter()
                .any(|endpoint| endpoint.host == "example.com")
        );
        assert!(requested.fs_write.contains(&PathBuf::from("/work/out.txt")));
    }

    #[test]
    fn marks_unknown_for_missing_extractor() {
        let operation = NormalizedOperation {
            kind: OperationKind::Exec,
            payload: json!({}),
            options: json!({}),
            labels: BTreeMap::new(),
            command: Some(NormalizedCommand::Shell("mycmd --flag".to_string())),
            cwd: Some(PathBuf::from("/work")),
            env: BTreeMap::new(),
            paths: Vec::new(),
            hosts: Vec::new(),
            reason_codes: Vec::new(),
            unknown: false,
            runtime: runtime(),
        };

        let requested = CapabilityExtractor::default().from_operation(&operation);
        assert!(!requested.unknown);
        assert!(
            requested
                .reason_codes
                .iter()
                .any(|code| code.contains("extractor.missing:mycmd"))
        );
        assert!(requested.net_connect.is_empty());
    }

    #[test]
    fn ls_is_not_treated_as_network_or_unknown() {
        let operation = NormalizedOperation {
            kind: OperationKind::Exec,
            payload: json!({}),
            options: json!({}),
            labels: BTreeMap::new(),
            command: Some(NormalizedCommand::Shell("ls".to_string())),
            cwd: Some(PathBuf::from("/work")),
            env: BTreeMap::new(),
            paths: Vec::new(),
            hosts: Vec::new(),
            reason_codes: Vec::new(),
            unknown: false,
            runtime: runtime(),
        };

        let requested = CapabilityExtractor::default().from_operation(&operation);
        assert!(!requested.unknown);
        assert!(requested.net_connect.is_empty());
    }

    #[test]
    fn pwd_is_not_treated_as_network_or_unknown() {
        let operation = NormalizedOperation {
            kind: OperationKind::Exec,
            payload: json!({}),
            options: json!({}),
            labels: BTreeMap::new(),
            command: Some(NormalizedCommand::Shell("pwd".to_string())),
            cwd: Some(PathBuf::from("/work")),
            env: BTreeMap::new(),
            paths: Vec::new(),
            hosts: Vec::new(),
            reason_codes: Vec::new(),
            unknown: false,
            runtime: runtime(),
        };

        let requested = CapabilityExtractor::default().from_operation(&operation);
        assert!(!requested.unknown);
        assert!(requested.net_connect.is_empty());
    }

    #[test]
    fn infers_default_https_port_from_url() {
        let endpoint = parse_endpoint("https://www.baidu.com/path?q=1").expect("valid endpoint");
        assert_eq!(endpoint.host, "www.baidu.com");
        assert_eq!(endpoint.protocol.as_deref(), Some("https"));
        assert_eq!(endpoint.port, Some(443));
    }
}
