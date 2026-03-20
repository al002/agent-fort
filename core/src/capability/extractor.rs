use std::path::Path;

use crate::operation::{NormalizedCommand, NormalizedOperation, OperationKind};

use super::command_parser::{CommandParseError, CommandParser};
use super::{CommandIR, CommandNode, NetEndpoint, RedirectionKind, RequestedCapabilities};

mod helpers;
mod profiles;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub struct CapabilityExtractor {
    parser: CommandParser,
}

impl Default for CapabilityExtractor {
    fn default() -> Self {
        Self {
            parser: CommandParser,
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

        let mut inline_shell_script_parsed = false;
        if matches!(binary.as_str(), "sh" | "bash" | "zsh" | "dash" | "ksh")
            && let Some(script) = script_from_argv(&command.argv)
        {
            match self.parser.parse(&script) {
                Ok(ir) => {
                    inline_shell_script_parsed = true;
                    requested.merge(self.from_command_ir(&ir, Some(cwd)));
                }
                Err(_) => {
                    requested.unknown = true;
                    requested.reason_codes.push("parser.failed".to_string());
                }
            }
        }

        profiles::apply_builtin_baseline(
            binary.as_str(),
            command,
            cwd,
            inline_shell_script_parsed,
            requested,
        );

        for token in &command.argv {
            if looks_like_credential_path(token) {
                requested.credential_access = true;
            }
        }
    }
}

pub(super) fn command_base_name(value: &str) -> String {
    std::path::Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(value)
        .to_ascii_lowercase()
}

pub(super) fn collect_positionals(argv: &[String]) -> Vec<String> {
    helpers::collect_positionals(argv)
}

pub(super) fn resolve_path(cwd: &Path, raw: &str) -> std::path::PathBuf {
    helpers::resolve_path(cwd, raw)
}

pub(super) fn parse_endpoint(raw: &str) -> Option<NetEndpoint> {
    helpers::parse_endpoint(raw)
}

pub(super) fn looks_like_credential_path(raw: &str) -> bool {
    helpers::looks_like_credential_path(raw)
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

fn maybe_mark_credential(path: &Path, requested: &mut RequestedCapabilities) {
    if looks_like_credential_path(path.to_string_lossy().as_ref()) {
        requested.credential_access = true;
    }
}
