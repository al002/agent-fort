use std::path::{Path, PathBuf};

use crate::operation::{NormalizedCommand, NormalizedOperation, OperationKind};

use super::command_parser::{CommandParseError, CommandParser};
use super::{CommandIR, CommandNode, NetEndpoint, RedirectionKind, RequestedCapabilities};

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

        apply_builtin_baseline(
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

fn apply_builtin_baseline(
    binary: &str,
    command: &CommandNode,
    cwd: &Path,
    inline_shell_script_parsed: bool,
    requested: &mut RequestedCapabilities,
) {
    if apply_builtin_dangerous(binary, command, cwd, requested) {
        return;
    }

    if is_shell_binary(binary)
        && has_inline_script_flag(&command.argv)
        && !inline_shell_script_parsed
    {
        requested.host_exec = true;
        requested.unknown = true;
        requested
            .reason_codes
            .push(format!("dynamic.script:{binary}"));
        return;
    }

    if is_eval_interpreter(binary) && has_inline_script_flag(&command.argv) {
        requested.host_exec = true;
        requested.unknown = true;
        requested
            .reason_codes
            .push("dynamic.script.inline".to_string());
        return;
    }

    if apply_builtin_safe_profile(binary, command, cwd, requested) {
        return;
    }

    requested.unknown = true;
    requested
        .reason_codes
        .push(format!("command.unclassified:{}", command.raw));
}

fn apply_builtin_dangerous(
    binary: &str,
    command: &CommandNode,
    cwd: &Path,
    requested: &mut RequestedCapabilities,
) -> bool {
    if binary == "rm" || binary == "unlink" {
        add_fs_delete_from_positionals(command, cwd, requested);
        if rm_has_force_flag(&command.argv) {
            requested.unknown = true;
            requested
                .reason_codes
                .push("command.dangerous:rm_force".to_string());
        }
        return true;
    }

    if binary == "sudo" || binary == "su" {
        requested.privilege = true;
        if binary == "sudo" && command_might_be_dangerous(&command.argv[1..]) {
            requested.unknown = true;
            requested
                .reason_codes
                .push("command.dangerous:sudo_delegate".to_string());
        }
        return true;
    }

    if binary == "kill" || binary == "pkill" || binary == "killall" {
        requested.process_control = true;
        return true;
    }

    false
}

fn apply_builtin_safe_profile(
    binary: &str,
    command: &CommandNode,
    cwd: &Path,
    requested: &mut RequestedCapabilities,
) -> bool {
    if is_safe_no_capability_command(binary) {
        return true;
    }

    if is_safe_read_positionals_command(binary) {
        add_fs_read_from_positionals(command, cwd, requested);
        return true;
    }

    if is_safe_read_cwd_or_positionals_command(binary) {
        let before = requested.fs_read.len();
        add_fs_read_from_positionals(command, cwd, requested);
        if requested.fs_read.len() == before {
            requested.fs_read.insert(cwd.to_path_buf());
        }
        return true;
    }

    match binary {
        "grep" => {
            apply_grep_profile(command, cwd, requested);
            true
        }
        "rg" => {
            apply_rg_profile(command, cwd, requested);
            true
        }
        "find" => {
            apply_find_profile(command, cwd, requested);
            true
        }
        "git" => apply_git_read_only_profile(command, cwd, requested),
        "base64" => {
            apply_base64_profile(command, cwd, requested);
            true
        }
        "sed" => apply_sed_read_only_profile(command, cwd, requested),
        _ => false,
    }
}

fn is_safe_no_capability_command(binary: &str) -> bool {
    matches!(
        binary,
        "cd" | "echo"
            | "expr"
            | "false"
            | "id"
            | "pwd"
            | "seq"
            | "true"
            | "uname"
            | "which"
            | "whoami"
    )
}

fn is_safe_read_positionals_command(binary: &str) -> bool {
    matches!(
        binary,
        "cat"
            | "cut"
            | "head"
            | "nl"
            | "paste"
            | "rev"
            | "tail"
            | "tr"
            | "uniq"
            | "wc"
            | "numfmt"
            | "tac"
    )
}

fn is_safe_read_cwd_or_positionals_command(binary: &str) -> bool {
    matches!(binary, "ls" | "stat")
}

fn command_might_be_dangerous(argv: &[String]) -> bool {
    let Some(binary) = argv.first().map(|arg| command_base_name(arg)) else {
        return false;
    };
    match binary.as_str() {
        "rm" | "unlink" => rm_has_force_flag(argv),
        "sudo" => command_might_be_dangerous(argv.get(1..).unwrap_or_default()),
        _ => false,
    }
}

fn rm_has_force_flag(argv: &[String]) -> bool {
    argv.iter().any(|arg| {
        arg == "-f"
            || arg == "-rf"
            || arg == "-fr"
            || arg == "--force"
            || arg.starts_with("--force=")
            || (arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.contains('f')
                && arg.contains('r'))
    })
}

fn apply_grep_profile(command: &CommandNode, cwd: &Path, requested: &mut RequestedCapabilities) {
    let positionals = collect_positionals(&command.argv);
    if positionals.len() <= 1 {
        return;
    }
    for path in positionals.iter().skip(1) {
        let resolved = resolve_path(cwd, path);
        requested.fs_read.insert(resolved.clone());
        maybe_mark_credential(&resolved, requested);
    }
}

fn apply_rg_profile(command: &CommandNode, cwd: &Path, requested: &mut RequestedCapabilities) {
    const UNSAFE_OPTIONS_WITH_ARGS: &[&str] = &["--pre", "--hostname-bin"];
    const UNSAFE_OPTIONS_WITHOUT_ARGS: &[&str] = &["--search-zip", "-z"];

    let has_unsafe_arg = command.argv.iter().skip(1).any(|arg| {
        UNSAFE_OPTIONS_WITHOUT_ARGS.contains(&arg.as_str())
            || UNSAFE_OPTIONS_WITH_ARGS
                .iter()
                .any(|option| arg == option || arg.starts_with(&format!("{option}=")))
    });
    if has_unsafe_arg {
        requested.host_exec = true;
        requested.unknown = true;
        requested.reason_codes.push("command.risky:rg".to_string());
        return;
    }

    let positionals = collect_positionals(&command.argv);
    if positionals.len() <= 1 {
        requested.fs_read.insert(cwd.to_path_buf());
        return;
    }
    for path in positionals.iter().skip(1) {
        let resolved = resolve_path(cwd, path);
        requested.fs_read.insert(resolved.clone());
        maybe_mark_credential(&resolved, requested);
    }
}

fn apply_find_profile(command: &CommandNode, cwd: &Path, requested: &mut RequestedCapabilities) {
    const EXEC_OPTIONS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];
    const DELETE_OPTIONS: &[&str] = &["-delete"];
    const WRITE_OPTIONS: &[&str] = &["-fls", "-fprint", "-fprint0", "-fprintf"];

    if command
        .argv
        .iter()
        .any(|arg| EXEC_OPTIONS.contains(&arg.as_str()))
    {
        requested.host_exec = true;
        requested.unknown = true;
        requested
            .reason_codes
            .push("command.dangerous:find_exec".to_string());
        return;
    }

    let roots = find_starting_paths(command);
    if command
        .argv
        .iter()
        .any(|arg| DELETE_OPTIONS.contains(&arg.as_str()))
    {
        if roots.is_empty() {
            requested.fs_delete.insert(cwd.to_path_buf());
        } else {
            for root in &roots {
                let resolved = resolve_path(cwd, root);
                requested.fs_delete.insert(resolved.clone());
                maybe_mark_credential(&resolved, requested);
            }
        }
        requested.unknown = true;
        requested
            .reason_codes
            .push("command.dangerous:find_delete".to_string());
        return;
    }

    let mut wrote = false;
    for index in 1..command.argv.len() {
        let arg = &command.argv[index];
        if WRITE_OPTIONS.contains(&arg.as_str())
            && let Some(path) = command.argv.get(index + 1)
        {
            let resolved = resolve_path(cwd, path);
            requested.fs_write.insert(resolved.clone());
            maybe_mark_credential(&resolved, requested);
            wrote = true;
        }
    }
    if wrote {
        return;
    }

    if roots.is_empty() {
        requested.fs_read.insert(cwd.to_path_buf());
    } else {
        for root in roots {
            let resolved = resolve_path(cwd, &root);
            requested.fs_read.insert(resolved.clone());
            maybe_mark_credential(&resolved, requested);
        }
    }
}

fn find_starting_paths(command: &CommandNode) -> Vec<String> {
    let mut roots = Vec::new();
    for token in command.argv.iter().skip(1) {
        if token == "--" {
            break;
        }
        if token.starts_with('-') || token == "!" || token == "(" || token == ")" {
            break;
        }
        roots.push(token.clone());
    }
    roots
}

fn apply_git_read_only_profile(
    command: &CommandNode,
    cwd: &Path,
    requested: &mut RequestedCapabilities,
) -> bool {
    if git_has_config_override_global_option(&command.argv) {
        return false;
    }

    let Some((subcommand_idx, subcommand)) =
        find_git_subcommand(&command.argv, &["status", "log", "diff", "show", "branch"])
    else {
        return false;
    };

    let subcommand_args = &command.argv[subcommand_idx + 1..];
    let read_only = match subcommand {
        "status" | "log" | "diff" | "show" => git_subcommand_args_are_read_only(subcommand_args),
        "branch" => {
            git_subcommand_args_are_read_only(subcommand_args)
                && git_branch_is_read_only(subcommand_args)
        }
        _ => false,
    };
    if !read_only {
        return false;
    }

    requested.fs_read.insert(cwd.to_path_buf());
    true
}

fn find_git_subcommand<'a>(
    command: &'a [String],
    subcommands: &[&str],
) -> Option<(usize, &'a str)> {
    if command.first().map(|arg| command_base_name(arg)).as_deref() != Some("git") {
        return None;
    }

    let mut skip_next = false;
    for (index, arg) in command.iter().enumerate().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }

        let token = arg.as_str();
        if is_git_global_option_with_inline_value(token) {
            continue;
        }
        if is_git_global_option_with_value(token) {
            skip_next = true;
            continue;
        }
        if token == "--" || token.starts_with('-') {
            continue;
        }
        if subcommands.contains(&token) {
            return Some((index, token));
        }
        return None;
    }
    None
}

fn is_git_global_option_with_value(arg: &str) -> bool {
    matches!(
        arg,
        "-C" | "-c"
            | "--config-env"
            | "--exec-path"
            | "--git-dir"
            | "--namespace"
            | "--super-prefix"
            | "--work-tree"
    )
}

fn is_git_global_option_with_inline_value(arg: &str) -> bool {
    matches!(
        arg,
        s if s.starts_with("--config-env=")
            || s.starts_with("--exec-path=")
            || s.starts_with("--git-dir=")
            || s.starts_with("--namespace=")
            || s.starts_with("--super-prefix=")
            || s.starts_with("--work-tree=")
    ) || ((arg.starts_with("-C") || arg.starts_with("-c")) && arg.len() > 2)
}

fn git_has_config_override_global_option(command: &[String]) -> bool {
    command.iter().map(String::as_str).any(|arg| {
        matches!(arg, "-c" | "--config-env")
            || (arg.starts_with("-c") && arg.len() > 2)
            || arg.starts_with("--config-env=")
    })
}

fn git_subcommand_args_are_read_only(args: &[String]) -> bool {
    const UNSAFE_GIT_FLAGS: &[&str] = &[
        "--output",
        "--ext-diff",
        "--textconv",
        "--exec",
        "--paginate",
    ];

    !args.iter().map(String::as_str).any(|arg| {
        UNSAFE_GIT_FLAGS.contains(&arg)
            || arg.starts_with("--output=")
            || arg.starts_with("--exec=")
    })
}

fn git_branch_is_read_only(branch_args: &[String]) -> bool {
    if branch_args.is_empty() {
        return true;
    }

    let mut saw_read_only_flag = false;
    for arg in branch_args.iter().map(String::as_str) {
        match arg {
            "--list" | "-l" | "--show-current" | "-a" | "--all" | "-r" | "--remotes" | "-v"
            | "-vv" | "--verbose" => {
                saw_read_only_flag = true;
            }
            _ if arg.starts_with("--format=") => {
                saw_read_only_flag = true;
            }
            _ => return false,
        }
    }
    saw_read_only_flag
}

fn apply_base64_profile(command: &CommandNode, cwd: &Path, requested: &mut RequestedCapabilities) {
    const OUTPUT_OPTIONS: &[&str] = &["-o", "--output"];
    let mut wrote = false;
    for index in 1..command.argv.len() {
        let arg = &command.argv[index];
        if OUTPUT_OPTIONS.contains(&arg.as_str())
            && let Some(target) = command.argv.get(index + 1)
        {
            let path = resolve_path(cwd, target);
            requested.fs_write.insert(path.clone());
            maybe_mark_credential(&path, requested);
            wrote = true;
            continue;
        }
        if let Some(target) = arg.strip_prefix("--output=") {
            let path = resolve_path(cwd, target);
            requested.fs_write.insert(path.clone());
            maybe_mark_credential(&path, requested);
            wrote = true;
            continue;
        }
        if arg.starts_with("-o") && arg != "-o" {
            let path = resolve_path(cwd, &arg[2..]);
            requested.fs_write.insert(path.clone());
            maybe_mark_credential(&path, requested);
            wrote = true;
        }
    }
    if wrote {
        return;
    }

    add_fs_read_from_positionals(command, cwd, requested);
}

fn apply_sed_read_only_profile(
    command: &CommandNode,
    cwd: &Path,
    requested: &mut RequestedCapabilities,
) -> bool {
    if !is_safe_sed_n_invocation(command) {
        return false;
    }
    if let Some(path) = command.argv.get(3) {
        let resolved = resolve_path(cwd, path);
        requested.fs_read.insert(resolved.clone());
        maybe_mark_credential(&resolved, requested);
    }
    true
}

fn is_safe_sed_n_invocation(command: &CommandNode) -> bool {
    command.argv.len() <= 4
        && command.argv.get(1).map(String::as_str) == Some("-n")
        && is_valid_sed_n_arg(command.argv.get(2).map(String::as_str))
}

fn is_valid_sed_n_arg(arg: Option<&str>) -> bool {
    let Some(value) = arg else {
        return false;
    };
    let Some(core) = value.strip_suffix('p') else {
        return false;
    };

    let parts: Vec<&str> = core.split(',').collect();
    match parts.as_slice() {
        [num] => !num.is_empty() && num.chars().all(|ch| ch.is_ascii_digit()),
        [left, right] => {
            !left.is_empty()
                && !right.is_empty()
                && left.chars().all(|ch| ch.is_ascii_digit())
                && right.chars().all(|ch| ch.is_ascii_digit())
        }
        _ => false,
    }
}

fn add_fs_read_from_positionals(
    command: &CommandNode,
    cwd: &Path,
    requested: &mut RequestedCapabilities,
) {
    for value in collect_positionals(&command.argv) {
        let path = resolve_path(cwd, &value);
        requested.fs_read.insert(path.clone());
        maybe_mark_credential(&path, requested);
    }
}

fn add_fs_delete_from_positionals(
    command: &CommandNode,
    cwd: &Path,
    requested: &mut RequestedCapabilities,
) {
    for value in collect_positionals(&command.argv) {
        let path = resolve_path(cwd, &value);
        requested.fs_delete.insert(path.clone());
        maybe_mark_credential(&path, requested);
    }
}

fn is_shell_binary(binary: &str) -> bool {
    matches!(binary, "sh" | "bash" | "zsh" | "dash" | "ksh")
}

fn is_eval_interpreter(binary: &str) -> bool {
    matches!(
        binary,
        "python" | "python3" | "node" | "deno" | "perl" | "ruby"
    )
}

fn has_inline_script_flag(argv: &[String]) -> bool {
    argv.iter()
        .any(|arg| arg == "-c" || arg == "-e" || arg == "--eval")
}

pub(super) fn collect_positionals(argv: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    let binary = argv
        .first()
        .map(|value| command_base_name(value))
        .unwrap_or_default();
    let mut index = 1usize;
    while index < argv.len() {
        let token = &argv[index];
        if token == "--" {
            result.extend(argv.iter().skip(index + 1).cloned());
            break;
        }
        if token.starts_with('-') {
            if option_consumes_next_value(binary.as_str(), token, argv.get(index + 1)) {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        result.push(token.clone());
        index += 1;
    }
    result
}

fn option_consumes_next_value(binary: &str, option: &str, next: Option<&String>) -> bool {
    let Some(next) = next.map(String::as_str) else {
        return false;
    };
    if next == "--" || next.starts_with('-') {
        return false;
    }

    if option.starts_with("--") {
        if option.contains('=') {
            return false;
        }
        return long_option_takes_value(option);
    }
    if !option.starts_with('-') || option.len() != 2 {
        return false;
    }

    let short = option.as_bytes()[1] as char;
    if matches!(short, 'o' | 'e' | 'f' | 'd' | 't' | 'u' | 'x' | 'I' | 'L') {
        return true;
    }

    matches!(short, 'n' | 'c' | 'A' | 'B' | 'C' | 'm' | 's' | 'w')
        && (matches!(binary, "head" | "tail" | "grep" | "rg")
            || next
                .chars()
                .all(|ch| ch.is_ascii_digit() || ch == '+' || ch == '-'))
}

fn long_option_takes_value(option: &str) -> bool {
    matches!(
        option,
        "--output"
            | "--file"
            | "--expression"
            | "--regexp"
            | "--max-count"
            | "--context"
            | "--before-context"
            | "--after-context"
            | "--glob"
            | "--type"
            | "--type-not"
            | "--threads"
            | "--sort"
            | "--sortr"
            | "--bytes"
            | "--lines"
    )
}

pub(super) fn resolve_path(cwd: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    let joined = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    crate::capability::matcher::normalize_lexical_path(&joined)
}

pub(super) fn parse_endpoint(raw: &str) -> Option<NetEndpoint> {
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

pub(super) fn looks_like_credential_path(raw: &str) -> bool {
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
    fn unclassified_command_is_unknown_without_rules() {
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
        assert!(requested.unknown);
        assert!(
            requested
                .reason_codes
                .iter()
                .any(|code| code == "command.unclassified:curl https://example.com -o out.txt")
        );
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
        assert!(requested.unknown);
        assert!(
            requested
                .reason_codes
                .iter()
                .any(|code| code == "command.unclassified:mycmd --flag")
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
        assert!(requested.fs_read.contains(&PathBuf::from("/work")));
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

    #[test]
    fn git_status_is_safe_builtin_and_reads_cwd_without_rules() {
        let operation = NormalizedOperation {
            kind: OperationKind::Exec,
            payload: json!({}),
            options: json!({}),
            labels: BTreeMap::new(),
            command: Some(NormalizedCommand::Shell("git status".to_string())),
            cwd: Some(PathBuf::from("/work/repo")),
            env: BTreeMap::new(),
            paths: Vec::new(),
            hosts: Vec::new(),
            reason_codes: Vec::new(),
            unknown: false,
            runtime: runtime(),
        };

        let requested = CapabilityExtractor::default().from_operation(&operation);
        assert!(!requested.unknown);
        assert!(requested.fs_read.contains(&PathBuf::from("/work/repo")));
    }

    #[test]
    fn git_fetch_without_url_is_marked_unknown() {
        let operation = NormalizedOperation {
            kind: OperationKind::Exec,
            payload: json!({}),
            options: json!({}),
            labels: BTreeMap::new(),
            command: Some(NormalizedCommand::Shell("git fetch origin".to_string())),
            cwd: Some(PathBuf::from("/work/repo")),
            env: BTreeMap::new(),
            paths: Vec::new(),
            hosts: Vec::new(),
            reason_codes: Vec::new(),
            unknown: false,
            runtime: runtime(),
        };

        let requested = CapabilityExtractor::default().from_operation(&operation);
        assert!(requested.unknown);
        assert!(
            requested
                .reason_codes
                .iter()
                .any(|code| code == "command.unclassified:git fetch origin")
        );
    }

    #[test]
    fn rm_force_marks_unknown_and_delete_capability() {
        let operation = NormalizedOperation {
            kind: OperationKind::Exec,
            payload: json!({}),
            options: json!({}),
            labels: BTreeMap::new(),
            command: Some(NormalizedCommand::Shell("rm -rf target".to_string())),
            cwd: Some(PathBuf::from("/work/repo")),
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
                .fs_delete
                .contains(&PathBuf::from("/work/repo/target"))
        );
        assert!(requested.unknown);
        assert!(
            requested
                .reason_codes
                .iter()
                .any(|code| code == "command.dangerous:rm_force")
        );
    }

    #[test]
    fn unclassified_command_stays_unknown_in_multi_command_script() {
        let operation = NormalizedOperation {
            kind: OperationKind::Exec,
            payload: json!({}),
            options: json!({}),
            labels: BTreeMap::new(),
            command: Some(NormalizedCommand::Shell(
                "git status && mycmd --flag".to_string(),
            )),
            cwd: Some(PathBuf::from("/work/repo")),
            env: BTreeMap::new(),
            paths: Vec::new(),
            hosts: Vec::new(),
            reason_codes: Vec::new(),
            unknown: false,
            runtime: runtime(),
        };

        let requested = CapabilityExtractor::default().from_operation(&operation);
        assert!(requested.unknown);
        assert!(
            requested
                .reason_codes
                .iter()
                .any(|code| code == "command.unclassified:mycmd --flag")
        );
    }

    #[test]
    fn collect_positionals_skips_option_values() {
        let argv = vec![
            "head".to_string(),
            "-n".to_string(),
            "10".to_string(),
            "file.txt".to_string(),
        ];

        let positionals = collect_positionals(&argv);
        assert_eq!(positionals, vec!["file.txt".to_string()]);
    }

    #[test]
    fn collect_positionals_keeps_args_after_valueless_options() {
        let argv = vec!["jq".to_string(), "-c".to_string(), "file.json".to_string()];

        let positionals = collect_positionals(&argv);
        assert_eq!(positionals, vec!["file.json".to_string()]);
    }
}
