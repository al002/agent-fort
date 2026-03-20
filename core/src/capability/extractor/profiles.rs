use std::path::Path;

use super::{CommandNode, RequestedCapabilities};
use super::{collect_positionals, command_base_name, maybe_mark_credential, resolve_path};

pub(super) fn apply_builtin_baseline(
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
