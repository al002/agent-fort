use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;
use thiserror::Error;
use tree_sitter::{Node, Parser};

use super::{
    Fact, Facts, Intent, NormalizedOperation, OperationKind, RuntimeContext, Target, TargetKind,
};

const DEFAULT_SYSTEM_ROOTS: &[&str] = &[
    "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/proc", "/sys", "/dev",
    "/var",
];

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

        let path_policy = PathPolicy::from_inputs(&runtime, &raw.payload, &raw.options);

        let mut targets = extract_targets(kind, &raw.payload, &raw.options);
        let mut facts = base_facts(&raw.payload, &raw.options, &labels);
        let mut affected_paths = extract_affected_paths(kind, &raw.payload, &raw.options, &runtime);

        apply_kind_defaults(kind, &mut facts, &affected_paths, &path_policy);
        apply_exec_fact_inference(
            kind,
            &mut facts,
            &mut affected_paths,
            &raw.payload,
            &raw.options,
            &runtime,
            &path_policy,
        );

        add_path_targets(&mut targets, &affected_paths);
        if let Fact::Known(host) = facts.primary_host.as_ref() {
            let mut dedupe = targets
                .iter()
                .map(|target| (target.kind, target.value.clone()))
                .collect::<BTreeSet<_>>();
            push_target(
                TargetKind::Host,
                host.to_string(),
                &mut dedupe,
                &mut targets,
            );
        }

        facts.touches_policy_dir =
            Fact::Known(touches_policy_dir(&affected_paths, &runtime.policy_dir));
        facts.affected_paths = dedupe_paths(affected_paths);
        facts.reason_codes = dedupe_strings(facts.reason_codes);

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

#[derive(Debug, Clone)]
struct PathPolicy {
    safe_roots: Vec<PathBuf>,
    system_roots: Vec<PathBuf>,
}

impl PathPolicy {
    fn from_inputs(runtime: &RuntimeContext, payload: &Value, options: &Value) -> Self {
        let mut safe_roots = Vec::new();
        if let Some(root) = runtime.workspace_root.as_deref() {
            safe_roots.push(normalize_lexical_path(root));
        }
        for root in find_string_array_path(payload, "risk.safe_roots")
            .into_iter()
            .chain(find_string_array_path(options, "risk.safe_roots"))
        {
            safe_roots.push(resolve_path(
                root.as_str(),
                runtime.workspace_root.as_deref(),
            ));
        }
        safe_roots = dedupe_paths(safe_roots);

        let mut system_roots = DEFAULT_SYSTEM_ROOTS
            .iter()
            .map(|root| PathBuf::from(root))
            .collect::<Vec<_>>();

        for add in find_string_array_path(payload, "risk.system_roots_add")
            .into_iter()
            .chain(find_string_array_path(options, "risk.system_roots_add"))
        {
            if add.starts_with('/') {
                system_roots.push(normalize_lexical_path(Path::new(&add)));
            }
        }

        let remove = find_string_array_path(payload, "risk.system_roots_remove")
            .into_iter()
            .chain(find_string_array_path(options, "risk.system_roots_remove"))
            .map(|value| normalize_lexical_path(Path::new(&value)))
            .collect::<BTreeSet<_>>();
        system_roots.retain(|root| !remove.contains(root));
        system_roots = dedupe_paths(system_roots);

        Self {
            safe_roots,
            system_roots,
        }
    }

    fn classify_path(&self, path: &Path) -> PathBucket {
        if self.is_safe_path(path) {
            return PathBucket::Safe;
        }
        if self.is_system_path(path) {
            return PathBucket::System;
        }
        PathBucket::Other
    }

    fn is_system_path(&self, path: &Path) -> bool {
        let normalized = normalize_lexical_path(path);
        if normalized == PathBuf::from("/") {
            return true;
        }
        path_under_roots(&normalized, &self.system_roots)
    }

    fn is_safe_path(&self, path: &Path) -> bool {
        path_under_roots(path, &self.safe_roots)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathBucket {
    Safe,
    System,
    Other,
}

fn path_under_roots(path: &Path, roots: &[PathBuf]) -> bool {
    let normalized = normalize_lexical_path(path);
    roots
        .iter()
        .any(|root| normalized == *root || normalized.starts_with(root))
}

fn base_facts(payload: &Value, options: &Value, labels: &BTreeMap<String, String>) -> Facts {
    Facts {
        interactive: bool_fact(
            payload,
            options,
            labels,
            &["interactive", "risk.override.interactive"],
        ),
        safe_file_read: bool_fact(
            payload,
            options,
            labels,
            &["safe_file_read", "risk.override.safe_file_read"],
        ),
        safe_file_write: bool_fact(
            payload,
            options,
            labels,
            &["safe_file_write", "risk.override.safe_file_write"],
        ),
        system_file_read: bool_fact(
            payload,
            options,
            labels,
            &["system_file_read", "risk.override.system_file_read"],
        ),
        system_file_write: bool_fact(
            payload,
            options,
            labels,
            &["system_file_write", "risk.override.system_file_write"],
        ),
        network_access: bool_fact(
            payload,
            options,
            labels,
            &["network_access", "risk.override.network_access"],
        ),
        system_admin: bool_fact(
            payload,
            options,
            labels,
            &["system_admin", "risk.override.system_admin"],
        ),
        process_control: bool_fact(
            payload,
            options,
            labels,
            &["process_control", "risk.override.process_control"],
        ),
        credential_access: bool_fact(
            payload,
            options,
            labels,
            &["credential_access", "risk.override.credential_access"],
        ),
        unknown_intent: bool_fact(
            payload,
            options,
            labels,
            &["unknown_intent", "risk.override.unknown_intent"],
        ),
        touches_policy_dir: Fact::Unknown,
        primary_host: host_fact(payload, options, labels),
        command_text: command_text_fact(payload, options),
        affected_paths: Vec::new(),
        reason_codes: Vec::new(),
    }
}

fn apply_kind_defaults(
    kind: OperationKind,
    facts: &mut Facts,
    affected_paths: &[PathBuf],
    path_policy: &PathPolicy,
) {
    set_if_unknown(&mut facts.interactive, false);

    match kind {
        OperationKind::FileRead => {
            apply_path_access_facts(facts, affected_paths, path_policy, AccessMode::Read);
            set_if_unknown(&mut facts.safe_file_write, false);
            set_if_unknown(&mut facts.system_file_write, false);
            set_if_unknown(&mut facts.network_access, false);
            set_if_unknown(&mut facts.system_admin, false);
            set_if_unknown(&mut facts.process_control, false);
            fill_credential_from_paths_if_unknown(facts, affected_paths);
            set_if_unknown(&mut facts.unknown_intent, false);
        }
        OperationKind::FileWrite | OperationKind::FilePatch => {
            apply_path_access_facts(facts, affected_paths, path_policy, AccessMode::Write);
            set_if_unknown(&mut facts.safe_file_read, false);
            set_if_unknown(&mut facts.system_file_read, false);
            set_if_unknown(&mut facts.network_access, false);
            set_if_unknown(&mut facts.system_admin, false);
            set_if_unknown(&mut facts.process_control, false);
            fill_credential_from_paths_if_unknown(facts, affected_paths);
            set_if_unknown(&mut facts.unknown_intent, false);
        }
        OperationKind::Fetch => {
            set_if_unknown(&mut facts.network_access, true);
            set_if_unknown(&mut facts.system_admin, false);
            set_if_unknown(&mut facts.process_control, false);
            set_if_unknown(&mut facts.safe_file_read, false);
            set_if_unknown(&mut facts.system_file_read, false);
            if !affected_paths.is_empty() {
                apply_path_access_facts(facts, affected_paths, path_policy, AccessMode::Write);
            } else {
                set_if_unknown(&mut facts.safe_file_write, false);
                set_if_unknown(&mut facts.system_file_write, false);
            }
            fill_credential_from_paths_if_unknown(facts, affected_paths);
            set_if_unknown(&mut facts.unknown_intent, false);
        }
        OperationKind::Exec => {}
        OperationKind::ToolCall | OperationKind::Unknown => {
            set_if_unknown(&mut facts.unknown_intent, true);
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AccessMode {
    Read,
    Write,
}

fn apply_path_access_facts(
    facts: &mut Facts,
    paths: &[PathBuf],
    path_policy: &PathPolicy,
    mode: AccessMode,
) {
    let mut saw_safe = false;
    let mut saw_system = false;
    let mut saw_other = false;

    for path in paths {
        match path_policy.classify_path(path) {
            PathBucket::Safe => saw_safe = true,
            PathBucket::System => saw_system = true,
            PathBucket::Other => saw_other = true,
        }
    }

    match mode {
        AccessMode::Read => {
            set_if_unknown(&mut facts.safe_file_read, saw_safe);
            set_if_unknown(&mut facts.system_file_read, saw_system);
        }
        AccessMode::Write => {
            set_if_unknown(&mut facts.safe_file_write, saw_safe);
            set_if_unknown(&mut facts.system_file_write, saw_system);
        }
    }

    if saw_other {
        set_if_unknown(&mut facts.unknown_intent, true);
        facts
            .reason_codes
            .push("path.outside_known_roots".to_string());
    }
}

fn fill_credential_from_paths_if_unknown(facts: &mut Facts, paths: &[PathBuf]) {
    if matches!(facts.credential_access, Fact::Unknown) {
        let flagged = paths
            .iter()
            .any(|path| is_credential_path(path.display().to_string().as_str()));
        facts.credential_access = Fact::Known(flagged);
    }
}

fn apply_exec_fact_inference(
    kind: OperationKind,
    facts: &mut Facts,
    affected_paths: &mut Vec<PathBuf>,
    payload: &Value,
    options: &Value,
    runtime: &RuntimeContext,
    path_policy: &PathPolicy,
) {
    if kind != OperationKind::Exec {
        return;
    }

    let command = extract_command_text(payload).or_else(|| extract_command_text(options));
    let Some(command) = command else {
        set_if_unknown(&mut facts.unknown_intent, true);
        facts.reason_codes.push("exec.command_missing".to_string());
        return;
    };

    let inference = analyze_exec_command(command.as_str(), runtime, path_policy);

    merge_fact(&mut facts.safe_file_read, inference.safe_file_read);
    merge_fact(&mut facts.safe_file_write, inference.safe_file_write);
    merge_fact(&mut facts.system_file_read, inference.system_file_read);
    merge_fact(&mut facts.system_file_write, inference.system_file_write);
    merge_fact(&mut facts.network_access, inference.network_access);
    merge_fact(&mut facts.system_admin, inference.system_admin);
    merge_fact(&mut facts.process_control, inference.process_control);
    merge_fact(&mut facts.credential_access, inference.credential_access);
    merge_fact(&mut facts.unknown_intent, inference.unknown_intent);

    if matches!(facts.primary_host, Fact::Unknown)
        && let Some(host) = inference.primary_host
    {
        facts.primary_host = Fact::Known(host);
    }

    affected_paths.extend(inference.affected_paths);
    facts.reason_codes.extend(inference.reason_codes);
}

#[derive(Debug, Clone)]
struct ExecInference {
    safe_file_read: Option<bool>,
    safe_file_write: Option<bool>,
    system_file_read: Option<bool>,
    system_file_write: Option<bool>,
    network_access: Option<bool>,
    system_admin: Option<bool>,
    process_control: Option<bool>,
    credential_access: Option<bool>,
    unknown_intent: Option<bool>,
    primary_host: Option<String>,
    affected_paths: Vec<PathBuf>,
    reason_codes: Vec<String>,
}

impl ExecInference {
    fn baseline() -> Self {
        Self {
            safe_file_read: Some(false),
            safe_file_write: Some(false),
            system_file_read: Some(false),
            system_file_write: Some(false),
            network_access: Some(false),
            system_admin: Some(false),
            process_control: Some(false),
            credential_access: Some(false),
            unknown_intent: Some(false),
            primary_host: None,
            affected_paths: Vec::new(),
            reason_codes: Vec::new(),
        }
    }

    fn unknown(reason: &str) -> Self {
        Self {
            safe_file_read: None,
            safe_file_write: None,
            system_file_read: None,
            system_file_write: None,
            network_access: None,
            system_admin: None,
            process_control: None,
            credential_access: None,
            unknown_intent: Some(true),
            primary_host: None,
            affected_paths: Vec::new(),
            reason_codes: vec![reason.to_string()],
        }
    }

    fn mark_unknown(&mut self, reason: &str) {
        self.unknown_intent = Some(true);
        self.reason_codes.push(reason.to_string());
    }
}

fn analyze_exec_command(
    command_text: &str,
    runtime: &RuntimeContext,
    path_policy: &PathPolicy,
) -> ExecInference {
    let mut parser = Parser::new();
    let language = tree_sitter_bash::LANGUAGE;
    if parser.set_language(&language.into()).is_err() {
        return ExecInference::unknown("exec.parser_language_unavailable");
    }

    let Some(tree) = parser.parse(command_text, None) else {
        return ExecInference::unknown("exec.parser_failed");
    };

    let mut analyzer =
        ExecAnalyzer::new(command_text, runtime.workspace_root.as_deref(), path_policy);
    analyzer.walk(tree.root_node());

    let command_count = analyzer.command_count;
    let recognized_any = analyzer.recognized_any;
    let mut result = analyzer.finish();
    if tree.root_node().has_error() {
        result.mark_unknown("exec.parse_has_error");
    }
    if command_count == 0 {
        result.mark_unknown("exec.no_command_nodes");
    }
    if command_count > 0 && !recognized_any {
        result.mark_unknown("exec.unclassified_command");
    }

    result.affected_paths = dedupe_paths(result.affected_paths);
    result.reason_codes = dedupe_strings(result.reason_codes);
    result
}

struct ExecAnalyzer<'a> {
    source: &'a str,
    workspace_root: Option<&'a Path>,
    path_policy: &'a PathPolicy,
    inference: ExecInference,
    command_count: usize,
    recognized_any: bool,
}

impl<'a> ExecAnalyzer<'a> {
    fn new(source: &'a str, workspace_root: Option<&'a Path>, path_policy: &'a PathPolicy) -> Self {
        Self {
            source,
            workspace_root,
            path_policy,
            inference: ExecInference::baseline(),
            command_count: 0,
            recognized_any: false,
        }
    }

    fn finish(self) -> ExecInference {
        self.inference
    }

    fn walk(&mut self, node: Node<'_>) {
        if node.kind() == "command" {
            self.analyze_command(node);
        }

        if node.kind().contains("redirect") {
            self.analyze_redirect(node);
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk(child);
        }
    }

    fn analyze_command(&mut self, node: Node<'_>) {
        let Ok(raw) = node.utf8_text(self.source.as_bytes()) else {
            self.inference.mark_unknown("exec.utf8_decode_failed");
            return;
        };
        let tokens = tokenize_shell_fragment(raw);
        if tokens.is_empty() {
            return;
        }

        self.command_count += 1;
        let command = canonical_command(&tokens[0]);
        let args = &tokens[1..];

        let mut recognized = false;

        if is_network_command(command.as_str()) {
            self.inference.network_access = Some(true);
            self.inference
                .reason_codes
                .push("exec.network_command".to_string());
            recognized = true;
        }
        if is_system_admin_command(command.as_str()) {
            self.inference.system_admin = Some(true);
            self.inference
                .reason_codes
                .push("exec.system_admin_command".to_string());
            recognized = true;
        }
        if is_process_control_command(command.as_str()) {
            self.inference.process_control = Some(true);
            self.inference
                .reason_codes
                .push("exec.process_control_command".to_string());
            recognized = true;
        }
        if is_credential_command(command.as_str()) {
            self.inference.credential_access = Some(true);
            self.inference
                .reason_codes
                .push("exec.credential_command".to_string());
            recognized = true;
        }

        if command == "git" {
            recognized = self.classify_git(args) || recognized;
        }

        recognized = self.classify_file_intent(command.as_str(), args) || recognized;

        if command == "curl" || command == "wget" {
            recognized = self.classify_fetch_outputs(args) || recognized;
        }

        for token in tokens {
            if let Some(host) = host_from_url(token.as_str()) {
                self.inference.network_access = Some(true);
                if self.inference.primary_host.is_none() {
                    self.inference.primary_host = Some(host);
                }
                recognized = true;
            }
            if is_credential_path(token.as_str()) {
                self.inference.credential_access = Some(true);
                recognized = true;
            }
        }

        if is_known_safe_command(command.as_str()) {
            recognized = true;
        }

        if recognized {
            self.recognized_any = true;
        }
    }

    fn classify_git(&mut self, args: &[String]) -> bool {
        let Some(sub) = args.first().map(|value| value.to_ascii_lowercase()) else {
            return false;
        };

        match sub.as_str() {
            "clone" | "fetch" | "pull" | "push" | "ls-remote" => {
                self.inference.network_access = Some(true);
                self.inference
                    .reason_codes
                    .push("exec.git_network".to_string());
                true
            }
            "add" | "commit" | "reset" | "checkout" | "clean" | "rm" => {
                self.inference.safe_file_write = Some(true);
                self.inference
                    .reason_codes
                    .push("exec.git_write".to_string());
                true
            }
            _ => true,
        }
    }

    fn classify_file_intent(&mut self, command: &str, args: &[String]) -> bool {
        if command == "sed" {
            let in_place = args.iter().any(|arg| arg == "-i" || arg.starts_with("-i"));
            if in_place {
                let paths = write_path_args(command, args);
                self.mark_paths(&paths, AccessMode::Write);
            } else {
                let paths = read_path_args(command, args);
                self.mark_paths(&paths, AccessMode::Read);
            }
            return true;
        }

        if is_read_file_command(command) {
            let paths = read_path_args(command, args);
            self.mark_paths(&paths, AccessMode::Read);
            return true;
        }

        if is_write_file_command(command) {
            let paths = write_path_args(command, args);
            self.mark_paths(&paths, AccessMode::Write);
            return true;
        }

        false
    }

    fn classify_fetch_outputs(&mut self, args: &[String]) -> bool {
        let mut recognized = false;
        let mut index = 0;
        while index < args.len() {
            let current = args[index].as_str();
            if (current == "-o" || current == "-O" || current == "--output")
                && index + 1 < args.len()
            {
                self.mark_paths(&[args[index + 1].clone()], AccessMode::Write);
                recognized = true;
                index += 2;
                continue;
            }
            index += 1;
        }
        recognized
    }

    fn analyze_redirect(&mut self, node: Node<'_>) {
        let Ok(raw) = node.utf8_text(self.source.as_bytes()) else {
            return;
        };
        let trimmed = raw.trim();
        if !trimmed.contains('>') {
            return;
        }

        self.inference
            .reason_codes
            .push("exec.redirect_write".to_string());

        if let Some(path) = parse_redirect_target(trimmed) {
            self.mark_paths(&[path], AccessMode::Write);
        } else {
            self.inference.mark_unknown("exec.redirect_target_unknown");
        }
        self.recognized_any = true;
    }

    fn mark_paths(&mut self, raw_paths: &[String], mode: AccessMode) {
        let mut saw_safe = false;
        let mut saw_system = false;
        let mut saw_other = false;

        for raw in raw_paths {
            let token = clean_token(raw);
            if token.is_empty() {
                continue;
            }
            if token.starts_with('$') || token.contains("$(") || token.contains("${") {
                saw_other = true;
                self.inference.mark_unknown("exec.dynamic_path");
                continue;
            }
            if token.contains("://") {
                continue;
            }
            if token == "-" {
                continue;
            }

            let resolved = resolve_path(token.as_str(), self.workspace_root);
            self.inference.affected_paths.push(resolved.clone());

            if is_credential_path(token.as_str()) {
                self.inference.credential_access = Some(true);
            }

            match self.path_policy.classify_path(&resolved) {
                PathBucket::Safe => saw_safe = true,
                PathBucket::System => saw_system = true,
                PathBucket::Other => saw_other = true,
            }
        }

        match mode {
            AccessMode::Read => {
                if saw_safe {
                    self.inference.safe_file_read = Some(true);
                }
                if saw_system {
                    self.inference.system_file_read = Some(true);
                }
            }
            AccessMode::Write => {
                if saw_safe {
                    self.inference.safe_file_write = Some(true);
                }
                if saw_system {
                    self.inference.system_file_write = Some(true);
                }
            }
        }

        if saw_other {
            self.inference.mark_unknown("exec.path_outside_known_roots");
        }
    }
}

fn read_path_args(command: &str, args: &[String]) -> Vec<String> {
    let filtered = non_option_args(args);
    match command {
        "grep" | "rg" | "awk" => filtered.into_iter().skip(1).collect(),
        "find" => filtered.into_iter().take(1).collect(),
        "sed" => filtered.into_iter().skip(1).collect(),
        _ => filtered,
    }
}

fn write_path_args(command: &str, args: &[String]) -> Vec<String> {
    let filtered = non_option_args(args);
    match command {
        "cp" | "mv" => {
            if filtered.len() >= 2 {
                filtered
            } else {
                Vec::new()
            }
        }
        "install" => filtered,
        "tee" => filtered,
        "sed" => filtered.into_iter().skip(1).collect(),
        _ => filtered,
    }
}

fn non_option_args(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|arg| !arg.starts_with('-'))
        .cloned()
        .collect()
}

fn is_network_command(command: &str) -> bool {
    matches!(
        command,
        "curl"
            | "wget"
            | "ssh"
            | "scp"
            | "sftp"
            | "ping"
            | "dig"
            | "nslookup"
            | "traceroute"
            | "nc"
            | "netcat"
            | "nmap"
            | "apt"
            | "apt-get"
            | "yum"
            | "dnf"
            | "pip"
            | "pip3"
            | "npm"
            | "pnpm"
            | "yarn"
            | "cargo"
            | "go"
            | "rustup"
            | "docker"
            | "podman"
            | "kubectl"
            | "git"
    )
}

fn is_system_admin_command(command: &str) -> bool {
    matches!(
        command,
        "sudo"
            | "su"
            | "systemctl"
            | "service"
            | "mount"
            | "umount"
            | "iptables"
            | "ufw"
            | "sysctl"
            | "useradd"
            | "usermod"
            | "userdel"
            | "groupadd"
            | "shutdown"
            | "reboot"
            | "poweroff"
            | "mkfs"
            | "fdisk"
            | "parted"
    )
}

fn is_process_control_command(command: &str) -> bool {
    matches!(
        command,
        "kill" | "killall" | "pkill" | "renice" | "taskset" | "strace" | "ptrace"
    )
}

fn is_credential_command(command: &str) -> bool {
    matches!(
        command,
        "ssh-add" | "pass" | "gpg" | "security" | "vault" | "aws" | "az" | "gcloud"
    )
}

fn is_known_safe_command(command: &str) -> bool {
    matches!(
        command,
        "echo" | "printf" | "pwd" | "which" | "whoami" | "id" | "date" | "uname" | "env" | "true"
    )
}

fn is_read_file_command(command: &str) -> bool {
    matches!(
        command,
        "cat"
            | "head"
            | "tail"
            | "less"
            | "more"
            | "grep"
            | "rg"
            | "awk"
            | "sed"
            | "find"
            | "ls"
            | "du"
            | "file"
    )
}

fn is_write_file_command(command: &str) -> bool {
    matches!(
        command,
        "tee"
            | "touch"
            | "mkdir"
            | "rmdir"
            | "cp"
            | "mv"
            | "install"
            | "chmod"
            | "chown"
            | "chgrp"
            | "truncate"
            | "dd"
            | "mkfs"
            | "ln"
            | "rm"
    )
}

fn parse_redirect_target(fragment: &str) -> Option<String> {
    let tokens = tokenize_shell_fragment(fragment);
    for (index, token) in tokens.iter().enumerate() {
        let Some(op_index) = token.find('>') else {
            continue;
        };

        let inline = token[op_index + 1..]
            .trim_start_matches('>')
            .trim()
            .trim_start_matches('&');
        if !inline.is_empty() {
            let candidate = clean_token(inline);
            if !candidate.is_empty() && !looks_like_fd_dup(candidate.as_str()) {
                return Some(candidate);
            }
            continue;
        }

        if let Some(next) = tokens.get(index + 1) {
            let candidate = clean_token(next);
            if !candidate.is_empty() && !looks_like_fd_dup(candidate.as_str()) {
                return Some(candidate);
            }
        }
    }
    None
}

fn looks_like_fd_dup(raw: &str) -> bool {
    raw == "-" || raw.chars().all(|ch| ch.is_ascii_digit())
}

fn tokenize_shell_fragment(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut single = false;
    let mut double = false;
    let mut escaped = false;

    for ch in raw.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' && !single {
            escaped = true;
            continue;
        }

        if ch == '\'' && !double {
            single = !single;
            continue;
        }

        if ch == '"' && !single {
            double = !double;
            continue;
        }

        if ch.is_whitespace() && !single && !double {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
            continue;
        }

        current.push(ch);
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn canonical_command(raw: &str) -> String {
    let cleaned = clean_token(raw);
    let leaf = cleaned
        .rsplit('/')
        .next()
        .unwrap_or(cleaned.as_str())
        .to_ascii_lowercase();
    leaf
}

fn clean_token(raw: &str) -> String {
    raw.trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches(';')
        .trim_matches(',')
        .to_string()
}

fn command_text_fact(payload: &Value, options: &Value) -> Fact<String> {
    if let Some(value) = extract_command_text(payload) {
        return Fact::Known(value);
    }
    if let Some(value) = extract_command_text(options) {
        return Fact::Known(value);
    }
    Fact::Unknown
}

fn extract_command_text(value: &Value) -> Option<String> {
    let command = value.as_object()?.get("command")?;
    if let Some(single) = command.as_str() {
        let trimmed = single.trim();
        if trimmed.is_empty() {
            return None;
        }
        return Some(trimmed.to_string());
    }
    if let Some(array) = command.as_array() {
        let parts = array
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        if parts.is_empty() {
            return None;
        }
        return Some(parts.join(" "));
    }
    None
}

fn bool_fact(
    payload: &Value,
    options: &Value,
    labels: &BTreeMap<String, String>,
    keys: &[&str],
) -> Fact<bool> {
    for key in keys {
        if let Some(value) = find_bool_path(payload, key) {
            return Fact::Known(value);
        }
        if let Some(value) = find_bool_path(options, key) {
            return Fact::Known(value);
        }
        if let Some(value) = labels.get(*key).and_then(|value| parse_bool_like(value)) {
            return Fact::Known(value);
        }
    }
    Fact::Unknown
}

fn find_bool_path(value: &Value, key: &str) -> Option<bool> {
    let raw = value_at_path(value, key)?;
    if let Some(boolean) = raw.as_bool() {
        return Some(boolean);
    }
    raw.as_str().and_then(parse_bool_like)
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

fn find_string_array_path(value: &Value, path: &str) -> Vec<String> {
    let Some(raw) = value_at_path(value, path).and_then(Value::as_array) else {
        return Vec::new();
    };
    raw.iter()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

fn set_if_unknown(target: &mut Fact<bool>, value: bool) {
    if matches!(target, Fact::Unknown) {
        *target = Fact::Known(value);
    }
}

fn merge_fact(target: &mut Fact<bool>, inferred: Option<bool>) {
    if matches!(target, Fact::Unknown)
        && let Some(value) = inferred
    {
        *target = Fact::Known(value);
    }
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

fn collect_tags(
    payload_labels: &BTreeMap<String, String>,
    payload: &Value,
    options: &Value,
) -> BTreeSet<String> {
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
            if let Some(command) =
                first_command_token(payload).or_else(|| first_command_token(options))
            {
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
    let normalized_policy_dir = normalize_lexical_path(policy_dir);
    paths.iter().any(|path| {
        let normalized_path = normalize_lexical_path(path);
        normalized_path.starts_with(&normalized_policy_dir)
    })
}

fn resolve_path(raw: &str, workspace_root: Option<&Path>) -> PathBuf {
    let candidate = PathBuf::from(raw);
    if candidate.is_absolute() {
        return normalize_lexical_path(&candidate);
    }
    if let Some(root) = workspace_root {
        return normalize_lexical_path(&root.join(candidate));
    }
    normalize_lexical_path(Path::new(raw))
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
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
        let token = tokenize_shell_fragment(single).into_iter().next()?;
        return Some(token);
    }
    if let Some(array) = command.as_array() {
        let first = array.first()?.as_str()?;
        if !first.trim().is_empty() {
            return Some(first.to_string());
        }
    }
    None
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

fn is_credential_path(raw: &str) -> bool {
    let text = raw.to_ascii_lowercase();
    text.contains("/.ssh/")
        || text.ends_with(".pem")
        || text.ends_with(".key")
        || text.contains("token")
        || text.contains("secret")
        || text.contains("credential")
        || text.contains("passwd")
        || text.contains("shadow")
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for path in paths {
        let normalized = normalize_lexical_path(&path);
        if seen.insert(normalized.display().to_string()) {
            result.push(normalized);
        }
    }
    result
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            result.push(trimmed.to_string());
        }
    }
    result
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
    fn normalizes_file_read_into_safe_read_fact() {
        let raw = RawOperation {
            kind: "file.read".to_string(),
            payload: json!({ "path": "README.md" }),
            options: json!({}),
            labels: BTreeMap::new(),
        };

        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize file read");

        assert_eq!(normalized.facts.safe_file_read, Fact::Known(true));
        assert_eq!(normalized.facts.system_file_read, Fact::Known(false));
        assert_eq!(normalized.facts.network_access, Fact::Known(false));
        assert_eq!(normalized.facts.unknown_intent, Fact::Known(false));
    }

    #[test]
    fn normalizes_file_write_into_system_write_fact() {
        let raw = RawOperation {
            kind: "file.write".to_string(),
            payload: json!({ "path": "/etc/hosts" }),
            options: json!({}),
            labels: BTreeMap::new(),
        };

        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize file write");

        assert_eq!(normalized.facts.system_file_write, Fact::Known(true));
        assert_eq!(normalized.facts.safe_file_write, Fact::Known(false));
        assert_eq!(normalized.facts.unknown_intent, Fact::Known(false));
    }

    #[test]
    fn infers_exec_categories_from_tree_sitter_parse() {
        let raw = RawOperation {
            kind: "exec".to_string(),
            payload: json!({ "command": "rm -rf /etc && curl https://example.com -o out.txt" }),
            options: json!({}),
            labels: BTreeMap::new(),
        };

        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize exec");

        assert_eq!(normalized.facts.system_file_write, Fact::Known(true));
        assert_eq!(normalized.facts.network_access, Fact::Known(true));
        assert_eq!(
            normalized.facts.primary_host,
            Fact::Known("example.com".to_string())
        );
    }

    #[test]
    fn does_not_flag_ls_root_as_write() {
        let raw = RawOperation {
            kind: "exec".to_string(),
            payload: json!({ "command": "ls /" }),
            options: json!({}),
            labels: BTreeMap::new(),
        };

        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize exec");

        assert_eq!(normalized.facts.system_file_read, Fact::Known(true));
        assert_eq!(normalized.facts.system_file_write, Fact::Known(false));
    }

    #[test]
    fn captures_redirect_target_path_for_exec() {
        let raw = RawOperation {
            kind: "exec".to_string(),
            payload: json!({ "command": "echo 4 > /a.txt" }),
            options: json!({}),
            labels: BTreeMap::new(),
        };

        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize exec");

        assert_eq!(normalized.facts.system_file_write, Fact::Known(true));
        assert_eq!(normalized.facts.safe_file_write, Fact::Known(false));
        assert_eq!(normalized.facts.unknown_intent, Fact::Known(false));
        assert!(
            normalized
                .facts
                .affected_paths
                .iter()
                .any(|path| path == &PathBuf::from("/a.txt"))
        );
    }

    #[test]
    fn applies_explicit_override_before_inference() {
        let raw = RawOperation {
            kind: "exec".to_string(),
            payload: json!({ "command": "curl https://example.com" }),
            options: json!({
                "risk": {
                    "override": {
                        "network_access": false,
                        "unknown_intent": false
                    }
                }
            }),
            labels: BTreeMap::new(),
        };

        let normalized = OperationNormalizer
            .normalize(raw, runtime())
            .expect("normalize exec");

        assert_eq!(normalized.facts.network_access, Fact::Known(false));
        assert_eq!(normalized.facts.unknown_intent, Fact::Known(false));
    }

    #[test]
    fn unknown_kind_sets_unknown_intent() {
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
        assert_eq!(normalized.facts.unknown_intent, Fact::Known(true));
    }
}
