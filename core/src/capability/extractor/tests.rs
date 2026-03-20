use std::collections::BTreeMap;
use std::path::PathBuf;

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
        stdin: None,
        shell: None,
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
        stdin: None,
        shell: None,
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
        stdin: None,
        shell: None,
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
        stdin: None,
        shell: None,
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
        stdin: None,
        shell: None,
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
        stdin: None,
        shell: None,
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
        stdin: None,
        shell: None,
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
        stdin: None,
        shell: None,
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
