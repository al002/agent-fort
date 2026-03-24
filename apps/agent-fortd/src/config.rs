use std::path::{Path, PathBuf};

use af_rpc_transport::Endpoint;
use af_sandbox::ResourceGovernanceMode;
use anyhow::{Context, Result, bail};
use uuid::Uuid;

#[cfg(windows)]
const DEFAULT_DAEMON_ENDPOINT: &str = "npipe://agent-fortd";
#[cfg(not(windows))]
const DEFAULT_DAEMON_ENDPOINT: &str = "/tmp/agent-fortd.sock";

#[cfg(not(windows))]
const DEFAULT_BWRAP_PATH: &str = "/usr/bin/bwrap";

#[cfg(windows)]
const DEFAULT_HELPER_FILE: &str = "af-helper.exe";
#[cfg(not(windows))]
const DEFAULT_HELPER_FILE: &str = "af-helper";

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub endpoint: Endpoint,
    pub daemon_instance_id: String,
    pub helper_path: PathBuf,
    pub bwrap_path: Option<PathBuf>,
    pub cgroup_root: Option<PathBuf>,
    pub store_path: PathBuf,
    pub policy_dir: PathBuf,
    pub command_rules_dir: PathBuf,
    pub command_rules_strict: bool,
    pub resource_governance_mode: ResourceGovernanceMode,
}

impl DaemonConfig {
    pub fn load() -> Result<Self> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        Self::load_from_args(&args)
    }

    fn load_from_args(args: &[String]) -> Result<Self> {
        let mut raw = ParsedArgs::default();

        let mut i = 0usize;
        while i < args.len() {
            match args[i].as_str() {
                "--endpoint" => {
                    let (value, next) = parse_value(args, i, "--endpoint")?;
                    raw.endpoint = Some(value);
                    i = next;
                }
                "--daemon-instance-id" => {
                    let (value, next) = parse_value(args, i, "--daemon-instance-id")?;
                    raw.daemon_instance_id = Some(value);
                    i = next;
                }
                "--helper-path" => {
                    let (value, next) = parse_value(args, i, "--helper-path")?;
                    raw.helper_path = Some(PathBuf::from(value));
                    i = next;
                }
                "--bwrap-path" => {
                    let (value, next) = parse_value(args, i, "--bwrap-path")?;
                    raw.bwrap_path = Some(PathBuf::from(value));
                    i = next;
                }
                "--cgroup-root" => {
                    let (value, next) = parse_value(args, i, "--cgroup-root")?;
                    raw.cgroup_root = Some(PathBuf::from(value));
                    i = next;
                }
                "--store-path" => {
                    let (value, next) = parse_value(args, i, "--store-path")?;
                    raw.store_path = Some(PathBuf::from(value));
                    i = next;
                }
                "--policy-dir" => {
                    let (value, next) = parse_value(args, i, "--policy-dir")?;
                    raw.policy_dir = Some(PathBuf::from(value));
                    i = next;
                }
                "--command-rules-dir" => {
                    let (value, next) = parse_value(args, i, "--command-rules-dir")?;
                    raw.command_rules_dir = Some(PathBuf::from(value));
                    i = next;
                }
                "--command-rules-strict" => {
                    let (value, next) = parse_value(args, i, "--command-rules-strict")?;
                    raw.command_rules_strict = Some(parse_bool_flag(&value)?);
                    i = next;
                }
                "--resource-governance-mode" => {
                    let (value, next) = parse_value(args, i, "--resource-governance-mode")?;
                    raw.resource_governance_mode =
                        Some(parse_resource_governance_mode_flag(&value)?);
                    i = next;
                }
                "--help" | "-h" => {
                    println!("{}", daemon_help_text());
                    std::process::exit(0);
                }
                other => bail!("unknown option for `agent-fortd`: `{other}`"),
            }
        }

        let endpoint_raw = raw
            .endpoint
            .unwrap_or_else(|| DEFAULT_DAEMON_ENDPOINT.to_string());
        let endpoint = Endpoint::parse(&endpoint_raw)
            .with_context(|| format!("parse daemon endpoint `{endpoint_raw}`"))?;

        let daemon_instance_id = raw
            .daemon_instance_id
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let helper_path = raw.helper_path.unwrap_or_else(default_helper_path);
        let bwrap_path = raw.bwrap_path.or_else(default_bwrap_path);
        let cgroup_root = raw.cgroup_root.or_else(default_cgroup_root);
        let store_path = raw.store_path.unwrap_or_else(default_store_path);
        let policy_dir = resolve_dir_path(raw.policy_dir.unwrap_or_else(default_policy_dir))?;
        ensure_policy_exists(&policy_dir)?;
        let command_rules_dir = resolve_dir_path(
            raw.command_rules_dir
                .unwrap_or_else(default_command_rules_dir),
        )?;

        Ok(Self {
            endpoint,
            daemon_instance_id,
            helper_path,
            bwrap_path,
            cgroup_root,
            store_path,
            policy_dir,
            command_rules_dir,
            command_rules_strict: raw.command_rules_strict.unwrap_or(false),
            resource_governance_mode: raw
                .resource_governance_mode
                .unwrap_or(ResourceGovernanceMode::BestEffort),
        })
    }
}

#[derive(Debug, Default)]
struct ParsedArgs {
    endpoint: Option<String>,
    daemon_instance_id: Option<String>,
    helper_path: Option<PathBuf>,
    bwrap_path: Option<PathBuf>,
    cgroup_root: Option<PathBuf>,
    store_path: Option<PathBuf>,
    policy_dir: Option<PathBuf>,
    command_rules_dir: Option<PathBuf>,
    command_rules_strict: Option<bool>,
    resource_governance_mode: Option<ResourceGovernanceMode>,
}

fn default_store_path() -> PathBuf {
    std::env::temp_dir().join("agent-fortd.sqlite3")
}

fn default_policy_dir() -> PathBuf {
    default_config_root().join("policies")
}

fn default_command_rules_dir() -> PathBuf {
    default_config_root().join("command-rules")
}

fn default_helper_path() -> PathBuf {
    if let Ok(executable) = std::env::current_exe()
        && let Some(parent) = executable.parent()
    {
        return parent.join(DEFAULT_HELPER_FILE);
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("/"))
        .join(DEFAULT_HELPER_FILE)
}

#[cfg(windows)]
fn default_bwrap_path() -> Option<PathBuf> {
    None
}

#[cfg(not(windows))]
fn default_bwrap_path() -> Option<PathBuf> {
    Some(PathBuf::from(DEFAULT_BWRAP_PATH))
}

#[cfg(windows)]
fn default_cgroup_root() -> Option<PathBuf> {
    None
}

#[cfg(not(windows))]
fn default_cgroup_root() -> Option<PathBuf> {
    Some(PathBuf::from("/sys/fs/cgroup"))
}

fn resolve_dir_path(path: PathBuf) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };

    match absolute.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(absolute),
        Err(error) => Err(error.into()),
    }
}

#[cfg(windows)]
fn default_config_root() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .map(|home| home.join("AppData").join("Roaming"))
        })
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("AgentFort")
}

#[cfg(not(windows))]
fn default_config_root() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("agent-fort");
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("agent-fort")
}

fn ensure_policy_exists(policy_dir: &Path) -> Result<()> {
    let yaml = policy_dir.join("static_policy.yaml");
    if yaml.is_file() {
        return Ok(());
    }

    let yml = policy_dir.join("static_policy.yml");
    if yml.is_file() {
        return Ok(());
    }

    bail!(
        "policy is required: expected {} or {}",
        yaml.display(),
        yml.display()
    )
}

fn parse_bool_flag(raw: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("invalid boolean value `{raw}`; expected true/false"),
    }
}

fn parse_resource_governance_mode_flag(raw: &str) -> Result<ResourceGovernanceMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "required" => Ok(ResourceGovernanceMode::Required),
        "best_effort" | "best-effort" => Ok(ResourceGovernanceMode::BestEffort),
        "disabled" => Ok(ResourceGovernanceMode::Disabled),
        _ => bail!(
            "invalid resource governance mode `{raw}`; expected required|best_effort|disabled"
        ),
    }
}

fn parse_value(args: &[String], index: usize, flag: &str) -> Result<(String, usize)> {
    let value = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("missing value for `{flag}`"))?;
    Ok((value.clone(), index + 2))
}

fn daemon_help_text() -> String {
    "Usage: agent-fortd [OPTIONS]\n\nOptions:\n  --endpoint <ENDPOINT>\n  --daemon-instance-id <ID>\n  --helper-path <PATH>\n  --bwrap-path <PATH>\n  --cgroup-root <PATH>\n  --store-path <PATH>\n  --policy-dir <PATH>\n  --command-rules-dir <PATH>\n  --command-rules-strict <BOOL>\n  --resource-governance-mode <MODE>\n  -h, --help"
        .to_string()
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn parses_default_endpoint() {
        let endpoint = Endpoint::parse(DEFAULT_DAEMON_ENDPOINT).expect("default endpoint is valid");
        #[cfg(windows)]
        assert_eq!(endpoint.as_uri(), "npipe://\\\\.\\pipe\\agent-fortd");
        #[cfg(not(windows))]
        assert_eq!(endpoint.as_uri(), "unix:///tmp/agent-fortd.sock");
    }

    #[test]
    fn has_default_store_path_in_system_temp_dir() {
        assert_eq!(
            default_store_path(),
            std::env::temp_dir().join("agent-fortd.sqlite3")
        );
    }

    #[test]
    fn has_default_policy_dir_under_default_config_root() {
        assert_eq!(default_policy_dir(), default_config_root().join("policies"));
    }

    #[test]
    fn default_helper_path_is_absolute() {
        assert!(default_helper_path().is_absolute());
    }

    #[test]
    fn default_command_rules_dir_is_under_default_config_root() {
        assert_eq!(
            default_command_rules_dir(),
            default_config_root().join("command-rules")
        );
    }

    #[test]
    fn policy_is_required() {
        let temp = TempDir::new().expect("create temp dir");
        let missing_policy = temp.path().join("missing-policy");
        let error = ensure_policy_exists(&missing_policy).expect_err("policy should be required");
        assert!(error.to_string().contains("policy is required"));
    }

    #[test]
    fn accepts_static_policy_yaml_when_present() {
        let temp = TempDir::new().expect("create temp dir");
        std::fs::write(temp.path().join("static_policy.yaml"), "version: 1\n")
            .expect("write policy");
        ensure_policy_exists(temp.path()).expect("policy should be accepted");
    }

    #[test]
    fn load_from_args_parses_explicit_flags() {
        let temp = TempDir::new().expect("create temp dir");
        let policy_dir = temp.path().join("policy");
        let rules_dir = temp.path().join("rules");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        std::fs::create_dir_all(&rules_dir).expect("create rules dir");
        std::fs::write(policy_dir.join("static_policy.yaml"), "version: 1\n").expect("write");

        let args = vec![
            "--endpoint".to_string(),
            "/tmp/custom.sock".to_string(),
            "--policy-dir".to_string(),
            policy_dir.display().to_string(),
            "--command-rules-dir".to_string(),
            rules_dir.display().to_string(),
            "--command-rules-strict".to_string(),
            "true".to_string(),
            "--resource-governance-mode".to_string(),
            "required".to_string(),
        ];

        let config = DaemonConfig::load_from_args(&args).expect("parse config");
        assert_eq!(config.endpoint.as_uri(), "unix:///tmp/custom.sock");
        assert!(config.command_rules_strict);
        assert_eq!(
            config.resource_governance_mode,
            ResourceGovernanceMode::Required
        );
    }
}
