use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = "npipe://agent-fortd";
#[cfg(not(windows))]
pub const DEFAULT_ENDPOINT: &str = "/tmp/agent-fortd.sock";
const INSTALL_STATE_FILE: &str = "install-state.json";

pub struct Cli {
    pub command: BootstrapCommand,
}

pub enum BootstrapCommand {
    Sync(SyncArgs),
    Start(StartArgs),
}

#[derive(Debug, Clone)]
pub struct SyncArgs {
    pub install_root: Option<PathBuf>,
    pub manifest_source: Option<String>,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StartArgs {
    pub install_root: Option<PathBuf>,
    pub endpoint: Option<String>,
    pub startup_timeout_ms: u64,
    pub ping_interval_ms: u64,
    pub daemon_path: Option<PathBuf>,
    pub bwrap_path: Option<PathBuf>,
    pub helper_path: Option<PathBuf>,
}

pub enum ParseOutcome {
    Run(Cli),
    Help(String),
}

impl Cli {
    pub fn parse_from_env() -> Result<ParseOutcome> {
        let args = env::args().skip(1).collect::<Vec<_>>();
        if args.is_empty() {
            return Ok(ParseOutcome::Help(root_help_text()));
        }

        let command = args[0].as_str();
        match command {
            "help" | "-h" | "--help" => Ok(ParseOutcome::Help(root_help_text())),
            "sync" => parse_sync(&args[1..]),
            "start" => parse_start(&args[1..]),
            other => bail!("unknown command `{other}`"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorOutput {
    pub ok: bool,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallState {
    pub version: String,
    pub endpoint: String,
    pub daemon_path: PathBuf,
    pub bwrap_path: PathBuf,
    pub helper_path: PathBuf,
    pub bundle_sha256: String,
    pub manifest_source: String,
    pub synced_at_unix_s: u64,
}

impl InstallState {
    pub fn file_path(install_root: &Path) -> PathBuf {
        install_root.join(INSTALL_STATE_FILE)
    }

    pub fn load(install_root: &Path) -> Result<Self> {
        let path = Self::file_path(install_root);
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read install state {}", path.display()))?;
        serde_json::from_str(&raw).context("parse install state JSON")
    }

    pub fn save(&self, install_root: &Path) -> Result<()> {
        fs::create_dir_all(install_root)
            .with_context(|| format!("create install root {}", install_root.display()))?;
        let path = Self::file_path(install_root);
        let raw = serde_json::to_string_pretty(self).context("serialize install state JSON")?;
        fs::write(&path, format!("{raw}\n"))
            .with_context(|| format!("write install state {}", path.display()))
    }
}

pub fn resolve_install_root(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(path) = explicit {
        return path;
    }
    default_install_root()
}

pub fn resolve_endpoint(explicit: Option<String>, state: Option<&InstallState>) -> String {
    if let Some(endpoint) = explicit {
        return endpoint;
    }
    if let Some(state) = state {
        return state.endpoint.clone();
    }
    DEFAULT_ENDPOINT.to_string()
}

pub fn resolve_manifest_source(explicit: Option<String>, install_root: &Path) -> Option<String> {
    if let Some(source) = explicit {
        return Some(source);
    }
    let default_path = install_root.join("manifest.json");
    if default_path.is_file() {
        return Some(default_path.to_string_lossy().to_string());
    }
    None
}

pub fn unix_now_s() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?;
    Ok(now.as_secs())
}

fn parse_sync(args: &[String]) -> Result<ParseOutcome> {
    if contains_help(args) {
        return Ok(ParseOutcome::Help(sync_help_text()));
    }

    let mut install_root = None;
    let mut manifest_source = None;
    let mut endpoint = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--install-root" => {
                let (value, next) = parse_value(args, i, "--install-root")?;
                install_root = Some(PathBuf::from(value));
                i = next;
            }
            "--manifest-source" => {
                let (value, next) = parse_value(args, i, "--manifest-source")?;
                manifest_source = Some(value);
                i = next;
            }
            "--endpoint" => {
                let (value, next) = parse_value(args, i, "--endpoint")?;
                endpoint = Some(value);
                i = next;
            }
            other => bail!("unknown option for `sync`: `{other}`"),
        }
    }

    Ok(ParseOutcome::Run(Cli {
        command: BootstrapCommand::Sync(SyncArgs {
            install_root,
            manifest_source,
            endpoint,
        }),
    }))
}

fn parse_start(args: &[String]) -> Result<ParseOutcome> {
    if contains_help(args) {
        return Ok(ParseOutcome::Help(start_help_text()));
    }

    let mut parsed = StartArgs {
        install_root: None,
        endpoint: None,
        startup_timeout_ms: 10_000,
        ping_interval_ms: 200,
        daemon_path: None,
        bwrap_path: None,
        helper_path: None,
    };

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--install-root" => {
                let (value, next) = parse_value(args, i, "--install-root")?;
                parsed.install_root = Some(PathBuf::from(value));
                i = next;
            }
            "--endpoint" => {
                let (value, next) = parse_value(args, i, "--endpoint")?;
                parsed.endpoint = Some(value);
                i = next;
            }
            "--startup-timeout-ms" => {
                let (value, next) = parse_value(args, i, "--startup-timeout-ms")?;
                parsed.startup_timeout_ms = value.parse::<u64>().with_context(|| {
                    format!("parse --startup-timeout-ms value `{value}` as u64")
                })?;
                i = next;
            }
            "--ping-interval-ms" => {
                let (value, next) = parse_value(args, i, "--ping-interval-ms")?;
                parsed.ping_interval_ms = value
                    .parse::<u64>()
                    .with_context(|| format!("parse --ping-interval-ms value `{value}` as u64"))?;
                i = next;
            }
            "--daemon-path" => {
                let (value, next) = parse_value(args, i, "--daemon-path")?;
                parsed.daemon_path = Some(PathBuf::from(value));
                i = next;
            }
            "--bwrap-path" => {
                let (value, next) = parse_value(args, i, "--bwrap-path")?;
                parsed.bwrap_path = Some(PathBuf::from(value));
                i = next;
            }
            "--helper-path" => {
                let (value, next) = parse_value(args, i, "--helper-path")?;
                parsed.helper_path = Some(PathBuf::from(value));
                i = next;
            }
            other => bail!("unknown option for `start`: `{other}`"),
        }
    }

    Ok(ParseOutcome::Run(Cli {
        command: BootstrapCommand::Start(parsed),
    }))
}

fn parse_value(args: &[String], index: usize, flag: &str) -> Result<(String, usize)> {
    let value = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("missing value for `{flag}`"))?
        .to_string();
    Ok((value, index + 2))
}

fn contains_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn root_help_text() -> String {
    "Prepare assets and start the local daemon\n\nUsage:\n  af-bootstrap <command> [options]\n\nCommands:\n  sync\n  start\n  help\n\nRun `af-bootstrap <command> --help` for command options.".to_string()
}

fn sync_help_text() -> String {
    "Usage: af-bootstrap sync [OPTIONS]\n\nOptions:\n  --install-root <PATH>\n  --manifest-source <SOURCE>\n  --endpoint <ENDPOINT>\n  -h, --help"
        .to_string()
}

fn start_help_text() -> String {
    "Usage: af-bootstrap start [OPTIONS]\n\nOptions:\n  --install-root <PATH>\n  --endpoint <ENDPOINT>\n  --startup-timeout-ms <MILLIS> (default: 10000)\n  --ping-interval-ms <MILLIS> (default: 200)\n  --daemon-path <PATH>\n  --bwrap-path <PATH>\n  --helper-path <PATH>\n  -h, --help"
        .to_string()
}

fn default_install_root() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .map(PathBuf::from)
                    .map(|home| home.join("AppData").join("Local"))
            })
            .unwrap_or_else(|| PathBuf::from("."));
        return base.join("AgentFort");
    }

    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("agent-fort");
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".local").join("share").join("agent-fort")
    }
}
