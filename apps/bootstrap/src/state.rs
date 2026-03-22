use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = "npipe://agent-fortd";
#[cfg(not(windows))]
pub const DEFAULT_ENDPOINT: &str = "/tmp/agent-fortd.sock";

const INSTALL_STATE_FILE: &str = "install-state.json";
const DAEMON_PID_FILE: &str = "daemon.pid";

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
    explicit.unwrap_or_else(default_install_root)
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

pub fn daemon_pid_file_path(install_root: &Path) -> PathBuf {
    install_root.join(DAEMON_PID_FILE)
}

pub fn unix_now_s() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?;
    Ok(now.as_secs())
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
