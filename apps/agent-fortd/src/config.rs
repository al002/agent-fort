use std::env;
use std::path::PathBuf;

use af_rpc_transport::Endpoint;
use anyhow::{Context, Result};
use uuid::Uuid;

const ENV_DAEMON_ENDPOINT: &str = "AF_DAEMON_ENDPOINT";
const ENV_DAEMON_INSTANCE_ID: &str = "AF_DAEMON_INSTANCE_ID";
const ENV_HELPER_PATH: &str = "AF_HELPER_PATH";
const ENV_BWRAP_PATH: &str = "AF_BWRAP_PATH";
const ENV_CGROUP_ROOT: &str = "AF_CGROUP_ROOT";
const ENV_STORE_PATH: &str = "AF_STORE_PATH";
const ENV_POLICY_DIR: &str = "AF_POLICY_DIR";
const DEFAULT_DAEMON_ENDPOINT: &str = "/tmp/agent-fortd.sock";
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
    pub bwrap_path: PathBuf,
    pub cgroup_root: PathBuf,
    pub store_path: PathBuf,
    pub policy_dir: PathBuf,
}

impl DaemonConfig {
    pub fn load() -> Result<Self> {
        let endpoint_raw =
            env::var(ENV_DAEMON_ENDPOINT).unwrap_or_else(|_| DEFAULT_DAEMON_ENDPOINT.to_string());
        let endpoint = Endpoint::parse(&endpoint_raw)
            .with_context(|| format!("parse daemon endpoint `{endpoint_raw}`"))?;

        let daemon_instance_id =
            env::var(ENV_DAEMON_INSTANCE_ID).unwrap_or_else(|_| Uuid::new_v4().to_string());
        let helper_path = env::var(ENV_HELPER_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_helper_path());
        let bwrap_path = env::var(ENV_BWRAP_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_BWRAP_PATH));
        let cgroup_root = env::var(ENV_CGROUP_ROOT)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup"));
        let store_path = env::var(ENV_STORE_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_store_path());
        let policy_dir = resolve_policy_dir(
            env::var(ENV_POLICY_DIR)
                .map(PathBuf::from)
                .unwrap_or_else(|_| default_policy_dir()),
        )?;

        Ok(Self {
            endpoint,
            daemon_instance_id,
            helper_path,
            bwrap_path,
            cgroup_root,
            store_path,
            policy_dir,
        })
    }
}

fn default_store_path() -> PathBuf {
    std::env::temp_dir().join("agent-fortd.sqlite3")
}

fn default_policy_dir() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("policies")
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

fn resolve_policy_dir(path: PathBuf) -> Result<PathBuf> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_endpoint() {
        let endpoint = Endpoint::parse(DEFAULT_DAEMON_ENDPOINT).expect("default endpoint is valid");
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
    fn has_default_policy_dir_under_current_working_directory() {
        assert_eq!(
            default_policy_dir(),
            std::env::current_dir()
                .expect("current directory is available")
                .join("policies")
        );
    }

    #[test]
    fn default_helper_path_is_absolute() {
        assert!(default_helper_path().is_absolute());
    }
}
