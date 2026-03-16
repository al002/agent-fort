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
const DEFAULT_DAEMON_ENDPOINT: &str = "/tmp/agent-fortd.sock";
const DEFAULT_BWRAP_PATH: &str = "/usr/bin/bwrap";
const DEFAULT_HELPER_PATH: &str = "helper";

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub endpoint: Endpoint,
    pub daemon_instance_id: String,
    pub helper_path: PathBuf,
    pub bwrap_path: PathBuf,
    pub cgroup_root: PathBuf,
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
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_HELPER_PATH));
        let bwrap_path = env::var(ENV_BWRAP_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_BWRAP_PATH));
        let cgroup_root = env::var(ENV_CGROUP_ROOT)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup"));

        Ok(Self {
            endpoint,
            daemon_instance_id,
            helper_path,
            bwrap_path,
            cgroup_root,
        })
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
}
