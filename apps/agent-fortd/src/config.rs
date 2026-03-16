use std::env;

use af_rpc_transport::Endpoint;
use anyhow::{Context, Result};
use uuid::Uuid;

const ENV_DAEMON_ENDPOINT: &str = "AF_DAEMON_ENDPOINT";
const ENV_DAEMON_INSTANCE_ID: &str = "AF_DAEMON_INSTANCE_ID";
const DEFAULT_DAEMON_ENDPOINT: &str = "/tmp/agent-fortd.sock";

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub endpoint: Endpoint,
    pub daemon_instance_id: String,
}

impl DaemonConfig {
    pub fn load() -> Result<Self> {
        let endpoint_raw =
            env::var(ENV_DAEMON_ENDPOINT).unwrap_or_else(|_| DEFAULT_DAEMON_ENDPOINT.to_string());
        let endpoint = Endpoint::parse(&endpoint_raw)
            .with_context(|| format!("parse daemon endpoint `{endpoint_raw}`"))?;

        let daemon_instance_id =
            env::var(ENV_DAEMON_INSTANCE_ID).unwrap_or_else(|_| Uuid::new_v4().to_string());

        Ok(Self {
            endpoint,
            daemon_instance_id,
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
