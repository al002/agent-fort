mod bootstrap;
mod config;
mod helper_client;
mod rpc_controller;
mod server;

use anyhow::Result;
use bootstrap::BootstrappedDaemon;
use config::DaemonConfig;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = DaemonConfig::load()?;
    let daemon = BootstrappedDaemon::new(config)?;
    daemon.run().await
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .init();
}
