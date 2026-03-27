mod config;
mod runtime;
mod server;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::runtime::LocalRuntime;
use crate::server::Server;

fn main() -> Result<()> {
    init_tracing();
    run()
}

fn run() -> Result<()> {
    let config = Config::load()?;
    let runtime = LocalRuntime::new(config.clone())?;
    let server = Server::new(config, runtime);
    server.run()
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .init();
}
