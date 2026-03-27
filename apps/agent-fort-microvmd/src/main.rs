#[cfg(unix)]
mod config;
#[cfg(unix)]
mod runtime;
#[cfg(unix)]
mod server;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[cfg(unix)]
use crate::config::Config;
#[cfg(unix)]
use crate::runtime::LocalRuntime;
#[cfg(unix)]
use crate::server::Server;

#[cfg(unix)]
fn main() -> Result<()> {
    init_tracing();
    run()
}

#[cfg(not(unix))]
fn main() -> Result<()> {
    init_tracing();
    anyhow::bail!("af-microvmd is only supported on Unix targets")
}

#[cfg(unix)]
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
