use std::env;
use std::io::{Read, Write};
use std::path::PathBuf;

use af_linux_sandbox::{LinuxSandboxConfig, LinuxSandboxRuntime};
use af_sandbox::{
    HELPER_MAX_REQUEST_BYTES, HELPER_PROTOCOL_VERSION, HelperExecuteRequest, HelperExecuteResponse,
    SandboxRuntime,
};
use anyhow::{Context, Result, bail};

const ENV_BWRAP_PATH: &str = "AF_BWRAP_PATH";
const ENV_CGROUP_ROOT: &str = "AF_CGROUP_ROOT";

fn main() {
    if let Err(err) = run() {
        let response = HelperExecuteResponse::failure(format!("helper fatal error: {err}"));
        let _ = write_json_response(&response);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut payload = Vec::new();
    let max_plus_one = u64::try_from(HELPER_MAX_REQUEST_BYTES)
        .expect("helper max request bytes fits into u64")
        + 1;
    std::io::stdin()
        .take(max_plus_one)
        .read_to_end(&mut payload)
        .context("read helper request from stdin")?;
    if payload.len() > HELPER_MAX_REQUEST_BYTES {
        bail!(
            "helper request too large: {} bytes > {} bytes",
            payload.len(),
            HELPER_MAX_REQUEST_BYTES
        );
    }
    let request: HelperExecuteRequest =
        serde_json::from_slice(&payload).context("parse helper request JSON")?;

    if request.protocol_version != HELPER_PROTOCOL_VERSION {
        let response = HelperExecuteResponse::failure(format!(
            "unsupported helper protocol version {}; expected {}",
            request.protocol_version, HELPER_PROTOCOL_VERSION
        ));
        write_json_response(&response)?;
        return Ok(());
    }

    let runtime = LinuxSandboxRuntime::new(resolve_linux_sandbox_config());
    let response = match runtime.execute(request.request) {
        Ok(result) => HelperExecuteResponse::success(result),
        Err(err) => HelperExecuteResponse::failure(err.to_string()),
    };
    write_json_response(&response)
}

fn resolve_linux_sandbox_config() -> LinuxSandboxConfig {
    let mut config = LinuxSandboxConfig::default();
    if let Ok(path) = env::var(ENV_BWRAP_PATH) {
        config.bwrap_path = PathBuf::from(path);
    }
    if let Ok(path) = env::var(ENV_CGROUP_ROOT) {
        config.cgroup_root = PathBuf::from(path);
    }
    config
}

fn write_json_response(response: &HelperExecuteResponse) -> Result<()> {
    let encoded = serde_json::to_string(response).context("serialize helper response JSON")?;
    let mut stdout = std::io::stdout();
    stdout
        .write_all(encoded.as_bytes())
        .context("write helper response JSON")?;
    stdout.flush().context("flush helper response JSON")
}
