use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use af_rpc_proto::codec::{decode_message, encode_message};
use af_rpc_proto::{PingRequest, PingResponse, RpcMethod, RpcRequest, RpcResponse, rpc_response};
use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::command::{
    InstallState, StartArgs, daemon_pid_file_path, resolve_endpoint, resolve_install_root,
};

const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;
const IO_TIMEOUT_MS: u64 = 500;
const SYSTEM_BWRAP_PATH: &str = "/usr/bin/bwrap";

#[derive(Debug, Serialize)]
pub struct StartOutput {
    pub ok: bool,
    pub endpoint: String,
    pub started: bool,
    pub daemon_pid: Option<u32>,
    pub daemon_instance_id: String,
}

struct DaemonSpawnConfig<'a> {
    endpoint: &'a str,
    bwrap_path: &'a Path,
    helper_path: &'a Path,
    policy_dir: Option<&'a Path>,
    command_rules_dir: Option<&'a Path>,
    command_rules_strict: Option<bool>,
    store_path: Option<&'a Path>,
}

pub fn run(args: StartArgs) -> Result<StartOutput> {
    let install_root = resolve_install_root(args.install_root);
    let mut state = InstallState::load(&install_root)?;
    let endpoint = resolve_endpoint(args.endpoint, Some(&state));
    let policy_dir = resolve_dir_path(args.policy_dir, default_policy_dir)?;
    ensure_policy_exists(&policy_dir)?;
    let command_rules_dir = resolve_dir_path(args.command_rules_dir, default_command_rules_dir)?;
    state.endpoint = endpoint.clone();
    if let Some(path) = args.daemon_path {
        state.daemon_path = path;
    }
    if let Some(path) = args.helper_path {
        state.helper_path = path;
    }

    ensure_file(&state.daemon_path, "daemon binary")?;
    ensure_file(&state.helper_path, "helper binary")?;
    let bwrap_path = resolve_bwrap_path(args.bwrap_path.as_deref(), &state.bwrap_path)?;

    if let Ok(response) = ping_once(&endpoint) {
        return Ok(StartOutput {
            ok: true,
            endpoint,
            started: false,
            daemon_pid: None,
            daemon_instance_id: response.daemon_instance_id,
        });
    }

    let daemon_pid = spawn_daemon(
        &state.daemon_path,
        DaemonSpawnConfig {
            endpoint: &endpoint,
            bwrap_path: &bwrap_path,
            helper_path: &state.helper_path,
            policy_dir: Some(policy_dir.as_path()),
            command_rules_dir: Some(command_rules_dir.as_path()),
            command_rules_strict: args.command_rules_strict,
            store_path: args.store_path.as_deref(),
        },
    )?;
    let deadline = Instant::now() + Duration::from_millis(args.startup_timeout_ms);
    let poll_interval = Duration::from_millis(args.ping_interval_ms.max(10));
    loop {
        if let Ok(response) = ping_once(&endpoint) {
            persist_daemon_pid(&install_root, daemon_pid)?;
            return Ok(StartOutput {
                ok: true,
                endpoint,
                started: true,
                daemon_pid: Some(daemon_pid),
                daemon_instance_id: response.daemon_instance_id,
            });
        }

        if Instant::now() >= deadline {
            bail!(
                "daemon startup timed out after {} ms",
                args.startup_timeout_ms
            );
        }
        sleep(poll_interval);
    }
}

fn persist_daemon_pid(install_root: &Path, daemon_pid: u32) -> Result<()> {
    let pid_path = daemon_pid_file_path(install_root);
    fs::write(&pid_path, format!("{daemon_pid}\n"))
        .with_context(|| format!("write daemon pid file {}", pid_path.display()))
}

fn ping_once(endpoint: &str) -> Result<PingResponse> {
    let mut stream = connect_endpoint(endpoint)?;
    set_io_timeout(&mut stream)?;

    let request_payload = encode_message(&PingRequest {});
    let request = RpcRequest {
        method: RpcMethod::Ping as i32,
        payload: request_payload,
    };
    let request_bytes = encode_message(&request);
    write_frame(&mut stream, &request_bytes)?;

    let response_bytes = read_frame(&mut stream)?;
    let response = decode_message::<RpcResponse>(&response_bytes)?;
    match response.outcome {
        Some(rpc_response::Outcome::Payload(payload)) => decode_message::<PingResponse>(&payload)
            .map_err(|error| anyhow::anyhow!("decode PingResponse failed: {error}")),
        Some(rpc_response::Outcome::Error(error)) => {
            bail!(
                "daemon ping error code={} message={}",
                error.code,
                error.message
            )
        }
        None => bail!("daemon ping returned empty outcome"),
    }
}

#[cfg(unix)]
fn connect_endpoint(endpoint: &str) -> Result<std::os::unix::net::UnixStream> {
    if endpoint.starts_with("npipe://") {
        bail!("named pipe endpoint is not implemented in bootstrap yet");
    }
    let path = endpoint.strip_prefix("unix://").unwrap_or(endpoint);
    std::os::unix::net::UnixStream::connect(path)
        .with_context(|| format!("connect to endpoint {path} failed"))
}

#[cfg(not(unix))]
fn connect_endpoint(_endpoint: &str) -> Result<std::net::TcpStream> {
    bail!("bootstrap start is not implemented on this platform yet")
}

fn set_io_timeout<T>(stream: &mut T) -> Result<()>
where
    T: SetIoTimeout,
{
    let timeout = Some(Duration::from_millis(IO_TIMEOUT_MS));
    stream
        .set_read_timeout(timeout)
        .context("set read timeout failed")?;
    stream
        .set_write_timeout(timeout)
        .context("set write timeout failed")?;
    Ok(())
}

fn write_frame(stream: &mut impl Write, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME_LEN {
        bail!(
            "request payload too large: {} > {}",
            payload.len(),
            MAX_FRAME_LEN
        );
    }
    let header = u32::try_from(payload.len())
        .context("request payload length overflow")?
        .to_be_bytes();
    stream
        .write_all(&header)
        .context("write frame header failed")?;
    stream
        .write_all(payload)
        .context("write frame payload failed")?;
    Ok(())
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("read frame header failed")?;

    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        bail!("response payload too large: {len} > {MAX_FRAME_LEN}");
    }

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .context("read frame payload failed")?;
    Ok(payload)
}

fn spawn_daemon(daemon_path: &Path, config: DaemonSpawnConfig<'_>) -> Result<u32> {
    let mut command = Command::new(daemon_path);
    command
        .arg("--endpoint")
        .arg(config.endpoint)
        .arg("--bwrap-path")
        .arg(config.bwrap_path)
        .arg("--helper-path")
        .arg(config.helper_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(policy_dir) = config.policy_dir {
        command.arg("--policy-dir").arg(policy_dir);
    }
    if let Some(command_rules_dir) = config.command_rules_dir {
        command.arg("--command-rules-dir").arg(command_rules_dir);
    }
    if let Some(command_rules_strict) = config.command_rules_strict {
        command
            .arg("--command-rules-strict")
            .arg(if command_rules_strict {
                "true"
            } else {
                "false"
            });
    }
    if let Some(store_path) = config.store_path {
        command.arg("--store-path").arg(store_path);
    }

    let child = command
        .spawn()
        .with_context(|| format!("spawn daemon {}", daemon_path.display()))?;
    Ok(child.id())
}

fn ensure_file(path: &Path, label: &str) -> Result<()> {
    if !path.is_file() {
        bail!("{label} not found at {}", path.display());
    }
    Ok(())
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
    );
}

fn resolve_bwrap_path(explicit: Option<&Path>, bundled: &Path) -> Result<PathBuf> {
    if let Some(explicit) = explicit {
        ensure_file(explicit, "bwrap binary")?;
        return Ok(explicit.to_path_buf());
    }
    if bundled.is_file() {
        return Ok(bundled.to_path_buf());
    }
    let system_path = PathBuf::from(SYSTEM_BWRAP_PATH);
    if system_path.is_file() {
        return Ok(system_path);
    }
    if let Some(found) = find_executable_in_path("bwrap") {
        return Ok(found);
    }

    bail!(
        "bwrap binary not found (tried bundle `{}`, system `{}`, PATH lookup)",
        bundled.display(),
        SYSTEM_BWRAP_PATH
    );
}

fn find_executable_in_path(binary_name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        #[cfg(windows)]
        let candidates = [format!("{binary_name}.exe"), binary_name.to_string()];
        #[cfg(not(windows))]
        let candidates = [binary_name.to_string()];

        for candidate in candidates {
            let candidate = dir.join(candidate);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn resolve_dir_path(path: Option<PathBuf>, default: fn() -> PathBuf) -> Result<PathBuf> {
    let raw = path.unwrap_or_else(default);
    let absolute = if raw.is_absolute() {
        raw
    } else {
        std::env::current_dir()?.join(raw)
    };

    match absolute.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(absolute),
        Err(error) => Err(error.into()),
    }
}

fn default_policy_dir() -> PathBuf {
    default_config_root().join("policies")
}

fn default_command_rules_dir() -> PathBuf {
    default_config_root().join("command-rules")
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

trait SetIoTimeout {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()>;
}

#[cfg(unix)]
impl SetIoTimeout for std::os::unix::net::UnixStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        std::os::unix::net::UnixStream::set_write_timeout(self, timeout)
    }
}

#[cfg(not(unix))]
impl SetIoTimeout for std::net::TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        std::net::TcpStream::set_write_timeout(self, timeout)
    }
}
