use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use af_rpc_proto::codec::{decode_message, encode_message};
use af_rpc_proto::{PingRequest, PingResponse, RpcMethod, RpcRequest, RpcResponse, rpc_response};
use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::command::{InstallState, StartArgs, resolve_endpoint, resolve_install_root};

const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;
const IO_TIMEOUT_MS: u64 = 500;

#[derive(Debug, Serialize)]
pub struct StartOutput {
    pub ok: bool,
    pub endpoint: String,
    pub started: bool,
    pub daemon_pid: Option<u32>,
    pub daemon_instance_id: String,
}

pub fn run(args: StartArgs) -> Result<StartOutput> {
    let install_root = resolve_install_root(args.install_root);
    let mut state = InstallState::load(&install_root)?;
    let endpoint = resolve_endpoint(args.endpoint, Some(&state));
    state.endpoint = endpoint.clone();
    if let Some(path) = args.daemon_path {
        state.daemon_path = path;
    }
    if let Some(path) = args.bwrap_path {
        state.bwrap_path = path;
    }
    if let Some(path) = args.helper_path {
        state.helper_path = path;
    }

    ensure_file(&state.daemon_path, "daemon binary")?;
    ensure_file(&state.bwrap_path, "bwrap binary")?;
    ensure_file(&state.helper_path, "helper binary")?;

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
        &endpoint,
        &state.bwrap_path,
        &state.helper_path,
        args.policy_dir.as_deref(),
    )?;
    let deadline = Instant::now() + Duration::from_millis(args.startup_timeout_ms);
    let poll_interval = Duration::from_millis(args.ping_interval_ms.max(10));
    loop {
        if let Ok(response) = ping_once(&endpoint) {
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

fn spawn_daemon(
    daemon_path: &Path,
    endpoint: &str,
    bwrap_path: &Path,
    helper_path: &Path,
    policy_dir: Option<&Path>,
) -> Result<u32> {
    let mut command = Command::new(daemon_path);
    command
        .env("AF_DAEMON_ENDPOINT", endpoint)
        .env("AF_BWRAP_PATH", bwrap_path)
        .env("AF_HELPER_PATH", helper_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(policy_dir) = policy_dir {
        command.env("AF_POLICY_DIR", policy_dir);
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
