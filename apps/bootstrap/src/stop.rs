use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::command::{InstallState, StopArgs, daemon_pid_file_path, resolve_install_root};

#[derive(Debug, Serialize)]
pub struct StopOutput {
    pub ok: bool,
    pub stopped: bool,
    pub daemon_pid: Option<u32>,
    pub endpoint: Option<String>,
    pub reason: Option<String>,
}

pub fn run(args: StopArgs) -> Result<StopOutput> {
    let install_root = resolve_install_root(args.install_root);
    let state = InstallState::load(&install_root).ok();
    let endpoint = args
        .endpoint
        .or_else(|| state.as_ref().map(|state| state.endpoint.clone()));

    let pid_path = daemon_pid_file_path(&install_root);
    if !pid_path.is_file() {
        return Ok(StopOutput {
            ok: true,
            stopped: false,
            daemon_pid: None,
            endpoint,
            reason: Some(format!("daemon pid file not found: {}", pid_path.display())),
        });
    }

    let raw_pid = fs::read_to_string(&pid_path)
        .with_context(|| format!("read daemon pid file {}", pid_path.display()))?;
    let daemon_pid = raw_pid.trim().parse::<u32>().with_context(|| {
        format!(
            "parse daemon pid from {} content `{}`",
            pid_path.display(),
            raw_pid.trim()
        )
    })?;

    let stopped = terminate_daemon(
        daemon_pid,
        Duration::from_millis(args.shutdown_timeout_ms.max(1)),
    )?;

    if let Err(error) = fs::remove_file(&pid_path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error).with_context(|| format!("remove pid file {}", pid_path.display()));
    }

    if let Some(endpoint) = endpoint.as_deref() {
        cleanup_endpoint_socket(endpoint)?;
    }

    Ok(StopOutput {
        ok: true,
        stopped,
        daemon_pid: Some(daemon_pid),
        endpoint,
        reason: if stopped {
            None
        } else {
            Some("daemon process was already exited".to_string())
        },
    })
}

#[cfg(unix)]
fn terminate_daemon(pid: u32, timeout: Duration) -> Result<bool> {
    let pid_raw = pid as libc::pid_t;

    if !process_exists(pid_raw) {
        return Ok(false);
    }

    let term_rc = unsafe { libc::kill(pid_raw, libc::SIGTERM) };
    if term_rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(false);
        }
        return Err(error).context("send SIGTERM to daemon failed");
    }

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_exists(pid_raw) {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let kill_rc = unsafe { libc::kill(pid_raw, libc::SIGKILL) };
    if kill_rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error).context("send SIGKILL to daemon failed");
        }
    }

    Ok(true)
}

#[cfg(unix)]
fn process_exists(pid: libc::pid_t) -> bool {
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    let error = std::io::Error::last_os_error();
    error.raw_os_error() != Some(libc::ESRCH)
}

#[cfg(windows)]
fn terminate_daemon(pid: u32, _timeout: Duration) -> Result<bool> {
    let status = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status()
        .context("run taskkill")?;

    if status.success() {
        return Ok(true);
    }

    Ok(false)
}

fn cleanup_endpoint_socket(endpoint: &str) -> Result<()> {
    #[cfg(unix)]
    {
        if endpoint.starts_with("npipe://") {
            return Ok(());
        }

        let path = endpoint.strip_prefix("unix://").unwrap_or(endpoint);
        if path.is_empty() {
            return Ok(());
        }

        let path_ref = Path::new(path);
        if path_ref.exists() {
            fs::remove_file(path_ref)
                .with_context(|| format!("remove daemon socket {}", path_ref.display()))?;
        }
    }

    Ok(())
}
