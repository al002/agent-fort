use std::collections::BTreeMap;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use af_sandbox::{
    NetworkPolicy, PtyPolicy, SandboxError, SandboxExecRequest, SandboxExecResult,
    SandboxExitStatus, SandboxMetrics, SandboxResult, SandboxRuntime, SyscallPolicy,
};

use crate::bwrap::{build_bwrap_args, build_bwrap_args_with_mount_proc, should_wrap_with_bwrap};
use crate::cgroup::attach_process;
use crate::rlimit::RlimitPlan;
use crate::seccomp::{
    apply_prepared_to_current_thread, prepare_bwrap_seccomp_fd, prepare_current_thread_filter,
};

const PREFLIGHT_STDERR_MAX_BYTES: usize = 64 * 1024;
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct LinuxSandboxConfig {
    pub bwrap_path: PathBuf,
    pub cgroup_root: PathBuf,
    pub inherit_env_keys: Vec<String>,
}

impl Default for LinuxSandboxConfig {
    fn default() -> Self {
        Self {
            bwrap_path: PathBuf::from("/usr/bin/bwrap"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            inherit_env_keys: vec![
                "PATH".to_string(),
                // "HOME".to_string(),
                // "USER".to_string(),
                // "LOGNAME".to_string(),
                // "HTTP_PROXY".to_string(),
                // "HTTPS_PROXY".to_string(),
                // "ALL_PROXY".to_string(),
                // "NO_PROXY".to_string(),
                // "http_proxy".to_string(),
                // "https_proxy".to_string(),
                // "all_proxy".to_string(),
                // "no_proxy".to_string(),
                "LANG".to_string(),
                "LC_ALL".to_string(),
                "LC_CTYPE".to_string(),
                "TZ".to_string(),
                "TERM".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct LinuxSandboxRuntime {
    config: LinuxSandboxConfig,
}

impl LinuxSandboxRuntime {
    pub fn new(config: LinuxSandboxConfig) -> Self {
        Self { config }
    }
}

impl Default for LinuxSandboxRuntime {
    fn default() -> Self {
        Self::new(LinuxSandboxConfig::default())
    }
}

impl SandboxRuntime for LinuxSandboxRuntime {
    fn execute(&self, request: SandboxExecRequest) -> SandboxResult<SandboxExecResult> {
        request.validate()?;
        ensure_supported_features(&request)?;

        let started_at = Instant::now();
        let wrap_with_bwrap = should_wrap_with_bwrap(&request);
        let PreparedCommand {
            mut command,
            preserved_fds,
        } = self.build_command(&request, wrap_with_bwrap)?;

        let rlimit_plan = RlimitPlan::from_limits(&request.limits).map_err(|err| {
            SandboxError::InvalidRequest(format!(
                "invalid resource limits for this platform: {err}"
            ))
        })?;
        let apply_runtime_seccomp =
            !wrap_with_bwrap && request.syscall_policy != SyscallPolicy::Unconfined;
        let seccomp_policy = request.syscall_policy;
        let prepared_runtime_seccomp = if apply_runtime_seccomp {
            prepare_current_thread_filter(seccomp_policy).map_err(|err| {
                SandboxError::Setup(format!("prepare runtime seccomp filter failed: {err}"))
            })?
        } else {
            None
        };
        unsafe {
            command.pre_exec(move || {
                set_no_new_privs()?;
                rlimit_plan.apply()?;
                if let Some(filter) = prepared_runtime_seccomp.as_ref() {
                    apply_prepared_to_current_thread(filter)?;
                }
                Ok(())
            });
        }

        let mut child = command
            .spawn()
            .map_err(|err| SandboxError::Spawn(format!("spawn sandboxed process failed: {err}")))?;
        drop(preserved_fds);

        let cgroup = match attach_process(
            &self.config.cgroup_root,
            child.id(),
            &request.limits,
            request.governance_mode,
        ) {
            Ok(attachment) => attachment,
            Err(err) => {
                terminate_child_process(&mut child);
                return Err(err);
            }
        };

        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                terminate_child_process(&mut child);
                return Err(SandboxError::Execute(
                    "stdout pipe was not available".to_string(),
                ));
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                terminate_child_process(&mut child);
                return Err(SandboxError::Execute(
                    "stderr pipe was not available".to_string(),
                ));
            }
        };

        let stdout_thread = spawn_capture_thread(stdout, request.capture.stdout_max_bytes);
        let stderr_thread = spawn_capture_thread(stderr, request.capture.stderr_max_bytes);

        let deadline = started_at + request.limits.elapsed_timeout;
        let (status, timed_out) = match wait_child_with_timeout(&mut child, deadline) {
            Ok(value) => value,
            Err(err) => {
                terminate_child_process(&mut child);
                let _ = join_capture_thread(stdout_thread, "stdout");
                let _ = join_capture_thread(stderr_thread, "stderr");
                return Err(err);
            }
        };
        let stdout_capture = join_capture_thread(stdout_thread, "stdout")?;
        let stderr_capture = join_capture_thread(stderr_thread, "stderr")?;

        let (exit_status, exit_code) = map_exit_status(status);
        Ok(SandboxExecResult {
            status: exit_status,
            exit_code,
            timed_out,
            stdout: String::from_utf8_lossy(&stdout_capture.bytes).to_string(),
            stderr: String::from_utf8_lossy(&stderr_capture.bytes).to_string(),
            stdout_truncated: stdout_capture.truncated,
            stderr_truncated: stderr_capture.truncated,
            metrics: SandboxMetrics {
                wall_time: started_at.elapsed(),
                cgroup_applied: cgroup.applied,
                cgroup_reason: cgroup.reason,
            },
        })
    }
}

impl LinuxSandboxRuntime {
    fn build_command(
        &self,
        request: &SandboxExecRequest,
        wrap_with_bwrap: bool,
    ) -> SandboxResult<PreparedCommand> {
        let mut prepared = if wrap_with_bwrap {
            let mut args = self.build_bwrap_args_with_fallback(request)?;
            let mut preserved_fds = Vec::new();
            if let Some(seccomp_fd) = prepare_bwrap_seccomp_fd(request.syscall_policy)
                .map_err(|err| SandboxError::Setup(format!("prepare seccomp fd failed: {err}")))?
            {
                insert_bwrap_seccomp_flag(&mut args, seccomp_fd.as_raw_fd())?;
                preserved_fds.push(seccomp_fd);
            }
            let mut command = Command::new(&self.config.bwrap_path);
            command.args(args);
            PreparedCommand {
                command,
                preserved_fds,
            }
        } else {
            let mut command = Command::new(&request.command[0]);
            command.args(&request.command[1..]);
            PreparedCommand {
                command,
                preserved_fds: Vec::new(),
            }
        };

        prepared.command.current_dir(&request.cwd);
        prepared.command.stdin(Stdio::null());
        prepared.command.stdout(Stdio::piped());
        prepared.command.stderr(Stdio::piped());
        apply_environment(
            &mut prepared.command,
            &self.config.inherit_env_keys,
            &request.env,
        );

        Ok(prepared)
    }

    fn build_bwrap_args_with_fallback(
        &self,
        request: &SandboxExecRequest,
    ) -> SandboxResult<Vec<String>> {
        if !request.filesystem.mount_proc {
            return build_bwrap_args(request);
        }

        if self.preflight_proc_mount_support(request)? {
            return build_bwrap_args(request);
        }

        build_bwrap_args_with_mount_proc(request, false)
    }

    fn preflight_proc_mount_support(&self, request: &SandboxExecRequest) -> SandboxResult<bool> {
        let mut preflight_request = request.clone();
        preflight_request.command = vec![resolve_true_command()];
        let args = build_bwrap_args_with_mount_proc(&preflight_request, true)?;
        let stderr = run_bwrap_preflight_capture_stderr(&self.config.bwrap_path, args)?;
        Ok(!is_proc_mount_failure(&stderr))
    }
}

fn ensure_supported_features(request: &SandboxExecRequest) -> SandboxResult<()> {
    if request.pty == PtyPolicy::Enabled {
        return Err(SandboxError::UnsupportedFeature(
            "pty execution is not implemented yet".to_string(),
        ));
    }
    if request.network == NetworkPolicy::ProxyOnly {
        return Err(SandboxError::UnsupportedFeature(
            "proxy-only network routing is not implemented yet".to_string(),
        ));
    }
    Ok(())
}

fn apply_environment(
    command: &mut Command,
    inherit_env_keys: &[String],
    request_env: &BTreeMap<String, String>,
) {
    command.env_clear();
    for key in inherit_env_keys {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    for (key, value) in request_env {
        command.env(key, value);
    }
}

fn set_no_new_privs() -> io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Debug)]
struct PreparedCommand {
    command: Command,
    preserved_fds: Vec<OwnedFd>,
}

fn insert_bwrap_seccomp_flag(args: &mut Vec<String>, fd: libc::c_int) -> SandboxResult<()> {
    let pos = args
        .iter()
        .position(|value| value == "--")
        .ok_or_else(|| SandboxError::Setup("bwrap args missing command separator".to_string()))?;
    args.splice(pos..pos, ["--seccomp".to_string(), fd.to_string()]);
    Ok(())
}

fn resolve_true_command() -> String {
    for candidate in ["/usr/bin/true", "/bin/true"] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "true".to_string()
}

fn is_proc_mount_failure(stderr: &str) -> bool {
    stderr.contains("Can't mount proc")
        && stderr.contains("/newroot/proc")
        && (stderr.contains("Invalid argument")
            || stderr.contains("Operation not permitted")
            || stderr.contains("Permission denied"))
}

fn run_bwrap_preflight_capture_stderr(
    bwrap_path: &Path,
    args: Vec<String>,
) -> SandboxResult<String> {
    let mut child = Command::new(bwrap_path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| SandboxError::Setup(format!("bwrap preflight failed: {err}")))?;
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate_child_process(&mut child);
            return Err(SandboxError::Setup(
                "bwrap preflight stderr pipe was not available".to_string(),
            ));
        }
    };
    let stderr_thread = spawn_capture_thread(stderr, PREFLIGHT_STDERR_MAX_BYTES);

    let deadline = Instant::now() + PREFLIGHT_TIMEOUT;
    let (_, timed_out) = match wait_child_with_timeout(&mut child, deadline) {
        Ok(value) => value,
        Err(err) => {
            terminate_child_process(&mut child);
            let _ = join_capture_thread(stderr_thread, "preflight stderr");
            return Err(SandboxError::Setup(format!(
                "bwrap preflight wait failed: {err}"
            )));
        }
    };
    if timed_out {
        let _ = join_capture_thread(stderr_thread, "preflight stderr");
        return Err(SandboxError::Setup(format!(
            "bwrap preflight timed out after {}ms",
            PREFLIGHT_TIMEOUT.as_millis()
        )));
    }

    let stderr_capture = join_capture_thread(stderr_thread, "preflight stderr").map_err(|err| {
        SandboxError::Setup(format!("bwrap preflight stderr capture failed: {err}"))
    })?;
    Ok(String::from_utf8_lossy(&stderr_capture.bytes).to_string())
}

fn wait_child_with_timeout(
    child: &mut std::process::Child,
    deadline: Instant,
) -> SandboxResult<(std::process::ExitStatus, bool)> {
    if let Some(result) = wait_child_with_timeout_pidfd(child, deadline)? {
        return Ok(result);
    }

    wait_child_with_timeout_polling(child, deadline)
}

fn wait_child_with_timeout_polling(
    child: &mut std::process::Child,
    deadline: Instant,
) -> SandboxResult<(std::process::ExitStatus, bool)> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((status, false));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let status = child.wait()?;
            return Ok((status, true));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_child_with_timeout_pidfd(
    child: &mut std::process::Child,
    deadline: Instant,
) -> SandboxResult<Option<(std::process::ExitStatus, bool)>> {
    let pid = libc::pid_t::try_from(child.id())
        .map_err(|_| SandboxError::Execute("child pid conversion failed".to_string()))?;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as libc::c_int };
    if fd < 0 {
        let err = io::Error::last_os_error();
        let unsupported = matches!(
            err.raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL | libc::EPERM)
        );
        if unsupported {
            return Ok(None);
        }
        return Err(SandboxError::Io(err));
    }

    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    loop {
        let timeout_ms = timeout_until(deadline);
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pollfd as *mut libc::pollfd, 1, timeout_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SandboxError::Io(err));
        }
        if rc == 0 {
            let _ = child.kill();
            let status = child.wait()?;
            return Ok(Some((status, true)));
        }

        let status = child.wait()?;
        return Ok(Some((status, false)));
    }
}

fn timeout_until(deadline: Instant) -> libc::c_int {
    let now = Instant::now();
    if now >= deadline {
        return 0;
    }
    let remaining = deadline.saturating_duration_since(now).as_millis();
    let max = libc::c_int::MAX as u128;
    if remaining > max {
        libc::c_int::MAX
    } else {
        remaining as libc::c_int
    }
}

fn terminate_child_process(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Debug)]
struct CaptureOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn spawn_capture_thread<R>(
    reader: R,
    max_bytes: usize,
) -> thread::JoinHandle<io::Result<CaptureOutput>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || read_with_limit(reader, max_bytes))
}

fn read_with_limit<R>(mut reader: R, max_bytes: usize) -> io::Result<CaptureOutput>
where
    R: Read,
{
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        if bytes.len() < max_bytes {
            let remaining = max_bytes - bytes.len();
            let to_copy = read.min(remaining);
            bytes.extend_from_slice(&buffer[..to_copy]);
            if to_copy < read {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }

    Ok(CaptureOutput { bytes, truncated })
}

fn join_capture_thread(
    handle: thread::JoinHandle<io::Result<CaptureOutput>>,
    stream_name: &str,
) -> SandboxResult<CaptureOutput> {
    match handle.join() {
        Ok(result) => result.map_err(SandboxError::from),
        Err(_) => Err(SandboxError::Execute(format!(
            "{stream_name} capture thread panicked"
        ))),
    }
}

fn map_exit_status(status: std::process::ExitStatus) -> (SandboxExitStatus, Option<i32>) {
    if let Some(code) = status.code() {
        return (SandboxExitStatus::Exited, Some(code));
    }
    if let Some(signal) = status.signal() {
        return (SandboxExitStatus::Signaled(signal), None);
    }
    (SandboxExitStatus::ExecFailed, None)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    use af_sandbox::{
        FilesystemMode, FilesystemPolicy, NetworkPolicy, OutputCapturePolicy, PtyPolicy,
        ResourceGovernanceMode, ResourceLimits, SandboxExecRequest, SandboxRuntime, SyscallPolicy,
        TraceContext,
    };

    use super::LinuxSandboxRuntime;

    fn full_access_request(command: Vec<String>) -> SandboxExecRequest {
        SandboxExecRequest {
            command,
            cwd: PathBuf::from("/tmp"),
            env: BTreeMap::new(),
            filesystem: FilesystemPolicy {
                mode: FilesystemMode::FullAccess,
                include_platform_defaults: false,
                mount_proc: true,
                readable_roots: vec![],
                writable_roots: vec![],
                mounts: vec![],
                unreadable_roots: vec![],
            },
            network: NetworkPolicy::Full,
            pty: PtyPolicy::Disabled,
            limits: ResourceLimits {
                elapsed_timeout: Duration::from_secs(5),
                cpu_time_limit_seconds: None,
                max_memory_bytes: None,
                max_processes: None,
                max_file_size_bytes: None,
                cpu_max_percent: None,
            },
            governance_mode: ResourceGovernanceMode::BestEffort,
            syscall_policy: SyscallPolicy::Unconfined,
            capture: OutputCapturePolicy {
                stdout_max_bytes: 16 * 1024,
                stderr_max_bytes: 16 * 1024,
            },
            trace: TraceContext::default(),
        }
    }

    #[test]
    fn executes_without_bwrap_for_full_access() {
        let runtime = LinuxSandboxRuntime::default();
        let request = full_access_request(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf 'sandbox-ok'".to_string(),
        ]);
        let result = runtime.execute(request).expect("execute request");

        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout, "sandbox-ok");
        assert!(!result.timed_out);
    }

    #[test]
    fn kills_process_on_timeout() {
        let runtime = LinuxSandboxRuntime::default();
        let mut request = full_access_request(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep 3".to_string(),
        ]);
        request.limits.elapsed_timeout = Duration::from_millis(150);

        let result = runtime.execute(request).expect("execute request");
        assert!(result.timed_out);
    }

    #[test]
    fn rejects_pty_until_supported() {
        let runtime = LinuxSandboxRuntime::default();
        let mut request = full_access_request(vec!["/bin/true".to_string()]);
        request.pty = PtyPolicy::Enabled;
        let err = runtime
            .execute(request)
            .expect_err("pty should be unsupported");
        assert!(err.to_string().contains("pty execution"));
    }

    #[test]
    fn rejects_proxy_only_until_supported() {
        let runtime = LinuxSandboxRuntime::default();
        let mut request = full_access_request(vec!["/bin/true".to_string()]);
        request.network = NetworkPolicy::ProxyOnly;
        let err = runtime
            .execute(request)
            .expect_err("proxy-only should be unsupported");
        assert!(err.to_string().contains("proxy-only network routing"));
    }

    #[test]
    fn baseline_seccomp_is_applied_in_direct_mode() {
        let runtime = LinuxSandboxRuntime::default();
        let mut request = full_access_request(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "while IFS=':' read -r k v; do if [ \"$k\" = \"Seccomp\" ]; then printf '%s' \"$v\"; break; fi; done < /proc/self/status".to_string(),
        ]);
        request.syscall_policy = SyscallPolicy::Baseline;

        let result = runtime.execute(request).expect("execute request");
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout.trim(), "2");
    }
}
