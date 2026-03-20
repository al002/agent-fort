use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use af_sandbox::{
    HELPER_PROTOCOL_VERSION, HelperExecuteRequest, HelperExecuteResponse, SandboxExecRequest,
    SandboxExecResult,
};
use anyhow::{Context, Result, bail};

#[derive(Debug, Clone)]
pub struct HelperClient {
    helper_path: PathBuf,
    bwrap_path: PathBuf,
    cgroup_root: PathBuf,
}

impl HelperClient {
    pub fn new(helper_path: PathBuf, bwrap_path: PathBuf, cgroup_root: PathBuf) -> Self {
        Self {
            helper_path,
            bwrap_path,
            cgroup_root,
        }
    }

    #[allow(dead_code)]
    pub fn execute(&self, request: SandboxExecRequest) -> Result<SandboxExecResult> {
        let request = HelperExecuteRequest::new(request);
        let encoded = serde_json::to_vec(&request).context("serialize helper request")?;

        let mut child = Command::new(&self.helper_path)
            .arg("--bwrap-path")
            .arg(&self.bwrap_path)
            .arg("--cgroup-root")
            .arg(&self.cgroup_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawn helper at {}", self.helper_path.display()))?;

        let mut stdin = child
            .stdin
            .take()
            .context("helper stdin was not captured")?;
        stdin
            .write_all(&encoded)
            .context("write helper request payload")?;
        drop(stdin);

        let output = child
            .wait_with_output()
            .context("wait for helper output failed")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("helper exited with status {}: {stderr}", output.status);
        }

        let response: HelperExecuteResponse =
            serde_json::from_slice(&output.stdout).context("parse helper response JSON failed")?;
        if response.protocol_version != HELPER_PROTOCOL_VERSION {
            bail!(
                "helper protocol mismatch: helper={} daemon={}",
                response.protocol_version,
                HELPER_PROTOCOL_VERSION
            );
        }
        if !response.ok {
            bail!(
                "helper execution failed: {}",
                response
                    .error
                    .unwrap_or_else(|| "unknown helper error".to_string())
            );
        }
        response
            .result
            .context("helper response had ok=true but missing result")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    use af_sandbox::{
        FilesystemMode, FilesystemPolicy, NetworkPolicy, OutputCapturePolicy, PtyPolicy,
        ResourceGovernanceMode, ResourceLimits, SandboxExecRequest, SyscallPolicy, TraceContext,
    };

    use super::HelperClient;

    #[test]
    fn executes_via_helper_process() {
        let helper_bin = resolve_helper_bin_for_test();
        let Some(helper_bin) = helper_bin else {
            return;
        };
        let client = HelperClient::new(
            helper_bin,
            PathBuf::from("/usr/bin/bwrap"),
            PathBuf::from("/sys/fs/cgroup"),
        );
        let request = SandboxExecRequest {
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf 'daemon-helper-ok'".to_string(),
            ],
            cwd: PathBuf::from("/tmp"),
            env: BTreeMap::new(),
            stdin: None,
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
                stdout_max_bytes: 4096,
                stderr_max_bytes: 4096,
            },
            trace: TraceContext {
                session_id: None,
                task_id: None,
                trace_id: Some("daemon-internal-smoke".to_string()),
            },
        };

        let result = client
            .execute(request)
            .expect("helper execution should succeed");
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout, "daemon-helper-ok");
    }

    fn resolve_helper_bin_for_test() -> Option<PathBuf> {
        if let Ok(path) = std::env::var("AF_HELPER_BIN") {
            let path = PathBuf::from(path);
            if path.is_file() {
                return Some(path);
            }
        }
        let fallback =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/af-helper");
        if fallback.is_file() {
            return Some(fallback);
        }
        None
    }
}
