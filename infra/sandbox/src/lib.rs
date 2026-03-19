use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type SandboxResult<T> = Result<T, SandboxError>;

pub const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
pub const HELPER_MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;

pub trait SandboxRuntime: Send + Sync {
    fn execute(&self, request: SandboxExecRequest) -> SandboxResult<SandboxExecResult>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FilesystemMode {
    #[default]
    Restricted,
    ReadOnly,
    FullAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NetworkPolicy {
    #[default]
    Disabled,
    Full,
    ProxyOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PtyPolicy {
    #[default]
    Disabled,
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ResourceGovernanceMode {
    Required,
    #[default]
    BestEffort,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SyscallPolicy {
    Unconfined,
    #[default]
    Baseline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritableRoot {
    pub root: PathBuf,
    pub read_only_subpaths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    pub mode: FilesystemMode,
    pub include_platform_defaults: bool,
    pub mount_proc: bool,
    pub readable_roots: Vec<PathBuf>,
    pub writable_roots: Vec<WritableRoot>,
    pub mounts: Vec<BindMount>,
    pub unreadable_roots: Vec<PathBuf>,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            mode: FilesystemMode::Restricted,
            include_platform_defaults: true,
            mount_proc: true,
            readable_roots: Vec::new(),
            writable_roots: Vec::new(),
            mounts: Vec::new(),
            unreadable_roots: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputCapturePolicy {
    pub stdout_max_bytes: usize,
    pub stderr_max_bytes: usize,
}

impl Default for OutputCapturePolicy {
    fn default() -> Self {
        Self {
            stdout_max_bytes: 1024 * 1024,
            stderr_max_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub wall_timeout: Duration,
    pub cpu_time_limit_seconds: Option<u64>,
    pub max_memory_bytes: Option<u64>,
    pub max_processes: Option<u64>,
    pub max_file_size_bytes: Option<u64>,
    pub cpu_max_percent: Option<u32>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            wall_timeout: Duration::from_secs(30),
            cpu_time_limit_seconds: None,
            max_memory_bytes: None,
            max_processes: None,
            max_file_size_bytes: None,
            cpu_max_percent: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TraceContext {
    pub session_id: Option<String>,
    pub task_id: Option<String>,
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxExecRequest {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub pty: PtyPolicy,
    pub limits: ResourceLimits,
    pub governance_mode: ResourceGovernanceMode,
    pub syscall_policy: SyscallPolicy,
    pub capture: OutputCapturePolicy,
    pub trace: TraceContext,
}

impl SandboxExecRequest {
    pub fn validate(&self) -> SandboxResult<()> {
        if self.command.is_empty() {
            return Err(SandboxError::InvalidRequest(
                "command cannot be empty".to_string(),
            ));
        }
        if self.command[0].trim().is_empty() {
            return Err(SandboxError::InvalidRequest(
                "command[0] cannot be empty".to_string(),
            ));
        }
        if !self.cwd.is_absolute() {
            return Err(SandboxError::InvalidRequest(format!(
                "cwd must be absolute: {}",
                self.cwd.display()
            )));
        }
        if self.limits.wall_timeout.is_zero() {
            return Err(SandboxError::InvalidRequest(
                "wall timeout must be greater than 0".to_string(),
            ));
        }
        if self.capture.stdout_max_bytes == 0 || self.capture.stderr_max_bytes == 0 {
            return Err(SandboxError::InvalidRequest(
                "capture limits must be greater than 0".to_string(),
            ));
        }
        if self.capture.stdout_max_bytes > MAX_CAPTURE_BYTES {
            return Err(SandboxError::InvalidRequest(format!(
                "stdout_max_bytes exceeds max allowed ({MAX_CAPTURE_BYTES}): {}",
                self.capture.stdout_max_bytes
            )));
        }
        if self.capture.stderr_max_bytes > MAX_CAPTURE_BYTES {
            return Err(SandboxError::InvalidRequest(format!(
                "stderr_max_bytes exceeds max allowed ({MAX_CAPTURE_BYTES}): {}",
                self.capture.stderr_max_bytes
            )));
        }
        if let Some(value) = self.limits.max_memory_bytes
            && value == 0
        {
            return Err(SandboxError::InvalidRequest(
                "max_memory_bytes must be greater than 0".to_string(),
            ));
        }
        if let Some(value) = self.limits.max_processes
            && value == 0
        {
            return Err(SandboxError::InvalidRequest(
                "max_processes must be greater than 0".to_string(),
            ));
        }
        if let Some(value) = self.limits.max_file_size_bytes
            && value == 0
        {
            return Err(SandboxError::InvalidRequest(
                "max_file_size_bytes must be greater than 0".to_string(),
            ));
        }
        if let Some(value) = self.limits.cpu_time_limit_seconds
            && value == 0
        {
            return Err(SandboxError::InvalidRequest(
                "cpu_time_limit_seconds must be greater than 0".to_string(),
            ));
        }
        if let Some(value) = self.limits.cpu_max_percent
            && value == 0
        {
            return Err(SandboxError::InvalidRequest(
                "cpu_max_percent must be greater than 0".to_string(),
            ));
        }
        self.validate_filesystem_paths()
    }

    fn validate_filesystem_paths(&self) -> SandboxResult<()> {
        for path in &self.filesystem.readable_roots {
            if !path.is_absolute() {
                return invalid_absolute_path("readable_roots", path);
            }
        }
        for path in &self.filesystem.unreadable_roots {
            if !path.is_absolute() {
                return invalid_absolute_path("unreadable_roots", path);
            }
        }
        for root in &self.filesystem.writable_roots {
            if !root.root.is_absolute() {
                return invalid_absolute_path("writable_roots.root", &root.root);
            }
            let normalized_root = normalize_lexical_absolute_path(&root.root);
            for path in &root.read_only_subpaths {
                if !path.is_absolute() {
                    return invalid_absolute_path("writable_roots.read_only_subpaths", path);
                }
                let normalized_subpath = normalize_lexical_absolute_path(path);
                if !normalized_subpath.starts_with(&normalized_root) {
                    return Err(SandboxError::InvalidRequest(format!(
                        "read-only subpath {} must stay under writable root {}",
                        path.display(),
                        root.root.display()
                    )));
                }
            }
        }
        for mount in &self.filesystem.mounts {
            if !mount.source.is_absolute() {
                return invalid_absolute_path("mounts.source", &mount.source);
            }
            if !mount.target.is_absolute() {
                return invalid_absolute_path("mounts.target", &mount.target);
            }
        }
        Ok(())
    }
}

fn invalid_absolute_path(field: &str, path: &Path) -> SandboxResult<()> {
    Err(SandboxError::InvalidRequest(format!(
        "{field} must contain absolute paths: {}",
        path.display()
    )))
}

fn normalize_lexical_absolute_path(path: &Path) -> PathBuf {
    debug_assert!(path.is_absolute());

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxExitStatus {
    Exited,
    Signaled(i32),
    ExecFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxMetrics {
    pub wall_time: Duration,
    pub cgroup_applied: bool,
    pub cgroup_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxExecResult {
    pub status: SandboxExitStatus,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub metrics: SandboxMetrics,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("invalid sandbox request: {0}")]
    InvalidRequest(String),
    #[error("unsupported sandbox feature: {0}")]
    UnsupportedFeature(String),
    #[error("sandbox setup failed: {0}")]
    Setup(String),
    #[error("sandbox spawn failed: {0}")]
    Spawn(String),
    #[error("sandbox execution failed: {0}")]
    Execute(String),
    #[error("sandbox io error: {0}")]
    Io(#[from] std::io::Error),
}

pub const HELPER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperExecuteRequest {
    pub protocol_version: u32,
    pub request: SandboxExecRequest,
}

impl HelperExecuteRequest {
    pub fn new(request: SandboxExecRequest) -> Self {
        Self {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperExecuteResponse {
    pub protocol_version: u32,
    pub ok: bool,
    pub result: Option<SandboxExecResult>,
    pub error: Option<String>,
}

impl HelperExecuteResponse {
    pub fn success(result: SandboxExecResult) -> Self {
        Self {
            protocol_version: HELPER_PROTOCOL_VERSION,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            protocol_version: HELPER_PROTOCOL_VERSION,
            ok: false,
            result: None,
            error: Some(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_basic_request() {
        let request = SandboxExecRequest {
            command: vec!["/bin/true".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: BTreeMap::new(),
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::Disabled,
            pty: PtyPolicy::Disabled,
            limits: ResourceLimits::default(),
            governance_mode: ResourceGovernanceMode::BestEffort,
            syscall_policy: SyscallPolicy::Unconfined,
            capture: OutputCapturePolicy::default(),
            trace: TraceContext::default(),
        };
        request.validate().expect("request should be valid");
    }

    #[test]
    fn rejects_relative_cwd() {
        let request = SandboxExecRequest {
            command: vec!["/bin/true".to_string()],
            cwd: PathBuf::from("."),
            env: BTreeMap::new(),
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::Disabled,
            pty: PtyPolicy::Disabled,
            limits: ResourceLimits::default(),
            governance_mode: ResourceGovernanceMode::BestEffort,
            syscall_policy: SyscallPolicy::Unconfined,
            capture: OutputCapturePolicy::default(),
            trace: TraceContext::default(),
        };
        let err = request.validate().expect_err("request should be invalid");
        assert!(err.to_string().contains("cwd"));
    }

    #[test]
    fn rejects_out_of_root_read_only_subpath() {
        let request = SandboxExecRequest {
            command: vec!["/bin/true".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: BTreeMap::new(),
            filesystem: FilesystemPolicy {
                mode: FilesystemMode::Restricted,
                include_platform_defaults: true,
                mount_proc: true,
                readable_roots: vec![],
                writable_roots: vec![WritableRoot {
                    root: PathBuf::from("/tmp/work"),
                    read_only_subpaths: vec![PathBuf::from("/tmp/other")],
                }],
                mounts: vec![],
                unreadable_roots: vec![],
            },
            network: NetworkPolicy::Disabled,
            pty: PtyPolicy::Disabled,
            limits: ResourceLimits::default(),
            governance_mode: ResourceGovernanceMode::BestEffort,
            syscall_policy: SyscallPolicy::Unconfined,
            capture: OutputCapturePolicy::default(),
            trace: TraceContext::default(),
        };
        let err = request.validate().expect_err("request should be invalid");
        assert!(err.to_string().contains("must stay under writable root"));
    }

    #[test]
    fn helper_protocol_roundtrip_is_serializable() {
        let request = SandboxExecRequest {
            command: vec!["/bin/true".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: BTreeMap::new(),
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::Disabled,
            pty: PtyPolicy::Disabled,
            limits: ResourceLimits::default(),
            governance_mode: ResourceGovernanceMode::BestEffort,
            syscall_policy: SyscallPolicy::Unconfined,
            capture: OutputCapturePolicy::default(),
            trace: TraceContext::default(),
        };
        let payload = HelperExecuteRequest::new(request);
        let encoded = serde_json::to_string(&payload).expect("serialize helper request");
        let decoded: HelperExecuteRequest =
            serde_json::from_str(&encoded).expect("deserialize helper request");
        assert_eq!(decoded.protocol_version, HELPER_PROTOCOL_VERSION);
    }

    #[test]
    fn rejects_read_only_subpath_that_escapes_root_via_parent_segments() {
        let request = SandboxExecRequest {
            command: vec!["/bin/true".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: BTreeMap::new(),
            filesystem: FilesystemPolicy {
                mode: FilesystemMode::Restricted,
                include_platform_defaults: true,
                mount_proc: true,
                readable_roots: vec![],
                writable_roots: vec![WritableRoot {
                    root: PathBuf::from("/tmp/work"),
                    read_only_subpaths: vec![PathBuf::from("/tmp/work/../escape")],
                }],
                mounts: vec![],
                unreadable_roots: vec![],
            },
            network: NetworkPolicy::Disabled,
            pty: PtyPolicy::Disabled,
            limits: ResourceLimits::default(),
            governance_mode: ResourceGovernanceMode::BestEffort,
            syscall_policy: SyscallPolicy::Unconfined,
            capture: OutputCapturePolicy::default(),
            trace: TraceContext::default(),
        };
        let err = request.validate().expect_err("request should be invalid");
        assert!(err.to_string().contains("must stay under writable root"));
    }

    #[test]
    fn rejects_relative_mount_source() {
        let request = SandboxExecRequest {
            command: vec!["/bin/true".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: BTreeMap::new(),
            filesystem: FilesystemPolicy {
                mode: FilesystemMode::Restricted,
                include_platform_defaults: true,
                mount_proc: true,
                readable_roots: vec![],
                writable_roots: vec![],
                mounts: vec![BindMount {
                    source: PathBuf::from("relative/source"),
                    target: PathBuf::from("/mnt/source"),
                    read_only: true,
                }],
                unreadable_roots: vec![],
            },
            network: NetworkPolicy::Disabled,
            pty: PtyPolicy::Disabled,
            limits: ResourceLimits::default(),
            governance_mode: ResourceGovernanceMode::BestEffort,
            syscall_policy: SyscallPolicy::Unconfined,
            capture: OutputCapturePolicy::default(),
            trace: TraceContext::default(),
        };

        let err = request.validate().expect_err("request should be invalid");
        assert!(err.to_string().contains("mounts.source"));
    }
}
