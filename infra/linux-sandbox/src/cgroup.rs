use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use af_sandbox::{ResourceGovernanceMode, ResourceLimits, SandboxError, SandboxResult};

#[derive(Debug)]
pub(crate) struct CgroupAttachment {
    _handle: Option<CgroupHandle>,
    pub(crate) applied: bool,
    pub(crate) reason: Option<String>,
}

impl CgroupAttachment {
    pub(crate) fn skipped(reason: impl Into<String>) -> Self {
        Self {
            _handle: None,
            applied: false,
            reason: Some(reason.into()),
        }
    }

    fn applied(handle: CgroupHandle) -> Self {
        Self {
            _handle: Some(handle),
            applied: true,
            reason: None,
        }
    }
}

#[derive(Debug)]
struct CgroupHandle {
    path: PathBuf,
}

impl Drop for CgroupHandle {
    fn drop(&mut self) {
        cleanup_leaf(self.path.as_path());
    }
}

pub(crate) fn attach_process(
    cgroup_root: &Path,
    pid: u32,
    limits: &ResourceLimits,
    mode: ResourceGovernanceMode,
) -> SandboxResult<CgroupAttachment> {
    match mode {
        ResourceGovernanceMode::Disabled => {
            return Ok(CgroupAttachment::skipped("resource governance disabled"));
        }
        ResourceGovernanceMode::BestEffort | ResourceGovernanceMode::Required => {}
    }

    match try_attach_process(cgroup_root, pid, limits) {
        Ok(handle) => Ok(CgroupAttachment::applied(handle)),
        Err(err) => match mode {
            ResourceGovernanceMode::Required => Err(SandboxError::Setup(format!(
                "failed to apply required cgroup limits: {err}"
            ))),
            ResourceGovernanceMode::BestEffort => Ok(CgroupAttachment::skipped(format!(
                "cgroup unavailable: {err}"
            ))),
            ResourceGovernanceMode::Disabled => unreachable!(),
        },
    }
}

fn try_attach_process(
    cgroup_root: &Path,
    pid: u32,
    limits: &ResourceLimits,
) -> io::Result<CgroupHandle> {
    ensure_v2(cgroup_root)?;
    let namespace_root = cgroup_root.join("agent-fort");
    fs::create_dir_all(&namespace_root)?;

    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let leaf = namespace_root.join(format!("task-{pid}-{now_nanos}"));
    fs::create_dir(&leaf)?;

    let attach_result = (|| {
        if let Some(value) = limits.max_processes {
            write_control_file(&leaf.join("pids.max"), value.to_string())?;
        }
        if let Some(value) = limits.max_memory_bytes {
            write_control_file(&leaf.join("memory.max"), value.to_string())?;
        }
        if let Some(percent) = limits.cpu_max_percent {
            let period: u64 = 100_000;
            let quota = ((period * u64::from(percent)) / 100).max(1);
            write_control_file(&leaf.join("cpu.max"), format!("{quota} {period}"))?;
        }
        write_control_file(&leaf.join("cgroup.procs"), pid.to_string())
    })();

    match attach_result {
        Ok(()) => Ok(CgroupHandle { path: leaf }),
        Err(err) => {
            cleanup_leaf(leaf.as_path());
            Err(err)
        }
    }
}

fn ensure_v2(cgroup_root: &Path) -> io::Result<()> {
    let controllers = cgroup_root.join("cgroup.controllers");
    if !controllers.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("cgroup v2 is not available at {}", cgroup_root.display()),
        ));
    }
    Ok(())
}

fn write_control_file(path: &Path, value: String) -> io::Result<()> {
    fs::write(path, format!("{value}\n"))
}

fn cleanup_leaf(path: &Path) {
    let _ = move_tasks_to_parent(path);
    for _ in 0..20 {
        match fs::remove_dir(path) {
            Ok(()) => return,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(_) => thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
    let _ = fs::remove_dir(path);
}

fn move_tasks_to_parent(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let procs_file = path.join("cgroup.procs");
    let parent_procs_file = parent.join("cgroup.procs");
    let content = fs::read_to_string(&procs_file)?;
    for line in content.lines() {
        let pid = line.trim();
        if pid.is_empty() {
            continue;
        }
        write_control_file(&parent_procs_file, pid.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::attach_process;
    use af_sandbox::{ResourceGovernanceMode, ResourceLimits};

    #[test]
    fn disabled_mode_skips_without_error() {
        let result = attach_process(
            Path::new("/definitely-not-a-cgroup-root"),
            std::process::id(),
            &ResourceLimits::default(),
            ResourceGovernanceMode::Disabled,
        )
        .expect("disabled mode should always skip");

        assert!(!result.applied);
    }

    #[test]
    fn best_effort_skips_when_not_available() {
        let result = attach_process(
            Path::new("/definitely-not-a-cgroup-root"),
            std::process::id(),
            &ResourceLimits::default(),
            ResourceGovernanceMode::BestEffort,
        )
        .expect("best effort should not fail hard");

        assert!(!result.applied);
        assert!(result.reason.is_some());
    }

    #[test]
    fn required_mode_fails_when_not_available() {
        let err = attach_process(
            Path::new("/definitely-not-a-cgroup-root"),
            std::process::id(),
            &ResourceLimits::default(),
            ResourceGovernanceMode::Required,
        )
        .expect_err("required mode should fail hard");
        assert!(err.to_string().contains("required cgroup limits"));
    }

    #[test]
    fn ensure_v2_requires_controllers_file() {
        let dir = std::env::temp_dir().join(format!("af-cgroup-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create tmp root");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("set perms");
        let err = attach_process(
            &dir,
            std::process::id(),
            &ResourceLimits::default(),
            ResourceGovernanceMode::Required,
        )
        .expect_err("root without cgroup.controllers should fail");
        assert!(err.to_string().contains("cgroup v2"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
