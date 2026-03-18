use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use af_sandbox::{
    FilesystemMode, FilesystemPolicy, NetworkPolicy, SandboxError, SandboxExecRequest,
    SandboxResult,
};

const LINUX_PLATFORM_DEFAULT_READ_ROOTS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr",
    "/etc",
    "/lib",
    "/lib64",
    "/nix/store",
    "/run/current-system/sw",
];

pub(crate) fn should_wrap_with_bwrap(request: &SandboxExecRequest) -> bool {
    request.filesystem.mode != FilesystemMode::FullAccess || request.network != NetworkPolicy::Full
}

pub(crate) fn build_bwrap_args(request: &SandboxExecRequest) -> SandboxResult<Vec<String>> {
    build_bwrap_args_with_mount_proc(request, request.filesystem.mount_proc)
}

pub(crate) fn build_bwrap_args_with_mount_proc(
    request: &SandboxExecRequest,
    mount_proc: bool,
) -> SandboxResult<Vec<String>> {
    let mut args = Vec::new();
    args.extend(["--new-session".to_string(), "--die-with-parent".to_string()]);
    append_filesystem_args(&mut args, &request.filesystem)?;
    args.push("--unshare-user".to_string());
    args.push("--unshare-pid".to_string());
    if request.network != NetworkPolicy::Full {
        args.push("--unshare-net".to_string());
    }
    if mount_proc {
        args.push("--proc".to_string());
        args.push("/proc".to_string());
    }
    args.push("--chdir".to_string());
    args.push(path_to_string(&request.cwd));
    args.push("--".to_string());
    args.extend(request.command.clone());
    Ok(args)
}

fn append_filesystem_args(args: &mut Vec<String>, policy: &FilesystemPolicy) -> SandboxResult<()> {
    match policy.mode {
        FilesystemMode::FullAccess => {
            args.extend(["--bind".to_string(), "/".to_string(), "/".to_string()]);
        }
        FilesystemMode::ReadOnly => {
            args.extend([
                "--ro-bind".to_string(),
                "/".to_string(),
                "/".to_string(),
                "--dev".to_string(),
                "/dev".to_string(),
            ]);
        }
        FilesystemMode::Restricted => append_restricted_reads(args, policy),
    }

    let mut writable_roots = policy.writable_roots.clone();
    let allowed_write_paths: Vec<PathBuf> = writable_roots
        .iter()
        .map(|root| root.root.clone())
        .collect();
    writable_roots.sort_by_key(|root| depth(root.root.as_path()));
    for writable_root in writable_roots {
        if !writable_root.root.exists() {
            return Err(SandboxError::InvalidRequest(format!(
                "writable root does not exist: {}",
                writable_root.root.display()
            )));
        }
        args.push("--bind".to_string());
        args.push(path_to_string(&writable_root.root));
        args.push(path_to_string(&writable_root.root));

        let mut read_only_subpaths = writable_root.read_only_subpaths;
        read_only_subpaths.sort_by_key(|path| depth(path.as_path()));
        for subpath in read_only_subpaths {
            if subpath.exists() {
                args.push("--ro-bind".to_string());
                args.push(path_to_string(&subpath));
                args.push(path_to_string(&subpath));
                continue;
            }
            if let Some(first_missing_component) = find_first_non_existent_component(&subpath)
                && is_within_allowed_write_paths(&first_missing_component, &allowed_write_paths)
            {
                args.push("--ro-bind".to_string());
                args.push("/dev/null".to_string());
                args.push(path_to_string(&first_missing_component));
            }
        }
    }

    let mut unreadable_roots = policy.unreadable_roots.clone();
    unreadable_roots.sort_by_key(|path| depth(path.as_path()));
    for unreadable_root in unreadable_roots {
        append_unreadable_path(args, unreadable_root.as_path(), &allowed_write_paths);
    }

    Ok(())
}

fn append_restricted_reads(args: &mut Vec<String>, policy: &FilesystemPolicy) {
    let mut readable_roots: BTreeSet<PathBuf> = policy.readable_roots.iter().cloned().collect();
    if policy.include_platform_defaults {
        readable_roots.extend(
            LINUX_PLATFORM_DEFAULT_READ_ROOTS
                .iter()
                .map(PathBuf::from)
                .filter(|path| path.exists()),
        );
    }

    if readable_roots.iter().any(|path| path == Path::new("/")) {
        args.extend([
            "--ro-bind".to_string(),
            "/".to_string(),
            "/".to_string(),
            "--dev".to_string(),
            "/dev".to_string(),
        ]);
        return;
    }

    args.extend([
        "--tmpfs".to_string(),
        "/".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
    ]);
    for root in readable_roots {
        if !root.exists() {
            continue;
        }
        args.push("--ro-bind".to_string());
        args.push(path_to_string(&root));
        args.push(path_to_string(&root));
    }
}

fn append_unreadable_path(args: &mut Vec<String>, path: &Path, allowed_write_paths: &[PathBuf]) {
    if !path.exists() {
        if let Some(first_missing_component) = find_first_non_existent_component(path)
            && is_within_allowed_write_paths(&first_missing_component, allowed_write_paths)
        {
            args.push("--ro-bind".to_string());
            args.push("/dev/null".to_string());
            args.push(path_to_string(&first_missing_component));
        }
        return;
    }

    if path.is_dir() {
        args.push("--perms".to_string());
        args.push("000".to_string());
        args.push("--tmpfs".to_string());
        args.push(path_to_string(path));
        args.push("--remount-ro".to_string());
        args.push(path_to_string(path));
        return;
    }

    args.push("--ro-bind".to_string());
    args.push("/dev/null".to_string());
    args.push(path_to_string(path));
}

fn depth(path: &Path) -> usize {
    path.components().count()
}

fn is_within_allowed_write_paths(path: &Path, allowed_write_paths: &[PathBuf]) -> bool {
    allowed_write_paths
        .iter()
        .any(|root| path.starts_with(root))
}

fn find_first_non_existent_component(target_path: &Path) -> Option<PathBuf> {
    let mut current = PathBuf::new();

    for component in target_path.components() {
        use std::path::Component;
        match component {
            Component::RootDir => {
                current.push(Path::new("/"));
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                current.pop();
                continue;
            }
            Component::Normal(part) => current.push(part),
            Component::Prefix(_) => continue,
        }

        if !current.exists() {
            return Some(current);
        }
    }

    None
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use af_sandbox::{
        FilesystemMode, FilesystemPolicy, NetworkPolicy, OutputCapturePolicy, PtyPolicy,
        ResourceGovernanceMode, ResourceLimits, SandboxExecRequest, SyscallPolicy, TraceContext,
        WritableRoot,
    };

    use super::{build_bwrap_args, should_wrap_with_bwrap};

    fn base_request() -> SandboxExecRequest {
        SandboxExecRequest {
            command: vec!["/bin/echo".to_string(), "ok".to_string()],
            cwd: "/tmp".into(),
            env: BTreeMap::new(),
            filesystem: FilesystemPolicy {
                mode: FilesystemMode::ReadOnly,
                include_platform_defaults: true,
                mount_proc: true,
                readable_roots: vec![],
                writable_roots: vec![],
                unreadable_roots: vec![],
            },
            network: NetworkPolicy::Disabled,
            pty: PtyPolicy::Disabled,
            limits: ResourceLimits::default(),
            governance_mode: ResourceGovernanceMode::BestEffort,
            syscall_policy: SyscallPolicy::Unconfined,
            capture: OutputCapturePolicy::default(),
            trace: TraceContext::default(),
        }
    }

    #[test]
    fn read_only_disabled_network_wraps() {
        let request = base_request();
        assert!(should_wrap_with_bwrap(&request));
        let args = build_bwrap_args(&request).expect("build bwrap args");
        assert!(args.contains(&"--unshare-net".to_string()));
        assert!(args.contains(&"--ro-bind".to_string()));
    }

    #[test]
    fn full_access_full_network_does_not_require_bwrap() {
        let mut request = base_request();
        request.filesystem.mode = FilesystemMode::FullAccess;
        request.network = NetworkPolicy::Full;
        assert!(!should_wrap_with_bwrap(&request));
    }

    #[test]
    fn writable_bind_is_emitted() {
        let mut request = base_request();
        request.filesystem.mode = FilesystemMode::Restricted;
        request.filesystem.writable_roots = vec![WritableRoot {
            root: PathBuf::from("/tmp"),
            read_only_subpaths: vec![],
        }];

        let args = build_bwrap_args(&request).expect("build bwrap args");
        assert!(
            args.windows(3)
                .any(|window| window == ["--bind", "/tmp", "/tmp"])
        );
    }

    #[test]
    fn missing_unreadable_under_writable_root_is_blocked() {
        let _ = std::fs::remove_file("/tmp/af-missing-deny");
        let _ = std::fs::remove_dir_all("/tmp/af-missing-deny");
        let mut request = base_request();
        request.filesystem.mode = FilesystemMode::Restricted;
        request.filesystem.writable_roots = vec![WritableRoot {
            root: PathBuf::from("/tmp"),
            read_only_subpaths: vec![],
        }];
        request.filesystem.unreadable_roots = vec![PathBuf::from("/tmp/af-missing-deny/path")];

        let args = build_bwrap_args(&request).expect("build bwrap args");
        assert!(
            args.windows(3)
                .any(|window| window == ["--ro-bind", "/dev/null", "/tmp/af-missing-deny"])
        );
    }

    #[test]
    fn missing_read_only_subpath_under_writable_root_is_blocked() {
        let _ = std::fs::remove_file("/tmp/af-missing-ro");
        let _ = std::fs::remove_dir_all("/tmp/af-missing-ro");
        let mut request = base_request();
        request.filesystem.mode = FilesystemMode::Restricted;
        request.filesystem.writable_roots = vec![WritableRoot {
            root: PathBuf::from("/tmp"),
            read_only_subpaths: vec![PathBuf::from("/tmp/af-missing-ro/path")],
        }];

        let args = build_bwrap_args(&request).expect("build bwrap args");
        assert!(
            args.windows(3)
                .any(|window| window == ["--ro-bind", "/dev/null", "/tmp/af-missing-ro"])
        );
    }
}
