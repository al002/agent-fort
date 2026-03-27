use std::fs;
use std::path::{Path, PathBuf};

use af_microvm::control::{
    ErrorCode, ExecError, ExecuteRequest, ExecuteResponse, HealthResponse, Runtime, WarmupRequest,
    WarmupResponse,
};
use anyhow::Result;

use crate::layout::StateLayout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub firecracker_path: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub state_root: PathBuf,
    pub vcpu_count: u8,
    pub memory_mib: u32,
    pub guest_vsock_port: u32,
}

#[derive(Debug, Clone)]
pub struct LinuxMicrovmRuntime {
    config: Config,
    layout: StateLayout,
}

impl LinuxMicrovmRuntime {
    pub fn new(config: Config) -> Result<Self> {
        fs::create_dir_all(&config.state_root)?;

        let layout = StateLayout::new(config.state_root.clone());
        fs::create_dir_all(layout.instances_dir())?;
        fs::create_dir_all(layout.sockets_dir())?;
        fs::create_dir_all(layout.logs_dir())?;

        Ok(Self { config, layout })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn layout(&self) -> &StateLayout {
        &self.layout
    }

    fn check(&self) -> Result<()> {
        ensure_file(&self.config.firecracker_path)?;
        ensure_file(&self.config.kernel_path)?;
        ensure_file(&self.config.rootfs_path)?;
        ensure_dir(self.layout.root())?;
        ensure_dir(&self.layout.instances_dir())?;
        ensure_dir(&self.layout.sockets_dir())?;
        ensure_dir(&self.layout.logs_dir())?;
        Ok(())
    }
}

impl Runtime for LinuxMicrovmRuntime {
    fn execute(&self, _request: ExecuteRequest) -> af_microvm::Result<ExecuteResponse> {
        self.check()
            .map_err(|error| af_microvm::Error::Invalid(error.to_string()))?;

        Ok(ExecuteResponse::err(ExecError {
            code: ErrorCode::BackendUnavailable,
            message: "linux microvm execute path is not implemented yet".to_string(),
        }))
    }

    fn warmup(&self, _request: WarmupRequest) -> af_microvm::Result<WarmupResponse> {
        self.check()
            .map_err(|error| af_microvm::Error::Invalid(error.to_string()))?;

        Ok(WarmupResponse::err(ExecError {
            code: ErrorCode::BackendUnavailable,
            message: "linux microvm warmup path is not implemented yet".to_string(),
        }))
    }

    fn health(&self) -> af_microvm::Result<HealthResponse> {
        match self.check() {
            Ok(()) => Ok(HealthResponse::ok()),
            Err(error) => Ok(HealthResponse::err(
                "backend_unavailable",
                error.to_string(),
            )),
        }
    }
}

fn ensure_file(path: &Path) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    anyhow::bail!("file not found: {}", path.display())
}

fn ensure_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    anyhow::bail!("directory not found: {}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_state_layout_dirs() {
        let root =
            std::env::temp_dir().join(format!("af-linux-microvm-test-{}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root).expect("cleanup old temp dir");
        }

        let runtime = LinuxMicrovmRuntime::new(Config {
            firecracker_path: PathBuf::from("/bin/false"),
            kernel_path: PathBuf::from("/bin/false"),
            rootfs_path: PathBuf::from("/bin/false"),
            state_root: root.clone(),
            vcpu_count: 1,
            memory_mib: 512,
            guest_vsock_port: 10_000,
        })
        .expect("create runtime");

        assert!(runtime.layout().instances_dir().is_dir());
        assert!(runtime.layout().sockets_dir().is_dir());
        assert!(runtime.layout().logs_dir().is_dir());

        std::fs::remove_dir_all(root).expect("cleanup temp dir");
    }
}
