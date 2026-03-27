use af_linux_microvm::{Config as LinuxConfig, LinuxMicrovmRuntime};
use af_microvm::control::{
    ExecuteRequest, ExecuteResponse, HealthResponse, Runtime, WarmupRequest, WarmupResponse,
};
use anyhow::Result;

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct LocalRuntime {
    inner: LinuxMicrovmRuntime,
}

impl LocalRuntime {
    pub fn new(config: Config) -> Result<Self> {
        let inner = LinuxMicrovmRuntime::new(LinuxConfig {
            firecracker_path: config.firecracker_path,
            kernel_path: config.kernel_path,
            rootfs_path: config.rootfs_path,
            state_root: config.state_root,
            vcpu_count: config.vcpu_count,
            memory_mib: config.memory_mib,
            guest_vsock_port: config.guest_vsock_port,
        })?;
        Ok(Self { inner })
    }
}

impl Runtime for LocalRuntime {
    fn execute(&self, request: ExecuteRequest) -> af_microvm::Result<ExecuteResponse> {
        self.inner.execute(request)
    }

    fn warmup(&self, request: WarmupRequest) -> af_microvm::Result<WarmupResponse> {
        self.inner.warmup(request)
    }

    fn health(&self) -> af_microvm::Result<HealthResponse> {
        self.inner.health()
    }
}
