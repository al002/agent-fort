use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLayout {
    root: PathBuf,
}

impl StateLayout {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn instances_dir(&self) -> PathBuf {
        self.root.join("instances")
    }

    pub fn sockets_dir(&self) -> PathBuf {
        self.root.join("sockets")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn vm(&self, vm_id: &str) -> VmLayout {
        VmLayout::new(self.instances_dir().join(vm_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLayout {
    root: PathBuf,
}

impl VmLayout {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn api_socket(&self) -> PathBuf {
        self.root.join("firecracker.sock")
    }

    pub fn log_fifo(&self) -> PathBuf {
        self.root.join("firecracker.log")
    }

    pub fn metrics_fifo(&self) -> PathBuf {
        self.root.join("firecracker.metrics")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_state_layout() {
        let layout = StateLayout::new(PathBuf::from("/var/lib/agent-fort/microvmd"));
        assert_eq!(
            layout.instances_dir(),
            PathBuf::from("/var/lib/agent-fort/microvmd/instances")
        );
        assert_eq!(
            layout.sockets_dir(),
            PathBuf::from("/var/lib/agent-fort/microvmd/sockets")
        );
    }

    #[test]
    fn builds_vm_layout() {
        let vm = StateLayout::new(PathBuf::from("/state")).vm("vm-1");
        assert_eq!(
            vm.api_socket(),
            PathBuf::from("/state/instances/vm-1/firecracker.sock")
        );
        assert_eq!(
            vm.log_fifo(),
            PathBuf::from("/state/instances/vm-1/firecracker.log")
        );
    }
}
