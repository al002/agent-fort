use std::path::PathBuf;

pub mod capability;

pub use capability::{
    BackendCapabilityLimits, BackendPolicy, BackendProfile, BackendResourceLimits, CapabilitySet,
    ContainerProfile, DefaultAction, MicrovmProfile, NetRule, RuntimeBackend, SandboxProfile,
    SessionGrant, StaticPolicy,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFile {
    pub absolute_path: PathBuf,
    pub relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDirectorySnapshot {
    pub root: PathBuf,
    pub files: Vec<PolicyFile>,
}

impl PolicyDirectorySnapshot {
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyReloadReason {
    FilesystemChange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReloadRequest {
    pub root: PathBuf,
    pub reason: PolicyReloadReason,
}
