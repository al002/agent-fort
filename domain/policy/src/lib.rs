use std::path::PathBuf;

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
