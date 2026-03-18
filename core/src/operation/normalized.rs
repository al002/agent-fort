use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedOperation {
    pub intent: Intent,
    pub facts: Facts,
    pub runtime: RuntimeContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub kind: OperationKind,
    pub labels: BTreeMap<String, String>,
    pub tags: BTreeSet<String>,
    pub targets: Vec<Target>,
}

impl Intent {
    pub fn operation_kind(&self) -> &'static str {
        self.kind.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    Exec,
    FileRead,
    FileWrite,
    FilePatch,
    Fetch,
    ToolCall,
    Unknown,
}

impl OperationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::FileRead => "file.read",
            Self::FileWrite => "file.write",
            Self::FilePatch => "file.patch",
            Self::Fetch => "fetch",
            Self::ToolCall => "tool.call",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for OperationKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub kind: TargetKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TargetKind {
    Path,
    Host,
    Tool,
    Other,
}

impl TargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Host => "host",
            Self::Tool => "tool",
            Self::Other => "other",
        }
    }
}

impl std::fmt::Display for TargetKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub interactive: Fact<bool>,
    pub requires_network: Fact<bool>,
    pub requires_write: Fact<bool>,
    pub touches_policy_dir: Fact<bool>,
    pub primary_host: Fact<String>,
    pub affected_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeContext {
    pub platform: RuntimePlatform,
    pub daemon_instance_id: String,
    pub policy_dir: PathBuf,
    pub workspace_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePlatform {
    Linux,
    Macos,
    Windows,
    Unknown,
}

impl RuntimePlatform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for RuntimePlatform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fact<T> {
    Known(T),
    Unknown,
}

impl<T> Fact<T> {
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    pub fn as_ref(&self) -> Fact<&T> {
        match self {
            Self::Known(value) => Fact::Known(value),
            Self::Unknown => Fact::Unknown,
        }
    }
}

impl<T> Default for Fact<T> {
    fn default() -> Self {
        Self::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_kind_has_stable_policy_key() {
        assert_eq!(OperationKind::Exec.as_str(), "exec");
        assert_eq!(OperationKind::FileRead.as_str(), "file.read");
        assert_eq!(OperationKind::FileWrite.as_str(), "file.write");
        assert_eq!(OperationKind::FilePatch.as_str(), "file.patch");
        assert_eq!(OperationKind::Fetch.as_str(), "fetch");
        assert_eq!(OperationKind::ToolCall.as_str(), "tool.call");
        assert_eq!(OperationKind::Unknown.as_str(), "unknown");
    }

    #[test]
    fn fact_default_is_unknown() {
        let value = Fact::<bool>::default();
        assert!(value.is_unknown());
    }
}
