use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedOperation {
    pub kind: OperationKind,
    pub payload: Value,
    pub options: Value,
    pub labels: BTreeMap<String, String>,
    pub command: Option<NormalizedCommand>,
    pub cwd: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
    pub paths: Vec<PathBuf>,
    pub hosts: Vec<String>,
    pub reason_codes: Vec<String>,
    pub unknown: bool,
    pub runtime: RuntimeContext,
}

impl NormalizedOperation {
    pub fn operation_kind(&self) -> &'static str {
        self.kind.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizedCommand {
    Shell(String),
    Argv(Vec<String>),
}

impl NormalizedCommand {
    pub fn as_shell_text(&self) -> Option<&str> {
        match self {
            Self::Shell(command) => Some(command.as_str()),
            Self::Argv(_) => None,
        }
    }

    pub fn argv(&self) -> Option<&[String]> {
        match self {
            Self::Argv(argv) => Some(argv.as_slice()),
            Self::Shell(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    Exec,
    FsRead,
    FsWrite,
    Net,
    Tool,
    Unknown,
}

impl OperationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::FsRead => "fs.read",
            Self::FsWrite => "fs.write",
            Self::Net => "net",
            Self::Tool => "tool",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_kind_has_stable_policy_key() {
        assert_eq!(OperationKind::Exec.as_str(), "exec");
        assert_eq!(OperationKind::FsRead.as_str(), "fs.read");
        assert_eq!(OperationKind::FsWrite.as_str(), "fs.write");
        assert_eq!(OperationKind::Net.as_str(), "net");
        assert_eq!(OperationKind::Tool.as_str(), "tool");
        assert_eq!(OperationKind::Unknown.as_str(), "unknown");
    }
}
