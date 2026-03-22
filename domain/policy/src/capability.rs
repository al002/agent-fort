use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    #[serde(default)]
    pub fs_read: Vec<String>,
    #[serde(default)]
    pub fs_write: Vec<String>,
    #[serde(default)]
    pub fs_delete: Vec<String>,
    #[serde(default)]
    pub net_connect: Vec<NetRule>,
    #[serde(default)]
    pub allow_host_exec: bool,
    #[serde(default)]
    pub allow_process_control: bool,
    #[serde(default)]
    pub allow_privilege: bool,
    #[serde(default)]
    pub allow_credential_access: bool,
}

impl CapabilitySet {
    pub fn empty() -> Self {
        Self {
            fs_read: Vec::new(),
            fs_write: Vec::new(),
            fs_delete: Vec::new(),
            net_connect: Vec::new(),
            allow_host_exec: false,
            allow_process_control: false,
            allow_privilege: false,
            allow_credential_access: false,
        }
    }
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendPolicy {
    #[serde(default)]
    pub backend_order: Vec<RuntimeBackend>,
    #[serde(default)]
    pub capability_limits: BTreeMap<RuntimeBackend, BackendCapabilityLimits>,
    #[serde(default)]
    pub profiles: BTreeMap<RuntimeBackend, BackendProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilityLimits {
    #[serde(default)]
    pub fs_read: Vec<String>,
    #[serde(default)]
    pub fs_write: Vec<String>,
    #[serde(default)]
    pub fs_delete: Vec<String>,
    #[serde(default)]
    pub net_connect: Vec<NetRule>,
    #[serde(default)]
    pub allow_host_exec: bool,
    #[serde(default)]
    pub allow_process_control: bool,
    #[serde(default)]
    pub allow_privilege: bool,
    #[serde(default)]
    pub allow_credential_access: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBackend {
    Sandbox,
    Microvm,
}

impl RuntimeBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::Microvm => "microvm",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendResourceLimits {
    pub cpu_ms: u64,
    pub memory_mb: u64,
    pub pids: u32,
    pub disk_mb: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendProfile {
    Sandbox(SandboxProfile),
    Microvm(MicrovmProfile),
}

impl BackendProfile {
    pub fn profile_id(&self) -> &str {
        match self {
            Self::Sandbox(profile) => &profile.profile_id,
            Self::Microvm(profile) => &profile.profile_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProfile {
    pub profile_id: String,
    pub network_default: String,
    #[serde(default)]
    pub writable_roots: Vec<String>,
    #[serde(default)]
    pub readonly_roots: Vec<String>,
    pub syscall_policy: String,
    pub limits: BackendResourceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrovmProfile {
    pub profile_id: String,
    pub snapshot_enabled: bool,
    pub vsock_policy: String,
    #[serde(default)]
    pub allowed_shares: Vec<String>,
    pub network_mode: String,
    pub limits: BackendResourceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NetRule {
    pub host: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Deny,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticPolicy {
    pub version: u32,
    pub revision: u64,
    pub default_action: DefaultAction,
    pub capabilities: CapabilitySet,
    pub backends: BackendPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrant {
    pub session_id: String,
    pub revision: u64,
    pub expires_at_unix_ms: Option<i64>,
    pub capabilities: CapabilitySet,
}
