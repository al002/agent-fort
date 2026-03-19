use af_policy::{BackendProfile, BackendResourceLimits, RuntimeBackend, StaticPolicyDocument};
use thiserror::Error;

use crate::capability::{NetEndpoint, RequestedCapabilities};

use super::backend_selector::SelectedBackend;
use super::{adapter_container, adapter_microvm, adapter_sandbox};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeExecPlan {
    Sandbox(SandboxRuntimePlan),
    Container(ContainerRuntimePlan),
    Microvm(MicrovmRuntimePlan),
}

impl RuntimeExecPlan {
    pub fn backend(&self) -> RuntimeBackend {
        match self {
            Self::Sandbox(_) => RuntimeBackend::Sandbox,
            Self::Container(_) => RuntimeBackend::Container,
            Self::Microvm(_) => RuntimeBackend::Microvm,
        }
    }

    pub fn profile_id(&self) -> &str {
        match self {
            Self::Sandbox(plan) => plan.profile_id.as_str(),
            Self::Container(plan) => plan.profile_id.as_str(),
            Self::Microvm(plan) => plan.profile_id.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxRuntimePlan {
    pub profile_id: String,
    pub writable_roots: Vec<String>,
    pub readonly_roots: Vec<String>,
    pub allowed_network: Vec<NetEndpoint>,
    pub syscall_policy: String,
    pub network_mode: String,
    pub limits: BackendResourceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRuntimePlan {
    pub profile_id: String,
    pub rootless: bool,
    pub drop_linux_capabilities: Vec<String>,
    pub seccomp_profile: String,
    pub readonly_rootfs: bool,
    pub allowed_volumes: Vec<String>,
    pub allowed_network: Vec<NetEndpoint>,
    pub network_mode: String,
    pub limits: BackendResourceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrovmRuntimePlan {
    pub profile_id: String,
    pub snapshot_enabled: bool,
    pub vsock_policy: String,
    pub allowed_shares: Vec<String>,
    pub allowed_network: Vec<NetEndpoint>,
    pub network_mode: String,
    pub limits: BackendResourceLimits,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeCompileError {
    #[error("backend profile missing for `{backend}`")]
    MissingProfile { backend: String },
    #[error("selected profile id mismatch: expected `{expected}`, got `{actual}`")]
    ProfileIdMismatch { expected: String, actual: String },
    #[error("backend profile type mismatch for `{backend}`")]
    ProfileTypeMismatch { backend: String },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeCompiler;

impl RuntimeCompiler {
    pub fn compile(
        &self,
        selected: &SelectedBackend,
        effective_caps: &RequestedCapabilities,
        static_policy: &StaticPolicyDocument,
    ) -> Result<RuntimeExecPlan, RuntimeCompileError> {
        let Some(profile) = static_policy.backends.profiles.get(&selected.backend) else {
            return Err(RuntimeCompileError::MissingProfile {
                backend: selected.backend.as_str().to_string(),
            });
        };

        let profile_id = profile.profile_id().to_string();
        if profile_id != selected.profile_id {
            return Err(RuntimeCompileError::ProfileIdMismatch {
                expected: selected.profile_id.clone(),
                actual: profile_id,
            });
        }

        let mut allowed_network = effective_caps
            .net_connect
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        allowed_network.sort();

        match (selected.backend, profile) {
            (RuntimeBackend::Sandbox, BackendProfile::Sandbox(profile)) => Ok(
                RuntimeExecPlan::Sandbox(adapter_sandbox::compile(profile, allowed_network)),
            ),
            (RuntimeBackend::Container, BackendProfile::Container(profile)) => Ok(
                RuntimeExecPlan::Container(adapter_container::compile(profile, allowed_network)),
            ),
            (RuntimeBackend::Microvm, BackendProfile::Microvm(profile)) => Ok(
                RuntimeExecPlan::Microvm(adapter_microvm::compile(profile, allowed_network)),
            ),
            _ => Err(RuntimeCompileError::ProfileTypeMismatch {
                backend: selected.backend.as_str().to_string(),
            }),
        }
    }
}
