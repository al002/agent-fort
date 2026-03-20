use af_policy::{RuntimeBackend, StaticPolicy};
use thiserror::Error;

use crate::capability::{RequestedCapabilities, requested_within_backend_limits};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedBackend {
    pub backend: RuntimeBackend,
    pub profile_id: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendSelectionError {
    #[error("backend `{backend}` missing capability_limits entry")]
    MissingCapabilityLimits { backend: String },
    #[error("backend `{backend}` profile is missing")]
    MissingProfile { backend: String },
    #[error("no runtime backend satisfies requested capabilities")]
    NoCandidate,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BackendSelector;

impl BackendSelector {
    pub fn select(
        &self,
        requested: &RequestedCapabilities,
        policy: &StaticPolicy,
    ) -> Result<SelectedBackend, BackendSelectionError> {
        for backend in &policy.backends.backend_order {
            let Some(limits) = policy.backends.capability_limits.get(backend) else {
                return Err(BackendSelectionError::MissingCapabilityLimits {
                    backend: backend.as_str().to_string(),
                });
            };
            let Some(profile) = policy.backends.profiles.get(backend) else {
                return Err(BackendSelectionError::MissingProfile {
                    backend: backend.as_str().to_string(),
                });
            };

            if requested_within_backend_limits(requested, limits) {
                return Ok(SelectedBackend {
                    backend: *backend,
                    profile_id: profile.profile_id().to_string(),
                });
            }
        }

        Err(BackendSelectionError::NoCandidate)
    }
}

#[cfg(test)]
mod tests {
    use af_policy::{
        BackendCapabilityLimits, BackendPolicy, BackendProfile, BackendResourceLimits,
        CapabilitySet, DefaultAction, RuntimeBackend, SandboxProfile, StaticPolicy,
    };

    use super::*;

    fn policy_fixture() -> StaticPolicy {
        StaticPolicy {
            version: 1,
            revision: 1,
            default_action: DefaultAction::Deny,
            capabilities: CapabilitySet {
                fs_read: vec!["/work/**".to_string()],
                fs_write: vec!["/work/**".to_string()],
                fs_delete: vec!["/work/**".to_string()],
                net_connect: Vec::new(),
                allow_host_exec: false,
                allow_process_control: false,
                allow_privilege: false,
                allow_credential_access: false,
            },
            backends: BackendPolicy {
                backend_order: vec![RuntimeBackend::Sandbox],
                capability_limits: [(
                    RuntimeBackend::Sandbox,
                    BackendCapabilityLimits {
                        fs_read: vec!["/work/**".to_string()],
                        fs_write: vec!["/work/**".to_string()],
                        fs_delete: vec!["/work/**".to_string()],
                        net_connect: Vec::new(),
                        allow_host_exec: false,
                        allow_process_control: false,
                        allow_privilege: false,
                        allow_credential_access: false,
                    },
                )]
                .into_iter()
                .collect(),
                profiles: [(
                    RuntimeBackend::Sandbox,
                    BackendProfile::Sandbox(SandboxProfile {
                        profile_id: "sandbox-default".to_string(),
                        network_default: "deny".to_string(),
                        writable_roots: vec!["/work/**".to_string()],
                        readonly_roots: vec!["/usr/**".to_string()],
                        syscall_policy: "baseline".to_string(),
                        limits: BackendResourceLimits {
                            cpu_ms: 1000,
                            memory_mb: 256,
                            pids: 64,
                            disk_mb: 128,
                            timeout_ms: 60_000,
                        },
                    }),
                )]
                .into_iter()
                .collect(),
            },
        }
    }

    #[test]
    fn selects_first_matching_backend() {
        let requested = RequestedCapabilities {
            fs_write: [std::path::PathBuf::from("/work/a.txt")]
                .into_iter()
                .collect(),
            ..RequestedCapabilities::default()
        };

        let selected = BackendSelector
            .select(&requested, &policy_fixture())
            .expect("select backend");

        assert_eq!(selected.backend, RuntimeBackend::Sandbox);
        assert_eq!(selected.profile_id, "sandbox-default");
    }
}
