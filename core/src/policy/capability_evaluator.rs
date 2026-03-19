use af_policy::{CapabilitySet, StaticPolicyDocument};

use crate::capability::{
    RequestedCapabilities, apply_delta_to_capability_set, diff_requested_vs_session_grant,
    subset_capability_set_within_static, subset_requested_vs_capabilities,
};

use super::CapabilityDecision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluationMode {
    pub interactive: bool,
}

impl EvaluationMode {
    pub const INTERACTIVE: Self = Self { interactive: true };
    pub const NON_INTERACTIVE: Self = Self { interactive: false };
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CapabilityPolicyEvaluator;

impl CapabilityPolicyEvaluator {
    pub fn decide(
        &self,
        requested: &RequestedCapabilities,
        session_grant: &CapabilitySet,
        static_policy: &StaticPolicyDocument,
        mode: EvaluationMode,
    ) -> CapabilityDecision {
        if !subset_capability_set_within_static(session_grant, &static_policy.capabilities) {
            return CapabilityDecision::Forbid {
                reason: "session_grant exceeds static_policy".to_string(),
            };
        }

        if requested.unknown {
            let _ = mode;
            let delta = diff_requested_vs_session_grant(requested, session_grant);
            return CapabilityDecision::Ask {
                delta,
                reason: "unknown capability".to_string(),
            };
        }

        if subset_requested_vs_capabilities(requested, session_grant) {
            return CapabilityDecision::Allow;
        }

        let delta = diff_requested_vs_session_grant(requested, session_grant);
        let expanded_grant = apply_delta_to_capability_set(session_grant, &delta);
        if subset_capability_set_within_static(&expanded_grant, &static_policy.capabilities) {
            return CapabilityDecision::Ask {
                delta,
                reason: "capability escalation required".to_string(),
            };
        }

        CapabilityDecision::Deny {
            reason: "requested capability exceeds static_policy".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use af_policy::{
        BackendCapabilitySet, BackendProfile, BackendResourceLimits, BackendStaticPolicy,
        CapabilitySet, DefaultAction, RuntimeBackend, SandboxProfile, StaticPolicyDocument,
    };

    use super::*;

    fn static_policy() -> StaticPolicyDocument {
        StaticPolicyDocument {
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
            backends: BackendStaticPolicy {
                backend_order: vec![RuntimeBackend::Sandbox],
                capability_matrix: [(
                    RuntimeBackend::Sandbox,
                    BackendCapabilitySet {
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
                            memory_mb: 128,
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
    fn allows_when_requested_subset_of_session_grant() {
        let requested = RequestedCapabilities {
            fs_write: [PathBuf::from("/work/a.txt")].into_iter().collect(),
            ..RequestedCapabilities::default()
        };
        let grant = CapabilitySet {
            fs_read: vec!["/work/**".to_string()],
            fs_write: vec!["/work/**".to_string()],
            fs_delete: vec!["/work/**".to_string()],
            net_connect: Vec::new(),
            allow_host_exec: false,
            allow_process_control: false,
            allow_privilege: false,
            allow_credential_access: false,
        };

        let decision = CapabilityPolicyEvaluator.decide(
            &requested,
            &grant,
            &static_policy(),
            EvaluationMode::INTERACTIVE,
        );

        assert_eq!(decision, CapabilityDecision::Allow);
    }

    #[test]
    fn asks_when_unknown_in_interactive_mode() {
        let requested = RequestedCapabilities {
            unknown: true,
            ..RequestedCapabilities::default()
        };
        let grant = CapabilitySet::default();

        let decision = CapabilityPolicyEvaluator.decide(
            &requested,
            &grant,
            &static_policy(),
            EvaluationMode::INTERACTIVE,
        );

        assert!(matches!(decision, CapabilityDecision::Ask { .. }));
    }

    #[test]
    fn asks_when_unknown_delta_exceeds_static_policy() {
        let requested = RequestedCapabilities {
            fs_read: [PathBuf::from("/outside/secret.txt")].into_iter().collect(),
            unknown: true,
            ..RequestedCapabilities::default()
        };
        let grant = CapabilitySet::default();

        let decision = CapabilityPolicyEvaluator.decide(
            &requested,
            &grant,
            &static_policy(),
            EvaluationMode::INTERACTIVE,
        );

        assert!(matches!(decision, CapabilityDecision::Ask { .. }));
    }

    #[test]
    fn asks_when_unknown_in_non_interactive_mode() {
        let requested = RequestedCapabilities {
            unknown: true,
            ..RequestedCapabilities::default()
        };

        let decision = CapabilityPolicyEvaluator.decide(
            &requested,
            &CapabilitySet::default(),
            &static_policy(),
            EvaluationMode::NON_INTERACTIVE,
        );

        assert!(matches!(decision, CapabilityDecision::Ask { .. }));
    }
}
