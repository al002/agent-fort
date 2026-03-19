use af_policy::SandboxProfile;

use crate::capability::NetEndpoint;

use super::compiler::SandboxRuntimePlan;

pub fn compile(profile: &SandboxProfile, allowed_network: Vec<NetEndpoint>) -> SandboxRuntimePlan {
    SandboxRuntimePlan {
        profile_id: profile.profile_id.clone(),
        writable_roots: profile.writable_roots.clone(),
        readonly_roots: profile.readonly_roots.clone(),
        allowed_network,
        syscall_policy: profile.syscall_policy.clone(),
        network_mode: profile.network_default.clone(),
        limits: profile.limits.clone(),
    }
}
