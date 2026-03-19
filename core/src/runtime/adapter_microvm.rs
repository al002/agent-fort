use af_policy::MicrovmProfile;

use crate::capability::NetEndpoint;

use super::compiler::MicrovmRuntimePlan;

pub fn compile(profile: &MicrovmProfile, allowed_network: Vec<NetEndpoint>) -> MicrovmRuntimePlan {
    MicrovmRuntimePlan {
        profile_id: profile.profile_id.clone(),
        snapshot_enabled: profile.snapshot_enabled,
        vsock_policy: profile.vsock_policy.clone(),
        allowed_shares: profile.allowed_shares.clone(),
        allowed_network,
        network_mode: profile.network_mode.clone(),
        limits: profile.limits.clone(),
    }
}
