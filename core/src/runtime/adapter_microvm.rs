use af_policy::MicrovmProfile;

use crate::capability::NetEndpoint;

use super::compiler::MicrovmRuntimePlan;

pub fn compile(profile: &MicrovmProfile, allowed_network: Vec<NetEndpoint>) -> MicrovmRuntimePlan {
    MicrovmRuntimePlan {
        profile_id: profile.profile_id.clone(),
        mode: profile.mode.clone(),
        max_total: profile.max_total,
        min_idle: profile.min_idle,
        warmup_on_start: profile.warmup_on_start,
        queue_limit: profile.queue_limit,
        queue_timeout_ms: profile.queue_timeout_ms,
        snapshot_enabled: profile.snapshot_enabled,
        vcpu_count: profile.vcpu_count,
        memory_mib: profile.memory_mib,
        allowed_network,
        limits: profile.limits.clone(),
    }
}
