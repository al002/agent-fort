use af_policy::ContainerProfile;

use crate::capability::NetEndpoint;

use super::compiler::ContainerRuntimePlan;

pub fn compile(
    profile: &ContainerProfile,
    allowed_network: Vec<NetEndpoint>,
) -> ContainerRuntimePlan {
    ContainerRuntimePlan {
        profile_id: profile.profile_id.clone(),
        rootless: profile.rootless,
        drop_linux_capabilities: profile.drop_linux_capabilities.clone(),
        seccomp_profile: profile.seccomp_profile.clone(),
        readonly_rootfs: profile.readonly_rootfs,
        allowed_volumes: profile.allowed_volumes.clone(),
        allowed_network,
        network_mode: profile.network_mode.clone(),
        limits: profile.limits.clone(),
    }
}
