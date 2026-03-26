use std::fs;
use std::path::{Path, PathBuf};

use af_policy::{BackendProfile, MicrovmProfile, RuntimeBackend, StaticPolicy};

use crate::{PolicyInfraError, PolicyInfraResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPolicy {
    pub policy: StaticPolicy,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StaticPolicyParser;

impl StaticPolicyParser {
    pub fn parse(&self, root: &Path) -> PolicyInfraResult<LoadedPolicy> {
        let (policy_path, relative_path) = find_policy_path(root)?;

        let raw = fs::read_to_string(&policy_path)?;
        let policy: StaticPolicy =
            serde_yaml::from_str(&raw).map_err(|error| PolicyInfraError::YamlParse {
                path: relative_path.clone(),
                message: error.to_string(),
            })?;

        validate_policy(&policy, &relative_path)?;

        Ok(LoadedPolicy { policy })
    }
}

fn find_policy_path(root: &Path) -> PolicyInfraResult<(PathBuf, String)> {
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(PolicyInfraError::DirectoryNotReadable {
                path: root.to_path_buf(),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PolicyInfraError::DirectoryNotReadable {
                path: root.to_path_buf(),
            });
        }
        Err(error) => return Err(error.into()),
    }

    let yaml = root.join("static_policy.yaml");
    if yaml.is_file() {
        return Ok((yaml, "static_policy.yaml".to_string()));
    }

    let yml = root.join("static_policy.yml");
    if yml.is_file() {
        return Ok((yml, "static_policy.yml".to_string()));
    }

    Err(PolicyInfraError::StaticPolicyMissing {
        root: root.to_path_buf(),
    })
}

fn validate_policy(policy: &StaticPolicy, path: &str) -> PolicyInfraResult<()> {
    if policy.version != 1 {
        return Err(PolicyInfraError::InvalidPolicy {
            path: path.to_string(),
            message: format!("unsupported static policy version: {}", policy.version),
        });
    }

    for backend in &policy.backends.backend_order {
        if !policy.backends.capability_limits.contains_key(backend) {
            return Err(PolicyInfraError::InvalidPolicy {
                path: path.to_string(),
                message: format!(
                    "backend `{}` missing capability_limits entry",
                    backend.as_str()
                ),
            });
        }
        if !policy.backends.profiles.contains_key(backend) {
            return Err(PolicyInfraError::InvalidPolicy {
                path: path.to_string(),
                message: format!("backend `{}` missing profile entry", backend.as_str()),
            });
        }
    }

    for (backend, profile) in &policy.backends.profiles {
        if !policy.backends.capability_limits.contains_key(backend) {
            return Err(PolicyInfraError::InvalidPolicy {
                path: path.to_string(),
                message: format!(
                    "profile backend `{}` missing capability_limits entry",
                    backend.as_str()
                ),
            });
        }
        let type_matches = matches!(
            (backend, profile),
            (RuntimeBackend::Sandbox, BackendProfile::Sandbox(_))
                | (RuntimeBackend::Microvm, BackendProfile::Microvm(_))
        );
        if !type_matches {
            return Err(PolicyInfraError::InvalidPolicy {
                path: path.to_string(),
                message: format!("profile type mismatch for backend `{}`", backend.as_str()),
            });
        }

        if let BackendProfile::Microvm(profile) = profile {
            validate_microvm_profile(profile, path)?;
        }
    }

    Ok(())
}

fn validate_microvm_profile(profile: &MicrovmProfile, path: &str) -> PolicyInfraResult<()> {
    let mode = profile.mode.trim().to_ascii_lowercase();
    if mode != "task" && mode != "resident" {
        return Err(PolicyInfraError::InvalidPolicy {
            path: path.to_string(),
            message: format!(
                "microvm profile `{}` has invalid mode `{}`",
                profile.profile_id, profile.mode
            ),
        });
    }

    if profile.max_total == 0 {
        return Err(PolicyInfraError::InvalidPolicy {
            path: path.to_string(),
            message: format!(
                "microvm profile `{}` must set max_total >= 1",
                profile.profile_id
            ),
        });
    }

    if profile.queue_limit == 0 {
        return Err(PolicyInfraError::InvalidPolicy {
            path: path.to_string(),
            message: format!(
                "microvm profile `{}` must set queue_limit >= 1",
                profile.profile_id
            ),
        });
    }

    if profile.queue_timeout_ms == 0 {
        return Err(PolicyInfraError::InvalidPolicy {
            path: path.to_string(),
            message: format!(
                "microvm profile `{}` must set queue_timeout_ms >= 1",
                profile.profile_id
            ),
        });
    }

    if profile.vcpu_count == 0 {
        return Err(PolicyInfraError::InvalidPolicy {
            path: path.to_string(),
            message: format!(
                "microvm profile `{}` must set vcpu_count >= 1",
                profile.profile_id
            ),
        });
    }

    if profile.memory_mib == 0 {
        return Err(PolicyInfraError::InvalidPolicy {
            path: path.to_string(),
            message: format!(
                "microvm profile `{}` must set memory_mib >= 1",
                profile.profile_id
            ),
        });
    }

    match mode.as_str() {
        "task" => {
            if profile.min_idle != 0 {
                return Err(PolicyInfraError::InvalidPolicy {
                    path: path.to_string(),
                    message: format!(
                        "microvm profile `{}` in task mode must set min_idle = 0",
                        profile.profile_id
                    ),
                });
            }
            if profile.snapshot_enabled {
                return Err(PolicyInfraError::InvalidPolicy {
                    path: path.to_string(),
                    message: format!(
                        "microvm profile `{}` in task mode cannot enable snapshot",
                        profile.profile_id
                    ),
                });
            }
        }
        "resident" => {
            if profile.min_idle == 0 || profile.min_idle > profile.max_total {
                return Err(PolicyInfraError::InvalidPolicy {
                    path: path.to_string(),
                    message: format!(
                        "microvm profile `{}` in resident mode requires 1 <= min_idle <= max_total",
                        profile.profile_id
                    ),
                });
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn parses_static_policy_file() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("static_policy.yaml"), valid_static_policy_yaml())
            .expect("write static policy");

        let loaded = StaticPolicyParser
            .parse(&root)
            .expect("parse static policy");

        assert_eq!(loaded.policy.version, 1);
        assert_eq!(loaded.policy.revision, 9);
    }

    #[test]
    fn rejects_missing_static_policy_file() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("extra.yaml"), "version: 1\nrules: []\n").expect("write file");

        let error = StaticPolicyParser
            .parse(&root)
            .expect_err("missing static policy should fail");

        assert!(matches!(
            error,
            PolicyInfraError::StaticPolicyMissing { .. }
        ));
    }

    fn valid_static_policy_yaml() -> &'static str {
        r#"
version: 1
revision: 9
default_action: deny
capabilities:
  fs_read: ["/work/**"]
  fs_write: ["/work/**"]
  fs_delete: ["/work/**"]
  net_connect: []
  allow_host_exec: false
  allow_process_control: false
  allow_privilege: false
  allow_credential_access: false
backends:
  backend_order: ["sandbox"]
  capability_limits:
    sandbox:
      fs_read: ["/work/**"]
      fs_write: ["/work/**"]
      fs_delete: ["/work/**"]
      net_connect: []
      allow_host_exec: false
      allow_process_control: false
      allow_privilege: false
      allow_credential_access: false
  profiles:
    sandbox:
      type: sandbox
      profile_id: "sandbox-default"
      network_default: "deny"
      writable_roots: ["/work/**"]
      readonly_roots: ["/usr/**"]
      syscall_policy: "baseline"
      limits:
        cpu_ms: 1000
        memory_mb: 128
        pids: 64
        disk_mb: 256
        timeout_ms: 60000
"#
    }

    #[test]
    fn rejects_invalid_microvm_profile_mode() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(
            root.join("static_policy.yaml"),
            microvm_policy_yaml("weird", 0, false, false),
        )
        .expect("write static policy");

        let error = StaticPolicyParser
            .parse(&root)
            .expect_err("invalid microvm mode should fail");

        assert!(matches!(error, PolicyInfraError::InvalidPolicy { .. }));
    }

    #[test]
    fn rejects_task_mode_with_min_idle() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(
            root.join("static_policy.yaml"),
            microvm_policy_yaml("task", 1, false, false),
        )
        .expect("write static policy");

        let error = StaticPolicyParser
            .parse(&root)
            .expect_err("task mode with min idle should fail");

        assert!(matches!(error, PolicyInfraError::InvalidPolicy { .. }));
    }

    #[test]
    fn parses_valid_microvm_profile() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(
            root.join("static_policy.yaml"),
            microvm_policy_yaml("resident", 1, true, true),
        )
        .expect("write static policy");

        let loaded = StaticPolicyParser
            .parse(&root)
            .expect("parse static policy");

        assert_eq!(
            loaded.policy.backends.backend_order,
            vec![RuntimeBackend::Microvm]
        );
    }

    fn microvm_policy_yaml(
        mode: &str,
        min_idle: u32,
        warmup_on_start: bool,
        snapshot_enabled: bool,
    ) -> String {
        format!(
            r#"
version: 1
revision: 9
default_action: deny
capabilities:
  fs_read: ["/work/**"]
  fs_write: ["/work/**"]
  fs_delete: ["/work/**"]
  net_connect: []
  allow_host_exec: false
  allow_process_control: false
  allow_privilege: false
  allow_credential_access: false
backends:
  backend_order: ["microvm"]
  capability_limits:
    microvm:
      fs_read: ["/work/**"]
      fs_write: []
      fs_delete: []
      net_connect: []
      allow_host_exec: false
      allow_process_control: false
      allow_privilege: false
      allow_credential_access: false
  profiles:
    microvm:
      type: microvm
      profile_id: "microvm-default"
      mode: "{mode}"
      max_total: 1
      min_idle: {min_idle}
      warmup_on_start: {warmup_on_start}
      queue_limit: 16
      queue_timeout_ms: 30000
      snapshot_enabled: {snapshot_enabled}
      vcpu_count: 1
      memory_mib: 256
      limits:
        cpu_ms: 1000
        memory_mb: 256
        pids: 64
        disk_mb: 256
        timeout_ms: 60000
"#
        )
    }
}
