use std::fs;

use af_policy::{BackendProfile, PolicyDirectorySnapshot, RuntimeBackend, StaticPolicyDocument};

use crate::{PolicyInfraError, PolicyInfraResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedStaticPolicy {
    pub snapshot: PolicyDirectorySnapshot,
    pub document: StaticPolicyDocument,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct YamlParser;

impl YamlParser {
    pub fn parse_static_policy(
        &self,
        snapshot: PolicyDirectorySnapshot,
    ) -> PolicyInfraResult<LoadedStaticPolicy> {
        let policy_file = snapshot
            .files
            .iter()
            .find(|file| {
                file.relative_path
                    .eq_ignore_ascii_case("static_policy.yaml")
                    || file.relative_path.eq_ignore_ascii_case("static_policy.yml")
            })
            .ok_or_else(|| PolicyInfraError::StaticPolicyMissing {
                root: snapshot.root.clone(),
            })?;

        let raw = fs::read_to_string(&policy_file.absolute_path)?;
        let document: StaticPolicyDocument =
            serde_yaml::from_str(&raw).map_err(|error| PolicyInfraError::YamlParse {
                path: policy_file.relative_path.clone(),
                message: error.to_string(),
            })?;

        validate_static_policy(&document, &policy_file.relative_path)?;

        Ok(LoadedStaticPolicy { snapshot, document })
    }
}

fn validate_static_policy(document: &StaticPolicyDocument, path: &str) -> PolicyInfraResult<()> {
    if document.version != 1 {
        return Err(PolicyInfraError::InvalidDocument {
            path: path.to_string(),
            message: format!("unsupported static policy version: {}", document.version),
        });
    }

    for backend in &document.backends.backend_order {
        if !document.backends.capability_matrix.contains_key(backend) {
            return Err(PolicyInfraError::InvalidDocument {
                path: path.to_string(),
                message: format!(
                    "backend `{}` missing capability_matrix entry",
                    backend.as_str()
                ),
            });
        }
        if !document.backends.profiles.contains_key(backend) {
            return Err(PolicyInfraError::InvalidDocument {
                path: path.to_string(),
                message: format!("backend `{}` missing profile entry", backend.as_str()),
            });
        }
    }

    for (backend, profile) in &document.backends.profiles {
        if !document.backends.capability_matrix.contains_key(backend) {
            return Err(PolicyInfraError::InvalidDocument {
                path: path.to_string(),
                message: format!(
                    "profile backend `{}` missing capability_matrix entry",
                    backend.as_str()
                ),
            });
        }
        let type_matches = matches!(
            (backend, profile),
            (RuntimeBackend::Sandbox, BackendProfile::Sandbox(_))
                | (RuntimeBackend::Container, BackendProfile::Container(_))
                | (RuntimeBackend::Microvm, BackendProfile::Microvm(_))
        );
        if !type_matches {
            return Err(PolicyInfraError::InvalidDocument {
                path: path.to_string(),
                message: format!("profile type mismatch for backend `{}`", backend.as_str()),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use crate::PolicyDirectoryLoader;

    use super::*;

    #[test]
    fn parses_static_policy_file() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("static_policy.yaml"), valid_static_policy_yaml())
            .expect("write static policy");

        let snapshot = PolicyDirectoryLoader::new(&root)
            .load()
            .expect("load directory snapshot");
        let loaded = YamlParser
            .parse_static_policy(snapshot)
            .expect("parse static policy");

        assert_eq!(loaded.document.version, 1);
        assert_eq!(loaded.document.revision, 9);
        assert_eq!(loaded.snapshot.file_count(), 1);
    }

    #[test]
    fn rejects_missing_static_policy_file() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(&root).expect("create policy dir");
        fs::write(root.join("extra.yaml"), "version: 1\nrules: []\n").expect("write file");

        let snapshot = PolicyDirectoryLoader::new(&root)
            .load()
            .expect("load directory snapshot");
        let error = YamlParser
            .parse_static_policy(snapshot)
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
  capability_matrix:
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
}
