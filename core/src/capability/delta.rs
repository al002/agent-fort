use std::path::PathBuf;

use af_policy::{CapabilitySet, NetRule};

use super::matcher::{endpoint_matches_any, path_matches_any};
use super::{NetEndpoint, RequestedCapabilities};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilityDelta {
    pub fs_read: Vec<PathBuf>,
    pub fs_write: Vec<PathBuf>,
    pub fs_delete: Vec<PathBuf>,
    pub net_connect: Vec<NetEndpoint>,
    pub host_exec: bool,
    pub process_control: bool,
    pub privilege: bool,
    pub credential_access: bool,
}

impl CapabilityDelta {
    pub fn is_empty(&self) -> bool {
        self.fs_read.is_empty()
            && self.fs_write.is_empty()
            && self.fs_delete.is_empty()
            && self.net_connect.is_empty()
            && !self.host_exec
            && !self.process_control
            && !self.privilege
            && !self.credential_access
    }
}

pub fn diff_requested_vs_session_grant(
    requested: &RequestedCapabilities,
    session_grant: &CapabilitySet,
) -> CapabilityDelta {
    let mut delta = CapabilityDelta::default();

    for path in &requested.fs_read {
        if !path_matches_any(path, &session_grant.fs_read) {
            delta.fs_read.push(path.clone());
        }
    }
    for path in &requested.fs_write {
        if !path_matches_any(path, &session_grant.fs_write) {
            delta.fs_write.push(path.clone());
        }
    }
    for path in &requested.fs_delete {
        if !path_matches_any(path, &session_grant.fs_delete) {
            delta.fs_delete.push(path.clone());
        }
    }
    for endpoint in &requested.net_connect {
        if !endpoint_matches_any(endpoint, &session_grant.net_connect) {
            delta.net_connect.push(endpoint.clone());
        }
    }

    delta.host_exec = requested.host_exec && !session_grant.allow_host_exec;
    delta.process_control = requested.process_control && !session_grant.allow_process_control;
    delta.privilege = requested.privilege && !session_grant.allow_privilege;
    delta.credential_access = requested.credential_access && !session_grant.allow_credential_access;

    delta
}

pub fn apply_delta_to_capability_set(
    session_grant: &CapabilitySet,
    delta: &CapabilityDelta,
) -> CapabilitySet {
    let mut next = session_grant.clone();

    for path in &delta.fs_read {
        next.fs_read.push(path.display().to_string());
    }
    for path in &delta.fs_write {
        next.fs_write.push(path.display().to_string());
    }
    for path in &delta.fs_delete {
        next.fs_delete.push(path.display().to_string());
    }
    for endpoint in &delta.net_connect {
        next.net_connect.push(NetRule {
            host: endpoint.host.clone(),
            port: endpoint.port,
            protocol: endpoint.protocol.clone(),
        });
    }

    next.allow_host_exec |= delta.host_exec;
    next.allow_process_control |= delta.process_control;
    next.allow_privilege |= delta.privilege;
    next.allow_credential_access |= delta.credential_access;

    sort_and_dedup(&mut next.fs_read);
    sort_and_dedup(&mut next.fs_write);
    sort_and_dedup(&mut next.fs_delete);
    next.net_connect.sort_by(|left, right| {
        left.host
            .cmp(&right.host)
            .then_with(|| left.port.cmp(&right.port))
            .then_with(|| left.protocol.cmp(&right.protocol))
    });
    next.net_connect.dedup();

    next
}

fn sort_and_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_delta_for_ungranted_write_and_network() {
        let requested = RequestedCapabilities {
            fs_write: [PathBuf::from("/work/new.txt")].into_iter().collect(),
            net_connect: [NetEndpoint::new(
                "example.com",
                Some(443),
                Some("https".to_string()),
            )]
            .into_iter()
            .collect(),
            ..RequestedCapabilities::default()
        };

        let grant = CapabilitySet {
            fs_read: vec!["/work/**".to_string()],
            fs_write: vec!["/work/existing/**".to_string()],
            fs_delete: Vec::new(),
            net_connect: Vec::new(),
            allow_host_exec: false,
            allow_process_control: false,
            allow_privilege: false,
            allow_credential_access: false,
        };

        let delta = diff_requested_vs_session_grant(&requested, &grant);
        assert_eq!(delta.fs_write, vec![PathBuf::from("/work/new.txt")]);
        assert_eq!(delta.net_connect.len(), 1);
    }
}
