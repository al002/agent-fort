use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestedCapabilities {
    pub fs_read: BTreeSet<PathBuf>,
    pub fs_write: BTreeSet<PathBuf>,
    pub fs_delete: BTreeSet<PathBuf>,
    pub net_connect: BTreeSet<NetEndpoint>,
    pub host_exec: bool,
    pub process_control: bool,
    pub privilege: bool,
    pub credential_access: bool,
    pub unknown: bool,
    pub reason_codes: Vec<String>,
    pub matched_rules: Vec<String>,
    pub risk_tags: Vec<String>,
}

impl RequestedCapabilities {
    pub fn merge(&mut self, mut other: RequestedCapabilities) {
        self.fs_read.append(&mut other.fs_read);
        self.fs_write.append(&mut other.fs_write);
        self.fs_delete.append(&mut other.fs_delete);
        self.net_connect.append(&mut other.net_connect);
        self.host_exec |= other.host_exec;
        self.process_control |= other.process_control;
        self.privilege |= other.privilege;
        self.credential_access |= other.credential_access;
        self.unknown |= other.unknown;
        self.reason_codes.append(&mut other.reason_codes);
        self.matched_rules.append(&mut other.matched_rules);
        self.risk_tags.append(&mut other.risk_tags);
        self.reason_codes.sort();
        self.reason_codes.dedup();
        self.matched_rules.sort();
        self.matched_rules.dedup();
        self.risk_tags.sort();
        self.risk_tags.dedup();
    }

    pub fn is_unknown_sensitive(&self) -> bool {
        self.unknown
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionConfidence {
    Exact,
    Conservative,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetEndpoint {
    pub host: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
}

impl NetEndpoint {
    pub fn new(host: impl Into<String>, port: Option<u16>, protocol: Option<String>) -> Self {
        Self {
            host: host.into(),
            port,
            protocol,
        }
    }
}
