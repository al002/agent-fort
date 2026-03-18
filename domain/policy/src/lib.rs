use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFile {
    pub absolute_path: PathBuf,
    pub relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDirectorySnapshot {
    pub root: PathBuf,
    pub files: Vec<PolicyFile>,
}

impl PolicyDirectorySnapshot {
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyReloadReason {
    FilesystemChange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReloadRequest {
    pub root: PathBuf,
    pub reason: PolicyReloadReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSource {
    pub relative_path: String,
    pub rule_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedRule {
    pub source: RuleSource,
    pub rule: PolicyRule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPolicies {
    pub snapshot: PolicyDirectorySnapshot,
    pub rules: Vec<LoadedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub version: u32,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub kind: PolicyRuleKind,
    #[serde(default)]
    pub priority: i64,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(rename = "match", default)]
    pub match_selector: PolicyMatch,
    pub when: String,
    pub effect: PolicyEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleKind {
    Guardrail,
    Allow,
    Approval,
    Deny,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMatch {
    #[serde(default)]
    pub operation_kinds: Vec<String>,
    pub interactive: Option<bool>,
    pub requires_network: Option<bool>,
    pub requires_write: Option<bool>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEffect {
    pub decision: PolicyDecision,
    pub reason: Option<String>,
    pub runtime_backend: Option<String>,
    #[serde(default)]
    pub requirements: Vec<String>,
    pub approval: Option<PolicyApproval>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Ask,
    Deny,
    Forbid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyApproval {
    pub summary: String,
    pub details: Option<String>,
    #[serde(default)]
    pub items: Vec<PolicyApprovalItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyApprovalItem {
    pub kind: String,
    pub target: Option<String>,
    pub summary: String,
}

fn default_enabled() -> bool {
    true
}
