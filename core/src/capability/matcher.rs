use std::path::{Component, Path, PathBuf};

use af_policy::{BackendCapabilityLimits, CapabilitySet, NetRule};

use super::{NetEndpoint, RequestedCapabilities};

pub fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized != PathBuf::from("/") {
                    normalized.pop();
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    if normalized.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        normalized
    }
}

pub fn requested_within_capabilities(
    requested: &RequestedCapabilities,
    capabilities: &CapabilitySet,
) -> bool {
    requested_within_patterns(
        requested,
        &capabilities.fs_read,
        &capabilities.fs_write,
        &capabilities.fs_delete,
        &capabilities.net_connect,
        capabilities.allow_host_exec,
        capabilities.allow_process_control,
        capabilities.allow_privilege,
        capabilities.allow_credential_access,
    )
}

pub fn requested_within_backend_limits(
    requested: &RequestedCapabilities,
    limits: &BackendCapabilityLimits,
) -> bool {
    requested_within_patterns(
        requested,
        &limits.fs_read,
        &limits.fs_write,
        &limits.fs_delete,
        &limits.net_connect,
        limits.allow_host_exec,
        limits.allow_process_control,
        limits.allow_privilege,
        limits.allow_credential_access,
    )
}

fn requested_within_patterns(
    requested: &RequestedCapabilities,
    fs_read: &[String],
    fs_write: &[String],
    fs_delete: &[String],
    net_connect: &[NetRule],
    allow_host_exec: bool,
    allow_process_control: bool,
    allow_privilege: bool,
    allow_credential_access: bool,
) -> bool {
    if requested
        .fs_read
        .iter()
        .any(|path| !path_matches_any(path, fs_read))
    {
        return false;
    }
    if requested
        .fs_write
        .iter()
        .any(|path| !path_matches_any(path, fs_write))
    {
        return false;
    }
    if requested
        .fs_delete
        .iter()
        .any(|path| !path_matches_any(path, fs_delete))
    {
        return false;
    }
    if requested
        .net_connect
        .iter()
        .any(|endpoint| !endpoint_matches_any(endpoint, net_connect))
    {
        return false;
    }

    (!requested.host_exec || allow_host_exec)
        && (!requested.process_control || allow_process_control)
        && (!requested.privilege || allow_privilege)
        && (!requested.credential_access || allow_credential_access)
}

pub fn capability_set_within_policy(left: &CapabilitySet, right: &CapabilitySet) -> bool {
    left.fs_read
        .iter()
        .all(|pattern| pattern_covered_by(pattern, &right.fs_read))
        && left
            .fs_write
            .iter()
            .all(|pattern| pattern_covered_by(pattern, &right.fs_write))
        && left
            .fs_delete
            .iter()
            .all(|pattern| pattern_covered_by(pattern, &right.fs_delete))
        && left
            .net_connect
            .iter()
            .all(|rule| net_rule_covered_by(rule, &right.net_connect))
        && (!left.allow_host_exec || right.allow_host_exec)
        && (!left.allow_process_control || right.allow_process_control)
        && (!left.allow_privilege || right.allow_privilege)
        && (!left.allow_credential_access || right.allow_credential_access)
}

pub fn intersect_requested_with_capabilities(
    requested: &RequestedCapabilities,
    capabilities: &CapabilitySet,
) -> RequestedCapabilities {
    let mut effective = RequestedCapabilities::default();

    for path in &requested.fs_read {
        if path_matches_any(path, &capabilities.fs_read) {
            effective.fs_read.insert(path.clone());
        }
    }
    for path in &requested.fs_write {
        if path_matches_any(path, &capabilities.fs_write) {
            effective.fs_write.insert(path.clone());
        }
    }
    for path in &requested.fs_delete {
        if path_matches_any(path, &capabilities.fs_delete) {
            effective.fs_delete.insert(path.clone());
        }
    }
    for endpoint in &requested.net_connect {
        if endpoint_matches_any(endpoint, &capabilities.net_connect) {
            effective.net_connect.insert(endpoint.clone());
        }
    }

    effective.host_exec = requested.host_exec && capabilities.allow_host_exec;
    effective.process_control = requested.process_control && capabilities.allow_process_control;
    effective.privilege = requested.privilege && capabilities.allow_privilege;
    effective.credential_access =
        requested.credential_access && capabilities.allow_credential_access;

    effective
}

pub fn path_matches_any(path: &Path, patterns: &[String]) -> bool {
    let normalized = normalize_lexical_path(path);
    patterns
        .iter()
        .any(|pattern| path_matches_pattern(&normalized, pattern))
}

pub fn path_matches_pattern(path: &Path, pattern: &str) -> bool {
    let path_segments = normalize_path_segments(path);
    let pattern_segments = normalize_pattern_segments(pattern);
    matches_segment_seq(path_segments.as_slice(), pattern_segments.as_slice())
}

fn normalize_path_segments(path: &Path) -> Vec<String> {
    normalize_lexical_path(path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect()
}

fn normalize_pattern_segments(pattern: &str) -> Vec<String> {
    let normalized = pattern.replace('\\', "/");
    let mut parts = Vec::new();

    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if parts.last().is_some_and(|last: &String| last != "**") {
                parts.pop();
            }
            continue;
        }
        parts.push(part.to_string());
    }

    parts
}

fn matches_segment_seq(path: &[String], pattern: &[String]) -> bool {
    if pattern.is_empty() {
        return path.is_empty();
    }

    if pattern[0] == "**" {
        if matches_segment_seq(path, &pattern[1..]) {
            return true;
        }
        if !path.is_empty() {
            return matches_segment_seq(&path[1..], pattern);
        }
        return false;
    }

    if path.is_empty() {
        return false;
    }
    if !matches_segment(&pattern[0], &path[0]) {
        return false;
    }

    matches_segment_seq(&path[1..], &pattern[1..])
}

fn matches_segment(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    wildcard_match(pattern.as_bytes(), value.as_bytes())
}

fn wildcard_match(pattern: &[u8], value: &[u8]) -> bool {
    let mut dp = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    dp[0][0] = true;

    for i in 1..=pattern.len() {
        if pattern[i - 1] == b'*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=pattern.len() {
        for j in 1..=value.len() {
            if pattern[i - 1] == b'*' {
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
            } else {
                dp[i][j] = dp[i - 1][j - 1] && pattern[i - 1] == value[j - 1];
            }
        }
    }

    dp[pattern.len()][value.len()]
}

pub fn endpoint_matches_any(endpoint: &NetEndpoint, rules: &[NetRule]) -> bool {
    rules
        .iter()
        .any(|rule| endpoint_matches_rule(endpoint, rule))
}

pub fn endpoint_matches_rule(endpoint: &NetEndpoint, rule: &NetRule) -> bool {
    let endpoint_host = normalize_host(endpoint.host.as_str());
    let rule_host = normalize_host(rule.host.as_str());

    let host_match = if let Some(suffix) = rule_host.strip_prefix('.') {
        endpoint_host.ends_with(rule_host.as_str()) || endpoint_host == suffix
    } else {
        endpoint_host == rule_host
    };
    if !host_match {
        return false;
    }

    let port_match = rule.port.is_none() || rule.port == endpoint.port;
    if !port_match {
        return false;
    }

    match (&endpoint.protocol, &rule.protocol) {
        (_, None) => true,
        (Some(protocol), Some(rule_protocol)) => {
            normalize_host(protocol.as_str()) == normalize_host(rule_protocol.as_str())
        }
        (None, Some(_)) => false,
    }
}

fn net_rule_covered_by(rule: &NetRule, allowed: &[NetRule]) -> bool {
    allowed.iter().any(|allow| {
        host_rule_covers(&allow.host, &rule.host)
            && (allow.port.is_none() || allow.port == rule.port)
            && (allow.protocol.is_none()
                || allow.protocol.as_ref().is_some_and(|allow_protocol| {
                    rule.protocol.as_ref().is_some_and(|rule_protocol| {
                        normalize_host(allow_protocol) == normalize_host(rule_protocol)
                    })
                }))
    })
}

fn host_rule_covers(allow_host: &str, requested_host: &str) -> bool {
    let allow = normalize_host(allow_host);
    let requested = normalize_host(requested_host);

    if let Some(suffix) = allow.strip_prefix('.') {
        requested.ends_with(allow.as_str()) || requested == suffix
    } else {
        allow == requested
    }
}

fn pattern_covered_by(pattern: &str, allowed: &[String]) -> bool {
    allowed
        .iter()
        .any(|candidate| candidate == pattern || candidate_covers_pattern(candidate, pattern))
}

fn candidate_covers_pattern(candidate: &str, pattern: &str) -> bool {
    let candidate = candidate.trim();
    let pattern = pattern.trim();

    if candidate == "/**" || candidate == "**" {
        return true;
    }

    if let Some(prefix) = candidate.strip_suffix("/**") {
        return pattern == prefix
            || pattern.starts_with(&format!("{prefix}/"))
            || pattern.starts_with(prefix);
    }

    candidate == pattern
}

fn normalize_host(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use af_policy::NetRule;

    use super::*;

    #[test]
    fn glob_matches_double_star() {
        assert!(path_matches_pattern(
            Path::new("/work/a/b/c.txt"),
            "/work/**"
        ));
        assert!(path_matches_pattern(
            Path::new("/work/a/b/c.txt"),
            "/work/**/c.txt"
        ));
        assert!(!path_matches_pattern(
            Path::new("/tmp/a/b/c.txt"),
            "/work/**"
        ));
    }

    #[test]
    fn endpoint_suffix_rule_matches_subdomain() {
        let endpoint = NetEndpoint::new("api.svc.internal", Some(443), Some("https".to_string()));
        let rule = NetRule {
            host: ".svc.internal".to_string(),
            port: Some(443),
            protocol: Some("https".to_string()),
        };

        assert!(endpoint_matches_rule(&endpoint, &rule));
    }

    #[test]
    fn subset_requires_all_requested_paths_covered() {
        let requested = RequestedCapabilities {
            fs_write: [PathBuf::from("/work/a.txt")].into_iter().collect(),
            ..RequestedCapabilities::default()
        };

        let capabilities = CapabilitySet {
            fs_read: Vec::new(),
            fs_write: vec!["/work/**".to_string()],
            fs_delete: Vec::new(),
            net_connect: Vec::new(),
            allow_host_exec: false,
            allow_process_control: false,
            allow_privilege: false,
            allow_credential_access: false,
        };

        assert!(requested_within_capabilities(&requested, &capabilities));
    }
}
