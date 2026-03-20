use std::path::{Path, PathBuf};

use super::NetEndpoint;
use super::command_base_name;

pub(super) fn collect_positionals(argv: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    let binary = argv
        .first()
        .map(|value| command_base_name(value))
        .unwrap_or_default();
    let mut index = 1usize;
    while index < argv.len() {
        let token = &argv[index];
        if token == "--" {
            result.extend(argv.iter().skip(index + 1).cloned());
            break;
        }
        if token.starts_with('-') {
            if option_consumes_next_value(binary.as_str(), token, argv.get(index + 1)) {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        result.push(token.clone());
        index += 1;
    }
    result
}

pub(super) fn resolve_path(cwd: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    let joined = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    crate::capability::matcher::normalize_lexical_path(&joined)
}

pub(super) fn parse_endpoint(raw: &str) -> Option<NetEndpoint> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (host_raw, protocol) = if let Some((scheme, rest)) = trimmed.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let without_userinfo = authority
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(authority);
        (without_userinfo, Some(scheme.to_ascii_lowercase()))
    } else {
        (trimmed, None)
    };

    let host_port = host_raw.trim();
    if host_port.is_empty() {
        return None;
    }

    let (host, mut port) = if let Some((host, port_raw)) = host_port.rsplit_once(':') {
        if port_raw.chars().all(|ch| ch.is_ascii_digit()) {
            (host, port_raw.parse::<u16>().ok())
        } else {
            (host_port, None)
        }
    } else {
        (host_port, None)
    };

    let normalized_host = host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized_host.is_empty() {
        return None;
    }
    if !normalized_host
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_')
    {
        return None;
    }

    if port.is_none()
        && let Some(scheme) = protocol.as_deref()
    {
        port = match scheme {
            "https" => Some(443),
            "http" => Some(80),
            _ => None,
        };
    }

    Some(NetEndpoint::new(normalized_host, port, protocol))
}

pub(super) fn looks_like_credential_path(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains(".ssh")
        || lower.contains(".aws/credentials")
        || lower.contains("/etc/shadow")
        || lower.contains("id_rsa")
}

fn option_consumes_next_value(binary: &str, option: &str, next: Option<&String>) -> bool {
    let Some(next) = next.map(String::as_str) else {
        return false;
    };
    if next == "--" || next.starts_with('-') {
        return false;
    }

    if option.starts_with("--") {
        if option.contains('=') {
            return false;
        }
        return long_option_takes_value(option);
    }
    if !option.starts_with('-') || option.len() != 2 {
        return false;
    }

    let short = option.as_bytes()[1] as char;
    if matches!(short, 'o' | 'e' | 'f' | 'd' | 't' | 'u' | 'x' | 'I' | 'L') {
        return true;
    }

    matches!(short, 'n' | 'c' | 'A' | 'B' | 'C' | 'm' | 's' | 'w')
        && (matches!(binary, "head" | "tail" | "grep" | "rg")
            || next
                .chars()
                .all(|ch| ch.is_ascii_digit() || ch == '+' || ch == '-'))
}

fn long_option_takes_value(option: &str) -> bool {
    matches!(
        option,
        "--output"
            | "--file"
            | "--expression"
            | "--regexp"
            | "--max-count"
            | "--context"
            | "--before-context"
            | "--after-context"
            | "--glob"
            | "--type"
            | "--type-not"
            | "--threads"
            | "--sort"
            | "--sortr"
            | "--bytes"
            | "--lines"
    )
}
