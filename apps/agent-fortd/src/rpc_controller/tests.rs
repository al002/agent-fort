use super::*;

#[test]
fn network_policy_is_disabled_when_no_endpoint_even_if_mode_full() {
    assert_eq!(
        network_policy_from_plan("full", true),
        NetworkPolicy::Disabled
    );
}

#[test]
fn network_policy_follows_mode_when_endpoint_exists() {
    assert_eq!(network_policy_from_plan("full", false), NetworkPolicy::Full);
    assert_eq!(
        network_policy_from_plan("proxy_only", false),
        NetworkPolicy::ProxyOnly
    );
    assert_eq!(
        network_policy_from_plan("deny", false),
        NetworkPolicy::Disabled
    );
}

#[test]
fn clears_unclassified_unknown_when_rule_covers_command() {
    let mut requested = RequestedCapabilities {
        unknown: true,
        reason_codes: vec![
            "command.unclassified:curl https://example.com".to_string(),
            "rule.command:curl https://example.com".to_string(),
            "rule.matched:00.rules:1#1".to_string(),
        ],
        ..RequestedCapabilities::default()
    };

    clear_unclassified_unknown_covered_by_rules(&mut requested);

    assert!(!requested.unknown);
    assert!(
        !requested
            .reason_codes
            .iter()
            .any(|code| code == "command.unclassified:curl https://example.com")
    );
    assert!(
        !requested
            .reason_codes
            .iter()
            .any(|code| code == "rule.command:curl https://example.com")
    );
}

#[test]
fn keeps_unknown_when_other_unknown_reason_exists() {
    let mut requested = RequestedCapabilities {
        unknown: true,
        reason_codes: vec![
            "command.unclassified:curl https://example.com".to_string(),
            "rule.command:curl https://example.com".to_string(),
            "parser.failed".to_string(),
        ],
        ..RequestedCapabilities::default()
    };

    clear_unclassified_unknown_covered_by_rules(&mut requested);

    assert!(requested.unknown);
    assert!(
        requested
            .reason_codes
            .iter()
            .any(|code| code == "parser.failed")
    );
}
