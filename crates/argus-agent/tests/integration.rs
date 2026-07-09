//! Fixture-level regression tests for agent-surface scans (GH-57).
//! Each rule has at least one malicious and one benign fixture; assertions
//! cover both the derived decision and the exact rule-id set.

use argus_agent::scan_agent_surface;
use argus_core::Decision;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn corpus_agent_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpus/agent/fixtures")
        .join(name)
}

fn scan(name: &str) -> (Decision, Vec<String>) {
    let report = scan_agent_surface(&fixture(name)).expect("scan fixture");
    (report.decision, report.rule_ids())
}

#[test]
fn agt01_malicious_skill_blocks() {
    let (decision, rules) = scan("agt01-malicious-skill");
    assert_eq!(decision, Decision::Block);
    assert_eq!(rules, vec!["AGT-01-injection-language"]);
}

#[test]
fn agt01_benign_skill_allows() {
    let (decision, rules) = scan("agt01-benign-skill");
    assert_eq!(decision, Decision::Allow);
    assert!(rules.is_empty(), "{rules:?}");
}

#[test]
fn agt03_curl_sh_hook_blocks() {
    let (decision, rules) = scan("agt03-curl-sh-hook");
    assert_eq!(decision, Decision::Block);
    assert_eq!(
        rules,
        vec![
            "AGT-03-remote-exec",
            "remote-download",
            "shell-pipe-execution"
        ]
    );
}

#[test]
fn agt03_benign_hook_allows() {
    let (decision, rules) = scan("agt03-benign-hook");
    assert_eq!(decision, Decision::Allow);
    assert!(rules.is_empty(), "{rules:?}");
}

#[test]
fn agt05_always_load_requires_approval() {
    let (decision, rules) = scan("agt05-alwaysload");
    assert_eq!(decision, Decision::AllowWithApproval);
    assert_eq!(rules, vec!["AGT-05-mcp-always-load"]);
}

#[test]
fn agt05_benign_config_allows() {
    let (decision, rules) = scan("agt05-benign-config");
    assert_eq!(decision, Decision::Allow);
    assert!(rules.is_empty(), "{rules:?}");
}

#[test]
fn gh59_benign_network_tool_surfaces_manifest_without_blocking() {
    let report = scan_agent_surface(&corpus_agent_fixture("skill-benign-net-tool"))
        .expect("scan benign network tool");
    assert_eq!(report.decision, Decision::AllowWithApproval);
    assert_eq!(report.rule_ids(), vec!["capability-manifest"]);

    let net = report
        .findings
        .iter()
        .find(|f| f.capability.as_deref() == Some("net_egress"))
        .expect("net egress capability");
    assert_eq!(
        net.resolved_host.as_deref(),
        Some("api.weather.example.invalid")
    );
    assert_eq!(
        net.evidence.as_deref(),
        Some(["scripts/fetch.sh:8".to_string()].as_slice())
    );

    let json = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(
        json["findings"][0]["capability"].as_str(),
        Some("net_egress")
    );
    assert_eq!(
        json["findings"][0]["resolved_host"].as_str(),
        Some("api.weather.example.invalid")
    );
}

#[test]
fn gh59_agent_config_backdoor_blocks_as_misfit() {
    let report = scan_agent_surface(&corpus_agent_fixture("skill-config-backdoor"))
        .expect("scan config backdoor");
    assert_eq!(report.decision, Decision::Block);
    let rules = report.rule_ids();
    assert!(
        rules.contains(&"capability-misfit".to_string()),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"agent-config-write".to_string()),
        "{rules:?}"
    );
    assert!(rules.contains(&"hook-persistence".to_string()), "{rules:?}");
    assert!(report
        .findings
        .iter()
        .any(|f| f.capability.as_deref() == Some("agent_config_write")));
}

#[test]
fn gh59_credential_exfiltration_blocks_with_resolved_host() {
    let report =
        scan_agent_surface(&corpus_agent_fixture("skill-cred-exfil")).expect("scan cred exfil");
    assert_eq!(report.decision, Decision::Block);
    let rules = report.rule_ids();
    assert!(
        rules.contains(&"AGT-03-secret-exfil".to_string()),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"credential-access".to_string()),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"network-exfiltration".to_string()),
        "{rules:?}"
    );

    let egress = report
        .findings
        .iter()
        .find(|f| f.capability.as_deref() == Some("net_egress"))
        .expect("net egress capability");
    assert_eq!(
        egress.resolved_host.as_deref(),
        Some("collector.attacker.example.invalid")
    );
}
