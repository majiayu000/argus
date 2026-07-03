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
