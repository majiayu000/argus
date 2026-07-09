//! Fixture-level regression tests for agent-surface scans (GH-57).
//! Each rule has at least one malicious and one benign fixture; assertions
//! cover both the derived decision and the exact rule-id set.

use argus_agent::{scan_agent_surface, scan_agent_surface_with_baseline, BaselineMode};
use argus_core::{Decision, Severity};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A per-test temp path for a baseline file (never inside a scanned fixture).
fn temp_baseline(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "argus-agt02-{}-{}-{:?}",
        tag,
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("baseline.json")
}

fn agt02_rule_ids(report: &argus_core::ScanReport) -> Vec<String> {
    report
        .findings
        .iter()
        .map(|f| f.rule_id.clone())
        .filter(|id| id.starts_with("AGT-02"))
        .collect()
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
fn agt02_baseline_create_writes_entries_without_drift() {
    let baseline = temp_baseline("create");
    let report = scan_agent_surface_with_baseline(
        &fixture("agt02-baseline-mcp"),
        BaselineMode::Update(&baseline),
    )
    .expect("update baseline");
    // Update defines the trust base — it must not emit any AGT-02 finding.
    assert!(agt02_rule_ids(&report).is_empty(), "{:?}", report.findings);
    // Baseline file written with the extracted description entries.
    let raw = std::fs::read_to_string(&baseline).expect("baseline written");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["version"], 1);
    let entries = value["entries"].as_object().unwrap();
    assert!(
        entries.contains_key(".mcp.json#mcpServers.fs.description"),
        "{entries:?}"
    );
    assert!(
        entries.contains_key(".mcp.json#mcpServers.fs.tools[0].description"),
        "{entries:?}"
    );
}

#[test]
fn agt02_unchanged_surface_has_no_drift() {
    let baseline = temp_baseline("unchanged");
    let dir = fixture("agt02-baseline-mcp");
    scan_agent_surface_with_baseline(&dir, BaselineMode::Update(&baseline)).unwrap();
    let report =
        scan_agent_surface_with_baseline(&dir, BaselineMode::Check(&baseline)).expect("check");
    assert!(agt02_rule_ids(&report).is_empty(), "{:?}", report.findings);
}

#[test]
fn agt02_drift_flags_medium_with_evidence() {
    let baseline = temp_baseline("drift");
    scan_agent_surface_with_baseline(
        &fixture("agt02-baseline-mcp"),
        BaselineMode::Update(&baseline),
    )
    .unwrap();
    let report = scan_agent_surface_with_baseline(
        &fixture("agt02-baseline-mcp-drift"),
        BaselineMode::Check(&baseline),
    )
    .expect("check drift");

    let drift: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "AGT-02")
        .collect();
    assert_eq!(drift.len(), 1, "{:?}", report.findings);
    assert_eq!(drift[0].severity, Severity::Medium);
    assert_eq!(drift[0].location.as_deref(), Some(".mcp.json"));
    let evidence = drift[0].evidence.as_ref().expect("evidence");
    assert!(
        evidence[0].starts_with(".mcp.json#mcpServers.fs.description old="),
        "{evidence:?}"
    );
    assert!(evidence[0].contains(" new="), "{evidence:?}");
    // Drift alone is re-approval, not a hard block.
    assert_eq!(report.decision, Decision::AllowWithApproval);
}

#[test]
fn agt02_missing_entry_reports_info() {
    let baseline = temp_baseline("missing");
    // Approve a two-server surface, then scan a one-server surface.
    let two = temp_baseline("missing-src");
    let two_dir = two.parent().unwrap();
    std::fs::write(
        two_dir.join(".mcp.json"),
        r#"{"mcpServers":{"fs":{"description":"reads files"},"net":{"description":"fetches urls"}}}"#,
    )
    .unwrap();
    scan_agent_surface_with_baseline(two_dir, BaselineMode::Update(&baseline)).unwrap();

    let one = temp_baseline("missing-dst");
    let one_dir = one.parent().unwrap();
    std::fs::write(
        one_dir.join(".mcp.json"),
        r#"{"mcpServers":{"fs":{"description":"reads files"}}}"#,
    )
    .unwrap();
    let report =
        scan_agent_surface_with_baseline(one_dir, BaselineMode::Check(&baseline)).expect("check");

    let missing: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "AGT-02-baseline-entry-missing")
        .collect();
    assert_eq!(missing.len(), 1, "{:?}", report.findings);
    assert_eq!(missing[0].severity, Severity::Info);
}

#[test]
fn agt02_skill_frontmatter_is_baselined_and_stable() {
    let baseline = temp_baseline("skill");
    let dir = fixture("agt02-baseline-skill");
    let created =
        scan_agent_surface_with_baseline(&dir, BaselineMode::Update(&baseline)).expect("update");
    assert!(
        agt02_rule_ids(&created).is_empty(),
        "{:?}",
        created.findings
    );
    let raw = std::fs::read_to_string(&baseline).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let entries = value["entries"].as_object().unwrap();
    assert!(
        entries.contains_key("SKILL.md#frontmatter.name"),
        "{entries:?}"
    );
    assert!(
        entries.contains_key("SKILL.md#frontmatter.description"),
        "{entries:?}"
    );

    let checked =
        scan_agent_surface_with_baseline(&dir, BaselineMode::Check(&baseline)).expect("check");
    assert!(
        agt02_rule_ids(&checked).is_empty(),
        "{:?}",
        checked.findings
    );
}

#[test]
fn agt02_unreadable_baseline_reports_info_not_panic() {
    let missing = std::env::temp_dir().join("argus-agt02-no-such-baseline.json");
    let _ = std::fs::remove_file(&missing);
    let report = scan_agent_surface_with_baseline(
        &fixture("agt02-baseline-mcp"),
        BaselineMode::Check(&missing),
    )
    .expect("check with missing baseline still succeeds");
    let info: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "AGT-02-baseline-unreadable")
        .collect();
    assert_eq!(info.len(), 1, "{:?}", report.findings);
    assert_eq!(info[0].severity, Severity::Info);
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
