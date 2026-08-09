//! End-to-end contract for opt-in weighted risk scoring (GH-146).
//!
//! The property that matters most is the one about *not* changing behaviour:
//! without `--risk-scoring` the exit code and report must be byte-identical to
//! before, because every existing consumer depends on the policy-driven
//! decision and the benchmark does not justify a cross-catalog per-rule map.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn argus(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .env("PATH", "/argus-test-no-executables")
        .output()
        .expect("run argus CLI")
}

/// A package that trips one Medium-severity lifecycle rule.
fn lifecycle_package(dir: &Path) -> String {
    fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","version":"1.0.0","scripts":{"postinstall":"node ./setup.js"}}"#,
    )
    .expect("write package.json");
    fs::write(dir.join("setup.js"), "console.log('hello');\n").expect("write setup.js");
    dir.to_string_lossy().into_owned()
}

#[test]
fn without_the_flag_no_risk_section_is_emitted() {
    let dir = tempfile::tempdir().expect("test dir");
    let pkg = lifecycle_package(dir.path());

    let out = argus(&["scan", &pkg, "--format", "json"]);
    let parsed: Value = serde_json::from_slice(&out.stdout).expect("parse JSON report");
    assert!(
        parsed.get("risk").is_none(),
        "risk must be absent unless requested: {parsed}"
    );
}

#[test]
fn scoring_reports_the_score_without_changing_the_exit_code() {
    let dir = tempfile::tempdir().expect("test dir");
    let pkg = lifecycle_package(dir.path());

    let baseline = argus(&["scan", &pkg, "--format", "json"]);
    let scored = argus(&["scan", &pkg, "--format", "json", "--risk-scoring"]);

    assert_eq!(
        baseline.status.code(),
        scored.status.code(),
        "reporting a score must not move the decision"
    );

    let parsed: Value = serde_json::from_slice(&scored.stdout).expect("parse JSON report");
    let risk = parsed.get("risk").expect("risk section present");
    assert!(risk["score"].as_u64().is_some());
    assert_eq!(risk["approval_threshold"], 3000);
    assert_eq!(risk["block_threshold"], 6000);
    assert!(
        !risk["contributions"]
            .as_array()
            .expect("contributions array")
            .is_empty(),
        "a scored report must show its working"
    );
}

#[test]
fn risk_decides_requires_risk_scoring() {
    let dir = tempfile::tempdir().expect("test dir");
    let pkg = lifecycle_package(dir.path());

    let out = argus(&["scan", &pkg, "--risk-decides"]);
    assert_ne!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("risk-scoring"),
        "expected a dependency diagnostic: {stderr}"
    );
}

#[test]
fn thresholds_move_the_decision_when_risk_decides() {
    let dir = tempfile::tempdir().expect("test dir");
    let pkg = lifecycle_package(dir.path());

    // Thresholds low enough that any finding blocks.
    let strict = argus(&[
        "scan",
        &pkg,
        "--risk-scoring",
        "--risk-decides",
        "--risk-approval-threshold",
        "1",
        "--risk-block-threshold",
        "2",
    ]);
    assert_eq!(strict.status.code(), Some(1));

    // Thresholds high enough that nothing does.
    let lenient = argus(&[
        "scan",
        &pkg,
        "--risk-scoring",
        "--risk-decides",
        "--risk-approval-threshold",
        "90000",
        "--risk-block-threshold",
        "100000",
    ]);
    assert_eq!(lenient.status.code(), Some(0));
}

#[test]
fn inverted_thresholds_fail_closed() {
    let dir = tempfile::tempdir().expect("test dir");
    let pkg = lifecycle_package(dir.path());

    let out = argus(&[
        "scan",
        &pkg,
        "--risk-scoring",
        "--risk-approval-threshold",
        "9000",
        "--risk-block-threshold",
        "1000",
    ]);
    // Operational failure, not a silently ignored flag.
    assert_eq!(out.status.code(), Some(2));
    assert!(
        out.stdout.is_empty(),
        "no report on an invalid configuration"
    );
}

#[test]
fn sarif_carries_the_score_and_contributions() {
    let dir = tempfile::tempdir().expect("test dir");
    let pkg = lifecycle_package(dir.path());

    let out = argus(&["scan", &pkg, "--format", "sarif", "--risk-scoring"]);
    let parsed: Value = serde_json::from_slice(&out.stdout).expect("parse SARIF");
    let risk = &parsed["runs"][0]["properties"]["argusRisk"][0];
    assert!(risk["score"].as_u64().is_some(), "SARIF: {parsed}");
    assert!(risk["contributions"].is_array());
}
