//! End-to-end contract for `argus lockfile-scan` (GH-144).
//!
//! Network egress is blocked in every case, so any dependency that would need
//! a registry fetch fails. That is deliberate: the important property is that
//! an unfetchable dependency is reported as *unassessed* and blocks, rather
//! than silently contributing nothing and letting the tree read as clean.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const SHA256_SRI: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn argus(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .env("PATH", "/argus-test-no-executables")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .output()
        .expect("run argus CLI")
}

fn write_lock(dir: &Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    fs::write(&path, body).expect("write lockfile fixture");
    path.to_string_lossy().into_owned()
}

/// A lockfile whose only entry is a local workspace path — nothing to fetch.
fn local_only_lock() -> String {
    r#"{
      "name":"root","version":"1.0.0","lockfileVersion":3,
      "packages":{
        "":{"name":"root","version":"1.0.0"},
        "node_modules/local-tool":{
          "version":"0.1.0",
          "resolved":"file:../local-tool"
        }
      }
    }"#
    .to_string()
}

fn registry_lock(version: &str) -> String {
    format!(
        r#"{{
          "name":"root","version":"1.0.0","lockfileVersion":3,
          "packages":{{
            "":{{"name":"root","version":"1.0.0"}},
            "node_modules/demo":{{
              "version":"{version}",
              "resolved":"https://registry.npmjs.org/demo/-/demo-{version}.tgz",
              "integrity":"{SHA256_SRI}"
            }}
          }}
        }}"#
    )
}

#[test]
fn lockfile_with_no_fetchable_dependencies_allows_and_reports_coverage() {
    let dir = tempfile::tempdir().expect("test dir");
    let lock = write_lock(dir.path(), "package-lock.json", &local_only_lock());

    let out = argus(&["lockfile-scan", &lock]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("decision: allow"), "stdout: {stdout}");
    assert!(
        stdout.contains("coverage: scanned 0 of"),
        "stdout: {stdout}"
    );
}

#[test]
fn unfetchable_dependency_is_reported_unassessed_and_blocks() {
    let dir = tempfile::tempdir().expect("test dir");
    let lock = write_lock(dir.path(), "package-lock.json", &registry_lock("1.0.0"));

    let out = argus(&["lockfile-scan", &lock]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Exit 1 = block. A dependency argus could not read is missing evidence,
    // never an implicit pass.
    assert_eq!(out.status.code(), Some(1), "stdout: {stdout}");
    assert!(
        stdout.contains("unassessed (fetch or scan failed):"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("demo"), "stdout: {stdout}");
}

#[test]
fn json_output_carries_coverage_and_failure_detail() {
    let dir = tempfile::tempdir().expect("test dir");
    let lock = write_lock(dir.path(), "package-lock.json", &registry_lock("1.0.0"));

    let out = argus(&["lockfile-scan", &lock, "--format", "json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(&stdout).expect("parse JSON report");

    assert_eq!(parsed["decision"], "block");
    assert_eq!(parsed["scanned"], 0);
    assert!(parsed["targets_total"].as_u64().expect("targets_total") >= 1);
    let failed = parsed["failed"].as_array().expect("failed array");
    assert_eq!(failed.len(), 1);
    assert!(!failed[0]["error"].as_str().expect("error text").is_empty());
}

#[test]
fn sarif_output_is_well_formed_when_nothing_could_be_scanned() {
    let dir = tempfile::tempdir().expect("test dir");
    let lock = write_lock(dir.path(), "package-lock.json", &registry_lock("1.0.0"));

    let out = argus(&["lockfile-scan", &lock, "--format", "sarif"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(&stdout).expect("parse SARIF");

    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"].is_array());
}

#[test]
fn changed_only_scans_the_delta_against_a_base_lockfile() {
    let dir = tempfile::tempdir().expect("test dir");
    let base = write_lock(dir.path(), "base-lock.json", &registry_lock("1.0.0"));
    let current = write_lock(dir.path(), "package-lock.json", &registry_lock("1.0.0"));

    // Identical lockfiles: the delta is empty, so nothing is fetched and the
    // run allows even though the same dependency is unfetchable without
    // `--base`.
    let out = argus(&[
        "lockfile-scan",
        &current,
        "--base",
        &base,
        "--base-lockfile-format",
        "package-lock",
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(&stdout).expect("parse JSON report");

    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}");
    assert_eq!(parsed["targets_total"], 0);
    assert_eq!(parsed["scanned"], 0);
    assert_eq!(parsed["comparisons_total"], 0);
    assert_eq!(parsed["version_changes"], serde_json::json!([]));
}

#[test]
fn changed_only_still_scans_a_dependency_the_base_did_not_have() {
    let dir = tempfile::tempdir().expect("test dir");
    let base = write_lock(dir.path(), "base-lock.json", &local_only_lock());
    let current = write_lock(dir.path(), "package-lock.json", &registry_lock("2.0.0"));

    let out = argus(&[
        "lockfile-scan",
        &current,
        "--base",
        &base,
        "--base-lockfile-format",
        "package-lock",
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(&stdout).expect("parse JSON report");

    assert_eq!(parsed["targets_total"], 1);
    assert_eq!(parsed["decision"], "block");
    assert_eq!(parsed["comparisons_total"], 0);
}

#[test]
fn changed_version_plans_a_base_current_comparison() {
    let dir = tempfile::tempdir().expect("test dir");
    let base = write_lock(dir.path(), "base-lock.json", &registry_lock("1.0.0"));
    let current = write_lock(dir.path(), "package-lock.json", &registry_lock("2.0.0"));

    let out = argus(&[
        "lockfile-scan",
        &current,
        "--base",
        &base,
        "--base-lockfile-format",
        "package-lock",
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(&stdout).expect("parse JSON report");

    // Network is deliberately unavailable, so the current artifact is
    // unassessed and the comparison cannot complete. It must still be visible
    // as one planned version comparison and must block.
    assert_eq!(out.status.code(), Some(1), "stdout: {stdout}");
    assert_eq!(parsed["comparisons_total"], 1);
    assert_eq!(parsed["version_changes"], serde_json::json!([]));
    assert_eq!(parsed["decision"], "block");
}

#[test]
fn whole_lockfile_help_and_empty_scan_validate_malicious_database() {
    let help = argus(&["lockfile-scan", "--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--malicious-db"));

    let dir = tempfile::tempdir().expect("test dir");
    let lock = write_lock(dir.path(), "package-lock.json", &local_only_lock());
    let database = dir.path().join("corrupt-intelligence.json");
    fs::write(&database, b"not json").expect("write corrupt database");
    let out = argus(&[
        "lockfile-scan",
        &lock,
        "--malicious-db",
        database.to_str().expect("UTF-8 test path"),
        "--format",
        "json",
    ]);

    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("load malicious-package database"));
}

#[test]
fn missing_lockfile_fails_before_any_network_work() {
    let out = argus(&["lockfile-scan", "/nonexistent/package-lock.json"]);
    assert_ne!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.is_empty(), "expected a diagnostic on stderr");
}
