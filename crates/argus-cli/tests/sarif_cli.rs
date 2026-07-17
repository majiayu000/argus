use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical repository root")
}

fn argus(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .output()
        .expect("run argus CLI")
}

#[test]
fn block_report_emits_sarif_and_keeps_exit_one() {
    let fixture = repo_root().join("corpus/fixtures/lifecycle-curl-sh");
    let output = argus(&["scan", fixture.to_str().unwrap(), "--format", "sarif"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");
    assert_eq!(document["version"], "2.1.0");
    assert_eq!(document["runs"][0]["tool"]["driver"]["name"], "argus");
    assert!(document["runs"][0]["results"].as_array().unwrap().len() >= 2);
}

#[test]
fn approval_report_emits_sarif_and_keeps_exit_two() {
    let fixture = repo_root().join("corpus/fixtures/benign-esbuild-like");
    let output = argus(&["scan", fixture.to_str().unwrap(), "--format", "sarif"]);
    assert_eq!(output.status.code(), Some(2));
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");
    assert_eq!(
        document["runs"][0]["results"][0]["properties"]["decision"],
        "allow-with-approval"
    );
}

#[test]
fn operational_error_writes_no_misleading_sarif() {
    let missing = repo_root().join("target/gh93-definitely-missing");
    assert!(!missing.exists(), "test path unexpectedly exists");
    let output = argus(&["scan", missing.to_str().unwrap(), "--format", "sarif"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("argus: error:"));
}

#[test]
fn agent_scan_emits_one_sarif_run() {
    let fixture = repo_root().join("crates/argus-agent/tests/fixtures/agt01-malicious-skill");
    let output = argus(&[
        "agent",
        "scan",
        fixture.to_str().unwrap(),
        "--format",
        "sarif",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");
    assert_eq!(document["runs"].as_array().unwrap().len(), 1);
    assert_eq!(
        document["runs"][0]["results"][0]["properties"]["artifact_kind"],
        "agent-surface"
    );
}

#[test]
fn corpus_eval_does_not_advertise_or_accept_sarif() {
    let help = argus(&["corpus", "eval", "--help"]);
    assert!(help.status.success());
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(!help_text.contains("sarif"), "{help_text}");

    let rejected = argus(&["corpus", "eval", "--format", "sarif"]);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
}
