//! Opt-in production-registry E2E smoke test.
//!
//! Immutable, popular benign versions exercise real DNS, TLS, registry APIs,
//! artifact downloads, integrity verification, extraction, static scanning,
//! JSON rendering, and process exit codes. Run explicitly because repository
//! unit/CI environments are not assumed to have network access.

use serde_json::Value;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .env("PATH", "/argus-public-e2e-no-executables")
        .output()
        .expect("run production argus binary")
}

fn assert_non_blocking(label: &str, output: &Output) {
    assert!(
        matches!(output.status.code(), Some(0 | 2)),
        "{label} unexpectedly blocked or failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{label} operational failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON report");
    assert_ne!(report["decision"], "block", "{label}: {report:#}");
    assert!(
        report["coordinate"]["purl"].is_string(),
        "{label}: {report:#}"
    );
}

#[test]
#[ignore = "requires live public package registries"]
fn immutable_benign_popular_packages_do_not_block() {
    for (label, args) in [
        (
            "npm/chalk",
            vec!["fetch", "chalk@5.3.0", "--format", "json"],
        ),
        (
            "pypi/requests",
            vec![
                "pypi-fetch",
                "requests@2.31.0",
                "--prefer",
                "wheel",
                "--format",
                "json",
            ],
        ),
        (
            "crates/serde",
            vec!["crates-fetch", "serde@1.0.228", "--format", "json"],
        ),
    ] {
        assert_non_blocking(label, &run(&args));
    }
}
