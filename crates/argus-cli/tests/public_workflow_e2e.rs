//! Opt-in public-workflow precision benchmark.
//!
//! Each sample is downloaded from an immutable upstream commit, verified by
//! SHA-256, and scanned through the production CLI. Workflow content is never
//! executed. The gate fails on any false block or incomplete scan.

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

const MANIFEST: &str = include_str!("../../../eval/workflows/public-benign.json");
const MAX_WORKFLOW_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Benchmark {
    schema_version: u8,
    label_source: String,
    samples: Vec<Sample>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    id: String,
    repository: String,
    commit: String,
    path: String,
    sha256: String,
}

#[test]
#[ignore = "requires live access to pinned public GitHub workflow files"]
fn pinned_benign_public_workflows_have_zero_false_blocks() {
    let benchmark: Benchmark = serde_json::from_str(MANIFEST).expect("parse workflow benchmark");
    assert_eq!(benchmark.schema_version, 1);
    assert!(!benchmark.label_source.trim().is_empty());
    assert!(!benchmark.samples.is_empty());

    for sample in benchmark.samples {
        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}",
            sample.repository, sample.commit, sample.path
        );
        let download = Command::new("curl")
            .args([
                "--location",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "30",
                "--max-filesize",
                "1048576",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                &url,
            ])
            .output()
            .expect("start curl");
        assert!(
            download.status.success(),
            "{} download failed: {}",
            sample.id,
            String::from_utf8_lossy(&download.stderr)
        );
        assert!(
            download.stdout.len() <= MAX_WORKFLOW_BYTES,
            "{} exceeds benchmark size limit",
            sample.id
        );
        let digest = format!("{:x}", Sha256::digest(&download.stdout));
        assert_eq!(digest, sample.sha256, "{} content drift", sample.id);

        let workspace = tempfile::tempdir().expect("workflow benchmark workspace");
        let workflow_dir = workspace.path().join(".github/workflows");
        fs::create_dir_all(&workflow_dir).expect("create workflow directory");
        fs::write(workflow_dir.join("sample.yml"), &download.stdout)
            .expect("write verified workflow");

        let scan = Command::new(env!("CARGO_BIN_EXE_argus"))
            .args(["agent", "scan"])
            .arg(workspace.path())
            .args(["--format", "json"])
            .output()
            .expect("run production argus binary");
        assert!(
            matches!(scan.status.code(), Some(0 | 2)) && scan.stderr.is_empty(),
            "{} scan incomplete\nstdout:\n{}\nstderr:\n{}",
            sample.id,
            String::from_utf8_lossy(&scan.stdout),
            String::from_utf8_lossy(&scan.stderr)
        );
        let report: Value = serde_json::from_slice(&scan.stdout).expect("parse scan report");
        assert_ne!(report["decision"], "block", "{}: {report:#}", sample.id);
    }
}
