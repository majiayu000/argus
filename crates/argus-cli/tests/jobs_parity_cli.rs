use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .env("PATH", "/argus-test-no-executables")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .output()
        .unwrap()
}

fn assert_decision(format: &str, output: &Output) {
    match format {
        "text" => {
            assert!(String::from_utf8_lossy(&output.stdout).contains("decision: block"));
        }
        "json" => {
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["decision"], "block");
        }
        "sarif" => {
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            let results = report["runs"][0]["results"].as_array().unwrap();
            assert!(!results.is_empty());
            assert!(results
                .iter()
                .any(|result| result["properties"]["decision"] == "block"));
        }
        other => panic!("unexpected format {other}"),
    }
}

#[test]
fn real_scan_output_and_exit_are_byte_identical_across_jobs_and_repeats() {
    // `argus-rules/tests/scanner_concurrency.rs` forces deliberate worker
    // reordering with a barrier and proves the underlying scanner actually
    // uses multiple invocation-local workers. This CLI test freezes the
    // resulting user-visible reduction across repeated processes.
    let fixture = repository_root().join("corpus/fixtures/lifecycle-curl-sh");
    let fixture = fixture.to_str().unwrap();
    for format in ["text", "json", "sarif"] {
        let mut baseline: Option<(Option<i32>, Vec<u8>, Vec<u8>)> = None;
        for jobs in ["1", "2", "8", "64"] {
            for _ in 0..20 {
                let output = invoke(&["scan", fixture, "--format", format, "--jobs", jobs]);
                assert_eq!(output.status.code(), Some(1));
                assert!(output.stderr.is_empty());
                assert_decision(format, &output);
                let actual = (
                    output.status.code(),
                    output.stdout.clone(),
                    output.stderr.clone(),
                );
                if let Some(expected) = &baseline {
                    assert_eq!(&actual, expected, "format={format}, jobs={jobs}");
                } else {
                    baseline = Some(actual);
                }
            }
        }
    }
}

#[test]
fn flattened_osv_route_has_identical_behavior_for_every_jobs_value() {
    let temporary = tempfile::tempdir().unwrap();
    let package = temporary.path().join("package");
    let cache = temporary.path().join("osv-cache");
    fs::create_dir(&package).unwrap();
    fs::create_dir(&cache).unwrap();
    fs::write(
        package.join("package.json"),
        br#"{"name":"jobs-osv-route","version":"1.0.0"}"#,
    )
    .unwrap();
    let package = package.to_str().unwrap();
    let cache = cache.to_str().unwrap();
    let mut baseline: Option<(Option<i32>, Vec<u8>, Vec<u8>)> = None;

    for jobs in ["1", "2", "8", "64"] {
        for _ in 0..20 {
            let output = invoke(&[
                "scan",
                package,
                "--format",
                "json",
                "--osv",
                "--osv-cache-dir",
                cache,
                "--osv-offline",
                "--jobs",
                jobs,
            ]);
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains("--osv requires a trusted resolved package coordinate"));
            let actual = (
                output.status.code(),
                output.stdout.clone(),
                output.stderr.clone(),
            );
            if let Some(expected) = &baseline {
                assert_eq!(&actual, expected, "jobs={jobs}");
            } else {
                baseline = Some(actual);
            }
        }
    }
}
