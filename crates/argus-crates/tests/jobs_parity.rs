use argus_core::{Decision, ExecutionContext, ScanConcurrency, ScanReport};
use argus_crates::{fetch_and_scan_crate_with_rules_and_context, CrateRef, CratesFetchOptions};
use argus_rules::RuleSession;
use argus_test_support::MockTransport;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};

const REGISTRY: &str = "https://mock.registry";
const NAME: &str = "jobs-parity";
const VERSION: &str = "1.0.0";

fn make_jobs_parity_crate(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for (rel, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_path(format!("{NAME}-{VERSION}/{rel}")).unwrap();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, *body).unwrap();
        }
        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

fn crates_jobs_packument(checksum: &str) -> Vec<u8> {
    format!(
        r#"{{"crate":{{"name":"{NAME}","max_stable_version":"{VERSION}"}},"versions":[{{"num":"{VERSION}","dl_path":"/api/v1/crates/{NAME}/{VERSION}/download","checksum":"{checksum}"}}]}}"#
    )
    .into_bytes()
}

fn crates_jobs_execution(jobs: usize) -> ExecutionContext {
    ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap()
}

fn scan_crates_jobs_fixture(
    files: &[(&str, &[u8])],
    rules: &RuleSession,
    jobs: usize,
) -> anyhow::Result<ScanReport> {
    let bytes = make_jobs_parity_crate(files);
    let transport = MockTransport::new();
    transport.insert(
        &format!("{REGISTRY}/api/v1/crates/{NAME}"),
        crates_jobs_packument(&hex::encode(Sha256::digest(&bytes))),
    );
    transport.insert(
        &format!("{REGISTRY}/api/v1/crates/{NAME}/{VERSION}/download"),
        bytes,
    );
    fetch_and_scan_crate_with_rules_and_context(
        &CrateRef::parse(&format!("{NAME}@{VERSION}")).unwrap(),
        &CratesFetchOptions {
            registry: REGISTRY.to_string(),
            ..CratesFetchOptions::default()
        },
        &transport,
        rules,
        &crates_jobs_execution(jobs),
    )
}

fn assert_crates_report_parity(
    scan_case: impl Fn(usize) -> anyhow::Result<ScanReport>,
) -> ScanReport {
    let baseline = scan_case(1).unwrap();
    let baseline_json = serde_json::to_vec(&baseline).unwrap();
    for jobs in [2, 8, 64] {
        assert_eq!(
            serde_json::to_vec(&scan_case(jobs).unwrap()).unwrap(),
            baseline_json,
            "report changed with jobs={jobs}"
        );
    }
    baseline
}

#[test]
fn crates_builtin_reports_and_errors_are_jobs_invariant() {
    let manifest = b"[package]\nname=\"jobs-parity\"\nversion=\"1.0.0\"\nedition=\"2021\"\n";
    let builtin = RuleSession::builtin().unwrap();
    let positive = assert_crates_report_parity(|jobs| {
        scan_crates_jobs_fixture(
            &[
                ("Cargo.toml", manifest),
                (
                    "build.rs",
                    b"fn main(){std::process::Command::new(\"curl\").spawn().unwrap();}",
                ),
                ("src/lib.rs", b"pub fn answer() -> u8 { 42 }\n"),
            ],
            &builtin,
            jobs,
        )
    });
    assert_eq!(positive.decision, Decision::Block);
    assert!(positive
        .findings
        .iter()
        .any(|finding| finding.rule_id == "build-rs-subprocess"));

    let clean = assert_crates_report_parity(|jobs| {
        scan_crates_jobs_fixture(
            &[
                ("Cargo.toml", manifest),
                ("src/lib.rs", b"pub fn answer() -> u8 { 42 }\n"),
            ],
            &builtin,
            jobs,
        )
    });
    assert_eq!(clean.decision, Decision::Allow);

    let rules_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        rules_dir.path().join("error.yaml"),
        "schema_version: 1\nrules:\n  - { id: jobs-error, description: jobs error, \
         policy_class: blocking, default_severity: high, \
         help_uri: https://example.test/jobs-error, languages: [text], \
         matcher: { kind: literal, pattern: marker } }\n",
    )
    .unwrap();
    let error_rules = RuleSession::load(Some(rules_dir.path()), &[]).unwrap();
    let malformed = [
        ("Cargo.toml", manifest.as_slice()),
        ("a-invalid.txt", b"marker \xff".as_slice()),
        ("b-invalid.txt", b"marker \xfe".as_slice()),
    ];
    let error_for = |jobs| {
        format!(
            "{:#}",
            scan_crates_jobs_fixture(&malformed, &error_rules, jobs).unwrap_err()
        )
    };
    let baseline_error = error_for(1);
    assert!(baseline_error.contains("a-invalid.txt"), "{baseline_error}");
    for jobs in [2, 8, 64] {
        assert_eq!(
            error_for(jobs),
            baseline_error,
            "error changed with jobs={jobs}"
        );
    }
}
