use argus_core::{Decision, ExecutionContext, ScanConcurrency};
use argus_pypi::{
    fetch_and_scan_pypi_with_rules_and_context, PreferredFormat, PypiFetchOptions, PypiPackageRef,
};
use argus_rules::RuleSession;
use argus_test_support::MockTransport;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};

fn pypi_jobs_sdist(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gzip);
        for (relative, body) in files {
            let mut header = tar::Header::new_gnu();
            header
                .set_path(format!("jobs-demo-1.0.0/{relative}"))
                .unwrap();
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

fn load_pypi_jobs_rules() -> RuleSession {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("rules.yaml"),
        "schema_version: 1\nrules:\n  - { id: \"pypi-jobs-marker\", \
         description: \"jobs marker\", policy_class: blocking, \
         default_severity: high, help_uri: \"https://example.test/pypi-jobs\", \
         languages: [text], matcher: { kind: literal, \
         pattern: \"ARGUS_EXTERNAL_RULE_MARKER\" } }\n",
    )
    .unwrap();
    RuleSession::load(Some(directory.path()), &[]).unwrap()
}

fn scan_pypi_jobs_fixture(
    files: &[(&str, &[u8])],
    rules: &RuleSession,
    jobs: usize,
) -> anyhow::Result<argus_core::ScanReport> {
    let registry = "https://mock.registry";
    let artifact = pypi_jobs_sdist(files);
    let artifact_url = format!("{registry}/p/jobs-demo-1.0.0.tar.gz");
    let sha256 = hex::encode(Sha256::digest(&artifact));
    let packument = format!(
        r#"{{"info":{{"name":"jobs-demo","version":"1.0.0"}},
        "releases":{{"1.0.0":[{{"filename":"jobs-demo-1.0.0.tar.gz",
        "url":"{artifact_url}","packagetype":"sdist",
        "digests":{{"sha256":"{sha256}"}}}}]}}}}"#
    );
    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/jobs-demo/json"),
        packument.into_bytes(),
    );
    transport.insert(&artifact_url, artifact);
    let options = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    let execution = ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap();
    fetch_and_scan_pypi_with_rules_and_context(
        &PypiPackageRef::parse("jobs-demo").unwrap(),
        &options,
        &transport,
        rules,
        &execution,
    )
}

fn assert_pypi_jobs_report_parity(
    files: &[(&str, &[u8])],
    rules: &RuleSession,
) -> argus_core::ScanReport {
    let mut baseline = None;
    let mut baseline_report = None;
    for jobs in [1, 2, 8, 64] {
        let report = scan_pypi_jobs_fixture(files, rules, jobs).unwrap();
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
fn pypi_positive_clean_error_and_external_are_identical_across_jobs() {
    let builtin = RuleSession::builtin().unwrap();
    let clean = assert_pypi_jobs_report_parity(
        &[(
            "setup.py",
            b"from setuptools import setup\nsetup(name='jobs-demo')\n",
        )],
        &builtin,
    );
    assert_eq!(clean.decision, Decision::Allow, "{:?}", clean.findings);

    let positive = assert_pypi_jobs_report_parity(
        &[("setup.py", b"import subprocess\nsubprocess.run(['true'])\n")],
        &builtin,
    );
    assert!(!positive.findings.is_empty());

    let external_rules = load_pypi_jobs_rules();
    let external = assert_pypi_jobs_report_parity(
        &[
            (
                "setup.py",
                b"from setuptools import setup\nsetup(name='jobs-demo')\n",
            ),
            ("marker.txt", b"ARGUS_EXTERNAL_RULE_MARKER"),
        ],
        &external_rules,
    );
    assert!(external
        .findings
        .iter()
        .any(|finding| finding.rule_id == "pypi-jobs-marker"));

    let malformed = [("setup.py", b"if True print('broken')".as_slice())];
    let mut baseline_error = None;
    for jobs in [1, 2, 8, 64] {
        let error = scan_pypi_jobs_fixture(&malformed, &builtin, jobs).unwrap_err();
        let actual = format!("{error:#}");
        assert!(actual.contains("setup.py"), "{actual}");
        if let Some(expected) = &baseline_error {
            assert_eq!(&actual, expected, "jobs={jobs}");
        } else {
            baseline_error = Some(actual);
        }
    }
}
