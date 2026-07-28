use argus_core::{Decision, ExecutionContext, ScanConcurrency, ScanReport};
use argus_maven::{fetch_and_scan_maven_with_rules_and_context, MavenFetchOptions, MavenRef};
use argus_rules::RuleSession;
use argus_test_support::MockTransport;
use sha2::{Digest, Sha256};
use std::io::Write;

const REGISTRY: &str = "https://repo1.maven.org/maven2";
const COORDINATE: &str = "com.example:jobs-parity:1.0.0";
const MANIFEST: &[u8] = b"Manifest-Version: 1.0\r\n";
const CLEAN_POM: &[u8] = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId><artifactId>jobs-parity</artifactId><version>1.0.0</version>
</project>"#;
const EVIL_POM: &[u8] = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId><artifactId>jobs-parity</artifactId><version>1.0.0</version>
  <build><plugins><plugin><groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId></plugin></plugins></build>
</project>"#;

fn make_maven_jobs_jar(files: &[(&str, &[u8])]) -> Vec<u8> {
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

fn maven_jobs_urls() -> (String, String, String) {
    let base = format!("{REGISTRY}/com/example/jobs-parity/1.0.0/jobs-parity-1.0.0");
    (
        format!("{base}.jar"),
        format!("{base}.pom"),
        format!("{base}.jar.sha256"),
    )
}

fn maven_jobs_execution(jobs: usize) -> ExecutionContext {
    ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap()
}

fn scan_maven_jobs_fixture(
    pom: &[u8],
    files: &[(&str, &[u8])],
    rules: &RuleSession,
    jobs: usize,
) -> anyhow::Result<ScanReport> {
    let bytes = make_maven_jobs_jar(files);
    let (jar_url, pom_url, sha_url) = maven_jobs_urls();
    let transport = MockTransport::new();
    transport.insert(&jar_url, bytes.clone());
    transport.insert(&pom_url, pom.to_vec());
    transport.insert(&sha_url, hex::encode(Sha256::digest(&bytes)).into_bytes());
    fetch_and_scan_maven_with_rules_and_context(
        &MavenRef::parse(COORDINATE).unwrap(),
        &MavenFetchOptions::default(),
        &transport,
        rules,
        &maven_jobs_execution(jobs),
    )
}

fn assert_maven_report_parity(
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
fn maven_builtin_reports_and_errors_are_jobs_invariant() {
    let builtin = RuleSession::builtin().unwrap();
    let positive = assert_maven_report_parity(|jobs| {
        scan_maven_jobs_fixture(
            EVIL_POM,
            &[("META-INF/MANIFEST.MF", MANIFEST)],
            &builtin,
            jobs,
        )
    });
    assert_eq!(positive.decision, Decision::Block);
    assert!(positive
        .findings
        .iter()
        .any(|finding| finding.rule_id == "maven-exec-plugin"));

    let clean = assert_maven_report_parity(|jobs| {
        scan_maven_jobs_fixture(
            CLEAN_POM,
            &[
                ("META-INF/MANIFEST.MF", MANIFEST),
                ("com/example/readme.txt", b"ordinary library"),
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
        ("META-INF/MANIFEST.MF", MANIFEST),
        ("a-invalid.txt", b"marker \xff".as_slice()),
        ("b-invalid.txt", b"marker \xfe".as_slice()),
    ];
    let error_for = |jobs| {
        format!(
            "{:#}",
            scan_maven_jobs_fixture(CLEAN_POM, &malformed, &error_rules, jobs).unwrap_err()
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
