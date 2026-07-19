#[allow(dead_code)]
#[derive(Clone, Copy)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[allow(dead_code)]
#[path = "../src/intel.rs"]
mod intel;
#[allow(dead_code)]
#[path = "../src/report.rs"]
mod report;
#[path = "../src/sarif.rs"]
mod sarif;

use argus_core::{
    ArtifactKind, Decision, Ecosystem, IntelMatchStatus, PackageCoordinate, ScanReport, Severity,
};
use argus_intel::{
    AtomicCleanupState, AtomicWriteOutcome, ImportOutcome, IntelDatabase as SnapshotDatabase,
};
use chrono::{TimeZone as _, Utc};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ACTIVE_SNAPSHOT: &str = r#"{"format_version":1,"source":"https://github.com/ossf/malicious-packages","revision":"1111111111111111111111111111111111111111","schema_versions":["1.7.4"],"archive_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","records_sha256":"71a1e333968c06304314aa8bdbfdfdf9c7b4a4d5f46c26b86ef169f23e364c5f","imported_at":"2020-01-01T00:00:00Z","records":[{"advisory_id":"MAL-TEST-1","aliases":["GHSA-test-test-test"],"affected":[{"ecosystem":"npm","original_ecosystem":"npm","canonical_name":"demo","original_name":"demo","exact_versions":["1.0.0"],"ranges":[]}]}],"snapshot_sha256":"b46fb914811f9a632eae82377eb3b67c9524ad3de942b86dd690fcef6735fc42"}"#;
const FUTURE_SNAPSHOT: &str = r#"{"format_version":1,"source":"https://github.com/ossf/malicious-packages","revision":"1111111111111111111111111111111111111111","schema_versions":["1.7.4"],"archive_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","records_sha256":"71a1e333968c06304314aa8bdbfdfdf9c7b4a4d5f46c26b86ef169f23e364c5f","imported_at":"2999-01-01T00:00:00Z","records":[{"advisory_id":"MAL-TEST-1","aliases":["GHSA-test-test-test"],"affected":[{"ecosystem":"npm","original_ecosystem":"npm","canonical_name":"demo","original_name":"demo","exact_versions":["1.0.0"],"ranges":[]}]}],"snapshot_sha256":"d767ca3afbfe0c878f10752b0416be348be9febcf9e489d5497805cf0205cdf5"}"#;
const ECOSYSTEM_MATRIX_SNAPSHOT: &str = r#"{"format_version":1,"source":"https://github.com/ossf/malicious-packages","revision":"2222222222222222222222222222222222222222","schema_versions":["1.7.4"],"archive_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","records_sha256":"db4ae62ea935d8b59c8e92dc3c9ab419d37a0123c17659fd53ef3ef7c00c05cd","imported_at":"2020-01-01T00:00:00Z","records":[{"advisory_id":"MAL-001-NPM","aliases":[],"affected":[{"ecosystem":"npm","original_ecosystem":"npm","canonical_name":"demo","original_name":"Demo","exact_versions":["1.0.0"],"ranges":[]}]},{"advisory_id":"MAL-002-PYPI","aliases":["GHSA-PYPI-TEST"],"affected":[{"ecosystem":"PyPI","original_ecosystem":"PyPI","canonical_name":"demo-pkg","original_name":"Demo_Pkg","exact_versions":[],"ranges":[{"range_type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"3.0.0"}]}]}]},{"advisory_id":"MAL-003-CRATES","aliases":[],"affected":[{"ecosystem":"crates.io","original_ecosystem":"crates.io","canonical_name":"demo_crate","original_name":"Demo_Crate","exact_versions":["1.2.3"],"ranges":[]}]},{"advisory_id":"MAL-004-GO","aliases":[],"affected":[{"ecosystem":"Go","original_ecosystem":"Go","canonical_name":"example.com/Owner/Module","original_name":"example.com/Owner/Module","exact_versions":[],"ranges":[{"range_type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]},{"advisory_id":"MAL-005-NUGET","aliases":[],"affected":[{"ecosystem":"NuGet","original_ecosystem":"NuGet","canonical_name":"demo.package","original_name":"Demo.Package","exact_versions":["4.5.6"],"ranges":[]}]},{"advisory_id":"MAL-006-MAVEN","aliases":[],"affected":[{"ecosystem":"Maven","original_ecosystem":"Maven","canonical_name":"com.example:demo","original_name":"com.example:demo","exact_versions":[],"ranges":[{"range_type":"ECOSYSTEM","events":[{"introduced":"2.0.0"},{"last_affected":"2.9.9"}]}]}]},{"advisory_id":"MAL-007-RUBYGEMS","aliases":[],"affected":[{"ecosystem":"RubyGems","original_ecosystem":"RubyGems","canonical_name":"DemoGem","original_name":"DemoGem","exact_versions":["3.2.1"],"ranges":[]}]},{"advisory_id":"MAL-008-PACKAGIST","aliases":[],"affected":[{"ecosystem":"Packagist","original_ecosystem":"Packagist","canonical_name":"vendor/package","original_name":"Vendor/Package","exact_versions":[],"ranges":[{"range_type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]},{"advisory_id":"MAL-009-WITHDRAWN","aliases":["GHSA-WITHDRAWN"],"withdrawn":"2020-01-01T00:00:00Z","affected":[{"ecosystem":"npm","original_ecosystem":"npm","canonical_name":"withdrawn-demo","original_name":"withdrawn-demo","exact_versions":["9.9.9"],"ranges":[]}]}],"snapshot_sha256":"d8c95026e7c0ae806b8150d143ef3a86e87f1436eddd62ae737fd3c3515e28ed"}"#;
const CROSS_ECOSYSTEM_SNAPSHOT: &str = r#"{"format_version":1,"source":"https://github.com/ossf/malicious-packages","revision":"3333333333333333333333333333333333333333","schema_versions":["1.7.4"],"archive_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","records_sha256":"687d5fe566d281c489adbff67a8b84d0fe675943e2cb946acacd39aa86b0dea1","imported_at":"2020-01-01T00:00:00Z","records":[{"advisory_id":"MAL-CROSS-NPM","aliases":[],"affected":[{"ecosystem":"npm","original_ecosystem":"npm","canonical_name":"shared-name","original_name":"shared-name","exact_versions":["1.0.0"],"ranges":[]}]}],"snapshot_sha256":"60c35cdcd9f89aca0c9c4f2c15bbefd6b44bbb3fd7607ac13230c98ab15a2446"}"#;

fn argus(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .output()
        .expect("run argus CLI")
}

fn write_snapshot(directory: &Path, name: &str, contents: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).expect("write synthetic intelligence snapshot");
    path
}

fn local_tempdir() -> tempfile::TempDir {
    let canonical_root = fs::canonicalize(std::env::current_dir().expect("current test directory"))
        .expect("canonical test directory");
    tempfile::Builder::new()
        .prefix(".argus-intel-cli-test-")
        .tempdir_in(canonical_root)
        .expect("local tempdir")
}

fn scan_started_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 0)
        .single()
        .expect("fixed scan clock")
}

fn synthetic_report(ecosystem: Ecosystem, name: &str, version: &str) -> ScanReport {
    ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: PathBuf::from(format!("{name}@{version}")),
        package_name: Some(name.to_string()),
        package_version: Some(version.to_string()),
        decision: Decision::Allow,
        findings: Vec::new(),
        coordinate: Some(
            PackageCoordinate::new(ecosystem, name, version).expect("synthetic coordinate"),
        ),
        intelligence: None,
    }
}

#[test]
fn matching_snapshot_blocks_with_complete_evidence() {
    let directory = local_tempdir();
    let database = write_snapshot(directory.path(), "active.json", ACTIVE_SNAPSHOT);
    let mut report = synthetic_report(Ecosystem::Npm, "demo", "1.0.0");

    intel::apply_malicious_snapshot(&mut report, Some(&database), scan_started_at())
        .expect("apply matching snapshot");

    assert_eq!(report.decision, Decision::Block);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "known-malicious-package");
    assert_eq!(report.findings[0].severity, Severity::Critical);
    let evidence = report.findings[0]
        .evidence
        .as_ref()
        .expect("malicious finding evidence");
    assert!(evidence.iter().any(|item| item == "advisory=MAL-TEST-1"));
    assert!(evidence
        .iter()
        .any(|item| item == "source_revision=1111111111111111111111111111111111111111"));
    assert_eq!(
        report.intelligence.as_ref().expect("intelligence").status,
        IntelMatchStatus::Matched
    );
}

#[test]
fn no_match_scope() {
    let directory = local_tempdir();
    let database = write_snapshot(directory.path(), "active.json", ACTIVE_SNAPSHOT);
    let mut report = synthetic_report(Ecosystem::Npm, "demo", "1.0.1");

    intel::apply_malicious_snapshot(&mut report, Some(&database), scan_started_at())
        .expect("apply non-matching snapshot");

    assert_eq!(report.decision, Decision::Allow);
    assert!(report.findings.is_empty());
    let status = report.intelligence.as_ref().expect("intelligence");
    assert_eq!(status.status, IntelMatchStatus::NoMatch);
    assert_eq!(status.age_seconds, 86_400);

    let text = report::render_report_text(&report);
    assert!(text.contains("malicious intelligence:"));
    assert!(text.contains("status: no_match"));
    assert!(text.contains("records_sha256: 71a1e333"));
    assert!(text.contains("findings: none"));

    let json = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(json["intelligence"]["status"], "no_match");
    assert_eq!(json["intelligence"]["age_seconds"], 86_400);

    let sarif = sarif::render_reports(&[report]).expect("render SARIF");
    assert_eq!(
        sarif["runs"][0]["properties"]["argusIntelligence"]["status"],
        "no_match"
    );
    assert_eq!(sarif["runs"][0]["results"], serde_json::json!([]));
}

#[test]
fn disabled_database_is_a_byte_for_byte_noop() {
    let mut report = synthetic_report(Ecosystem::Npm, "demo", "1.0.0");
    let before = serde_json::to_vec(&report).expect("serialize before");
    intel::apply_malicious_snapshot(&mut report, None, scan_started_at())
        .expect("disabled intelligence");
    let after = serde_json::to_vec(&report).expect("serialize after");
    assert_eq!(after, before);
}

#[test]
fn corrupt_db_and_future_snapshot_fail_before_mutating_report() {
    let directory = local_tempdir();
    let corrupt = write_snapshot(directory.path(), "corrupt.json", "{}");
    let future = write_snapshot(directory.path(), "future.json", FUTURE_SNAPSHOT);

    for database in [&corrupt, &future] {
        let mut report = synthetic_report(Ecosystem::Npm, "demo", "1.0.0");
        let before = serde_json::to_vec(&report).expect("serialize before");
        let error = intel::apply_malicious_snapshot(&mut report, Some(database), scan_started_at())
            .expect_err("invalid snapshot must fail");
        assert!(!error.to_string().is_empty());
        assert_eq!(
            serde_json::to_vec(&report).expect("serialize after"),
            before
        );
    }
}

#[test]
fn sarif_intelligence_properties() {
    let directory = local_tempdir();
    let database = write_snapshot(directory.path(), "active.json", ACTIVE_SNAPSHOT);
    let mut report = synthetic_report(Ecosystem::Npm, "demo", "1.0.1");
    intel::apply_malicious_snapshot(&mut report, Some(&database), scan_started_at())
        .expect("apply non-matching snapshot");
    let document = sarif::render_reports(&[report]).expect("render intelligence SARIF");
    assert_eq!(
        document["runs"][0]["properties"]["argusIntelligence"]["status"],
        "no_match"
    );

    let disabled = synthetic_report(Ecosystem::Npm, "demo", "1.0.1");
    let document = sarif::render_reports(&[disabled]).expect("render disabled SARIF");
    assert!(document["runs"][0].get("properties").is_none());
}

#[test]
fn all_eight_ecosystems_match_and_block_through_shared_postprocessor() {
    let directory = local_tempdir();
    let database = write_snapshot(
        directory.path(),
        "ecosystem-matrix.json",
        ECOSYSTEM_MATRIX_SNAPSHOT,
    );
    let cases = [
        (
            Ecosystem::Npm,
            "Demo",
            "1.0.0",
            "npm",
            "demo",
            "MAL-001-NPM",
            "match_basis=exact:",
        ),
        (
            Ecosystem::PyPi,
            "Demo_Pkg",
            "2.0.0",
            "PyPI",
            "demo-pkg",
            "MAL-002-PYPI",
            "match_basis=range:",
        ),
        (
            Ecosystem::CratesIo,
            "Demo_Crate",
            "1.2.3",
            "crates.io",
            "demo_crate",
            "MAL-003-CRATES",
            "match_basis=exact:",
        ),
        (
            Ecosystem::Go,
            "example.com/Owner/Module",
            "v1.5.0",
            "Go",
            "example.com/Owner/Module",
            "MAL-004-GO",
            "match_basis=range:",
        ),
        (
            Ecosystem::NuGet,
            "Demo.Package",
            "4.5.6",
            "NuGet",
            "demo.package",
            "MAL-005-NUGET",
            "match_basis=exact:",
        ),
        (
            Ecosystem::Maven,
            "com.example:demo",
            "2.5.0",
            "Maven",
            "com.example:demo",
            "MAL-006-MAVEN",
            "match_basis=range:",
        ),
        (
            Ecosystem::RubyGems,
            "DemoGem",
            "3.2.1",
            "RubyGems",
            "DemoGem",
            "MAL-007-RUBYGEMS",
            "match_basis=exact:",
        ),
        (
            Ecosystem::Packagist,
            "Vendor/Package",
            "1.5.0",
            "Packagist",
            "vendor/package",
            "MAL-008-PACKAGIST",
            "match_basis=range:",
        ),
    ];

    let mut reports = Vec::new();
    for (ecosystem, name, version, ecosystem_name, canonical_name, advisory, match_basis) in cases {
        let mut report = synthetic_report(ecosystem, name, version);
        intel::apply_malicious_snapshot(&mut report, Some(&database), scan_started_at())
            .expect("apply matching ecosystem snapshot");
        assert_eq!(report.decision, Decision::Block, "ecosystem={ecosystem:?}");
        assert_eq!(report.findings.len(), 1, "ecosystem={ecosystem:?}");
        assert_eq!(report.findings[0].rule_id, "known-malicious-package");
        assert_eq!(report.findings[0].severity, Severity::Critical);
        assert_eq!(
            report.intelligence.as_ref().expect("intelligence").status,
            IntelMatchStatus::Matched,
            "ecosystem={ecosystem:?}"
        );
        let evidence = report.findings[0].evidence.as_ref().expect("evidence");
        assert!(evidence
            .iter()
            .any(|item| item == &format!("advisory={advisory}")));
        assert!(evidence.iter().any(|item| item.starts_with(match_basis)));

        let json = serde_json::to_value(&report).expect("serialize ecosystem report");
        assert_eq!(json["coordinate"]["ecosystem"], ecosystem_name);
        assert_eq!(json["coordinate"]["canonical_name"], canonical_name);
        assert_eq!(json["intelligence"]["status"], "matched");
        assert_eq!(json["findings"][0]["rule_id"], "known-malicious-package");
        assert_eq!(json["findings"][0]["severity"], "critical");
        for field in [
            "ecosystem",
            "canonical_name",
            "version",
            "purl",
            "original_ecosystem",
            "original_name",
            "original_version",
        ] {
            assert!(!json["coordinate"][field].is_null(), "coordinate.{field}");
        }
        for field in [
            "source",
            "revision",
            "imported_at",
            "age_seconds",
            "archive_sha256",
            "records_sha256",
            "snapshot_sha256",
            "status",
        ] {
            assert!(
                !json["intelligence"][field].is_null(),
                "intelligence.{field}"
            );
        }
        for field in ["rule_id", "severity", "detail", "evidence"] {
            assert!(!json["findings"][0][field].is_null(), "finding.{field}");
        }

        let text = report::render_report_text(&report);
        assert!(text.contains("decision: block"));
        assert!(text.contains("status: matched"));
        assert!(text.contains("known-malicious-package"));
        reports.push(report);
    }

    let sarif = sarif::render_reports(&reports).expect("render ecosystem matrix SARIF");
    assert_eq!(
        sarif["runs"][0]["properties"]["argusIntelligence"]["status"],
        "matched"
    );
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("SARIF results");
    assert_eq!(results.len(), 8);
    assert!(results.iter().all(|result| {
        result["ruleId"] == "known-malicious-package" && result["level"] == "error"
    }));
    let npm_evidence = reports[0].findings[0]
        .evidence
        .as_ref()
        .expect("npm evidence");
    assert!(npm_evidence.iter().any(|item| item == "aliases="));
    let pypi_evidence = reports[1].findings[0]
        .evidence
        .as_ref()
        .expect("PyPI evidence");
    assert!(pypi_evidence
        .iter()
        .any(|item| item == "aliases=GHSA-PYPI-TEST"));
}

#[test]
fn withdrawn_record_is_a_clean_no_match_with_snapshot_properties() {
    let directory = local_tempdir();
    let database = write_snapshot(
        directory.path(),
        "ecosystem-matrix.json",
        ECOSYSTEM_MATRIX_SNAPSHOT,
    );
    let mut report = synthetic_report(Ecosystem::Npm, "withdrawn-demo", "9.9.9");
    intel::apply_malicious_snapshot(&mut report, Some(&database), scan_started_at())
        .expect("apply withdrawn snapshot");

    assert_eq!(report.decision, Decision::Allow);
    assert!(report.findings.is_empty());
    assert_eq!(
        report.intelligence.as_ref().expect("intelligence").status,
        IntelMatchStatus::NoMatch
    );
    let text = report::render_report_text(&report);
    assert!(text.contains("status: no_match"));
    assert!(text.contains("findings: none"));
    let sarif = sarif::render_reports(&[report]).expect("render withdrawn SARIF");
    assert_eq!(sarif["runs"][0]["results"], serde_json::json!([]));
    assert_eq!(
        sarif["runs"][0]["properties"]["argusIntelligence"]["status"],
        "no_match"
    );
}

#[test]
fn same_name_in_different_ecosystems_does_not_cross_match_in_any_output() {
    let directory = local_tempdir();
    let database = write_snapshot(
        directory.path(),
        "cross-ecosystem.json",
        CROSS_ECOSYSTEM_SNAPSHOT,
    );
    let mut npm = synthetic_report(Ecosystem::Npm, "shared-name", "1.0.0");
    let mut pypi = synthetic_report(Ecosystem::PyPi, "shared-name", "1.0.0");

    intel::apply_malicious_snapshot(&mut npm, Some(&database), scan_started_at())
        .expect("apply npm same-name snapshot");
    intel::apply_malicious_snapshot(&mut pypi, Some(&database), scan_started_at())
        .expect("apply PyPI same-name snapshot");

    assert_eq!(
        npm.coordinate
            .as_ref()
            .expect("npm coordinate")
            .canonical_name,
        pypi.coordinate
            .as_ref()
            .expect("PyPI coordinate")
            .canonical_name
    );
    assert_eq!(npm.decision, Decision::Block);
    assert_eq!(npm.findings.len(), 1);
    assert_eq!(
        npm.intelligence.as_ref().expect("npm intelligence").status,
        IntelMatchStatus::Matched
    );
    assert_eq!(pypi.decision, Decision::Allow);
    assert!(pypi.findings.is_empty());
    assert_eq!(
        pypi.intelligence
            .as_ref()
            .expect("PyPI intelligence")
            .status,
        IntelMatchStatus::NoMatch
    );

    let npm_text = report::render_report_text(&npm);
    assert!(npm_text.contains("decision: block"));
    assert!(npm_text.contains("status: matched"));
    assert!(npm_text.contains("MAL-CROSS-NPM"));
    let pypi_text = report::render_report_text(&pypi);
    assert!(pypi_text.contains("decision: allow"));
    assert!(pypi_text.contains("status: no_match"));
    assert!(pypi_text.contains("findings: none"));
    assert!(!pypi_text.contains("MAL-CROSS-NPM"));

    let npm_json = serde_json::to_value(&npm).expect("serialize npm same-name report");
    let pypi_json = serde_json::to_value(&pypi).expect("serialize PyPI same-name report");
    assert_eq!(npm_json["coordinate"]["ecosystem"], "npm");
    assert_eq!(npm_json["intelligence"]["status"], "matched");
    assert_eq!(
        npm_json["findings"][0]["evidence"]
            .as_array()
            .expect("npm evidence")
            .iter()
            .find(|item| item.as_str() == Some("advisory=MAL-CROSS-NPM"))
            .and_then(Value::as_str),
        Some("advisory=MAL-CROSS-NPM")
    );
    assert_eq!(pypi_json["coordinate"]["ecosystem"], "PyPI");
    assert_eq!(pypi_json["intelligence"]["status"], "no_match");
    assert_eq!(pypi_json["findings"], serde_json::json!([]));

    let npm_sarif = sarif::render_reports(&[npm]).expect("render npm same-name SARIF");
    assert_eq!(
        npm_sarif["runs"][0]["properties"]["argusIntelligence"]["status"],
        "matched"
    );
    assert_eq!(
        npm_sarif["runs"][0]["results"]
            .as_array()
            .expect("npm SARIF results")
            .len(),
        1
    );
    let pypi_sarif = sarif::render_reports(&[pypi]).expect("render PyPI same-name SARIF");
    assert_eq!(
        pypi_sarif["runs"][0]["properties"]["argusIntelligence"]["status"],
        "no_match"
    );
    assert_eq!(pypi_sarif["runs"][0]["results"], serde_json::json!([]));
}

#[test]
fn cli_exposes_frozen_intel_syntax_and_validates_status_offline() {
    let import_help = argus(&["intel", "import", "--help"]);
    assert!(import_help.status.success());
    let help = String::from_utf8_lossy(&import_help.stdout);
    for flag in ["--source", "--revision", "--output"] {
        assert!(help.contains(flag), "{help}");
    }
    for command in [
        "scan",
        "fetch",
        "pypi-fetch",
        "crates-fetch",
        "go-fetch",
        "nuget-fetch",
        "maven-fetch",
        "gems-fetch",
        "composer-fetch",
    ] {
        let help = argus(&[command, "--help"]);
        assert!(help.status.success(), "command={command}");
        assert!(
            String::from_utf8_lossy(&help.stdout).contains("--malicious-db"),
            "command={command}"
        );
    }

    let directory = local_tempdir();
    let database = write_snapshot(
        directory.path(),
        "ecosystem-matrix.json",
        ECOSYSTEM_MATRIX_SNAPSHOT,
    );
    let status = argus(&["intel", "status", "--db", database.to_str().unwrap()]);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let output = String::from_utf8_lossy(&status.stdout);
    assert!(output.contains("malicious intelligence snapshot:"));
    assert!(output.contains("active_records: 8"), "{output}");
    assert!(output.contains("withdrawn_records: 1"), "{output}");
}

#[test]
fn import_cleanup_outcomes_are_reported_without_overstating_backup_state() {
    let directory = local_tempdir();
    let database = write_snapshot(directory.path(), "active.json", ACTIVE_SNAPSHOT);
    let snapshot = SnapshotDatabase::load(&database)
        .expect("load import outcome fixture")
        .snapshot()
        .clone();
    let cases = [
        (AtomicWriteOutcome::Committed, None),
        (
            AtomicWriteOutcome::CommittedWithCleanupWarning {
                backup_name: ".argus-intel-old-pending".to_string(),
                state: AtomicCleanupState::Pending,
                cause: "permission denied".to_string(),
            },
            Some(AtomicCleanupState::Pending),
        ),
        (
            AtomicWriteOutcome::CommittedWithCleanupWarning {
                backup_name: ".argus-intel-old-uncertain".to_string(),
                state: AtomicCleanupState::DurabilityUncertain,
                cause: "directory fsync failed".to_string(),
            },
            Some(AtomicCleanupState::DurabilityUncertain),
        ),
    ];

    for (atomic_outcome, expected_warning) in cases {
        let outcome = ImportOutcome {
            snapshot: snapshot.clone(),
            atomic_outcome,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        intel::write_import_outcome(&outcome, &database, &mut stdout, &mut stderr)
            .expect("write import outcome");
        let stdout = String::from_utf8(stdout).expect("UTF-8 stdout");
        let stderr = String::from_utf8(stderr).expect("UTF-8 stderr");

        assert!(stdout.contains("malicious intelligence snapshot:"));
        assert!(stdout.contains("active_records: 1"));
        assert!(stdout.contains("withdrawn_records: 0"));
        match expected_warning {
            None => assert!(stderr.is_empty()),
            Some(AtomicCleanupState::Pending) => {
                assert!(stderr.starts_with("warning: malicious intelligence snapshot committed"));
                assert!(stderr.contains(r#"retained_backup=".argus-intel-old-pending""#));
                assert!(stderr.contains(r#"cause="permission denied""#));
                assert!(!stderr.contains("durability is uncertain"));
            }
            Some(AtomicCleanupState::DurabilityUncertain) => {
                assert!(stderr.starts_with("warning: malicious intelligence snapshot committed"));
                assert!(stderr.contains("backup cleanup durability is uncertain"));
                assert!(stderr.contains(r#"backup_identifier=".argus-intel-old-uncertain""#));
                assert!(stderr.contains(r#"cause="directory fsync failed""#));
                assert!(!stderr.contains("retained_backup"));
            }
        }
    }
}

#[test]
fn ordinary_scan_rejects_malicious_database_without_trusted_coordinate() {
    let directory = local_tempdir();
    fs::write(
        directory.path().join("package.json"),
        r#"{"name":"demo","version":"1.0.0"}"#,
    )
    .expect("write package");
    let database = write_snapshot(directory.path(), "active.json", ACTIVE_SNAPSHOT);
    let output = argus(&[
        "scan",
        directory.path().to_str().unwrap(),
        "--malicious-db",
        database.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("trusted resolved package coordinate"));
}

#[test]
fn default_scan_output_omits_intelligence_fields() {
    let directory = local_tempdir();
    fs::write(
        directory.path().join("package.json"),
        r#"{"name":"demo","version":"1.0.0"}"#,
    )
    .expect("write package");
    let output = argus(&[
        "scan",
        directory.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid report JSON");
    assert!(json.get("intelligence").is_none());
    assert!(json.get("coordinate").is_none());
}
