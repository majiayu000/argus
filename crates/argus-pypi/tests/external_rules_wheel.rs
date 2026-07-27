use argus_core::Severity;
use argus_pypi::scan_wheel_zip_with_rules;
use argus_rules::RuleSession;
use std::io::Write as _;

const RULE_ID: &str = "pypi-wheel-external-marker";
const MARKER: &str = "ARGUS_WHEEL_EXTERNAL_MARKER";

fn make_wheel() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
        let options: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        writer
            .start_file("demo-1.0.0.dist-info/METADATA", options)
            .unwrap();
        writer
            .write_all(b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n")
            .unwrap();
        writer.start_file("demo/__init__.py", options).unwrap();
        writer.write_all(MARKER.as_bytes()).unwrap();
        writer.finish().unwrap();
    }
    bytes
}

fn session(off: bool) -> RuleSession {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("rules.yaml"),
        format!(
            "schema_version: 1\nrules:\n  - {{ id: \"{RULE_ID}\", description: \"wheel external rule\", policy_class: blocking, default_severity: high, help_uri: \"https://example.test/wheel-rule\", languages: [python], matcher: {{ kind: literal, pattern: \"{MARKER}\" }} }}\n"
        ),
    )
    .unwrap();
    let overrides = off
        .then(|| format!("{RULE_ID}=off"))
        .into_iter()
        .collect::<Vec<_>>();
    RuleSession::load(Some(directory.path()), &overrides).unwrap()
}

#[test]
fn wheel_external_rule_matches_and_can_be_disabled() {
    let wheel = make_wheel();
    let extracted = tempfile::tempdir().unwrap();
    let enabled = session(false);
    let scan = scan_wheel_zip_with_rules(&wheel, extracted.path(), 1024 * 1024, &enabled).unwrap();
    let finding = scan
        .findings
        .iter()
        .find(|finding| finding.rule_id == RULE_ID)
        .unwrap();
    assert_eq!(
        (
            finding.severity,
            finding.location.as_deref(),
            finding.evidence.as_deref()
        ),
        (
            Severity::High,
            Some("demo/__init__.py"),
            Some(["demo/__init__.py:1".to_string()].as_slice())
        )
    );

    let extracted = tempfile::tempdir().unwrap();
    let disabled = session(true);
    let scan = scan_wheel_zip_with_rules(&wheel, extracted.path(), 1024 * 1024, &disabled).unwrap();
    assert!(!scan
        .findings
        .iter()
        .any(|finding| finding.rule_id == RULE_ID));
}
