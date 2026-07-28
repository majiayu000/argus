use argus_composer::{fetch_and_scan_composer_with_rules, ComposerFetchOptions, ComposerRef};
use argus_core::{Decision, Severity};
use argus_rules::RuleSession;
use argus_test_support::MockTransport;
use sha1::{Digest, Sha1};
use std::io::Write;

const EXTERNAL_RULE_ID: &str = "composer-external-marker";

fn make_composer_zip_fixture(files: &[(&str, &[u8])]) -> Vec<u8> {
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

fn external_rule_session(off: bool) -> RuleSession {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("rules.yaml"),
        format!(
            "schema_version: 1\nrules:\n  - {{ id: \"{EXTERNAL_RULE_ID}\", description: \"external test rule\", policy_class: blocking, default_severity: high, help_uri: \"https://example.test/external-rule\", languages: [text], matcher: {{ kind: literal, pattern: \"ARGUS_EXTERNAL_RULE_MARKER\" }} }}\n"
        ),
    )
    .unwrap();
    let overrides = off
        .then(|| format!("{EXTERNAL_RULE_ID}=off"))
        .into_iter()
        .collect::<Vec<_>>();
    RuleSession::load(Some(dir.path()), &overrides).unwrap()
}

fn scan_fixture(rules: &RuleSession) -> argus_core::ScanReport {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/external/legacy.zip/refs/tags/1.0.0";
    let zip = make_composer_zip_fixture(&[
        (
            "vendor-external/composer.json",
            br#"{"name":"vendor/external","version":"1.0.0"}"#,
        ),
        (
            "vendor-external/marker.php",
            b"<?php // ARGUS_EXTERNAL_RULE_MARKER\n",
        ),
    ]);
    let shasum = hex::encode(Sha1::digest(&zip));
    let metadata = format!(
        r#"{{"packages":{{"vendor/external":[{{"version":"1.0.0","dist":{{"type":"zip","url":"{dist_url}","reference":"abc123","shasum":"{shasum}"}}}}]}}}}"#
    );
    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/vendor/external.json"),
        metadata.into_bytes(),
    );
    transport.insert(dist_url, zip);
    let options = ComposerFetchOptions {
        registry: registry.to_string(),
        ..ComposerFetchOptions::default()
    };
    fetch_and_scan_composer_with_rules(
        &ComposerRef::parse("vendor/external@1.0.0").unwrap(),
        &options,
        &transport,
        rules,
    )
    .unwrap()
}

#[test]
fn composer_external_rule_matches_and_can_be_disabled() {
    let enabled = external_rule_session(false);
    let report = scan_fixture(&enabled);
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == EXTERNAL_RULE_ID)
        .unwrap();
    let location = "vendor-external/marker.php";
    assert_eq!(
        (finding.severity, finding.location.as_deref()),
        (Severity::High, Some(location))
    );
    assert_eq!(finding.evidence, Some(vec![format!("{location}:1")]));
    assert_eq!(report.decision, Decision::Block);
    assert_eq!(report.rules.as_ref(), enabled.metadata());
    let metadata = report.rules.as_ref().unwrap();
    assert_eq!(metadata.loaded_external_files, vec!["rules.yaml"]);
    assert_eq!(metadata.external_rule_count, 1);
    assert_eq!(metadata.disabled_rule_ids, Vec::<String>::new());
    assert_eq!(metadata.applied_overrides, Vec::<String>::new());
    assert_eq!(metadata.external_rules.len(), 1);
    let external_rule = &metadata.external_rules[0];
    assert_eq!(
        (
            external_rule.id.as_str(),
            external_rule.description.as_str(),
            external_rule.help_uri.as_str(),
            external_rule.severity,
        ),
        (
            EXTERNAL_RULE_ID,
            "external test rule",
            "https://example.test/external-rule",
            Severity::High,
        )
    );

    let disabled = external_rule_session(true);
    let report = scan_fixture(&disabled);
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.rule_id == EXTERNAL_RULE_ID));
    assert_eq!(report.decision, Decision::Allow);
    assert_eq!(report.rules.as_ref(), disabled.metadata());
    let metadata = report.rules.unwrap();
    assert_eq!(metadata.disabled_rule_ids, vec![EXTERNAL_RULE_ID]);
    assert_eq!(
        metadata.applied_overrides,
        vec![format!("{EXTERNAL_RULE_ID}=off")]
    );
}
