use super::*;
use argus_core::{ArtifactKind, Decision};
use std::fs;
use tempfile::TempDir;

const HELP: &str = "https://example.test/rules#external";

fn rule(id: &str, language: &str, matcher: &str, severity: &str, policy: &str) -> String {
    format!(
        r#"{{ id: "{id}", description: "external description", policy_class: {policy}, default_severity: {severity}, help_uri: "{HELP}", languages: [{language}], matcher: {matcher} }}"#
    )
}

fn catalog(records: &[String]) -> String {
    format!(
        "schema_version: 1\nrules:\n  - {}\n",
        records.join("\n  - ")
    )
}

fn write_catalog(root: &Path, rel: &str, records: &[String]) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, catalog(records)).unwrap();
}

fn report(findings: Vec<Finding>) -> ScanReport {
    ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: "fixture".into(),
        package_name: None,
        package_version: None,
        decision: Decision::Allow,
        findings,
        coordinate: None,
        intelligence: None,
        rules: None,
    }
}

#[test]
fn loads_sorted_catalogs_and_matches_literal_regex_language_and_line() {
    let temp = TempDir::new().unwrap();
    write_catalog(
        temp.path(),
        "z/rules.yml",
        &[rule(
            "z-regex",
            "python",
            r#"{ kind: regex, pattern: "t.ke[nN]" }"#,
            "medium",
            "approval-only",
        )],
    );
    write_catalog(
        temp.path(),
        "a.yaml",
        &[rule(
            "a-literal",
            "javascript",
            r#"{ kind: literal, pattern: "TOKEN" }"#,
            "high",
            "blocking",
        )],
    );
    fs::write(temp.path().join("README.md"), "ignored companion").unwrap();
    let session = RuleSession::load(Some(temp.path()), &[]).unwrap();
    assert_eq!(
        session.metadata().unwrap().loaded_external_files,
        vec!["a.yaml", "z/rules.yml"]
    );
    let mut findings = Vec::new();
    session
        .scan_bytes(
            "src/index.js",
            b"first\nconst secret = TOKEN;\n",
            &mut findings,
        )
        .unwrap();
    session
        .scan_bytes("src/index.py", b"token = 1\n", &mut findings)
        .unwrap();
    session
        .scan_bytes("src/index.rs", b"TOKEN token\n", &mut findings)
        .unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].rule_id, "a-literal");
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].detail, "external description");
    assert_eq!(findings[0].location.as_deref(), Some("src/index.js"));
    assert_eq!(
        findings[0].evidence.as_deref(),
        Some(["src/index.js:2".to_string()].as_slice())
    );
    assert_eq!(findings[1].rule_id, "z-regex");
}

#[test]
fn script_extension_case_and_line_boundaries_are_closed() {
    let temp = TempDir::new().unwrap();
    write_catalog(
        temp.path(),
        "rules.yaml",
        &[
            rule(
                "javascript-marker",
                "javascript",
                r#"{ kind: literal, pattern: "JS_MARKER" }"#,
                "low",
                "blocking",
            ),
            rule(
                "python-marker",
                "python",
                r#"{ kind: literal, pattern: "PY_MARKER" }"#,
                "low",
                "blocking",
            ),
            rule(
                "typescript-marker",
                "typescript",
                r#"{ kind: literal, pattern: "TS_MARKER" }"#,
                "low",
                "blocking",
            ),
        ],
    );
    let session = RuleSession::load(Some(temp.path()), &[]).unwrap();
    let mut findings = Vec::new();
    session
        .scan_bytes("types.PYI", "多字节\r\nPY_MARKER".as_bytes(), &mut findings)
        .unwrap();
    session
        .scan_bytes("view.JsX", b"JS_MARKER", &mut findings)
        .unwrap();
    session
        .scan_bytes("view.TsX", b"first\nTS_MARKER\n", &mut findings)
        .unwrap();
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0].evidence.as_deref().unwrap(), ["types.PYI:2"]);
    assert_eq!(findings[1].evidence.as_deref().unwrap(), ["view.JsX:1"]);
    assert_eq!(findings[2].evidence.as_deref().unwrap(), ["view.TsX:2"]);
}

#[test]
fn overrides_are_typed_auditable_and_preserve_package_policy() {
    let temp = TempDir::new().unwrap();
    write_catalog(
        temp.path(),
        "rules.yaml",
        &[
            rule(
                "external-off",
                "text",
                r#"{ kind: literal, pattern: "needle" }"#,
                "high",
                "blocking",
            ),
            rule(
                "external-low",
                "text",
                r#"{ kind: literal, pattern: "other" }"#,
                "high",
                "blocking",
            ),
        ],
    );
    let overrides = vec![
        "external-off=off".to_string(),
        "external-low=severity:info".to_string(),
    ];
    let session = RuleSession::load(Some(temp.path()), &overrides).unwrap();
    let mut findings = Vec::new();
    session
        .scan_bytes("data.txt", b"needle other", &mut findings)
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "external-low");
    assert_eq!(findings[0].severity, Severity::Info);
    let mut report = report(findings);
    session.finalize_package(&mut report);
    assert_eq!(report.decision, Decision::Block);
    let metadata = report.rules.unwrap();
    assert_eq!(metadata.disabled_rule_ids, vec!["external-off"]);
    assert_eq!(
        metadata.applied_overrides,
        vec!["external-low=severity:info", "external-off=off"]
    );
}

#[test]
fn external_policy_classes_drive_package_decisions() {
    let temp = TempDir::new().unwrap();
    write_catalog(
        temp.path(),
        "rules.yaml",
        &[
            rule(
                "external-approval",
                "text",
                r#"{ kind: literal, pattern: "approval" }"#,
                "medium",
                "approval-only",
            ),
            rule(
                "external-info",
                "text",
                r#"{ kind: literal, pattern: "informational" }"#,
                "info",
                "info-only",
            ),
        ],
    );
    let session = RuleSession::load(Some(temp.path()), &[]).unwrap();

    let mut approval_findings = Vec::new();
    session
        .scan_bytes("approval.txt", b"approval", &mut approval_findings)
        .unwrap();
    let mut approval = report(approval_findings);
    session.finalize_package(&mut approval);
    assert_eq!(approval.decision, Decision::AllowWithApproval);

    let mut info_findings = Vec::new();
    session
        .scan_bytes("info.txt", b"informational", &mut info_findings)
        .unwrap();
    let mut info = report(info_findings);
    session.finalize_package(&mut info);
    assert_eq!(info.decision, Decision::Allow);
}

#[test]
fn invalid_duplicate_collision_and_bad_regex_fail_the_whole_directory() {
    let temp = TempDir::new().unwrap();
    let valid = rule(
        "external-valid",
        "text",
        r#"{ kind: literal, pattern: "ok" }"#,
        "low",
        "blocking",
    );
    write_catalog(temp.path(), "a.yaml", std::slice::from_ref(&valid));
    fs::write(temp.path().join("b.yaml"), "not: [valid").unwrap();
    assert!(RuleSession::load(Some(temp.path()), &[]).is_err());
    fs::remove_file(temp.path().join("b.yaml")).unwrap();
    write_catalog(temp.path(), "b.yaml", &[valid]);
    assert!(RuleSession::load(Some(temp.path()), &[]).is_err());
    fs::remove_file(temp.path().join("b.yaml")).unwrap();
    write_catalog(
        temp.path(),
        "b.yaml",
        &[rule(
            "remote-download",
            "text",
            r#"{ kind: literal, pattern: "x" }"#,
            "high",
            "blocking",
        )],
    );
    assert!(RuleSession::load(Some(temp.path()), &[]).is_err());
    fs::remove_file(temp.path().join("b.yaml")).unwrap();
    write_catalog(
        temp.path(),
        "b.yaml",
        &[rule(
            "bad-regex",
            "text",
            r#"{ kind: regex, pattern: "[" }"#,
            "high",
            "blocking",
        )],
    );
    assert!(RuleSession::load(Some(temp.path()), &[]).is_err());
}

#[test]
fn empty_selected_directory_is_auditable_and_unknown_override_fails() {
    let temp = TempDir::new().unwrap();
    let session = RuleSession::load(Some(temp.path()), &[]).unwrap();
    let metadata = session.metadata().unwrap();
    assert!(metadata.loaded_external_files.is_empty());
    assert_eq!(metadata.external_rule_count, 0);
    assert_eq!(metadata.digest.len(), 64);
    assert!(RuleSession::load(None, &["unknown-rule=off".to_string()]).is_err());
}

#[test]
fn eligible_binary_invalid_utf8_and_oversized_inputs_fail_closed() {
    let temp = TempDir::new().unwrap();
    write_catalog(
        temp.path(),
        "rules.yaml",
        &[rule(
            "text-rule",
            "text",
            r#"{ kind: literal, pattern: "x" }"#,
            "low",
            "blocking",
        )],
    );
    let session = RuleSession::load(Some(temp.path()), &[]).unwrap();
    assert!(session
        .scan_bytes("x.txt", b"x\0", &mut Vec::new())
        .is_err());
    assert!(session
        .scan_bytes("x.txt", &[0xff], &mut Vec::new())
        .is_err());
    assert!(session
        .scan_bytes(
            "x.txt",
            &vec![b'x'; MAX_EXTERNAL_INPUT_BYTES + 1],
            &mut Vec::new()
        )
        .is_err());
}

#[test]
fn total_finding_and_evidence_limits_apply_across_virtual_inputs() {
    let temp = TempDir::new().unwrap();
    write_catalog(
        temp.path(),
        "rules.yaml",
        &[rule(
            "bounded-rule",
            "text",
            r#"{ kind: literal, pattern: "x" }"#,
            "low",
            "blocking",
        )],
    );
    let session = RuleSession::load(Some(temp.path()), &[]).unwrap();
    let template = Finding::new("bounded-rule", Severity::Low, "external description");
    let at_limit = vec![template.clone(); MAX_EXTERNAL_FINDINGS];
    session.validate_external_limits(&at_limit).unwrap();
    let over_limit = vec![template; MAX_EXTERNAL_FINDINGS + 1];
    assert!(session.validate_external_limits(&over_limit).is_err());

    let mut evidence = Finding::new("bounded-rule", Severity::Low, "external description");
    evidence.evidence = Some(vec!["x".repeat(MAX_EXTERNAL_EVIDENCE_BYTES)]);
    session
        .validate_external_limits(std::slice::from_ref(&evidence))
        .unwrap();
    evidence.evidence = Some(vec!["x".repeat(MAX_EXTERNAL_EVIDENCE_BYTES + 1)]);
    assert!(session
        .validate_external_limits(std::slice::from_ref(&evidence))
        .is_err());
}

#[cfg(unix)]
#[test]
fn symlink_root_and_internal_file_are_allowed_but_escapes_fail() {
    use std::os::unix::fs::symlink;

    let outer = TempDir::new().unwrap();
    let real = outer.path().join("real");
    fs::create_dir(&real).unwrap();
    write_catalog(
        &real,
        "real.yaml",
        &[rule(
            "symlink-rule",
            "text",
            r#"{ kind: literal, pattern: "x" }"#,
            "low",
            "blocking",
        )],
    );
    symlink(real.join("real.yaml"), real.join("alias.yml")).unwrap();
    let root_link = outer.path().join("root-link");
    symlink(&real, &root_link).unwrap();
    let session = RuleSession::load(Some(&root_link), &[]).unwrap();
    assert_eq!(session.external_rule_count(), 1);

    let outside = outer.path().join("outside.yaml");
    fs::write(
        &outside,
        catalog(&[rule(
            "outside",
            "text",
            r#"{ kind: literal, pattern: "x" }"#,
            "low",
            "blocking",
        )]),
    )
    .unwrap();
    symlink(&outside, real.join("escape.yaml")).unwrap();
    assert!(RuleSession::load(Some(&real), &[]).is_err());
}

#[test]
fn typed_typosquat_parameters_drive_matching_and_audit_metadata() {
    let default = RuleSession::builtin().unwrap();
    let mut findings = Vec::new();
    default
        .push_typosquat_findings(
            argus_core::Ecosystem::Npm,
            "react-dxx",
            "npm name",
            &mut findings,
        )
        .unwrap();
    assert!(findings.is_empty());

    let configured = RuleSession::load(
        None,
        &["typosquatting=param:max_edit_distance=2".to_string()],
    )
    .unwrap();
    configured
        .push_typosquat_findings(
            argus_core::Ecosystem::Npm,
            "react-dxx",
            "npm name",
            &mut findings,
        )
        .unwrap();
    assert_eq!(findings[0].rule_id, "typosquatting");
    let metadata = configured.metadata().expect("explicit override is audited");
    assert_eq!(
        metadata.parameter_overrides,
        ["typosquatting=param:max_edit_distance=2"]
    );
    assert_eq!(metadata.data.len(), 10);
    assert!(metadata.data.iter().all(|asset| asset.sha256.len() == 64));
}

#[test]
fn typosquat_and_low_reputation_switches_are_independent() {
    for (overrides, expected_rule_ids) in [
        (
            Vec::<String>::new(),
            vec!["typosquatting", "low-reputation"],
        ),
        (
            vec!["typosquatting=off".to_string()],
            vec!["low-reputation"],
        ),
        (
            vec!["low-reputation=off".to_string()],
            vec!["typosquatting"],
        ),
        (
            vec![
                "typosquatting=off".to_string(),
                "low-reputation=off".to_string(),
            ],
            Vec::<&str>::new(),
        ),
    ] {
        let session = RuleSession::load(None, &overrides).unwrap();
        let mut findings = Vec::new();
        session
            .push_typosquat_findings(
                argus_core::Ecosystem::Npm,
                "reactt",
                "npm name",
                &mut findings,
            )
            .unwrap();
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            expected_rule_ids
        );
    }
}

mod matcher_matrix;
mod resource_limits;
