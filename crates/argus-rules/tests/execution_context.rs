use argus_core::{ExecutionContext, Finding, ScanConcurrency, Severity};
use argus_rules::{
    scan_package_dir_with_rules_and_context, scan_text_files_with_context, RuleSession,
    MAX_EXTERNAL_INPUT_BYTES,
};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

fn external_session() -> RuleSession {
    let rules_dir = tempfile::tempdir().unwrap();
    fs::write(
        rules_dir.path().join("rules.yaml"),
        "schema_version: 1\nrules:\n  - { id: \"ordered-external\", description: \"ordered\", policy_class: blocking, default_severity: high, help_uri: \"https://example.test/ordered\", languages: [javascript], matcher: { kind: literal, pattern: \"MATCH\" } }\n",
    )
    .unwrap();
    RuleSession::load(Some(rules_dir.path()), &[]).unwrap()
}

fn package() -> tempfile::TempDir {
    let package = tempfile::tempdir().unwrap();
    fs::write(
        package.path().join("package.json"),
        r#"{"name":"execution-demo","version":"1.0.0"}"#,
    )
    .unwrap();
    for (rel, body) in [
        ("z-last.js", "MATCH"),
        ("a-first.js", "MATCH"),
        ("middle.js", "const clean = true;"),
    ] {
        fs::write(package.path().join(rel), body).unwrap();
    }
    package
}

#[test]
fn jobs_values_preserve_byte_identical_reports_and_order() {
    let rules = external_session();
    let package = package();
    let mut baseline = None;
    for jobs in [1, 2, 8, 64] {
        let execution = ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap();
        for _ in 0..20 {
            let report =
                scan_package_dir_with_rules_and_context(package.path(), &rules, &execution)
                    .unwrap();
            let json = serde_json::to_vec(&report).unwrap();
            if let Some(expected) = &baseline {
                assert_eq!(&json, expected);
            } else {
                baseline = Some(json);
            }
            let locations = report
                .findings
                .iter()
                .filter(|finding| finding.rule_id == "ordered-external")
                .map(|finding| finding.location.as_deref().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(locations, ["a-first.js", "z-last.js"]);
        }
    }
}

#[test]
fn lowest_canonical_external_input_error_wins() {
    let rules = external_session();
    let package = package();
    fs::write(package.path().join("a-first.js"), [0xff]).unwrap();
    fs::write(package.path().join("b-second.js"), [0]).unwrap();

    for jobs in [1, 2, 64] {
        let execution = ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap();
        let error = scan_package_dir_with_rules_and_context(package.path(), &rules, &execution)
            .unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("a-first.js"), "{detail}");
        assert!(detail.contains("not valid UTF-8"), "{detail}");
    }
}

#[test]
fn nested_ordered_work_stays_within_the_invocation_pool() {
    let execution = ExecutionContext::new(ScanConcurrency::new(2).unwrap()).unwrap();
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    execution
        .execute_ordered(
            &[0, 1],
            None,
            |_, _| {
                execution.execute_ordered(
                    &[0, 1],
                    None,
                    |_, _| {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        std::thread::yield_now();
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok::<_, ()>(())
                    },
                    |_, _| Ok(()),
                )
            },
            |_, _| Ok(()),
        )
        .unwrap();
    assert!(peak.load(Ordering::SeqCst) <= 2);
}

fn sentinel_findings() -> Vec<Finding> {
    vec![Finding::new("sentinel", Severity::Info, "pre-existing")]
}

fn assert_only_sentinel(findings: &[Finding]) {
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "sentinel");
    assert_eq!(findings[0].detail, "pre-existing");
}

#[test]
fn external_scan_errors_do_not_leak_lower_path_findings() {
    let rules = external_session();
    let execution = ExecutionContext::new(ScanConcurrency::new(2).unwrap()).unwrap();
    let good = b"MATCH".as_slice();
    let invalid = [0xff];
    let mut findings = sentinel_findings();

    let error = rules
        .scan_virtual_inputs_with_context(
            2,
            [("a-success.js", good), ("b-invalid.js", invalid.as_slice())],
            &mut findings,
            &execution,
        )
        .unwrap_err();

    assert!(format!("{error:#}").contains("b-invalid.js"));
    assert_only_sentinel(&findings);
}

#[test]
fn external_budget_errors_do_not_leak_staged_findings() {
    let rules = external_session();
    let execution = ExecutionContext::new(ScanConcurrency::new(2).unwrap()).unwrap();
    let first = format!("a{}.js", "x".repeat(600_000));
    let second = format!("b{}.js", "x".repeat(600_000));
    let bytes = b"MATCH".as_slice();
    let mut findings = sentinel_findings();

    let error = rules
        .scan_virtual_inputs_with_context(
            2,
            [(first.as_str(), bytes), (second.as_str(), bytes)],
            &mut findings,
            &execution,
        )
        .unwrap_err();

    assert!(format!("{error:#}").contains("evidence exceeds"));
    assert_only_sentinel(&findings);
}

#[test]
fn oversized_virtual_input_is_rejected_before_matching_without_partial_findings() {
    let rules = external_session();
    let execution = ExecutionContext::new(ScanConcurrency::new(2).unwrap()).unwrap();
    let good = b"MATCH".as_slice();
    let oversized = vec![b'M'; MAX_EXTERNAL_INPUT_BYTES + 1];
    let mut findings = sentinel_findings();

    let error = rules
        .scan_virtual_inputs_with_context(
            2,
            [
                ("a-success.js", good),
                ("b-oversized.bin", oversized.as_slice()),
            ],
            &mut findings,
            &execution,
        )
        .unwrap_err();

    assert!(format!("{error:#}").contains("exceeds"));
    assert_only_sentinel(&findings);
}

#[test]
fn bounded_worker_read_rechecks_size_after_discovery() {
    let package = tempfile::tempdir().unwrap();
    let first = package.path().join("a-trigger.txt");
    let grown = package.path().join("b-grown.txt");
    fs::write(&first, b"first").unwrap();
    fs::write(&grown, b"small").unwrap();
    let execution = ExecutionContext::serial().unwrap();

    let (outputs, skipped) = scan_text_files_with_context(package.path(), 5, &execution, |file| {
        if file.rel == "a-trigger.txt" {
            fs::write(&grown, b"123456").unwrap();
        }
        Ok(file.rel.clone())
    })
    .unwrap();

    assert_eq!(outputs, ["a-trigger.txt"]);
    // A file that grew past the limit between discovery and read is oversized,
    // not binary: the distinction is what lets callers fail closed on it.
    assert_eq!(skipped.oversized, ["b-grown.txt"]);
    assert!(skipped.binary.is_empty());
}
