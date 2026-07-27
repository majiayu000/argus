use argus_core::{ExecutionContext, Finding, ScanConcurrency, Severity};
use argus_rules::{
    ExternalScanBudget, RuleSession, MAX_EXTERNAL_EVIDENCE_BYTES, MAX_EXTERNAL_FINDINGS,
    MAX_EXTERNAL_SCAN_FILES,
};
use std::fs;

fn session(rule_count: usize) -> RuleSession {
    let directory = tempfile::tempdir().unwrap();
    let rules = (0..rule_count)
        .map(|index| {
            format!(
                "  - {{ id: \"budget-{index}\", description: \"budget\", \
                 policy_class: blocking, default_severity: high, \
                 help_uri: \"https://example.test/budget-{index}\", \
                 languages: [javascript], matcher: {{ kind: literal, pattern: \"MATCH\" }} }}\n"
            )
        })
        .collect::<String>();
    fs::write(
        directory.path().join("rules.yaml"),
        format!("schema_version: 1\nrules:\n{rules}"),
    )
    .unwrap();
    RuleSession::load(Some(directory.path()), &[]).unwrap()
}

fn build_context(jobs: usize) -> ExecutionContext {
    ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap()
}

fn names(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{prefix}-{index:05}.js"))
        .collect()
}

#[test]
fn input_cap_is_shared_across_multiple_surfaces_and_failed_phase_is_atomic() {
    let rules = session(1);
    let first_names = names("first", MAX_EXTERNAL_SCAN_FILES - 1);
    let first = first_names
        .iter()
        .map(|name| (name.as_str(), b"clean".as_slice()))
        .collect::<Vec<_>>();
    for jobs in [1, 2, 8, 64] {
        let execution = build_context(jobs);
        let mut findings = vec![Finding::new("sentinel", Severity::Info, "existing")];
        let mut budget = ExternalScanBudget::default();
        rules
            .scan_virtual_inputs_with_budget_and_context(
                first.len(),
                first.iter().copied(),
                &mut findings,
                &execution,
                &mut budget,
            )
            .unwrap();

        let overflow = [
            ("second-a.js", b"clean".as_slice()),
            ("second-b.js", b"clean".as_slice()),
        ];
        let error = rules
            .scan_virtual_inputs_with_budget_and_context(
                overflow.len(),
                overflow,
                &mut findings,
                &execution,
                &mut budget,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("exceeds"));
        assert_eq!(findings.len(), 1);

        rules
            .scan_virtual_inputs_with_budget_and_context(
                1,
                [("second-only.js", b"clean".as_slice())],
                &mut findings,
                &execution,
                &mut budget,
            )
            .unwrap();
        assert_eq!(findings.len(), 1);
    }
}

#[test]
fn finding_cap_is_not_multiplied_by_surface_or_jobs() {
    let rules = session(10);
    let first_names = names("matched", MAX_EXTERNAL_FINDINGS / 10);
    let first = first_names
        .iter()
        .map(|name| (name.as_str(), b"MATCH".as_slice()))
        .collect::<Vec<_>>();
    for jobs in [1, 2, 8, 64] {
        let execution = build_context(jobs);
        let mut findings = Vec::new();
        let mut budget = ExternalScanBudget::default();
        rules
            .scan_virtual_inputs_with_budget_and_context(
                first.len(),
                first.iter().copied(),
                &mut findings,
                &execution,
                &mut budget,
            )
            .unwrap();
        assert_eq!(findings.len(), MAX_EXTERNAL_FINDINGS);

        let error = rules
            .scan_virtual_inputs_with_budget_and_context(
                1,
                [("overflow.js", b"MATCH".as_slice())],
                &mut findings,
                &execution,
                &mut budget,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("findings exceed"));
        assert_eq!(findings.len(), MAX_EXTERNAL_FINDINGS);
    }
}

#[test]
fn evidence_cap_is_shared_across_surfaces_and_failed_phase_is_atomic() {
    let rules = session(1);
    let long = MAX_EXTERNAL_EVIDENCE_BYTES / 2 + 128;
    let first_name = format!("a{}.js", "x".repeat(long));
    let second_name = format!("b{}.js", "x".repeat(long));
    for jobs in [1, 2, 8, 64] {
        let execution = build_context(jobs);
        let mut findings = Vec::new();
        let mut budget = ExternalScanBudget::default();
        rules
            .scan_virtual_inputs_with_budget_and_context(
                1,
                [(first_name.as_str(), b"MATCH".as_slice())],
                &mut findings,
                &execution,
                &mut budget,
            )
            .unwrap();
        assert_eq!(findings.len(), 1);

        let error = rules
            .scan_virtual_inputs_with_budget_and_context(
                1,
                [(second_name.as_str(), b"MATCH".as_slice())],
                &mut findings,
                &execution,
                &mut budget,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("evidence exceeds"));
        assert_eq!(findings.len(), 1);

        rules
            .scan_virtual_inputs_with_budget_and_context(
                1,
                [("short.js", b"MATCH".as_slice())],
                &mut findings,
                &execution,
                &mut budget,
            )
            .unwrap();
        assert_eq!(findings.len(), 2);
    }
}
