use argus_agent::{
    scan_agent_surface_with_snapshot_and_rules_and_context, AgentScanOutcome, BaselineMode,
    SnapshotMode,
};
use argus_core::{Decision, ExecutionContext, ScanConcurrency};
use argus_rules::RuleSession;
use std::fs;
use std::path::{Path, PathBuf};

fn agent_fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn build_execution(jobs: usize) -> ExecutionContext {
    ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap()
}

fn outcome_fingerprint(outcome: AgentScanOutcome) -> (Vec<u8>, Option<String>, Option<usize>) {
    (
        serde_json::to_vec(&outcome.report).unwrap(),
        outcome.operational_error.map(|error| format!("{error:#}")),
        outcome.snapshot_entry_count,
    )
}

fn scan_with_jobs(
    path: &Path,
    baseline: BaselineMode<'_>,
    snapshot: SnapshotMode<'_>,
    rules: &RuleSession,
    jobs: usize,
) -> anyhow::Result<AgentScanOutcome> {
    scan_agent_surface_with_snapshot_and_rules_and_context(
        path,
        baseline,
        snapshot,
        None,
        rules,
        &build_execution(jobs),
    )
}

fn assert_outcome_parity(mut operation: impl FnMut(usize) -> anyhow::Result<AgentScanOutcome>) {
    let mut baseline = None;
    for jobs in [1, 2, 8, 64] {
        for _ in 0..3 {
            let actual = outcome_fingerprint(operation(jobs).unwrap());
            if let Some(expected) = &baseline {
                assert_eq!(&actual, expected, "jobs={jobs}");
            } else {
                baseline = Some(actual);
            }
        }
    }
}

fn load_agent_jobs_session(root: &Path) -> RuleSession {
    fs::create_dir_all(root).unwrap();
    fs::write(
        root.join("external.yaml"),
        "schema_version: 1\nrules:\n  - { id: \"agent-jobs-external\", \
         description: \"marker\", policy_class: blocking, default_severity: high, \
         help_uri: \"https://example.test/agent-jobs\", languages: [markdown], \
         matcher: { kind: literal, pattern: \"AGENT_JOBS_MARKER\" } }\n",
    )
    .unwrap();
    RuleSession::load(Some(root), &[]).unwrap()
}

#[test]
fn normal_clean_malicious_and_external_scans_are_identical_across_jobs() {
    let builtin = RuleSession::builtin().unwrap();
    for path in [
        agent_fixture_path("agt01-benign-skill"),
        agent_fixture_path("agt01-malicious-skill"),
    ] {
        assert_outcome_parity(|jobs| {
            scan_with_jobs(
                &path,
                BaselineMode::None,
                SnapshotMode::None,
                &builtin,
                jobs,
            )
        });
    }

    let temporary = tempfile::tempdir().unwrap();
    let surface = temporary.path().join("surface");
    fs::create_dir(&surface).unwrap();
    fs::write(
        surface.join("SKILL.md"),
        "---\nname: jobs\ndescription: marker\n---\nAGENT_JOBS_MARKER\n",
    )
    .unwrap();
    let rules = load_agent_jobs_session(&temporary.path().join("rules"));
    assert_outcome_parity(|jobs| {
        scan_with_jobs(
            &surface,
            BaselineMode::None,
            SnapshotMode::None,
            &rules,
            jobs,
        )
    });
}

#[test]
fn baseline_snapshot_and_incomplete_outcomes_are_identical_across_jobs() {
    let rules = RuleSession::builtin().unwrap();
    let baseline_store = tempfile::tempdir().unwrap();
    let baseline_surface = agent_fixture_path("agt02-baseline-skill");
    let mut baseline_update_fingerprint = None;
    let mut baseline_bytes = None;
    for jobs in [1, 2, 8, 64] {
        let destination = baseline_store.path().join(format!("baseline-{jobs}.json"));
        let outcome = scan_with_jobs(
            &baseline_surface,
            BaselineMode::Update(&destination),
            SnapshotMode::None,
            &rules,
            jobs,
        )
        .unwrap();
        let actual_fingerprint = outcome_fingerprint(outcome);
        let actual_bytes = fs::read(&destination).unwrap();
        if let Some(expected) = &baseline_update_fingerprint {
            assert_eq!(&actual_fingerprint, expected, "baseline update jobs={jobs}");
            assert_eq!(
                Some(&actual_bytes),
                baseline_bytes.as_ref(),
                "baseline persisted bytes jobs={jobs}"
            );
        } else {
            baseline_update_fingerprint = Some(actual_fingerprint);
            baseline_bytes = Some(actual_bytes);
        }
        assert_outcome_parity(|check_jobs| {
            scan_with_jobs(
                &baseline_surface,
                BaselineMode::Check(&destination),
                SnapshotMode::None,
                &rules,
                check_jobs,
            )
        });
    }

    let surface = tempfile::tempdir().unwrap();
    fs::write(surface.path().join("AGENTS.md"), "approved").unwrap();
    let snapshot_store = tempfile::tempdir().unwrap();
    let mut snapshot_update_fingerprint = None;
    let mut snapshot_bytes = None;
    for jobs in [1, 2, 8, 64] {
        let destination = snapshot_store.path().join(format!("snapshot-{jobs}.json"));
        let outcome = scan_with_jobs(
            surface.path(),
            BaselineMode::None,
            SnapshotMode::Update(&destination),
            &rules,
            jobs,
        )
        .unwrap();
        let actual_fingerprint = outcome_fingerprint(outcome);
        let actual_bytes = fs::read(&destination).unwrap();
        if let Some(expected) = &snapshot_update_fingerprint {
            assert_eq!(&actual_fingerprint, expected, "snapshot update jobs={jobs}");
            assert_eq!(
                Some(&actual_bytes),
                snapshot_bytes.as_ref(),
                "snapshot persisted bytes jobs={jobs}"
            );
        } else {
            snapshot_update_fingerprint = Some(actual_fingerprint);
            snapshot_bytes = Some(actual_bytes);
        }
        assert_outcome_parity(|check_jobs| {
            scan_with_jobs(
                surface.path(),
                BaselineMode::None,
                SnapshotMode::Check(&destination),
                &rules,
                check_jobs,
            )
        });
    }

    fs::write(surface.path().join("AGENTS.md"), b"changed\0binary").unwrap();
    let snapshot = snapshot_store.path().join("snapshot-1.json");
    assert_outcome_parity(|jobs| {
        let outcome = scan_with_jobs(
            surface.path(),
            BaselineMode::None,
            SnapshotMode::Check(&snapshot),
            &rules,
            jobs,
        )?;
        assert!(outcome.operational_error.is_some(), "jobs={jobs}");
        assert_eq!(outcome.report.decision, Decision::Block, "jobs={jobs}");
        assert!(
            outcome
                .report
                .findings
                .iter()
                .any(|finding| finding.rule_id.starts_with("AGT-04-")),
            "jobs={jobs}: {:?}",
            outcome.report.findings
        );
        Ok(outcome)
    });
}

#[test]
fn deterministic_semantic_error_is_identical_across_jobs() {
    let surface = tempfile::tempdir().unwrap();
    fs::write(surface.path().join("SKILL.md"), "---\nname: jobs\n---\n").unwrap();
    fs::create_dir(surface.path().join("scripts")).unwrap();
    fs::write(
        surface.path().join("scripts/a-invalid.py"),
        "def broken(:\n pass\n",
    )
    .unwrap();
    fs::write(
        surface.path().join("scripts/b-invalid.py"),
        "def also_broken(:\n pass\n",
    )
    .unwrap();
    let rules = RuleSession::builtin().unwrap();
    let mut baseline = None;
    for jobs in [1, 2, 8, 64] {
        let error = scan_with_jobs(
            surface.path(),
            BaselineMode::None,
            SnapshotMode::None,
            &rules,
            jobs,
        )
        .err()
        .expect("malformed semantic surface must fail");
        let detail = format!("{error:#}");
        assert!(detail.contains("a-invalid.py"), "{detail}");
        if let Some(expected) = &baseline {
            assert_eq!(&detail, expected);
        } else {
            baseline = Some(detail);
        }
    }
}
