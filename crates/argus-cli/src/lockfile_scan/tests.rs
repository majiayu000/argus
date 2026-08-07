use super::*;
use argus_core::{ArtifactKind, Finding, Severity};
use argus_lockfile::{IntegrityState, LockfileScanTarget};

fn target(
    kind: LockfileScanTargetKind,
    ecosystem: Option<Ecosystem>,
    name: Option<&str>,
    version: Option<&str>,
) -> LockfileScanTarget {
    LockfileScanTarget {
        kind,
        coordinate: None,
        ecosystem,
        name: name.map(str::to_string),
        version: version.map(str::to_string),
        formats: Vec::new(),
        sources: Vec::new(),
        integrity_state: IntegrityState::UnavailableByFormat,
        expected_integrity: Vec::new(),
        locators: name.map(|n| vec![n.to_string()]).unwrap_or_default(),
        constraints: Vec::new(),
        occurrences: Vec::new(),
    }
}

fn report(path: &str, decision: Decision, findings: Vec<Finding>) -> ScanReport {
    ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: path.into(),
        package_name: Some(path.to_string()),
        package_version: None,
        decision,
        findings,
        coordinate: None,
        intelligence: None,
        rules: None,
        vulnerability: None,
    }
}

fn outcome(reports: Vec<ScanReport>, failed: Vec<FailedTarget>) -> LockfileScanOutcome {
    LockfileScanOutcome::derive(
        "package-lock.json".into(),
        Parts {
            targets_total: reports.len() + failed.len(),
            reports,
            skipped: Vec::new(),
            failed,
        },
    )
}

// ---------------------------------------------------------------------------
// Planning: every target is either a job or an explicit, attributed skip.
// ---------------------------------------------------------------------------

#[test]
fn registry_targets_become_jobs_and_others_become_attributed_skips() {
    let targets = vec![
        target(
            LockfileScanTargetKind::RegistryFetchable,
            Some(Ecosystem::Npm),
            Some("left-pad"),
            Some("1.3.0"),
        ),
        target(
            LockfileScanTargetKind::LocalExcluded,
            Some(Ecosystem::Npm),
            Some("workspace-pkg"),
            Some("0.1.0"),
        ),
        target(
            LockfileScanTargetKind::Unsupported,
            None,
            Some("git-dep"),
            None,
        ),
        target(
            LockfileScanTargetKind::Conflicting,
            Some(Ecosystem::Npm),
            Some("dup"),
            Some("2.0.0"),
        ),
    ];

    let (jobs, skipped) = plan(&targets);
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].spec, "left-pad@1.3.0");
    assert_eq!(jobs[0].ecosystem, Ecosystem::Npm);

    let reasons: Vec<SkipReason> = skipped.iter().map(|skip| skip.reason).collect();
    assert_eq!(
        reasons,
        vec![
            SkipReason::LocalDependency,
            SkipReason::UnsupportedSource,
            SkipReason::ConflictingResolution,
        ]
    );
    // Every skip carries a human-readable cause; a bare count would let
    // unscanned surface disappear into a summary line.
    assert!(skipped.iter().all(|skip| !skip.detail.is_empty()));
}

#[test]
fn registry_target_without_a_complete_coordinate_is_skipped_not_guessed() {
    let targets = vec![target(
        LockfileScanTargetKind::RegistryFetchable,
        Some(Ecosystem::Npm),
        Some("no-version"),
        None,
    )];
    let (jobs, skipped) = plan(&targets);
    assert!(jobs.is_empty());
    assert_eq!(skipped[0].reason, SkipReason::IncompleteCoordinate);
}

#[test]
fn every_ecosystem_the_lockfile_parser_emits_has_a_fetcher() {
    for ecosystem in [
        Ecosystem::Npm,
        Ecosystem::PyPi,
        Ecosystem::CratesIo,
        Ecosystem::Go,
        Ecosystem::NuGet,
        Ecosystem::Maven,
        Ecosystem::RubyGems,
        Ecosystem::Packagist,
    ] {
        assert!(
            fetcher_for(ecosystem).is_some(),
            "no fetcher registered for {ecosystem:?}"
        );
    }
}

#[test]
fn maven_specs_use_the_native_group_artifact_version_syntax() {
    assert_eq!(
        spec_for(Ecosystem::Maven, "org.example:widget", "1.2.3"),
        "org.example:widget:1.2.3"
    );
    assert_eq!(
        spec_for(Ecosystem::Npm, "left-pad", "1.3.0"),
        "left-pad@1.3.0"
    );
}

// ---------------------------------------------------------------------------
// Aggregation: the worst package decides, and a failure is never "clean".
// ---------------------------------------------------------------------------

#[test]
fn aggregate_decision_takes_the_worst_scanned_package() {
    let allow = outcome(vec![report("a", Decision::Allow, Vec::new())], Vec::new());
    assert_eq!(allow.decision, Decision::Allow);

    let approval = outcome(
        vec![
            report("a", Decision::Allow, Vec::new()),
            report("b", Decision::AllowWithApproval, Vec::new()),
        ],
        Vec::new(),
    );
    assert_eq!(approval.decision, Decision::AllowWithApproval);

    let block = outcome(
        vec![
            report("a", Decision::AllowWithApproval, Vec::new()),
            report("b", Decision::Block, Vec::new()),
            report("c", Decision::Allow, Vec::new()),
        ],
        Vec::new(),
    );
    assert_eq!(block.decision, Decision::Block);
}

#[test]
fn an_unassessed_dependency_blocks_rather_than_reporting_clean() {
    // Every package that *was* scanned came back clean. The one that could
    // not be fetched is missing evidence, not evidence of safety.
    let result = outcome(
        vec![report("a", Decision::Allow, Vec::new())],
        vec![FailedTarget {
            locator: "b".to_string(),
            ecosystem: Ecosystem::Npm,
            error: "connection refused".to_string(),
        }],
    );
    assert_eq!(result.decision, Decision::Block);
    assert_eq!(result.scanned, 1);
    assert_eq!(result.targets_total, 2);
}

#[test]
fn empty_lockfile_allows() {
    let result = outcome(Vec::new(), Vec::new());
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.scanned, 0);
}

// ---------------------------------------------------------------------------
// Output: coverage is stated before findings.
// ---------------------------------------------------------------------------

#[test]
fn text_output_states_coverage_and_names_unscanned_dependencies() {
    let mut result = outcome(
        vec![report(
            "evil@1.0.0",
            Decision::Block,
            vec![Finding::new(
                "remote-download",
                Severity::Critical,
                "script downloads a remote payload",
            )],
        )],
        vec![FailedTarget {
            locator: "unreachable@2.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            error: "404 Not Found".to_string(),
        }],
    );
    result.skipped.push(SkippedTarget {
        locator: "../local-pkg".to_string(),
        ecosystem: Some(Ecosystem::Npm),
        reason: SkipReason::LocalDependency,
        detail: SkipReason::LocalDependency.describe().to_string(),
    });

    let text = render_text(&result);
    assert!(text.contains("decision: block"));
    assert!(text.contains("coverage: scanned 1 of 2 resolved targets"));
    assert!(text.contains("remote-download"));
    assert!(text.contains("unassessed (fetch or scan failed):"));
    assert!(text.contains("unreachable@2.0.0 — 404 Not Found"));
    assert!(text.contains("not scanned:"));
    assert!(text.contains("../local-pkg"));
}

#[test]
fn clean_packages_do_not_pad_the_findings_section() {
    let result = outcome(
        vec![
            report("clean@1.0.0", Decision::Allow, Vec::new()),
            report(
                "noisy@1.0.0",
                Decision::AllowWithApproval,
                vec![Finding::new(
                    "lifecycle-script",
                    Severity::Medium,
                    "declares an install-time lifecycle script",
                )],
            ),
        ],
        Vec::new(),
    );
    let text = render_text(&result);
    assert!(!text.contains("clean@1.0.0"));
    assert!(text.contains("noisy@1.0.0"));
}
