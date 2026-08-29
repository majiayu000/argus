use super::*;
use argus_core::{ArtifactKind, Finding, PackageCoordinate, Severity};
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
        risk: None,
    }
}

fn versioned_report(
    name: &str,
    version: &str,
    decision: Decision,
    findings: Vec<Finding>,
) -> ScanReport {
    let coordinate = PackageCoordinate::new(Ecosystem::Npm, name, version).unwrap();
    ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: coordinate.purl.clone().into(),
        package_name: Some(name.to_string()),
        package_version: Some(version.to_string()),
        decision,
        findings,
        coordinate: Some(coordinate),
        intelligence: None,
        rules: None,
        vulnerability: None,
        risk: None,
    }
}

fn versioned_target(name: &str, version: &str) -> LockfileScanTarget {
    let mut target = target(
        LockfileScanTargetKind::RegistryFetchable,
        Some(Ecosystem::Npm),
        Some(name),
        Some(version),
    );
    target.coordinate = Some(PackageCoordinate::new(Ecosystem::Npm, name, version).unwrap());
    target
}

fn outcome(reports: Vec<ScanReport>, failed: Vec<FailedTarget>) -> LockfileScanOutcome {
    LockfileScanOutcome::derive(
        "package-lock.json".into(),
        Parts {
            targets_total: reports.len() + failed.len(),
            reports,
            skipped: Vec::new(),
            failed,
            comparisons_total: 0,
            version_changes: Vec::new(),
            comparison_failed: Vec::new(),
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
// Version comparison: stable finding identity and fail-closed base evidence.
// ---------------------------------------------------------------------------

#[test]
fn finding_delta_ignores_explanation_churn_but_retains_new_capabilities() {
    let base = vec![
        Finding::new("lifecycle-script", Severity::Medium, "old wording")
            .at("package.json#scripts.preinstall")
            .with_capability("process_exec", vec!["package.json:4".to_string()], None),
    ];
    let current = vec![
        Finding::new("lifecycle-script", Severity::Medium, "new wording")
            .at("package.json#scripts.preinstall")
            .with_capability("process_exec", vec!["package.json:8".to_string()], None),
        Finding::new("remote-download", Severity::High, "downloads a payload")
            .at("setup.mjs")
            .with_capability(
                "net_egress",
                vec!["setup.mjs:12".to_string()],
                Some("payload.example.invalid".to_string()),
            ),
    ];

    let (introduced, resolved) = finding_delta(&base, &current);
    assert_eq!(
        introduced
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>(),
        ["remote-download"]
    );
    assert!(resolved.is_empty());
}

#[test]
fn changed_coordinate_reports_introduced_and_resolved_findings() {
    let change = LockfileScanTargetChange {
        base: versioned_target("demo", "1.0.0"),
        current: versioned_target("demo", "2.0.0"),
    };
    let base = outcome(
        vec![versioned_report(
            "demo",
            "1.0.0",
            Decision::AllowWithApproval,
            vec![Finding::new(
                "version-shape-anomaly",
                Severity::Medium,
                "old anomaly",
            )],
        )],
        Vec::new(),
    );
    let current = outcome(
        vec![versioned_report(
            "demo",
            "2.0.0",
            Decision::Block,
            vec![Finding::new(
                "remote-download",
                Severity::High,
                "new execution surface",
            )],
        )],
        Vec::new(),
    );

    let (assessed, failed) = assess_version_changes(&[change], &current, &base);
    assert!(failed.is_empty());
    assert_eq!(assessed.len(), 1);
    assert_eq!(assessed[0].base.purl, "pkg:npm/demo@1.0.0");
    assert_eq!(assessed[0].current.purl, "pkg:npm/demo@2.0.0");
    assert_eq!(assessed[0].introduced[0].rule_id, "remote-download");
    assert_eq!(assessed[0].resolved[0].rule_id, "version-shape-anomaly");
}

#[test]
fn unavailable_base_comparison_blocks_the_current_outcome() {
    let change = LockfileScanTargetChange {
        base: versioned_target("demo", "1.0.0"),
        current: versioned_target("demo", "2.0.0"),
    };
    let mut current = outcome(
        vec![versioned_report(
            "demo",
            "2.0.0",
            Decision::Allow,
            Vec::new(),
        )],
        Vec::new(),
    );
    let base = outcome(
        Vec::new(),
        vec![FailedTarget {
            locator: "demo".to_string(),
            ecosystem: Ecosystem::Npm,
            error: "synthetic registry failure".to_string(),
        }],
    );

    let (assessed, failed) = assess_version_changes(&[change], &current, &base);
    current.comparisons_total = 1;
    current.version_changes = assessed;
    current.comparison_failed = failed;
    current.refresh_decision();

    assert_eq!(current.decision, Decision::Block);
    assert_eq!(current.comparison_failed.len(), 1);
    assert!(current.comparison_failed[0]
        .error
        .contains("synthetic registry failure"));
    let text = render_text(&current);
    assert!(text.contains("comparison: assessed 0 of 1 changed targets"));
    assert!(text.contains("comparison unavailable:"));
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
