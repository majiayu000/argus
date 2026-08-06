use argus_core::{Ecosystem, PackageCoordinate};
use argus_lockfile::{
    build_scan_targets, diff_scan_targets, Coverage, DetectedLockfile, FormatVersion,
    IntegrityEvidence, IntegrityState, LockfileError, LockfileFormat, LockfileScanTargetKind,
    NormalizedDependency, NormalizedSource, ParseOutput, SourceKind,
};

fn coordinate(name: &str, version: &str) -> PackageCoordinate {
    PackageCoordinate::new(Ecosystem::Npm, name, version).expect("valid coordinate")
}

fn source(kind: SourceKind, location: &str) -> NormalizedSource {
    NormalizedSource {
        kind,
        location: (!matches!(kind, SourceKind::UnavailableByFormat)).then(|| location.to_string()),
        immutable_revision: None,
        locator: location.to_string(),
    }
}

fn record(
    name: &str,
    version: &str,
    source: NormalizedSource,
    locator: &str,
    condition: Option<&str>,
) -> NormalizedDependency {
    let coordinate = coordinate(name, version);
    NormalizedDependency {
        coordinate: Some(coordinate.clone()),
        format: LockfileFormat::PackageLock,
        sources: vec![source],
        integrity_state: IntegrityState::RequiredPresent,
        integrity: vec![IntegrityEvidence {
            algorithm: Some("sha512".to_string()),
            value: Some("aaaaaaaa".to_string()),
            locator: locator.to_string(),
        }],
        raw_name: Some(coordinate.original_name),
        raw_version: Some(coordinate.original_version),
        locator: locator.to_string(),
        condition: condition.map(str::to_string),
        platform: Some("linux".to_string()),
        occurrence_index: 0,
    }
}

fn output(records: Vec<NormalizedDependency>) -> ParseOutput {
    let units = records.len();
    ParseOutput {
        detected: DetectedLockfile {
            format: LockfileFormat::PackageLock,
            version: FormatVersion::PackageLock3,
            evidence: vec!["synthetic".to_string()],
        },
        records,
        coverage: Coverage {
            total_units: units,
            recognized_units: units,
            unsupported_units: 0,
            record_units: units,
            traversed_non_record_units: 0,
        },
        metadata_integrity: Vec::new(),
    }
}

#[test]
fn duplicate_occurrences_merge_and_sort_without_losing_evidence() {
    let first = record(
        "demo",
        "1.0.0",
        source(SourceKind::Registry, "https://registry.example.invalid/npm"),
        "z-occurrence",
        Some("node >= 20"),
    );
    let mut second = first.clone();
    second.locator = "a-occurrence".to_string();
    second.integrity[0].locator = "a-integrity".to_string();
    second.condition = Some("node >= 18".to_string());

    let targets = build_scan_targets(&output(vec![first, second])).expect("targets");
    assert_eq!(targets.len(), 1);
    let target = &targets[0];
    assert_eq!(target.kind, LockfileScanTargetKind::RegistryFetchable);
    assert_eq!(target.locators, ["a-occurrence", "z-occurrence"]);
    assert_eq!(target.constraints.len(), 2);
    assert_eq!(target.expected_integrity.len(), 2);
    assert_eq!(target.occurrences.len(), 2);
}

#[test]
fn classification_is_explicit_and_fail_closed() {
    let mut local = record(
        "local",
        "1.0.0",
        source(SourceKind::Path, "../local"),
        "local",
        None,
    );
    local.coordinate = None;
    local.raw_name = None;
    local.raw_version = None;
    let unsupported = record(
        "url",
        "1.0.0",
        source(SourceKind::UnavailableByFormat, "unused"),
        "url",
        None,
    );
    let conflicting = {
        let mut value = record(
            "mixed",
            "1.0.0",
            source(SourceKind::Registry, "https://registry.example.invalid/npm"),
            "mixed",
            None,
        );
        value.sources.push(source(SourceKind::Path, "../mixed"));
        value
    };
    let targets =
        build_scan_targets(&output(vec![local, unsupported, conflicting])).expect("targets");
    assert!(targets
        .iter()
        .any(|target| target.kind == LockfileScanTargetKind::LocalExcluded));
    assert!(targets
        .iter()
        .any(|target| target.kind == LockfileScanTargetKind::Unsupported));
    assert!(targets
        .iter()
        .any(|target| target.kind == LockfileScanTargetKind::Conflicting));
}

#[test]
fn delta_ignores_locator_order_but_reports_security_changes() {
    let mut base = record(
        "demo",
        "1.0.0",
        source(SourceKind::Registry, "https://registry.example.invalid/npm"),
        "one",
        Some("linux"),
    );
    let mut current = base.clone();
    base.locator = "z-occurrence".to_string();
    current.locator = "a-occurrence".to_string();
    assert!(diff_scan_targets(
        &build_scan_targets(&output(vec![base.clone()])).unwrap(),
        &build_scan_targets(&output(vec![current.clone()])).unwrap(),
    )
    .changed
    .is_empty());

    current.raw_version = Some("1.1.0".to_string());
    current.coordinate = Some(coordinate("demo", "1.1.0"));
    let delta = diff_scan_targets(
        &build_scan_targets(&output(vec![base])).unwrap(),
        &build_scan_targets(&output(vec![current])).unwrap(),
    );
    assert_eq!(delta.changed.len(), 1);
    assert!(delta.added.is_empty());
    assert!(delta.removed.is_empty());
}

#[test]
fn nested_source_and_integrity_locators_are_evidence_noise_for_delta() {
    let mut base = record(
        "demo",
        "1.0.0",
        source(SourceKind::Registry, "https://registry.example.invalid/npm"),
        "z-occurrence",
        Some("linux"),
    );
    base.sources[0].locator = "z-source-locator".to_string();
    base.integrity[0].locator = "z-integrity-locator".to_string();
    let mut current = base.clone();
    current.locator = "a-occurrence".to_string();
    current.sources[0].locator = "a-source-locator".to_string();
    current.integrity[0].locator = "a-integrity-locator".to_string();
    let delta = diff_scan_targets(
        &build_scan_targets(&output(vec![base])).unwrap(),
        &build_scan_targets(&output(vec![current])).unwrap(),
    );
    assert!(delta.changed.is_empty());
}

#[test]
fn divergent_source_integrity_associations_are_conflicting() {
    let first = record(
        "demo",
        "1.0.0",
        source(
            SourceKind::Registry,
            "https://registry-a.example.invalid/npm",
        ),
        "a",
        Some("linux"),
    );
    let mut second = record(
        "demo",
        "1.0.0",
        source(
            SourceKind::Registry,
            "https://registry-b.example.invalid/npm",
        ),
        "b",
        Some("darwin"),
    );
    second.integrity[0].value = Some("bbbbbbbb".to_string());
    second.platform = Some("darwin".to_string());
    let targets = build_scan_targets(&output(vec![first, second])).expect("targets");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].kind, LockfileScanTargetKind::Conflicting);
    assert_eq!(targets[0].occurrences.len(), 2);
}

#[test]
fn coordinate_less_identity_is_source_qualified() {
    let local_a = || {
        let mut value = record(
            "local",
            "1.0.0",
            source(SourceKind::Path, "../A"),
            "A-occurrence",
            None,
        );
        value.coordinate = None;
        value.raw_name = None;
        value.raw_version = None;
        value
    };
    let local_b = || {
        let mut value = local_a();
        value.sources[0].location = Some("../B".to_string());
        value.sources[0].locator = "../B".to_string();
        value.locator = "B-occurrence".to_string();
        value
    };
    let base = build_scan_targets(&output(vec![local_a()])).expect("base");
    let current = build_scan_targets(&output(vec![local_a(), local_b()])).expect("current");
    let delta = diff_scan_targets(&base, &current);
    assert!(delta.changed.is_empty());
    assert!(delta.removed.is_empty());
    assert_eq!(delta.added.len(), 1);
}

#[test]
fn ambiguous_multi_version_churn_stays_added_and_removed() {
    let base = build_scan_targets(&output(vec![
        record(
            "foo",
            "1.0.0",
            source(SourceKind::Registry, "https://registry.example.invalid/npm"),
            "foo-1",
            None,
        ),
        record(
            "foo",
            "2.0.0",
            source(SourceKind::Registry, "https://registry.example.invalid/npm"),
            "foo-2",
            None,
        ),
    ]))
    .expect("base");
    let current = build_scan_targets(&output(vec![record(
        "foo",
        "2.1.0",
        source(SourceKind::Registry, "https://registry.example.invalid/npm"),
        "foo-2.1",
        None,
    )]))
    .expect("current");
    let delta = diff_scan_targets(&base, &current);
    assert!(delta.changed.is_empty());
    assert_eq!(delta.removed.len(), 2);
    assert_eq!(delta.added.len(), 1);
}

#[test]
fn malformed_coordinate_less_record_is_rejected_by_canonical_validator() {
    let mut malformed = record(
        "broken",
        "1.0.0",
        source(SourceKind::Registry, "https://registry.example.invalid/npm"),
        "broken",
        None,
    );
    malformed.coordinate = None;
    malformed.raw_name = None;
    malformed.raw_version = None;
    assert!(matches!(
        build_scan_targets(&output(vec![malformed])),
        Err(LockfileError::InvalidModel { .. })
    ));
}
