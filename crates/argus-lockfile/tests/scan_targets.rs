use argus_core::{Ecosystem, PackageCoordinate};
use argus_lockfile::{
    build_scan_targets, diff_scan_targets, Coverage, DetectedLockfile, FormatVersion,
    IntegrityEvidence, IntegrityState, LockfileFormat, LockfileScanTargetKind,
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
    local.raw_name = Some("local".to_string());
    local.raw_version = Some("1.0.0".to_string());
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
