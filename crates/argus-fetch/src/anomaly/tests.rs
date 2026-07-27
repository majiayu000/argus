use super::*;
use serde_json::{json, Map, Value};

fn packument(target: &str, events: &[(&str, &str)]) -> Packument {
    let mut versions = Map::new();
    let mut times = Map::new();
    for (version, published_at) in events {
        versions.insert(
            (*version).to_string(),
            json!({
                "dist": {
                    "tarball": format!("https://registry.example/demo-{version}.tgz"),
                    "integrity": "sha512-AA"
                },
                "_npmUser": {"name": "publisher"}
            }),
        );
        times.insert(
            (*version).to_string(),
            Value::String((*published_at).to_string()),
        );
    }
    serde_json::from_value(json!({
        "name": "demo",
        "dist-tags": {"latest": target},
        "versions": versions,
        "time": times
    }))
    .expect("valid test packument")
}

fn suspicious_events() -> Vec<(&'static str, &'static str)> {
    vec![
        ("1.0.0", "2025-01-01T00:00:00Z"),
        ("1.1.0", "2025-01-10T00:00:00Z"),
        ("1.2.0", "2025-01-20T00:00:00Z"),
        ("1.3.0", "2025-02-01T00:00:00Z"),
        ("1.4.0", "2025-02-10T00:00:00Z"),
        ("1.5.0", "2025-02-20T00:00:00Z"),
        ("3.0.0", "2025-02-21T00:00:00Z"),
    ]
}

#[test]
fn anomaly_insufficient_history_is_explicit() {
    let packet = packument(
        "3.0.0",
        &[
            ("1.0.0", "2025-01-01T00:00:00Z"),
            ("3.0.0", "2025-02-21T00:00:00Z"),
        ],
    );
    let findings = version_shape_findings(&packet, "3.0.0").expect("evaluate");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "npm-version-shape-unassessed");
    assert_eq!(findings[0].severity, Severity::Info);
    assert!(findings[0].detail.contains("found 1"));
}

#[test]
fn anomaly_ordering_is_independent_of_json_order() {
    let mut events = suspicious_events();
    events.reverse();
    let packet = packument("3.0.0", &events);
    let findings = version_shape_findings(&packet, "3.0.0").expect("evaluate");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "version-shape-anomaly");
}

#[test]
fn version_shape_matrix_excludes_legitimate_edges() {
    let mut single_major = suspicious_events();
    single_major.pop();
    single_major.push(("2.0.0", "2025-02-21T00:00:00Z"));
    assert!(
        version_shape_findings(&packument("2.0.0", &single_major), "2.0.0")
            .expect("single major")
            .is_empty()
    );

    let mut backport = suspicious_events();
    backport.pop();
    backport.push(("1.4.1", "2025-02-21T00:00:00Z"));
    assert!(
        version_shape_findings(&packument("1.4.1", &backport), "1.4.1")
            .expect("backport")
            .is_empty()
    );

    let mut late = suspicious_events();
    late.pop();
    late.push(("3.0.0", "2025-03-01T00:00:00Z"));
    assert!(version_shape_findings(&packument("3.0.0", &late), "3.0.0")
        .expect("late major")
        .is_empty());

    let mut same_time = suspicious_events();
    same_time.insert(6, ("1.6.0", "2025-02-21T00:00:00Z"));
    assert!(
        version_shape_findings(&packument("3.0.0", &same_time), "3.0.0")
            .expect("same-time publication")
            .is_empty()
    );

    let mut prerelease = suspicious_events();
    prerelease.pop();
    prerelease.push(("3.0.0-beta.1", "2025-02-21T00:00:00Z"));
    let findings = version_shape_findings(&packument("3.0.0-beta.1", &prerelease), "3.0.0-beta.1")
        .expect("prerelease");
    assert_eq!(findings[0].rule_id, "npm-version-shape-unassessed");
}

#[test]
fn version_shape_evidence_names_versions_times_and_policy() {
    let packet = packument("3.0.0", &suspicious_events());
    let finding = version_shape_findings(&packet, "3.0.0")
        .expect("evaluate")
        .pop()
        .expect("finding");
    assert!(finding.detail.contains("policy=npm-anomaly-v1"));
    assert!(finding.detail.contains("target=3.0.0@2025-02-21"));
    assert!(finding.detail.contains("predecessor=1.5.0@2025-02-20"));
    assert!(finding.detail.contains("major_delta>=2"));
}

#[test]
fn cache_ttl_boundary_is_inclusive() {
    let now = DateTime::parse_from_rfc3339("2025-02-21T00:15:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let fetched = now - Duration::minutes(15);
    assert!(cache_entry_is_reusable(fetched, now, fetched).unwrap());
    assert!(!cache_entry_is_reusable(fetched, now + Duration::nanoseconds(1), fetched).unwrap());
}

#[test]
fn session_version_shape_parameters_change_the_assessment_boundary() {
    let events = [
        ("1.0.0", "2025-01-01T00:00:00Z"),
        ("1.1.0", "2025-02-10T00:00:00Z"),
        ("3.0.0", "2025-02-11T00:00:00Z"),
    ];
    let packet = packument("3.0.0", &events);
    let default = version_shape_findings_with_parameters(
        &packet,
        "3.0.0",
        NpmVersionShapeParameters::default(),
    )
    .unwrap();
    assert_eq!(default[0].rule_id, "npm-version-shape-unassessed");

    let rules = argus_rules::RuleSession::load(
        None,
        &[
            "version-shape-anomaly=param:minimum_predecessors=2".to_string(),
            "version-shape-anomaly=param:baseline_transitions=1".to_string(),
        ],
    )
    .unwrap();
    let configured = version_shape_findings_with_parameters(
        &packet,
        "3.0.0",
        rules.npm_version_shape_parameters().unwrap(),
    )
    .unwrap();
    assert_eq!(configured[0].rule_id, "version-shape-anomaly");
}
