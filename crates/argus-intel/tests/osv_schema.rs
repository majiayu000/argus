mod fixtures;

use argus_core::{Ecosystem, PackageCoordinate};
use argus_intel::{
    import_snapshot, validate_osv_coordinate, ImportLimits, ImportRequest, CANONICAL_SOURCE,
    SUPPORTED_SCHEMA_VERSIONS,
};
use chrono::{TimeZone, Utc};
use fixtures::{archive, exact_record, MockArchiveTransport, REVISION};
use serde_json::{json, Value};
use std::fs;

fn import_record(record: &Value) -> anyhow::Result<argus_intel::ImportOutcome> {
    let directory = tempfile::tempdir()?;
    let output = fs::canonicalize(directory.path())?.join("intel.json");
    let result = import_snapshot(
        &ImportRequest {
            source: CANONICAL_SOURCE,
            revision: REVISION,
            output: &output,
            imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            limits: ImportLimits::default(),
        },
        &MockArchiveTransport::new(archive(&[(
            "osv/malicious/schema.json",
            &serde_json::to_vec(record)?,
        )])),
    );
    if result.is_err() {
        assert!(!output.exists(), "failed schema import replaced output");
    }
    result
}

fn full_record() -> Value {
    json!({
        "schema_version": "1.7.4",
        "id": "MAL-STRICT-SCHEMA",
        "modified": "2026-01-01T00:00:00Z",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "strict"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
            }]
        }]
    })
}

fn insert_at(record: &mut Value, parent_pointer: &str, field: &str, value: Value) {
    record
        .pointer_mut(parent_pointer)
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert(field.to_string(), value);
}

#[test]
fn explicit_null_is_rejected_for_every_optional_non_null_field() {
    let cases = [
        ("", "published"),
        ("", "withdrawn"),
        ("", "summary"),
        ("", "details"),
        ("/affected/0/package", "purl"),
        ("/affected/0/ranges/0", "repo"),
        ("/affected/0/ranges/0/events/0", "introduced"),
        ("/affected/0/ranges/0/events/1", "fixed"),
        ("/affected/0/ranges/0/events/1", "last_affected"),
        ("/affected/0/ranges/0/events/1", "limit"),
    ];
    for (parent, field) in cases {
        let mut record = full_record();
        insert_at(&mut record, parent, field, Value::Null);
        assert!(
            import_record(&record).is_err(),
            "explicit null `{parent}/{field}` was accepted"
        );
    }

    let mut severity_source = full_record();
    severity_source["severity"] = json!([{"type":"CVSS_V3","score":"CVSS:3.1/AV:N","source":null}]);
    assert!(import_record(&severity_source).is_err());

    for field in ["contact", "type"] {
        let mut credit = full_record();
        credit["credits"] = json!([{"name":"Researcher"}]);
        insert_at(&mut credit, "/credits/0", field, Value::Null);
        assert!(
            import_record(&credit).is_err(),
            "credit.{field} null accepted"
        );
    }
}

#[test]
fn schema_versions_are_closed_to_the_supported_official_tags() {
    for version in SUPPORTED_SCHEMA_VERSIONS {
        let mut record = full_record();
        record["schema_version"] = (*version).into();
        assert!(
            import_record(&record).is_ok(),
            "supported schema {version} was rejected"
        );
    }

    let mut legacy = full_record();
    legacy.as_object_mut().unwrap().remove("schema_version");
    assert!(import_record(&legacy).is_ok());
    legacy["severity"] = json!([{
        "type":"CVSS_V3",
        "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }]);
    assert!(
        import_record(&legacy).is_err(),
        "missing schema_version was treated as a modern schema"
    );

    for invalid_version in [json!("1.7.1"), json!("9.0.0"), json!(""), Value::Null] {
        let mut record = full_record();
        record["schema_version"] = invalid_version;
        assert!(import_record(&record).is_err());
    }

    let mut invalid_id = full_record();
    invalid_id["id"] = "NOT-AN-OSV-ID".into();
    assert!(import_record(&invalid_id).is_err());

    for ecosystem in ["FreeBSD", "opam", "Azure Linux", "TuxCare", "vcpkg"] {
        let mut spoofed = full_record();
        spoofed["affected"][0]["package"]["ecosystem"] = ecosystem.into();
        assert!(
            import_record(&spoofed).is_err(),
            "post-1.7.4 ecosystem `{ecosystem}` was accepted"
        );
    }

    let mut source = full_record();
    source["severity"] = json!([{
        "type":"CVSS_V3",
        "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "source":"NVD"
    }]);
    assert!(import_record(&source).is_err());
    source["schema_version"] = "1.8.0".into();
    for allowed_source in ["NVD", "CNA", "SELF"] {
        source["severity"][0]["source"] = allowed_source.into();
        assert!(
            import_record(&source).is_ok(),
            "1.8.0 source `{allowed_source}` was rejected"
        );
    }
    source["severity"][0]["source"] = "UNKNOWN".into();
    assert!(import_record(&source).is_err());

    let mut early_upstream = full_record();
    early_upstream["schema_version"] = "1.6.0".into();
    early_upstream["upstream"] = json!(["MAL-PARENT"]);
    assert!(import_record(&early_upstream).is_err());
}

#[test]
fn maven_exact_coordinate_rejects_unresolved_property_expressions() {
    for version in ["${revision}", "1.2.3-${changelist}"] {
        let coordinate =
            PackageCoordinate::new(Ecosystem::Maven, "org.example:demo", version).unwrap();
        assert!(
            validate_osv_coordinate(&coordinate).is_err(),
            "unresolved Maven property `{version}` was accepted"
        );
    }
    for version in ["1.2.3-SNAPSHOT", "1.2.3-redhat-00001"] {
        let coordinate =
            PackageCoordinate::new(Ecosystem::Maven, "org.example:demo", version).unwrap();
        validate_osv_coordinate(&coordinate).unwrap();
    }
}

#[test]
fn legal_unscanned_ecosystem_is_validated_then_filtered() {
    let record: Value = serde_json::from_slice(&exact_record(
        "MAL-DEBIAN-STRICT",
        "Debian:12",
        "openssl",
        "1",
    ))
    .unwrap();
    let outcome = import_record(&record).unwrap();
    assert!(outcome.snapshot.records.is_empty());
    assert_eq!(outcome.snapshot.record_counts().active_records, 0);
}

#[test]
fn frozen_profiles_preserve_historical_string_rules_and_1_7_deltas() {
    let mut one_one = full_record();
    one_one["schema_version"] = "1.1.0".into();
    one_one["database_specific"] = json!({"source":"historical"});
    assert!(import_record(&one_one).is_ok());

    let mut one_six = full_record();
    one_six["schema_version"] = "1.6.0".into();
    one_six["id"] = "historical arbitrary identifier".into();
    one_six["affected"][0]["package"]["ecosystem"] = "Historical:".into();
    assert!(import_record(&one_six).unwrap().snapshot.records.is_empty());

    for ecosystem in ["Ubuntu", "Chainguard", "Mageia"] {
        let mut one_seven = full_record();
        one_seven["schema_version"] = "1.7.0".into();
        one_seven["affected"][0]["package"]["ecosystem"] = ecosystem.into();
        assert!(
            import_record(&one_seven).is_ok(),
            "1.7.0 ecosystem `{ecosystem}` was rejected"
        );
    }

    for (version, should_accept) in [("1.7.0", false), ("1.7.4", true)] {
        let mut delta = full_record();
        delta["schema_version"] = version.into();
        delta["id"] = "JLSEC-2026-1".into();
        delta["affected"][0]["package"]["ecosystem"] = "Julia".into();
        assert_eq!(
            import_record(&delta).is_ok(),
            should_accept,
            "unexpected frozen profile behavior for {version}"
        );
    }
}

#[test]
fn collection_nullability_is_frozen_per_schema_profile() {
    for version in ["1.0.0", "1.1.0", "1.2.0", "1.3.0"] {
        for field in ["aliases", "severity", "references"] {
            let mut record = full_record();
            record["schema_version"] = version.into();
            record[field] = Value::Null;
            assert!(
                import_record(&record).is_err(),
                "{field}: null was accepted by historical schema {version}"
            );
        }
    }
    for version in [
        "1.4.0", "1.5.0", "1.6.0", "1.6.1", "1.6.2", "1.6.3", "1.6.4", "1.6.5", "1.6.6", "1.6.7",
        "1.7.0", "1.7.2", "1.7.3", "1.7.4", "1.7.5", "1.8.0",
    ] {
        let mut record = full_record();
        record["schema_version"] = version.into();
        record["aliases"] = Value::Null;
        record["severity"] = Value::Null;
        record["references"] = Value::Null;
        assert!(
            import_record(&record).is_ok(),
            "nullable collections were rejected by schema {version}"
        );
    }
    let mut nullable_affected = full_record();
    nullable_affected["schema_version"] = "1.4.0".into();
    nullable_affected["affected"] = Value::Null;
    let error = import_record(&nullable_affected).unwrap_err();
    assert!(format!("{error:#}").contains("no affected packages"));
}

#[test]
fn historical_affected_requires_versions_without_a_supported_range() {
    for version in ["1.0.0", "1.1.0", "1.2.0", "1.3.0"] {
        let mut empty = full_record();
        empty["schema_version"] = version.into();
        empty["affected"][0]["ranges"] = json!([]);
        empty["affected"][0]["versions"] = json!([]);
        assert!(
            import_record(&empty).is_err(),
            "empty historical affected entry was accepted for {version}"
        );

        let mut exact = empty.clone();
        exact["affected"][0]["versions"] = json!(["1.0.0"]);
        assert!(
            import_record(&exact).is_ok(),
            "historical exact versions were rejected for {version}"
        );
    }

    let mut one_zero_ecosystem = full_record();
    one_zero_ecosystem["schema_version"] = "1.0.0".into();
    one_zero_ecosystem["affected"][0]["ranges"][0]["type"] = "ECOSYSTEM".into();
    assert!(
        import_record(&one_zero_ecosystem).is_err(),
        "1.0 ECOSYSTEM range incorrectly satisfied the historical condition"
    );

    let mut modern_empty = full_record();
    modern_empty["schema_version"] = "1.4.0".into();
    modern_empty["affected"][0]["ranges"] = json!([]);
    assert!(import_record(&modern_empty).is_ok());
}

#[test]
fn malformed_unscanned_ranges_fail_before_ecosystem_filtering() {
    type RangeMutation = (&'static str, fn(&mut Value));
    let mutations: [RangeMutation; 5] = [
        ("unknown-type", |record| {
            record["affected"][0]["ranges"][0]["type"] = "OTHER".into()
        }),
        ("two-fields", |record| {
            record["affected"][0]["ranges"][0]["events"][0]["fixed"] = "1".into()
        }),
        ("close-first", |record| {
            record["affected"][0]["ranges"][0]["events"] =
                json!([{"fixed":"1"}, {"introduced":"0"}])
        }),
        ("double-introduced", |record| {
            record["affected"][0]["ranges"][0]["events"] =
                json!([{"introduced":"0"}, {"introduced":"1"}])
        }),
        ("git-without-repo", |record| {
            record["affected"][0]["ranges"][0]["type"] = "GIT".into()
        }),
    ];
    for (label, mutate) in mutations {
        let mut record = full_record();
        record["affected"][0]["package"]["ecosystem"] = "Debian:12".into();
        mutate(&mut record);
        assert!(
            import_record(&record).is_err(),
            "malformed unscanned range `{label}` was filtered instead of rejected"
        );
    }

    let mut non_git_repo = full_record();
    non_git_repo["affected"][0]["package"]["ecosystem"] = "Debian:12".into();
    non_git_repo["affected"][0]["ranges"][0]["repo"] = "https://example.test/repo".into();
    assert!(
        import_record(&non_git_repo).is_ok(),
        "official schema permits repo on non-GIT ranges"
    );
}
