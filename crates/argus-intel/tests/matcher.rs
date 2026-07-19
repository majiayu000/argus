mod fixtures;

use argus_core::{Ecosystem, IntelMatchStatus, PackageCoordinate, Severity};
use argus_intel::{
    import_snapshot, ImportLimits, ImportRequest, IntelDatabase, CANONICAL_SOURCE,
    RULE_KNOWN_MALICIOUS,
};
use chrono::{TimeZone, Utc};
use fixtures::{archive, exact_record, range_record, MockArchiveTransport, REVISION};

const MODIFIED: &str = "2026-01-01T00:00:00Z";

fn database(entries: &[(&str, &[u8])]) -> (tempfile::TempDir, IntelDatabase) {
    let dir = tempfile::tempdir().unwrap();
    let path = std::fs::canonicalize(dir.path())
        .unwrap()
        .join("intel.json");
    let bytes = archive(entries);
    import_snapshot(
        &ImportRequest {
            source: CANONICAL_SOURCE,
            revision: REVISION,
            output: &path,
            imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            limits: ImportLimits::default(),
        },
        &MockArchiveTransport::new(bytes),
    )
    .unwrap();
    let database = IntelDatabase::load(&path).unwrap();
    (dir, database)
}

#[test]
fn osv_match_matrix() {
    let fixtures = [
        ("npm.json", exact_record("MAL-NPM", "npm", "demo", "1.2.3")),
        (
            "pypi.json",
            range_record("MAL-PYPI", "PyPI", "demo_pkg", "ECOSYSTEM", "1.0", "2.0"),
        ),
        (
            "crates.json",
            exact_record("MAL-CRATE", "crates.io", "demo", "1.2.3"),
        ),
        (
            "go.json",
            exact_record("MAL-GO", "Go", "example.com/Demo", "1.2.3"),
        ),
        (
            "nuget.json",
            range_record("MAL-NUGET", "NuGet", "Demo", "ECOSYSTEM", "1.0", "2.0"),
        ),
        (
            "maven.json",
            range_record(
                "MAL-MAVEN",
                "Maven",
                "com.Example:Demo",
                "ECOSYSTEM",
                "1.0-alpha",
                "2.0",
            ),
        ),
        (
            "gem.json",
            exact_record("MAL-GEM", "RubyGems", "Demo", "1.2.3"),
        ),
        (
            "composer.json",
            range_record(
                "MAL-COMPOSER",
                "Packagist",
                "Vendor/Demo",
                "ECOSYSTEM",
                "1.0.0",
                "2.0.0",
            ),
        ),
    ];
    let owned_paths = fixtures
        .iter()
        .map(|(path, _)| format!("osv/malicious/{path}"))
        .collect::<Vec<_>>();
    let entries = fixtures
        .iter()
        .zip(&owned_paths)
        .map(|((_, body), path)| (path.as_str(), body.as_slice()))
        .collect::<Vec<_>>();
    let (_dir, db) = database(&entries);
    let cases = [
        (Ecosystem::Npm, "demo", "1.2.3"),
        (Ecosystem::PyPi, "Demo.Pkg", "1.5"),
        (Ecosystem::CratesIo, "demo", "1.2.3"),
        (Ecosystem::Go, "example.com/Demo", "v1.2.3"),
        (Ecosystem::NuGet, "DEMO", "1.5"),
        (Ecosystem::Maven, "com.Example:Demo", "1.5"),
        (Ecosystem::RubyGems, "Demo", "1.2.3"),
        (Ecosystem::Packagist, "vendor/demo", "1.5.0"),
    ];
    for (ecosystem, name, version) in cases {
        let coordinate = PackageCoordinate::new(ecosystem, name, version).unwrap();
        let result = db.match_coordinate(&coordinate).unwrap();
        assert_eq!(result.status, IntelMatchStatus::Matched, "{ecosystem:?}");
        assert_eq!(result.findings.len(), 1, "{ecosystem:?}");
    }
    let adjacent = PackageCoordinate::new(Ecosystem::NuGet, "demo", "2.0").unwrap();
    assert_eq!(
        db.match_coordinate(&adjacent).unwrap().status,
        IntelMatchStatus::NoMatch
    );
}

#[test]
fn malicious_finding() {
    let body = exact_record("MAL-EVIDENCE", "npm", "demo", "1.0.0");
    let (_dir, db) = database(&[("osv/malicious/evidence.json", &body)]);
    let coordinate = PackageCoordinate::new(Ecosystem::Npm, "demo", "1.0.0").unwrap();
    let result = db.match_coordinate(&coordinate).unwrap();
    let finding = &result.findings[0];
    assert_eq!(finding.rule_id, RULE_KNOWN_MALICIOUS);
    assert_eq!(finding.severity, Severity::Critical);
    let evidence = finding.evidence.as_ref().unwrap().join("\n");
    assert!(evidence.contains("advisory=MAL-EVIDENCE"));
    assert!(evidence.contains("aliases=MAL-EVIDENCE-ALIAS"));
    assert!(evidence.contains(&format!("source_revision={REVISION}")));
    assert!(evidence.contains("match_basis=exact:1.0.0"));
    let status = db
        .status(
            Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap(),
            result.status,
        )
        .unwrap();
    assert_eq!(status.age_seconds, 86_400);
}

#[test]
fn forged_public_coordinates_fail_closed_before_index_lookup() {
    let body = exact_record("MAL-DTO", "npm", "demo", "1.0.0");
    let (_dir, db) = database(&[("osv/malicious/dto.json", &body)]);
    let valid = PackageCoordinate::new(Ecosystem::Npm, "demo", "1.0.0").unwrap();

    let mut canonical_name = valid.clone();
    canonical_name.canonical_name = "definitely-absent".to_string();
    let mut purl = valid.clone();
    purl.purl = "pkg:npm/other@1.0.0".to_string();
    let mut original_ecosystem = valid.clone();
    original_ecosystem.original_ecosystem = "PyPI".to_string();
    let mut version = valid;
    version.version = "2.0.0".to_string();

    let cases = [
        (
            "canonical_name/no-candidate",
            canonical_name,
            "canonical package name",
        ),
        ("purl", purl, "package purl"),
        (
            "original_ecosystem",
            original_ecosystem,
            "original ecosystem",
        ),
        ("version", version, "package version"),
    ];
    for (label, coordinate, expected_detail) in cases {
        let error = db.match_coordinate(&coordinate).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("validate package coordinate before intelligence matching"),
            "{label}: {chain}"
        );
        assert!(chain.contains(expected_detail), "{label}: {chain}");
    }
}

#[test]
fn malformed_matrix() {
    let malformed = serde_json::to_vec(&serde_json::json!({
        "schema_version": "1.7.4",
        "id": "MAL-BAD",
        "modified": MODIFIED,
        "affected": [{
            "package": {"ecosystem": "npm", "name": "demo"},
            "ranges": [{
                "type": "GIT",
                "repo": "https://example.test/repo",
                "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]
            }]
        }]
    }))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let output = std::fs::canonicalize(dir.path())
        .unwrap()
        .join("intel.json");
    let error = import_snapshot(
        &ImportRequest {
            source: CANONICAL_SOURCE,
            revision: REVISION,
            output: &output,
            imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            limits: ImportLimits::default(),
        },
        &MockArchiveTransport::new(archive(&[("osv/malicious/bad.json", &malformed)])),
    )
    .unwrap_err();
    assert!(error.to_string().contains("range type"));
    assert!(!output.exists());
}

#[test]
fn typed_comparator_boundaries() {
    let fixtures = [
        (
            "pypi.json",
            range_record(
                "MAL-PEP440",
                "PyPI",
                "typed",
                "ECOSYSTEM",
                "1!1.0a1",
                "1!1.0.post1",
            ),
        ),
        (
            "nuget.json",
            range_record(
                "MAL-NUGET-TYPED",
                "NuGet",
                "typed",
                "ECOSYSTEM",
                "1.0.0-alpha.1",
                "1.0.0",
            ),
        ),
        (
            "maven.json",
            range_record(
                "MAL-MAVEN-TYPED",
                "Maven",
                "org.example:typed",
                "ECOSYSTEM",
                "1.0-alpha1",
                "1.0-sp1",
            ),
        ),
        (
            "gem.json",
            range_record(
                "MAL-GEM-TYPED",
                "RubyGems",
                "typed",
                "ECOSYSTEM",
                "1.0.a1",
                "1.0",
            ),
        ),
        (
            "composer.json",
            range_record(
                "MAL-COMPOSER-TYPED",
                "Packagist",
                "vendor/typed",
                "ECOSYSTEM",
                "1.0.0-alpha1",
                "1.0.0",
            ),
        ),
    ];
    let paths = fixtures
        .iter()
        .map(|(name, _)| format!("osv/malicious/{name}"))
        .collect::<Vec<_>>();
    let entries = fixtures
        .iter()
        .zip(&paths)
        .map(|((_, body), path)| (path.as_str(), body.as_slice()))
        .collect::<Vec<_>>();
    let (_dir, db) = database(&entries);
    let matches = [
        (Ecosystem::PyPi, "typed", "1!1.0rc1"),
        (Ecosystem::NuGet, "typed", "1.0.0-beta.2"),
        (Ecosystem::Maven, "org.example:typed", "1.0-rc1"),
        (Ecosystem::RubyGems, "typed", "1.0.b1"),
        (Ecosystem::Packagist, "vendor/typed", "1.0.0-beta1"),
    ];
    for (ecosystem, name, version) in matches {
        let coordinate = PackageCoordinate::new(ecosystem, name, version).unwrap();
        assert_eq!(
            db.match_coordinate(&coordinate).unwrap().status,
            IntelMatchStatus::Matched,
            "{ecosystem:?} {version}"
        );
    }
    let stable = PackageCoordinate::new(Ecosystem::NuGet, "typed", "1.0.0").unwrap();
    assert_eq!(
        db.match_coordinate(&stable).unwrap().status,
        IntelMatchStatus::NoMatch
    );
    let unprefixed_go =
        PackageCoordinate::new(Ecosystem::Go, "example.com/typed", "1.2.3").unwrap();
    assert_eq!(
        db.match_coordinate(&unprefixed_go).unwrap().status,
        IntelMatchStatus::NoMatch
    );
}

#[test]
fn range_union_limit_open_end_withdrawn_and_alias_collision() {
    let union = serde_json::to_vec(&serde_json::json!({
        "schema_version": "1.7.4",
        "id": "MAL-UNION",
        "modified": MODIFIED,
        "aliases": ["SHARED", "SHARED"],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "union"},
            "versions": ["9.9.9"],
            "ranges": [{"type": "SEMVER", "events": [
                {"introduced": "1.0.0"}, {"fixed": "2.0.0"},
                {"introduced": "3.0.0"}, {"last_affected": "4.0.0"},
                {"introduced": "5.0.0"}
            ]}]
        }]
    }))
    .unwrap();
    let limit = serde_json::to_vec(&serde_json::json!({
        "schema_version": "1.7.4",
        "id": "MAL-LIMIT",
        "modified": MODIFIED,
        "aliases": ["SHARED"],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "union"},
            "ranges": [{"type": "SEMVER", "events": [
                {"introduced": "8.0.0"}, {"limit": "10.0.0"}
            ]}]
        }]
    }))
    .unwrap();
    let withdrawn = serde_json::to_vec(&serde_json::json!({
        "schema_version": "1.7.4",
        "id": "MAL-WITHDRAWN",
        "modified": MODIFIED,
        "withdrawn": "2026-01-01T00:00:00Z",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "withdrawn"},
            "versions": ["1.0.0"]
        }]
    }))
    .unwrap();
    let (_dir, db) = database(&[
        ("osv/malicious/union.json", &union),
        ("osv/malicious/limit.json", &limit),
        ("osv/withdrawn/withdrawn.json", &withdrawn),
    ]);
    let counts = db.snapshot().record_counts();
    assert_eq!(counts.active_records, 2);
    assert_eq!(counts.withdrawn_records, 1);
    for version in ["1.5.0", "4.0.0", "5.0.0", "9.9.9"] {
        let coordinate = PackageCoordinate::new(Ecosystem::Npm, "union", version).unwrap();
        assert_eq!(
            db.match_coordinate(&coordinate).unwrap().status,
            IntelMatchStatus::Matched,
            "{version}"
        );
    }
    let collision = PackageCoordinate::new(Ecosystem::Npm, "union", "9.0.0").unwrap();
    assert_eq!(db.match_coordinate(&collision).unwrap().findings.len(), 2);
    let exclusive = PackageCoordinate::new(Ecosystem::Npm, "union", "10.0.0").unwrap();
    assert_eq!(
        db.match_coordinate(&exclusive).unwrap().status,
        IntelMatchStatus::Matched,
        "open-ended MAL-UNION remains active at 10.0.0"
    );
    let withdrawn_coordinate =
        PackageCoordinate::new(Ecosystem::Npm, "withdrawn", "1.0.0").unwrap();
    assert_eq!(
        db.match_coordinate(&withdrawn_coordinate).unwrap().status,
        IntelMatchStatus::NoMatch
    );
}

#[test]
fn malformed_event_and_record_matrix() {
    let cases = [
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-MULTI","modified":MODIFIED,"affected":[{
                "package":{"ecosystem":"npm","name":"bad"},
                "ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0","fixed":"2.0.0"}]}]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-CLOSE","modified":MODIFIED,"affected":[{
                "package":{"ecosystem":"npm","name":"bad"},
                "ranges":[{"type":"SEMVER","events":[{"fixed":"2.0.0"}]}]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-OPEN","modified":MODIFIED,"affected":[{
                "package":{"ecosystem":"npm","name":"bad"},
                "ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"introduced":"2.0.0"}]}]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-ORDER","modified":MODIFIED,"affected":[{
                "package":{"ecosystem":"npm","name":"bad"},
                "ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"1.0.0"}]}]
            }]
        }),
        serde_json::json!({
            "schema_version":"9.0.0","id":"BAD-SCHEMA","modified":MODIFIED,"affected":[{
                "package":{"ecosystem":"npm","name":"bad"},"versions":["1.0.0"]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-EMPTY","modified":MODIFIED,"affected":[]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-SECOND-ZERO","modified":MODIFIED,"affected":[{
                "package":{"ecosystem":"npm","name":"bad"},
                "ranges":[{"type":"SEMVER","events":[
                    {"introduced":"0"},{"fixed":"1.0.0"},
                    {"introduced":"0"}
                ]}]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-EMPTY-FIXED","modified":MODIFIED,"affected":[{
                "package":{"ecosystem":"npm","name":"bad"},
                "ranges":[{"type":"SEMVER","events":[
                    {"introduced":"1.0.0"},{"fixed":"1.0.0"}
                ]}]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-EMPTY-LIMIT","modified":MODIFIED,"affected":[{
                "package":{"ecosystem":"npm","name":"bad"},
                "ranges":[{"type":"SEMVER","events":[
                    {"introduced":"1.0.0"},{"limit":"1.0.0"}
                ]}]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-GEM-GRAMMAR","modified":MODIFIED,"affected":[{
                "package":{"ecosystem":"RubyGems","name":"bad"},
                "versions":["1.0_1"]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-PEP-PRE-AFTER-POST","modified":MODIFIED,
            "affected":[{
                "package":{"ecosystem":"PyPI","name":"bad"},
                "versions":["1.0post1a1"]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-PEP-POST-AFTER-DEV","modified":MODIFIED,
            "affected":[{
                "package":{"ecosystem":"PyPI","name":"bad"},
                "versions":["1.0.dev1post1"]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-SEVERITY-SOURCE","modified":MODIFIED,
            "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N","source":"UNKNOWN"}],
            "affected":[{
                "package":{"ecosystem":"npm","name":"bad"},"versions":["1.0.0"]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-SEVERITY-TYPE","modified":MODIFIED,
            "severity":[{"type":"CVSS_V5","score":"critical"}],
            "affected":[{
                "package":{"ecosystem":"npm","name":"bad"},"versions":["1.0.0"]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-SEVERITY-SCORE","modified":MODIFIED,
            "severity":[{"type":"CVSS_V3","score":"critical","source":"SELF"}],
            "affected":[{
                "package":{"ecosystem":"npm","name":"bad"},"versions":["1.0.0"]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-ECOSYSTEM","modified":MODIFIED,
            "affected":[{
                "package":{"ecosystem":"NotARealEcosystem","name":"bad"},"versions":["1.0.0"]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-DATABASE-SPECIFIC","modified":MODIFIED,
            "database_specific":[],
            "affected":[{
                "package":{"ecosystem":"npm","name":"bad"},"versions":["1.0.0"]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-ECOSYSTEM-SPECIFIC","modified":MODIFIED,
            "affected":[{
                "package":{"ecosystem":"npm","name":"bad"},"versions":["1.0.0"],
                "ecosystem_specific":"not-an-object"
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-REFERENCE-URL","modified":MODIFIED,
            "references":[{"type":"ADVISORY","url":"not a URI"}],
            "affected":[{
                "package":{"ecosystem":"npm","name":"bad"},"versions":["1.0.0"]
            }]
        }),
        serde_json::json!({
            "schema_version":"1.7.4","id":"BAD-CREDIT-TYPE","modified":MODIFIED,
            "credits":[{"name":"Researcher","type":"UNKNOWN"}],
            "affected":[{
                "package":{"ecosystem":"npm","name":"bad"},"versions":["1.0.0"]
            }]
        }),
    ];
    for (index, value) in cases.into_iter().enumerate() {
        let body = serde_json::to_vec(&value).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let output = std::fs::canonicalize(dir.path())
            .unwrap()
            .join(format!("bad-{index}.json"));
        let result = import_snapshot(
            &ImportRequest {
                source: CANONICAL_SOURCE,
                revision: REVISION,
                output: &output,
                imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
                limits: ImportLimits::default(),
            },
            &MockArchiveTransport::new(archive(&[("osv/malicious/bad.json", &body)])),
        );
        assert!(result.is_err(), "malformed case {index} was accepted");
        assert!(!output.exists());
    }
}

#[test]
fn official_gem_and_maven_regressions() {
    let gem = exact_record("MAL-GEM-OFFICIAL", "RubyGems", "official", "1.a");
    let maven = range_record(
        "MAL-MAVEN-OFFICIAL",
        "Maven",
        "org.example:official",
        "ECOSYSTEM",
        "1.0-1",
        "1.0.1",
    );
    let inclusive = serde_json::to_vec(&serde_json::json!({
        "schema_version":"1.7.4","id":"MAL-INCLUSIVE-EQUAL","modified":MODIFIED,"affected":[{
            "package":{"ecosystem":"npm","name":"inclusive"},
            "ranges":[{"type":"SEMVER","events":[
                {"introduced":"1.0.0"},{"last_affected":"1.0.0"}
            ]}]
        }]
    }))
    .unwrap();
    let (_dir, db) = database(&[
        ("osv/malicious/gem.json", &gem),
        ("osv/malicious/maven.json", &maven),
        ("osv/malicious/inclusive.json", &inclusive),
    ]);
    let gem_equivalent = PackageCoordinate::new(Ecosystem::RubyGems, "official", "1.0.a").unwrap();
    assert_eq!(
        db.match_coordinate(&gem_equivalent).unwrap().status,
        IntelMatchStatus::Matched,
        "Gem::Version canonical zero segments must compare equal"
    );
    let maven_hyphen =
        PackageCoordinate::new(Ecosystem::Maven, "org.example:official", "1.0-1").unwrap();
    let maven_dot =
        PackageCoordinate::new(Ecosystem::Maven, "org.example:official", "1.0.1").unwrap();
    assert_eq!(
        db.match_coordinate(&maven_hyphen).unwrap().status,
        IntelMatchStatus::Matched
    );
    assert_eq!(
        db.match_coordinate(&maven_dot).unwrap().status,
        IntelMatchStatus::NoMatch,
        "Maven ComparableVersion distinguishes hyphen list from dot segment"
    );
    let exact_boundary = PackageCoordinate::new(Ecosystem::Npm, "inclusive", "1.0.0").unwrap();
    assert_eq!(
        db.match_coordinate(&exact_boundary).unwrap().status,
        IntelMatchStatus::Matched
    );
}

#[test]
fn official_go_and_pep440_boundaries() {
    let go = range_record(
        "MAL-GO-OFFICIAL",
        "Go",
        "example.com/official",
        "SEMVER",
        "1.2.0",
        "1.3.0",
    );
    let pep = exact_record("MAL-PEP-OFFICIAL", "PyPI", "pep-official", "1.0-1");
    let (_dir, db) = database(&[
        ("osv/malicious/go.json", &go),
        ("osv/malicious/pep.json", &pep),
    ]);

    for version in ["v1.2.5", "1.2.5"] {
        let coordinate =
            PackageCoordinate::new(Ecosystem::Go, "example.com/official", version).unwrap();
        assert_eq!(
            db.match_coordinate(&coordinate).unwrap().status,
            IntelMatchStatus::Matched,
            "Go registry/OSV prefix normalization failed for {version}"
        );
    }
    let post = PackageCoordinate::new(Ecosystem::PyPi, "pep-official", "1.0.post1").unwrap();
    let dotted = PackageCoordinate::new(Ecosystem::PyPi, "pep-official", "1.0.1").unwrap();
    assert_eq!(
        db.match_coordinate(&post).unwrap().status,
        IntelMatchStatus::Matched,
        "PEP 440 implicit post release must equal explicit post release"
    );
    assert_eq!(
        db.match_coordinate(&dotted).unwrap().status,
        IntelMatchStatus::NoMatch,
        "PEP 440 implicit post release must not become a dotted release"
    );
}

#[test]
fn upstream_osv_schema_fields_and_required_modified() {
    let valid = serde_json::to_vec(&serde_json::json!({
        "schema_version":"1.7.4",
        "id":"MAL-UPSTREAM-SCHEMA",
        "modified":MODIFIED,
        "published":"2025-12-31T00:00:00Z",
        "aliases":null,
        "upstream":["MAL-UPSTREAM-PARENT"],
        "severity":[{
            "type":"CVSS_V3",
            "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }],
        "references":[{"type":"ADVISORY","url":"https://osv.dev/vulnerability/MAL-UPSTREAM-SCHEMA"}],
        "credits":[{
            "name":"Security Researcher",
            "contact":["security@example.com","@security"],
            "type":"FINDER"
        }],
        "affected":[{
            "package":{"ecosystem":"npm","name":"schema-demo"},
            "versions":["1.0.0"]
        }]
    }))
    .unwrap();
    let (_dir, database) = database(&[("osv/malicious/schema.json", &valid)]);
    let coordinate = PackageCoordinate::new(Ecosystem::Npm, "schema-demo", "1.0.0").unwrap();
    assert_eq!(
        database.match_coordinate(&coordinate).unwrap().status,
        IntelMatchStatus::Matched
    );

    let missing_modified = serde_json::to_vec(&serde_json::json!({
        "schema_version":"1.7.4",
        "id":"MAL-MISSING-MODIFIED",
        "affected":[{
            "package":{"ecosystem":"npm","name":"schema-demo"},
            "versions":["1.0.0"]
        }]
    }))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let output = std::fs::canonicalize(dir.path())
        .unwrap()
        .join("missing-modified.json");
    let error = import_snapshot(
        &ImportRequest {
            source: CANONICAL_SOURCE,
            revision: REVISION,
            output: &output,
            imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            limits: ImportLimits::default(),
        },
        &MockArchiveTransport::new(archive(&[(
            "osv/malicious/missing-modified.json",
            &missing_modified,
        )])),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("missing field `modified`"));
    assert!(!output.exists());

    let supported_non_scanned_ecosystem = exact_record(
        "MAL-DEBIAN-SCHEMA",
        "Debian:12",
        "openssl",
        "not-parsed-after-schema-validation",
    );
    let dir = tempfile::tempdir().unwrap();
    let output = std::fs::canonicalize(dir.path())
        .unwrap()
        .join("debian.json");
    let snapshot = import_snapshot(
        &ImportRequest {
            source: CANONICAL_SOURCE,
            revision: REVISION,
            output: &output,
            imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            limits: ImportLimits::default(),
        },
        &MockArchiveTransport::new(archive(&[(
            "osv/malicious/debian.json",
            &supported_non_scanned_ecosystem,
        )])),
    )
    .unwrap();
    assert!(snapshot.snapshot.records.is_empty());
}

#[test]
fn overlapping_ranges_have_one_deterministic_records_digest() {
    let segmented = serde_json::to_vec(&serde_json::json!({
        "schema_version":"1.7.4","id":"MAL-OVERLAP","modified":MODIFIED,"affected":[{
            "package":{"ecosystem":"npm","name":"overlap"},
            "ranges":[
                {"type":"SEMVER","events":[
                    {"introduced":"1.0.0"},{"fixed":"3.0.0"}
                ]},
                {"type":"SEMVER","events":[
                    {"introduced":"2.0.0"},{"last_affected":"4.0.0"}
                ]}
            ]
        }]
    }))
    .unwrap();
    let merged = serde_json::to_vec(&serde_json::json!({
        "schema_version":"1.7.4","id":"MAL-OVERLAP","modified":MODIFIED,"affected":[{
            "package":{"ecosystem":"npm","name":"overlap"},
            "ranges":[{"type":"SEMVER","events":[
                {"introduced":"1.0.0"},{"last_affected":"4.0.0"}
            ]}]
        }]
    }))
    .unwrap();
    let snapshots = [&segmented, &merged]
        .into_iter()
        .map(|body| {
            let dir = tempfile::tempdir().unwrap();
            let output = std::fs::canonicalize(dir.path())
                .unwrap()
                .join("overlap.json");
            import_snapshot(
                &ImportRequest {
                    source: CANONICAL_SOURCE,
                    revision: REVISION,
                    output: &output,
                    imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
                    limits: ImportLimits::default(),
                },
                &MockArchiveTransport::new(archive(&[("osv/malicious/overlap.json", body)])),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(snapshots[0].snapshot.records, snapshots[1].snapshot.records);
    assert_eq!(
        snapshots[0].snapshot.records_sha256,
        snapshots[1].snapshot.records_sha256
    );
}
