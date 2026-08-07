use super::*;

#[test]
fn decision_serializes_kebab_case() {
    assert_eq!(
        serde_json::to_string(&Decision::AllowWithApproval).unwrap(),
        "\"allow-with-approval\""
    );
}

#[test]
fn rule_ids_dedups_in_order() {
    let report = ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: PathBuf::from("/tmp/x"),
        package_name: None,
        package_version: None,
        decision: Decision::Block,
        findings: vec![
            Finding::new("lifecycle-script", Severity::High, "preinstall"),
            Finding::new("remote-download", Severity::High, "curl"),
            Finding::new("lifecycle-script", Severity::High, "postinstall"),
        ],
        coordinate: None,
        intelligence: None,
        rules: None,
        vulnerability: None,
    };
    assert_eq!(
        report.rule_ids(),
        vec!["lifecycle-script", "remote-download"]
    );
}

#[test]
fn coordinate_matrix() {
    let cases = [
        (
            Ecosystem::Npm,
            "@Scope/Demo",
            "@scope/demo",
            "pkg:npm/%40scope/demo@1.2.3",
            "\"npm\"",
        ),
        (
            Ecosystem::PyPi,
            "Demo_pkg.Name",
            "demo-pkg-name",
            "pkg:pypi/demo-pkg-name@1.2.3",
            "\"PyPI\"",
        ),
        (
            Ecosystem::CratesIo,
            "Demo_Pkg",
            "demo_pkg",
            "pkg:cargo/demo_pkg@1.2.3",
            "\"crates.io\"",
        ),
        (
            Ecosystem::Go,
            "github.com/Owner/Repo",
            "github.com/Owner/Repo",
            "pkg:golang/github.com/Owner/Repo@v1.2.3",
            "\"Go\"",
        ),
        (
            Ecosystem::NuGet,
            "Clean.Pkg",
            "clean.pkg",
            "pkg:nuget/clean.pkg@1.2.3",
            "\"NuGet\"",
        ),
        (
            Ecosystem::Maven,
            "Com.Example:Demo",
            "Com.Example:Demo",
            "pkg:maven/Com.Example/Demo@1.2.3",
            "\"Maven\"",
        ),
        (
            Ecosystem::RubyGems,
            "Demo_Gem",
            "Demo_Gem",
            "pkg:gem/Demo_Gem@1.2.3",
            "\"RubyGems\"",
        ),
        (
            Ecosystem::Packagist,
            "Vendor/Package",
            "vendor/package",
            "pkg:composer/vendor/package@1.2.3",
            "\"Packagist\"",
        ),
    ];

    for (ecosystem, original_name, canonical_name, expected_purl, serialized) in cases {
        let version = if ecosystem == Ecosystem::Go {
            "v1.2.3"
        } else {
            "1.2.3"
        };
        let coordinate =
            PackageCoordinate::new(ecosystem, original_name, version).expect("coordinate");
        assert_eq!(coordinate.canonical_name, canonical_name);
        assert_eq!(coordinate.version, version);
        assert_eq!(coordinate.purl, expected_purl);
        assert_eq!(coordinate.original_ecosystem, ecosystem.osv_name());
        assert_eq!(coordinate.original_name, original_name);
        assert_eq!(coordinate.original_version, version);
        assert_eq!(serde_json::to_string(&ecosystem).unwrap(), serialized);
    }

    let crate_dash = PackageCoordinate::new(Ecosystem::CratesIo, "demo-pkg", "1.0.0").unwrap();
    let crate_underscore =
        PackageCoordinate::new(Ecosystem::CratesIo, "demo_pkg", "1.0.0").unwrap();
    assert_ne!(crate_dash, crate_underscore);

    let npm = PackageCoordinate::new(Ecosystem::Npm, "demo", "1.0.0").unwrap();
    let pypi = PackageCoordinate::new(Ecosystem::PyPi, "demo", "1.0.0").unwrap();
    assert_ne!(npm, pypi, "cross-ecosystem names must never merge");

    assert!(PackageCoordinate::new(Ecosystem::Npm, "", "1.0.0").is_err());
    assert!(PackageCoordinate::new(Ecosystem::Npm, "demo", "").is_err());
    assert!(PackageCoordinate::new(Ecosystem::Npm, "de\u{0}mo", "1.0.0").is_err());
    assert!(PackageCoordinate::new(Ecosystem::Npm, "demo", "1.0\n.0").is_err());
    assert!(canonicalize_package_name(Ecosystem::Npm, "démø").is_err());
    assert!(canonicalize_package_name(Ecosystem::CratesIo, "craté").is_err());
    assert!(canonicalize_package_name(Ecosystem::NuGet, "NúGet.Package").is_err());
    assert!(canonicalize_package_name(Ecosystem::PyPi, "pÿpi").is_err());
    assert!(canonicalize_package_name(Ecosystem::Npm, "@scope/name/extra").is_err());
    assert!(canonicalize_package_name(Ecosystem::Maven, "group:artifact:extra").is_err());
    assert!(canonicalize_package_name(Ecosystem::Packagist, "vendor/package/extra").is_err());

    let mut inconsistent = PackageCoordinate::new(Ecosystem::Npm, "@scope/demo", "1.0.0").unwrap();
    inconsistent.canonical_name = "@scope/other".to_string();
    assert!(inconsistent.validate().is_err());
    inconsistent.canonical_name = "@scope/demo".to_string();
    inconsistent.purl = "pkg:npm/%40scope/other@1.0.0".to_string();
    assert!(inconsistent.validate().is_err());
}

#[test]
fn intelligence_status() {
    use chrono::TimeZone as _;

    let imported_at = Utc.with_ymd_and_hms(2026, 7, 19, 1, 2, 3).single().unwrap();
    let scan_started_at = Utc.with_ymd_and_hms(2026, 7, 19, 1, 4, 8).single().unwrap();
    let age_seconds = IntelSnapshotStatus::age_seconds(imported_at, scan_started_at).unwrap();
    assert_eq!(age_seconds, 125);
    assert_eq!(
        IntelSnapshotStatus::age_seconds(imported_at, imported_at).unwrap(),
        0
    );
    assert!(IntelSnapshotStatus::age_seconds(scan_started_at, imported_at).is_err());

    let status = IntelSnapshotStatus {
        source: "https://github.com/ossf/malicious-packages".to_string(),
        revision: "a".repeat(40),
        imported_at,
        age_seconds,
        archive_sha256: "b".repeat(64),
        records_sha256: "c".repeat(64),
        snapshot_sha256: "d".repeat(64),
        status: IntelMatchStatus::NoMatch,
    };
    let json = serde_json::to_value(&status).unwrap();
    assert_eq!(json["status"], "no_match");
    assert_eq!(json["age_seconds"], 125);

    let report = ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: PathBuf::from("/tmp/demo"),
        package_name: Some("demo".to_string()),
        package_version: Some("1.0.0".to_string()),
        decision: Decision::Allow,
        findings: Vec::new(),
        coordinate: None,
        intelligence: None,
        rules: None,
        vulnerability: None,
    };
    let report_json = serde_json::to_value(report).unwrap();
    assert!(report_json.get("coordinate").is_none());
    assert!(report_json.get("intelligence").is_none());
    assert!(report_json.get("vulnerability").is_none());
}
