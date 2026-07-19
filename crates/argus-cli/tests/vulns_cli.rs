#![cfg(unix)]

use argus_core::{Ecosystem, PackageCoordinate};
use argus_lockfile::{parse_lockfile, BoundedInput, DetectionRequest};
use argus_osv::cache::{CacheEntry, CacheQuerySummary, SecureCache, CACHE_FILE_NAME};
use argus_osv::severity::{NormalizedSeverity, SeverityEvidence, SeverityLevel, SeveritySource};
use argus_osv::{
    collect_lockfile_coordinates, AdvisoryEvidence, AffectedEvidence, NormalizedAdvisory,
    RangeEvidence,
};
use chrono::{Duration, SecondsFormat, Utc};
use serde_json::{json, Value};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA256_SRI: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const H1: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn argus<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .env("PATH", "/argus-test-no-executables")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .output()
        .expect("run argus CLI")
}

fn coordinate(ecosystem: Ecosystem, name: &str, version: &str) -> PackageCoordinate {
    PackageCoordinate::new(ecosystem, name, version).expect("valid test coordinate")
}

fn cache_entry(
    coordinate: PackageCoordinate,
    fetched_at: chrono::DateTime<Utc>,
    advisories: Vec<NormalizedAdvisory>,
) -> CacheEntry {
    CacheEntry {
        coordinate,
        fetched_at,
        query_summaries: advisories
            .iter()
            .map(|advisory| CacheQuerySummary {
                primary_id: advisory.primary_id.clone(),
                modified: advisory.batch_summary_modified.clone(),
            })
            .collect(),
        advisories,
        response_sha256: String::new(),
    }
}

fn advisory(coordinate: &PackageCoordinate, level: SeverityLevel) -> NormalizedAdvisory {
    advisory_with_id(coordinate, "GHSA-TEST-0001", level)
}

fn advisory_with_id(
    coordinate: &PackageCoordinate,
    primary_id: &str,
    level: SeverityLevel,
) -> NormalizedAdvisory {
    let now = Utc::now() - Duration::hours(1);
    let modified = now.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let severity = match level {
        SeverityLevel::High => NormalizedSeverity {
            level,
            base_score: Some("7.5".to_string()),
            evidence: vec![
                SeverityEvidence {
                    severity_type: "CVSS_V3".to_string(),
                    score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
                    source: Some(SeveritySource::Nvd),
                },
                SeverityEvidence {
                    severity_type: "Ubuntu".to_string(),
                    score: "medium".to_string(),
                    source: Some(SeveritySource::Cna),
                },
            ],
        },
        SeverityLevel::Unknown => NormalizedSeverity {
            level,
            base_score: None,
            evidence: vec![SeverityEvidence {
                severity_type: "Ubuntu".to_string(),
                score: "medium".to_string(),
                source: Some(SeveritySource::SelfReported),
            }],
        },
        _ => NormalizedSeverity {
            level,
            base_score: None,
            evidence: Vec::new(),
        },
    };
    NormalizedAdvisory {
        coordinate: coordinate.clone(),
        primary_id: primary_id.to_string(),
        aliases: vec![
            format!("CVE-2099-{}", &primary_id[primary_id.len() - 4..]),
            format!("OSV-ALIAS-{}", &primary_id[primary_id.len() - 4..]),
        ],
        evidence: AdvisoryEvidence {
            locators: Vec::new(),
            affected: vec![AffectedEvidence {
                affected_index: 0,
                exact_versions: vec![coordinate.version.clone()],
                ranges: vec![
                    RangeEvidence {
                        affected_index: 0,
                        range_type: "SEMVER".to_string(),
                        introduced: "0".to_string(),
                        fixed: Some("2.0.0".to_string()),
                        last_affected: None,
                        limit: None,
                    },
                    RangeEvidence {
                        affected_index: 0,
                        range_type: "SEMVER".to_string(),
                        introduced: "0.5.0".to_string(),
                        fixed: Some("1.5.0".to_string()),
                        last_affected: None,
                        limit: None,
                    },
                ],
            }],
        },
        severity,
        references: Vec::new(),
        batch_summary_modified: modified.clone(),
        detail_modified: modified,
        database_modified: now,
        published: Some(now),
        source_url: format!("https://api.osv.dev/v1/vulns/{primary_id}"),
    }
}

fn seed_cache(
    root: &Path,
    fetched_at: chrono::DateTime<Utc>,
    entries: Vec<(PackageCoordinate, Vec<NormalizedAdvisory>)>,
) -> PathBuf {
    SecureCache::new(root)
        .commit(
            Path::new("cache"),
            entries
                .into_iter()
                .map(|(coordinate, advisories)| cache_entry(coordinate, fetched_at, advisories)),
            Utc::now(),
        )
        .expect("seed secure cache");
    root.join("cache")
}

fn package_args(ecosystem: &str, name: &str, version: &str, cache_dir: &Path) -> Vec<String> {
    vec![
        "vulns".to_string(),
        "package".to_string(),
        "--ecosystem".to_string(),
        ecosystem.to_string(),
        "--name".to_string(),
        name.to_string(),
        "--version".to_string(),
        version.to_string(),
        "--cache-dir".to_string(),
        cache_dir.to_string_lossy().into_owned(),
        "--offline".to_string(),
    ]
}

#[test]
fn package_eight_ecosystems_use_the_shared_coordinate_contract() {
    let root = tempfile::tempdir().expect("tempdir");
    let cases = [
        ("npm", Ecosystem::Npm, "@scope/Demo", "1.2.3"),
        ("pypi", Ecosystem::PyPi, "Demo_Pkg", "1.2.3"),
        ("crates.io", Ecosystem::CratesIo, "Demo_Crate", "1.2.3"),
        (
            "go",
            Ecosystem::Go,
            "example.com/Owner/Module",
            "v1.2.3+incompatible",
        ),
        ("nuget", Ecosystem::NuGet, "Demo.Package", "1.2.3"),
        ("maven", Ecosystem::Maven, "com.example:demo", "1.2.3.Final"),
        ("rubygems", Ecosystem::RubyGems, "DemoGem", "1.2.3"),
        ("packagist", Ecosystem::Packagist, "Vendor/Package", "1.2.3"),
    ];
    let entries = cases
        .iter()
        .map(|(_, ecosystem, name, version)| (coordinate(*ecosystem, name, version), Vec::new()))
        .collect();
    let cache = seed_cache(root.path(), Utc::now(), entries);
    for (ecosystem, _, name, version) in cases {
        let mut args = package_args(ecosystem, name, version, &cache);
        args.extend(["--format".to_string(), "json".to_string()]);
        let output = argus(&args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{ecosystem}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{ecosystem}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("vulnerability JSON");
        assert_eq!(report["evidence"]["status"], "complete_no_match");
        assert_eq!(report["evidence"]["source_mode"], "offline_fresh");
    }
}

#[test]
fn invalid_coordinate_and_option_contracts_fail_before_output() {
    let root = tempfile::tempdir().expect("tempdir");
    let cache = root.path().join("cache");
    let cases = [
        vec![
            "vulns",
            "package",
            "--ecosystem",
            "npm",
            "--name",
            "demo",
            "--version",
            "1.0.0",
        ],
        vec![
            "vulns",
            "package",
            "--ecosystem",
            "npm",
            "--name",
            "demo",
            "--version",
            "^1.0.0",
            "--cache-dir",
            cache.to_str().expect("path"),
            "--offline",
        ],
        vec![
            "vulns",
            "package",
            "--ecosystem",
            "npm",
            "--name",
            "demo",
            "--version",
            "1.0.0",
            "--cache-dir",
            cache.to_str().expect("path"),
            "--allow-stale",
        ],
        vec![
            "vulns",
            "package",
            "--ecosystem",
            "npm",
            "--name",
            "demo",
            "--version",
            "1.0.0",
            "--cache-dir",
            cache.to_str().expect("path"),
            "--max-age-seconds",
            "2592001",
        ],
    ];
    for args in cases {
        let output = argus(args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn ecosystem_aliases_are_rejected_exactly() {
    let root = tempfile::tempdir().expect("tempdir");
    let cache = root.path().join("cache");
    for alias in ["py-pi", "crates-io", "ruby-gems"] {
        let output = argus(package_args(alias, "demo", "1.0.0", &cache));
        assert_eq!(output.status.code(), Some(2), "{alias}");
        assert!(output.stdout.is_empty(), "{alias}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("invalid value"), "{alias}: {stderr}");
    }
}

#[test]
fn ranges_incomplete_versions_and_whitespace_are_rejected_before_cache_access() {
    let root = tempfile::tempdir().expect("tempdir");
    let cache = root.path().join("does-not-exist");
    let cases = [
        ("npm", "demo", "^1.0.0", "exact package version"),
        ("npm", "demo", "1.0.0 || 2.0.0", "whitespace"),
        (
            "maven",
            "com.example:demo",
            "[1.0,2.0)",
            "Maven version ranges",
        ),
        (
            "maven",
            "com.example:demo",
            "(,1.0]",
            "Maven version ranges",
        ),
        ("maven", "com.example:demo", "1.*", "Maven version ranges"),
        (
            "maven",
            "com.example:demo",
            "LATEST",
            "Maven version ranges",
        ),
        (
            "maven",
            "com.example:demo",
            "RELEASE",
            "Maven version ranges",
        ),
        ("go", "example.com/demo", "v1", "major, minor, and patch"),
        ("go", "example.com/demo", "v1.2", "major, minor, and patch"),
        ("npm", "demo", " 1.0.0", "whitespace"),
        ("npm", "demo", "1.0.0 ", "whitespace"),
        ("npm", "demo", "1. 0.0", "whitespace"),
    ];
    for (ecosystem, name, version, expected) in cases {
        let output = argus(package_args(ecosystem, name, version, &cache));
        assert_eq!(
            output.status.code(),
            Some(2),
            "{ecosystem} {version}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{ecosystem} {version}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{ecosystem} {version}: {stderr}");
        assert!(!stderr.contains("offline cache snapshot is missing"));
    }
}

#[test]
fn result_states_and_exit_codes_are_distinct() {
    let clean_root = tempfile::tempdir().expect("clean root");
    let clean_coordinate = coordinate(Ecosystem::Npm, "clean-demo", "1.0.0");
    let clean_cache = seed_cache(
        clean_root.path(),
        Utc::now(),
        vec![(clean_coordinate, Vec::new())],
    );
    let clean = argus(package_args("npm", "clean-demo", "1.0.0", &clean_cache));
    assert_eq!(clean.status.code(), Some(0));

    let active_root = tempfile::tempdir().expect("active root");
    let active_coordinate = coordinate(Ecosystem::Npm, "active-demo", "1.0.0");
    let active_cache = seed_cache(
        active_root.path(),
        Utc::now(),
        vec![(
            active_coordinate.clone(),
            vec![advisory(&active_coordinate, SeverityLevel::High)],
        )],
    );
    let approval = argus(package_args("npm", "active-demo", "1.0.0", &active_cache));
    assert_eq!(approval.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&approval.stdout).contains("known-vulnerability"));

    let mut blocking_args = package_args("npm", "active-demo", "1.0.0", &active_cache);
    blocking_args.extend(["--fail-on-severity".to_string(), "high".to_string()]);
    let blocking = argus(&blocking_args);
    assert_eq!(blocking.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&blocking.stdout).contains("decision: block"));
}

#[test]
fn active_unknown_and_multi_advisory_evidence_is_complete_in_every_renderer() {
    let root = tempfile::tempdir().expect("tempdir");
    let package = coordinate(Ecosystem::Npm, "matrix-demo", "1.0.0");
    let high = advisory_with_id(&package, "GHSA-MATRIX-0001", SeverityLevel::High);
    let unknown = advisory_with_id(&package, "GHSA-MATRIX-0002", SeverityLevel::Unknown);
    let raw_modified = high.batch_summary_modified.clone();
    let cache = seed_cache(
        root.path(),
        Utc::now(),
        vec![(package, vec![high, unknown])],
    );

    for format in ["text", "json", "sarif"] {
        let mut args = package_args("npm", "matrix-demo", "1.0.0", &cache);
        args.extend(["--format".to_string(), format.to_string()]);
        let output = argus(&args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{format}");
        match format {
            "text" => {
                let text = String::from_utf8(output.stdout).expect("text output");
                for expected in [
                    "status: complete_with_findings",
                    "source_mode: offline_fresh",
                    "cache: <argus-osv-cache>",
                    "maximum_age_seconds=",
                    "GHSA-MATRIX-0001",
                    "GHSA-MATRIX-0002",
                    "CVE-2099-0001",
                    "OSV-ALIAS-0002",
                    "\"introduced\":\"0\"",
                    "\"introduced\":\"0.5.0\"",
                    "type=CVSS_V3",
                    "type=Ubuntu",
                    "normalized_severity: unknown",
                    "batch_summary_modified:",
                    "detail_modified:",
                    "database_modified:",
                    "https://api.osv.dev/v1/vulns/GHSA-MATRIX-0001",
                ] {
                    assert!(text.contains(expected), "{expected}: {text}");
                }
                assert!(text.contains(&raw_modified));
            }
            "json" => {
                let json: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
                assert_eq!(json["evidence"]["status"], "complete_with_findings");
                assert_eq!(json["evidence"]["source_mode"], "offline_fresh");
                assert_eq!(json["cache_label"], "<argus-osv-cache>");
                assert!(json["evidence"]["maximum_age_seconds"].as_u64().is_some());
                assert_eq!(json["advisories"].as_array().expect("advisories").len(), 2);
                let first = &json["advisories"][0];
                assert_eq!(first["aliases"].as_array().expect("aliases").len(), 2);
                assert_eq!(
                    first["evidence"]["affected"][0]["ranges"]
                        .as_array()
                        .expect("ranges")
                        .len(),
                    2
                );
                assert_eq!(
                    first["severity"]["evidence"]
                        .as_array()
                        .expect("severity evidence")
                        .len(),
                    2
                );
                assert_eq!(first["batch_summary_modified"], raw_modified);
                assert_eq!(first["detail_modified"], raw_modified);
                assert_eq!(
                    first["source_url"],
                    "https://api.osv.dev/v1/vulns/GHSA-MATRIX-0001"
                );
                assert_eq!(json["advisories"][1]["severity"]["level"], "unknown");
            }
            "sarif" => {
                let sarif: Value = serde_json::from_slice(&output.stdout).expect("SARIF output");
                let run = &sarif["runs"][0];
                assert_eq!(
                    run["properties"]["argusVulnerability"]["status"],
                    "complete_with_findings"
                );
                assert_eq!(
                    run["properties"]["argusVulnerability"]["source_mode"],
                    "offline_fresh"
                );
                assert_eq!(run["properties"]["cache_label"], "<argus-osv-cache>");
                let results = run["results"].as_array().expect("SARIF results");
                assert_eq!(results.len(), 2);
                let first = &results[0]["properties"];
                assert_eq!(first["aliases"].as_array().expect("aliases").len(), 2);
                assert_eq!(
                    first["evidence"]["affected"][0]["ranges"]
                        .as_array()
                        .expect("ranges")
                        .len(),
                    2
                );
                assert_eq!(
                    first["severity_evidence"]
                        .as_array()
                        .expect("severity evidence")
                        .len(),
                    2
                );
                assert_eq!(first["batch_summary_modified"], raw_modified);
                assert_eq!(first["detail_modified"], raw_modified);
                assert!(first["database_modified"].as_str().is_some());
                assert_eq!(
                    first["source_url"],
                    "https://api.osv.dev/v1/vulns/GHSA-MATRIX-0001"
                );
                assert_eq!(results[1]["properties"]["normalized_severity"], "unknown");
            }
            _ => unreachable!("covered renderer"),
        }
    }
}

#[test]
fn offline_matrix_is_fail_closed_and_hides_cache_path() {
    let missing_root = tempfile::tempdir().expect("missing root");
    let missing_cache = missing_root.path().join("missing-cache");
    let missing = argus(package_args("npm", "demo", "1.0.0", &missing_cache));
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&missing.stderr)
        .contains(&missing_root.path().to_string_lossy().to_string()));

    let stale_root = tempfile::tempdir().expect("stale root");
    let stale_coordinate = coordinate(Ecosystem::Npm, "stale-demo", "1.0.0");
    let stale_cache = seed_cache(
        stale_root.path(),
        Utc::now() - Duration::hours(2),
        vec![(stale_coordinate, Vec::new())],
    );
    let mut unauthorized_args = package_args("npm", "stale-demo", "1.0.0", &stale_cache);
    unauthorized_args.extend(["--max-age-seconds".to_string(), "0".to_string()]);
    let unauthorized = argus(&unauthorized_args);
    assert_eq!(unauthorized.status.code(), Some(2));
    assert!(unauthorized.stdout.is_empty());

    let mut authorized_args = unauthorized_args;
    authorized_args.push("--allow-stale".to_string());
    let authorized = argus(&authorized_args);
    assert_eq!(authorized.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&authorized.stdout).contains("vulnerability-data-stale"));

    let corrupt_root = tempfile::tempdir().expect("corrupt root");
    let corrupt_coordinate = coordinate(Ecosystem::Npm, "corrupt-demo", "1.0.0");
    let corrupt_cache = seed_cache(
        corrupt_root.path(),
        Utc::now(),
        vec![(corrupt_coordinate, Vec::new())],
    );
    fs::write(corrupt_cache.join(CACHE_FILE_NAME), b"{not-json").expect("corrupt cache");
    let corrupt = argus(package_args("npm", "corrupt-demo", "1.0.0", &corrupt_cache));
    assert_eq!(corrupt.status.code(), Some(2));
    assert!(corrupt.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&corrupt.stderr)
        .contains(&corrupt_root.path().to_string_lossy().to_string()));

    let empty_root = tempfile::tempdir().expect("empty lockfile root");
    let empty_lockfile = empty_root.path().join("composer.lock");
    fs::write(
        &empty_lockfile,
        json!({"content-hash":"fixture","packages":[],"packages-dev":[]}).to_string(),
    )
    .expect("write empty lockfile");
    let empty_cache = empty_root.path().join("missing-cache");
    let empty = argus([
        "vulns",
        "lockfile",
        empty_lockfile.to_str().expect("path"),
        "--cache-dir",
        empty_cache.to_str().expect("path"),
        "--offline",
    ]);
    assert_eq!(empty.status.code(), Some(2));
    assert!(empty.stdout.is_empty());
}

#[test]
fn authorized_stale_cache_evidence_is_visible_in_every_renderer() {
    let root = tempfile::tempdir().expect("tempdir");
    let package = coordinate(Ecosystem::Npm, "stale-render-demo", "1.0.0");
    let cache = seed_cache(
        root.path(),
        Utc::now() - Duration::hours(2),
        vec![(package, Vec::new())],
    );
    for format in ["text", "json", "sarif"] {
        let mut args = package_args("npm", "stale-render-demo", "1.0.0", &cache);
        args.extend([
            "--max-age-seconds".to_string(),
            "0".to_string(),
            "--allow-stale".to_string(),
            "--format".to_string(),
            format.to_string(),
        ]);
        let output = argus(&args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        match format {
            "text" => {
                let text = String::from_utf8(output.stdout).expect("text output");
                assert!(text.contains("status: complete_stale"));
                assert!(text.contains("source_mode: offline_stale"));
                assert!(text.contains("cache: <argus-osv-cache>"));
                assert!(text.contains("maximum_age_seconds="));
                assert!(text.contains("vulnerability-data-stale"));
            }
            "json" => {
                let json: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
                assert_eq!(json["evidence"]["status"], "complete_stale");
                assert_eq!(json["evidence"]["source_mode"], "offline_stale");
                assert_eq!(json["cache_label"], "<argus-osv-cache>");
                assert!(
                    json["evidence"]["maximum_age_seconds"]
                        .as_u64()
                        .expect("age")
                        >= 7_200
                );
            }
            "sarif" => {
                let sarif: Value = serde_json::from_slice(&output.stdout).expect("SARIF output");
                let run = &sarif["runs"][0];
                assert_eq!(
                    run["properties"]["argusVulnerability"]["status"],
                    "complete_stale"
                );
                assert_eq!(
                    run["properties"]["argusVulnerability"]["source_mode"],
                    "offline_stale"
                );
                assert_eq!(run["properties"]["cache_label"], "<argus-osv-cache>");
                assert_eq!(run["results"][0]["ruleId"], "vulnerability-data-stale");
            }
            _ => unreachable!("covered renderer"),
        }
    }
}

#[test]
fn all_renderers_expose_source_age_and_stable_cache_label() {
    let root = tempfile::tempdir().expect("tempdir");
    let package = coordinate(Ecosystem::Npm, "render-demo", "1.0.0");
    let cache = seed_cache(root.path(), Utc::now(), vec![(package, Vec::new())]);
    for format in ["text", "json", "sarif"] {
        let mut args = package_args("npm", "render-demo", "1.0.0", &cache);
        args.extend(["--format".to_string(), format.to_string()]);
        let output = argus(&args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rendered = String::from_utf8(output.stdout).expect("UTF-8 output");
        assert!(rendered.contains("offline_fresh"), "{format}: {rendered}");
        assert!(rendered.contains("maximum_age_seconds"), "{format}");
        assert!(rendered.contains("<argus-osv-cache>"), "{format}");
        assert!(!rendered.contains(&root.path().to_string_lossy().to_string()));
    }
}

fn representative_lockfiles() -> Vec<(&'static str, String)> {
    vec![
        (
            "package-lock.json",
            format!(
                r#"{{"name":"root","version":"1.0.0","lockfileVersion":3,"packages":{{"":{{"name":"root","version":"1.0.0"}},"node_modules/demo":{{"version":"1.0.0","resolved":"https://registry.npmjs.org/demo.tgz","integrity":"{SHA256_SRI}"}}}}}}"#
            ),
        ),
        (
            "yarn.lock",
            format!(
                "__metadata:\n  version: 4\n  cacheKey: 10c0\n\"demo@npm:^1\":\n  version: \"1.0.0\"\n  resolution: \"demo@npm:1.0.0\"\n  checksum: 10c0/{}\n",
                "0".repeat(64)
            ),
        ),
        (
            "pnpm-lock.yaml",
            format!("lockfileVersion: '9.0'\npackages:\n  'demo@1.0.0':\n    resolution:\n      integrity: {SHA256_SRI}\nsnapshots:\n  'demo@1.0.0': {{}}\n"),
        ),
        (
            "poetry.lock",
            format!("[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\nfiles=[{{file=\"demo.whl\",hash=\"sha256:{SHA256}\"}}]\n[metadata]\nlock-version=\"2.1\"\npython-versions=\">=3.9\"\ncontent-hash=\"fixture\"\n"),
        ),
        (
            "uv.lock",
            format!("version=1\n[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\nsource={{registry=\"https://pypi.org/simple\"}}\nsdist={{url=\"https://files.pythonhosted.org/demo.tar.gz\",hash=\"sha256:{SHA256}\",size=1}}\n"),
        ),
        (
            "Cargo.lock",
            format!("version=4\n[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\nsource=\"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum=\"{SHA256}\"\n"),
        ),
        ("go.sum", format!("example.com/demo v1.2.3 h1:{H1}\n")),
        (
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    demo (1.2.3)\nDEPENDENCIES\n  demo\nBUNDLED WITH\n  3.0.0\n".to_string(),
        ),
        (
            "composer.lock",
            json!({"content-hash":"fixture","packages":[],"packages-dev":[]}).to_string(),
        ),
    ]
}

#[test]
fn nine_lockfile_families_query_without_network_or_package_managers() {
    for (basename, raw) in representative_lockfiles() {
        let root = tempfile::tempdir().expect("tempdir");
        let lockfile = root.path().join(basename);
        fs::write(&lockfile, &raw).expect("write lockfile");
        let bounded = BoundedInput::new(raw.as_bytes(), basename).expect("bounded lockfile");
        let parsed = parse_lockfile(
            &bounded,
            DetectionRequest {
                basename: Some(basename),
                explicit_format: None,
            },
        )
        .expect("parse lockfile");
        let coordinates =
            collect_lockfile_coordinates(&parsed.records).expect("normalize coordinates");
        let entries = coordinates
            .queries
            .into_iter()
            .map(|query| (query.coordinate, Vec::new()))
            .collect();
        let cache = seed_cache(root.path(), Utc::now(), entries);
        let output = argus([
            "vulns",
            "lockfile",
            lockfile.to_str().expect("path"),
            "--cache-dir",
            cache.to_str().expect("path"),
            "--offline",
            "--format",
            "json",
        ]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{basename}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{basename}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("JSON report");
        assert_eq!(report["evidence"]["status"], "complete_no_match");
    }
}
