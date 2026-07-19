//! Offline npm metadata-anomaly integration coverage.

use argus_fetch::{fetch_and_scan, FetchOptions, PackageRef};
use argus_test_support::MockTransport;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha512};
use std::path::Path;
use tar::Header;
use url::Url;

const PACKAGE: &str = "argus-demo";
const TARGET_VERSION: &str = "3.0.0";
const TARGET_TIME: &str = "2025-02-21T00:00:00Z";
const PUBLISHER: &str = "alice";

fn make_targz() -> Vec<u8> {
    make_targz_with_manifest(PACKAGE, TARGET_VERSION)
}

fn make_targz_with_manifest(name: &str, version: &str) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        let body = json!({"name": name, "version": version})
            .to_string()
            .into_bytes();
        let mut header = Header::new_gnu();
        header.set_path("package/package.json").unwrap();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, body.as_slice()).unwrap();
        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

fn search_url(registry: &str) -> String {
    let mut base = Url::parse(registry).unwrap();
    let path = base.path().to_string();
    if !path.ends_with('/') {
        base.set_path(&format!("{path}/"));
    }
    let mut endpoint = base.join("-/v1/search").unwrap();
    endpoint
        .query_pairs_mut()
        .append_pair("text", PUBLISHER)
        .append_pair("size", "250")
        .append_pair("from", "0")
        .append_pair("quality", "0")
        .append_pair("popularity", "0")
        .append_pair("maintenance", "1");
    endpoint.to_string()
}

fn search_object(name: &str, version: &str, date: &str, publisher: &str) -> Value {
    json!({
        "package": {
            "name": name,
            "version": version,
            "date": date,
            "publisher": {"username": publisher}
        }
    })
}

fn search_response(objects: Vec<Value>) -> Vec<u8> {
    json!({"total": objects.len(), "objects": objects})
        .to_string()
        .into_bytes()
}

fn suspicious_search_objects() -> Vec<Value> {
    (0..5)
        .map(|index| {
            search_object(
                &format!("alice-pkg-{index}"),
                "1.0.0",
                "2025-02-20T12:00:00Z",
                PUBLISHER,
            )
        })
        .collect()
}

fn fixture(registry: &str, target_time: &str) -> (Vec<u8>, Vec<u8>, String) {
    let tarball = make_targz();
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let tarball_url = format!(
        "{}/{PACKAGE}/-/{PACKAGE}-{TARGET_VERSION}.tgz",
        registry.trim_end_matches('/')
    );
    let history = [
        ("1.0.0", "2025-01-01T00:00:00Z"),
        ("1.1.0", "2025-01-10T00:00:00Z"),
        ("1.2.0", "2025-01-20T00:00:00Z"),
        ("1.3.0", "2025-02-01T00:00:00Z"),
        ("1.4.0", "2025-02-10T00:00:00Z"),
        ("1.5.0", "2025-02-20T00:00:00Z"),
    ];
    let mut versions = Map::new();
    let mut times = Map::new();
    for (version, published_at) in history {
        versions.insert(
            version.to_string(),
            json!({
                "dist": {
                    "tarball": tarball_url,
                    "integrity": integrity
                },
                "_npmUser": {"name": PUBLISHER}
            }),
        );
        times.insert(version.to_string(), json!(published_at));
    }
    versions.insert(
        TARGET_VERSION.to_string(),
        json!({
            "dist": {
                "tarball": tarball_url,
                "integrity": integrity
            },
            "_npmUser": {"name": PUBLISHER}
        }),
    );
    times.insert(TARGET_VERSION.to_string(), json!(target_time));
    let packument = json!({
        "name": PACKAGE,
        "dist-tags": {"latest": TARGET_VERSION},
        "versions": versions,
        "time": times
    })
    .to_string()
    .into_bytes();
    (packument, tarball, tarball_url)
}

fn transport_with(registry: &str, target_time: &str, response: Option<Vec<u8>>) -> MockTransport {
    let (packument, tarball, tarball_url) = fixture(registry, target_time);
    let transport = MockTransport::new();
    transport.insert(
        &format!("{}/{PACKAGE}", registry.trim_end_matches('/')),
        packument,
    );
    transport.insert(&tarball_url, tarball);
    if let Some(body) = response {
        transport.insert(&search_url(registry), body);
    }
    transport
}

fn transport_with_events(
    registry: &str,
    target_version: &str,
    events: &[(&str, &str)],
    response: Vec<u8>,
) -> MockTransport {
    let tarball = make_targz();
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let tarball_url = format!(
        "{}/{PACKAGE}/-/{PACKAGE}-{target_version}.tgz",
        registry.trim_end_matches('/')
    );
    let mut versions = Map::new();
    let mut times = Map::new();
    for (version, published_at) in events {
        versions.insert(
            (*version).to_string(),
            json!({
                "dist": {"tarball": tarball_url, "integrity": integrity},
                "_npmUser": {"name": PUBLISHER}
            }),
        );
        times.insert((*version).to_string(), json!(published_at));
    }
    let packument = json!({
        "name": PACKAGE,
        "dist-tags": {"latest": target_version},
        "versions": versions,
        "time": times
    });
    let transport = MockTransport::new();
    transport.insert(
        &format!("{}/{PACKAGE}", registry.trim_end_matches('/')),
        packument.to_string().into_bytes(),
    );
    transport.insert(&tarball_url, tarball);
    transport.insert(&search_url(registry), response);
    transport
}

fn options(registry: &str, cache: Option<&Path>) -> FetchOptions {
    FetchOptions {
        registry: registry.to_string(),
        metadata_anomaly: true,
        metadata_cache_dir: cache.map(Path::to_path_buf),
        ..FetchOptions::default()
    }
}

fn scan(
    registry: &str,
    cache: Option<&Path>,
    transport: &MockTransport,
) -> anyhow::Result<argus_core::ScanReport> {
    scan_version(registry, TARGET_VERSION, cache, transport)
}

fn scan_version(
    registry: &str,
    version: &str,
    cache: Option<&Path>,
    transport: &MockTransport,
) -> anyhow::Result<argus_core::ScanReport> {
    fetch_and_scan(
        &PackageRef::parse(&format!("{PACKAGE}@{version}")).unwrap(),
        &options(registry, cache),
        transport,
    )
}

#[test]
fn rapid_publish_window_uses_exact_publisher_distinct_packages() {
    let registry = "https://mock.registry/npm/private";
    let mut objects = suspicious_search_objects();
    objects.push(objects[0].clone());
    objects.push(search_object(
        "wrong-publisher",
        "1.0.0",
        "2025-02-20T12:00:00Z",
        "alice-team",
    ));
    objects.push(search_object(
        "outside-window",
        "1.0.0",
        "2025-02-19T23:59:59Z",
        PUBLISHER,
    ));
    let transport = transport_with(registry, TARGET_TIME, Some(search_response(objects)));

    let report = scan(registry, None, &transport).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "rapid-publish-window")
        .expect("rapid publish finding");
    assert!(finding.detail.contains("distinct_packages=5"));
    assert!(finding.detail.contains("publisher=alice"));
    let evidence = finding.evidence.as_ref().expect("anomaly evidence");
    assert!(evidence.iter().any(|item| item == "policy=npm-anomaly-v1"));
    assert!(evidence.iter().any(|item| item == "distinct_packages=5"));
    let report_json = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(
        report_json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["rule_id"] == "rapid-publish-window")
            .unwrap()["evidence"][0],
        "policy=npm-anomaly-v1"
    );
    assert_eq!(transport.request_count(&search_url(registry)), 1);
}

#[test]
fn rapid_publish_benign_is_explicitly_unassessed() {
    let registry = "https://mock.registry";
    let transport = transport_with(
        registry,
        TARGET_TIME,
        Some(search_response(
            suspicious_search_objects().into_iter().take(4).collect(),
        )),
    );

    let report = scan(registry, None, &transport).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "npm-rapid-publish-unassessed")
        .expect("unassessed finding");
    assert_eq!(finding.severity, argus_core::Severity::Info);
    assert!(finding.detail.contains("observed_distinct_packages=4"));
}

#[test]
fn anomaly_transport_rejects_truncated_or_invalid_search_data() {
    let registry = "https://mock.registry";
    let cases = [
        (
            json!({"total": 251, "objects": []})
                .to_string()
                .into_bytes(),
            "exceeds one-page cap",
        ),
        (
            json!({"total": 5, "objects": suspicious_search_objects()
                .into_iter()
                .take(4)
                .collect::<Vec<_>>()})
            .to_string()
            .into_bytes(),
            "truncated or inconsistent",
        ),
        (
            json!({"total": 1, "objects": [{"package": {
                "name": "demo", "version": "1.0.0", "date": TARGET_TIME
            }}]})
            .to_string()
            .into_bytes(),
            "parse npm search response",
        ),
        (vec![b'x'; 2 * 1024 * 1024 + 1], "exceeds cap"),
    ];

    for (body, expected) in cases {
        let transport = transport_with(registry, TARGET_TIME, Some(body));
        let error = format!("{:#}", scan(registry, None, &transport).unwrap_err());
        assert!(
            error.contains(expected),
            "expected {expected:?}, got {error}"
        );
    }
}

#[test]
fn anomaly_transport_rejects_plaintext_registry_before_search() {
    let registry = "http://mock.registry";
    let transport = transport_with(registry, TARGET_TIME, None);
    let error = format!("{:#}", scan(registry, None, &transport).unwrap_err());
    assert!(error.contains("must use HTTPS"), "got {error}");
    assert_eq!(transport.request_count(&search_url(registry)), 0);
}

#[test]
fn anomaly_transport_rejects_redirect_outside_registry_base() {
    let registry = "https://mock.registry/npm/private";
    let transport = transport_with(registry, TARGET_TIME, None);
    transport.insert_redirect(
        &search_url(registry),
        "https://mock.registry/npm/public/-/v1/search",
    );

    let error = format!("{:#}", scan(registry, None, &transport).unwrap_err());
    assert!(
        error.contains("base path") || error.contains("rejected"),
        "got {error}"
    );
}

#[test]
fn anomaly_transport_cache_reuses_only_fresh_bounded_data() {
    let registry = "https://mock.registry";
    let cache = tempfile::tempdir().unwrap();
    let transport = transport_with(
        registry,
        TARGET_TIME,
        Some(search_response(suspicious_search_objects())),
    );

    scan(registry, Some(cache.path()), &transport).unwrap();
    scan(registry, Some(cache.path()), &transport).unwrap();
    assert_eq!(transport.request_count(&search_url(registry)), 1);

    let future_target = "2999-02-21T00:00:00Z";
    let future_transport = transport_with(
        registry,
        future_target,
        Some(search_response(suspicious_search_objects())),
    );
    scan(registry, Some(cache.path()), &future_transport).unwrap();
    scan(registry, Some(cache.path()), &future_transport).unwrap();
    assert_eq!(future_transport.request_count(&search_url(registry)), 2);
}

#[cfg(unix)]
#[test]
fn anomaly_transport_expired_cache_is_atomically_replaced() {
    use std::os::unix::fs::MetadataExt;

    let registry = "https://mock.registry";
    let cache = tempfile::tempdir().unwrap();
    let transport = transport_with(
        registry,
        TARGET_TIME,
        Some(search_response(suspicious_search_objects())),
    );
    scan(registry, Some(cache.path()), &transport).unwrap();
    let cache_path = std::fs::read_dir(cache.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut entry: Value = serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
    entry["fetched_at"] = json!(TARGET_TIME);
    std::fs::write(&cache_path, serde_json::to_vec(&entry).unwrap()).unwrap();
    let stale_inode = std::fs::metadata(&cache_path).unwrap().ino();

    scan(registry, Some(cache.path()), &transport).unwrap();
    assert_eq!(transport.request_count(&search_url(registry)), 2);
    assert_ne!(std::fs::metadata(&cache_path).unwrap().ino(), stale_inode);
    let refreshed: Value = serde_json::from_slice(&std::fs::read(cache_path).unwrap()).unwrap();
    assert_ne!(refreshed["fetched_at"], TARGET_TIME);
}

#[test]
fn anomaly_transport_corrupt_cache_is_an_operational_error() {
    let registry = "https://mock.registry";
    let cache = tempfile::tempdir().unwrap();
    let transport = transport_with(
        registry,
        TARGET_TIME,
        Some(search_response(suspicious_search_objects())),
    );
    scan(registry, Some(cache.path()), &transport).unwrap();
    let cache_path = std::fs::read_dir(cache.path())
        .unwrap()
        .next()
        .expect("cache entry")
        .unwrap()
        .path();
    std::fs::write(&cache_path, b"{not-json").unwrap();

    let error = format!(
        "{:#}",
        scan(registry, Some(cache.path()), &transport).unwrap_err()
    );
    assert!(error.contains("parse metadata cache"), "got {error}");
}

#[test]
fn anomaly_transport_default_path_makes_no_search_request() {
    let registry = "https://mock.registry";
    let transport = transport_with(registry, TARGET_TIME, None);
    let report = fetch_and_scan(
        &PackageRef::parse(PACKAGE).unwrap(),
        &FetchOptions {
            registry: registry.to_string(),
            ..FetchOptions::default()
        },
        &transport,
    )
    .unwrap();
    assert!(
        !report.findings.iter().any(|finding| {
            finding.rule_id == "version-shape-anomaly" || finding.rule_id == "rapid-publish-window"
        }),
        "{:?}",
        report.findings
    );
    assert_eq!(transport.request_count(&search_url(registry)), 0);
}

#[test]
fn anomaly_transport_failure_is_not_downgraded() {
    let registry = "https://mock.registry";
    let transport = transport_with(registry, TARGET_TIME, None);
    transport.insert_status(&search_url(registry), 503);
    let error = format!("{:#}", scan(registry, None, &transport).unwrap_err());
    assert!(error.contains("status 503"), "got {error}");
    assert!(!error.contains("unassessed"), "got {error}");
}

#[test]
fn anomaly_transport_accepts_redirect_within_registry_base() {
    let registry = "https://mock.registry/npm/private";
    let redirected = "https://mock.registry/npm/private/search-page";
    let transport = transport_with(registry, TARGET_TIME, None);
    transport.insert_redirect(&search_url(registry), redirected);
    transport.insert(redirected, search_response(suspicious_search_objects()));

    let report = scan(registry, None, &transport).unwrap();
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "rapid-publish-window"));
    assert_eq!(transport.request_count(redirected), 1);
}

#[test]
fn anomaly_transport_cache_key_keeps_registry_base_paths_distinct() {
    let cache = tempfile::tempdir().unwrap();
    let private_registry = "https://mock.registry/npm/private";
    let public_registry = "https://mock.registry/npm/public";
    let private_transport = transport_with(
        private_registry,
        TARGET_TIME,
        Some(search_response(suspicious_search_objects())),
    );
    let public_transport = transport_with(
        public_registry,
        TARGET_TIME,
        Some(search_response(suspicious_search_objects())),
    );

    scan(private_registry, Some(cache.path()), &private_transport).unwrap();
    scan(public_registry, Some(cache.path()), &public_transport).unwrap();
    assert_eq!(
        private_transport.request_count(&search_url(private_registry)),
        1
    );
    assert_eq!(
        public_transport.request_count(&search_url(public_registry)),
        1
    );
    assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 2);
}

#[test]
fn anomaly_transport_missing_required_metadata_fails_closed() {
    let registry = "https://mock.registry";
    for (field, expected) in [
        ("time", "requires packument `time`"),
        ("publisher", "_npmUser.name"),
    ] {
        let (packument, tarball, tarball_url) = fixture(registry, TARGET_TIME);
        let mut document: Value = serde_json::from_slice(&packument).unwrap();
        if field == "time" {
            document.as_object_mut().unwrap().remove("time");
        } else {
            document["versions"][TARGET_VERSION]
                .as_object_mut()
                .unwrap()
                .remove("_npmUser");
        }
        let transport = MockTransport::new();
        transport.insert(
            &format!("{registry}/{PACKAGE}"),
            document.to_string().into_bytes(),
        );
        transport.insert(&tarball_url, tarball);
        let error = format!("{:#}", scan(registry, None, &transport).unwrap_err());
        assert!(error.contains(expected), "field={field}: {error}");
    }
}

#[test]
fn anomaly_transport_conflicting_normalized_version_times_fail_closed() {
    let registry = "https://mock.registry";
    let (packument, tarball, tarball_url) = fixture(registry, TARGET_TIME);
    let mut document: Value = serde_json::from_slice(&packument).unwrap();
    document["versions"]["3.0.0+rebuilt"] = document["versions"][TARGET_VERSION].clone();
    document["time"]["3.0.0+rebuilt"] = json!("2025-02-22T00:00:00Z");
    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/{PACKAGE}"),
        document.to_string().into_bytes(),
    );
    transport.insert(&tarball_url, tarball);
    let error = format!("{:#}", scan(registry, None, &transport).unwrap_err());
    assert!(
        error.contains("conflicting publication times"),
        "got {error}"
    );
}

#[test]
fn version_shape_matrix_freezes_minor_delay_and_baseline_boundaries() {
    let registry = "https://mock.registry";
    let prefix = [
        ("1.0.0", "2025-01-01T00:00:00Z"),
        ("1.1.0", "2025-01-05T00:00:00Z"),
        ("1.2.0", "2025-01-10T00:00:00Z"),
        ("1.3.0", "2025-01-15T00:00:00Z"),
        ("1.4.0", "2025-01-20T00:00:00Z"),
        ("1.5.0", "2025-02-01T00:00:00Z"),
    ];
    for (target_time, expected) in [
        ("2025-02-04T00:00:00Z", true),
        ("2025-02-04T00:00:01Z", false),
    ] {
        let mut events = prefix.to_vec();
        events.push(("1.15.0", target_time));
        let transport =
            transport_with_events(registry, "1.15.0", &events, search_response(Vec::new()));
        let report = scan_version(registry, "1.15.0", None, &transport).unwrap();
        assert_eq!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "version-shape-anomaly"),
            expected,
            "target_time={target_time}"
        );
    }

    let established = [
        ("1.0.0", "2025-01-01T00:00:00Z"),
        ("1.10.0", "2025-01-05T00:00:00Z"),
        ("1.11.0", "2025-01-10T00:00:00Z"),
        ("1.12.0", "2025-01-15T00:00:00Z"),
        ("1.13.0", "2025-01-20T00:00:00Z"),
        ("1.14.0", "2025-02-01T00:00:00Z"),
        ("1.24.0", "2025-02-02T00:00:00Z"),
    ];
    let transport = transport_with_events(
        registry,
        "1.24.0",
        &established,
        search_response(Vec::new()),
    );
    let report = scan_version(registry, "1.24.0", None, &transport).unwrap();
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "version-shape-anomaly"));
}

#[test]
fn rapid_publish_window_freezes_24h_250_and_order_boundaries() {
    let registry = "https://mock.registry";
    let mut objects = vec![
        search_object("alice-pkg-0", "1.0.0", "2025-02-20T00:00:00Z", PUBLISHER),
        search_object("alice-pkg-0", "2.0.0", TARGET_TIME, PUBLISHER),
        search_object("alice-pkg-1", "1.0.0", "2025-02-20T06:00:00Z", PUBLISHER),
        search_object("alice-pkg-2", "1.0.0", "2025-02-20T12:00:00Z", PUBLISHER),
        search_object("alice-pkg-3", "1.0.0", "2025-02-20T18:00:00Z", PUBLISHER),
        search_object("alice-pkg-4", "1.0.0", "2025-02-20T23:59:59Z", PUBLISHER),
    ];
    while objects.len() < 250 {
        objects.push(search_object(
            &format!("other-pkg-{}", objects.len()),
            "1.0.0",
            "2025-02-20T12:00:00Z",
            "other",
        ));
    }
    objects.reverse();
    let transport = transport_with(registry, TARGET_TIME, Some(search_response(objects)));
    let report = scan(registry, None, &transport).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "rapid-publish-window")
        .expect("bounded rapid publish finding");
    assert!(finding.detail.contains("distinct_packages=5"));
    assert!(finding
        .detail
        .contains("packages=alice-pkg-0,alice-pkg-1,alice-pkg-2,alice-pkg-3,alice-pkg-4"));
}

#[cfg(unix)]
#[test]
fn anomaly_transport_rejects_symlink_cache_directory_and_entry() {
    use std::os::unix::fs::symlink;

    let registry = "https://mock.registry";
    let root = tempfile::tempdir().unwrap();
    let real_cache = root.path().join("real");
    std::fs::create_dir(&real_cache).unwrap();
    let linked_cache = root.path().join("linked");
    symlink(&real_cache, &linked_cache).unwrap();
    let transport = transport_with(
        registry,
        TARGET_TIME,
        Some(search_response(suspicious_search_objects())),
    );
    let error = format!(
        "{:#}",
        scan(registry, Some(&linked_cache), &transport).unwrap_err()
    );
    assert!(error.contains("real directory"), "got {error}");

    scan(registry, Some(&real_cache), &transport).unwrap();
    let entry = std::fs::read_dir(&real_cache)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::remove_file(&entry).unwrap();
    let target = root.path().join("target");
    std::fs::write(&target, b"{}").unwrap();
    symlink(&target, &entry).unwrap();
    let error = format!(
        "{:#}",
        scan(registry, Some(&real_cache), &transport).unwrap_err()
    );
    assert!(error.contains("entry is a symlink"), "got {error}");
}

#[test]
fn fetch_report_identity_ignores_manifest_spoofing_and_is_repeatable() {
    let registry = "https://mock.registry";
    let (packument, _, tarball_url) = fixture(registry, TARGET_TIME);
    let spoofed_tarball = make_targz_with_manifest("spoofed-name", "999.0.0");
    let integrity = format!(
        "sha512-{}",
        STANDARD.encode(Sha512::digest(&spoofed_tarball))
    );
    let mut document: Value = serde_json::from_slice(&packument).unwrap();
    document["versions"][TARGET_VERSION]["dist"]["integrity"] = json!(integrity);
    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/{PACKAGE}"),
        document.to_string().into_bytes(),
    );
    transport.insert(&tarball_url, spoofed_tarball);
    transport.insert(
        &search_url(registry),
        search_response(suspicious_search_objects()),
    );

    let first = scan(registry, None, &transport).unwrap();
    let second = scan(registry, None, &transport).unwrap();
    assert_eq!(first.package_name.as_deref(), Some(PACKAGE));
    assert_eq!(first.package_version.as_deref(), Some(TARGET_VERSION));
    assert_eq!(
        first.path,
        std::path::PathBuf::from(format!("{PACKAGE}@{TARGET_VERSION}"))
    );
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap()
    );
}
