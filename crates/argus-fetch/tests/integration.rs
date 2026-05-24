//! End-to-end test for `fetch_and_scan` using a mock transport. No network.
//!
//! Builds a tiny tarball in memory, computes its real SHA-512 + base64
//! integrity string, synthesises a packument JSON pointing at it, and runs
//! the full fetch pipeline against a `MockTransport` that hands back the
//! right bytes for the right URLs.

use anyhow::{anyhow, Result};
use argus_core::Decision;
use argus_fetch::{fetch_and_scan, FetchOptions, PackageRef, Transport};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::sync::Mutex;
use tar::Header;

struct MockTransport {
    routes: Mutex<HashMap<String, Vec<u8>>>,
}

impl MockTransport {
    fn new() -> Self {
        Self {
            routes: Mutex::new(HashMap::new()),
        }
    }
    fn insert(&self, url: &str, body: Vec<u8>) {
        self.routes.lock().unwrap().insert(url.to_string(), body);
    }
}

impl Transport for MockTransport {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let body = self
            .routes
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| anyhow!("MockTransport: no route for {url}"))?;
        if body.len() as u64 > max_bytes {
            return Err(anyhow!(
                "MockTransport: body for {url} ({} bytes) exceeds cap {max_bytes}",
                body.len()
            ));
        }
        Ok(body)
    }
}

fn make_targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for (path, body) in entries {
            let mut header = Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, *body).unwrap();
        }
        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

#[test]
fn fetch_and_scan_allow_path() {
    let cache = tempfile::tempdir().unwrap();
    let registry = "https://mock.registry";
    let tarball = make_targz(&[
        (
            "package/package.json",
            br#"{"name":"argus-demo","version":"1.0.0"}"#,
        ),
        ("package/index.js", b"module.exports = {};"),
    ]);
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let tarball_url = format!("{registry}/argus-demo/-/argus-demo-1.0.0.tgz");
    let packument = format!(
        r#"{{
          "name": "argus-demo",
          "dist-tags": {{"latest": "1.0.0"}},
          "versions": {{
            "1.0.0": {{"dist": {{"tarball": "{tarball_url}", "integrity": "{integrity}"}}}}
          }}
        }}"#
    );

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/argus-demo"), packument.into_bytes());
    transport.insert(&tarball_url, tarball);

    let opts = FetchOptions {
        registry: registry.to_string(),
        cache_dir: Some(cache.path().to_path_buf()),
        ..FetchOptions::default()
    };
    let pkg = PackageRef::parse("argus-demo").unwrap();

    let report = fetch_and_scan(&pkg, &opts, &transport).unwrap();
    assert_eq!(report.decision, Decision::Allow);
    assert!(
        report.findings.is_empty(),
        "got findings: {:?}",
        report.findings
    );
    assert_eq!(report.package_name.as_deref(), Some("argus-demo"));
}

#[test]
fn fetch_rejects_tampered_tarball() {
    let cache = tempfile::tempdir().unwrap();
    let registry = "https://mock.registry";
    let tarball = make_targz(&[(
        "package/package.json",
        br#"{"name":"argus-demo","version":"1.0.0"}"#,
    )]);
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let mut tampered = tarball.clone();
    *tampered.last_mut().unwrap() ^= 0x01;

    let tarball_url = format!("{registry}/argus-demo/-/argus-demo-1.0.0.tgz");
    let packument = format!(
        r#"{{
          "name": "argus-demo",
          "dist-tags": {{"latest": "1.0.0"}},
          "versions": {{
            "1.0.0": {{"dist": {{"tarball": "{tarball_url}", "integrity": "{integrity}"}}}}
          }}
        }}"#
    );

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/argus-demo"), packument.into_bytes());
    transport.insert(&tarball_url, tampered);

    let opts = FetchOptions {
        registry: registry.to_string(),
        cache_dir: Some(cache.path().to_path_buf()),
        ..FetchOptions::default()
    };
    let pkg = PackageRef::parse("argus-demo").unwrap();
    let err = fetch_and_scan(&pkg, &opts, &transport)
        .unwrap_err()
        .to_string();
    assert!(err.contains("integrity"), "got: {err}");
}

#[test]
fn fetch_resolves_dist_tag() {
    let cache = tempfile::tempdir().unwrap();
    let registry = "https://mock.registry";
    let tarball = make_targz(&[(
        "package/package.json",
        br#"{"name":"argus-demo","version":"2.0.0-beta.1"}"#,
    )]);
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let tarball_url = format!("{registry}/argus-demo/-/argus-demo-2.0.0-beta.1.tgz");
    let packument = format!(
        r#"{{
          "name": "argus-demo",
          "dist-tags": {{"latest": "1.0.0", "beta": "2.0.0-beta.1"}},
          "versions": {{
            "1.0.0":         {{"dist": {{"tarball": "ignored", "integrity": "sha512-aaaa"}}}},
            "2.0.0-beta.1":  {{"dist": {{"tarball": "{tarball_url}", "integrity": "{integrity}"}}}}
          }}
        }}"#
    );

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/argus-demo"), packument.into_bytes());
    transport.insert(&tarball_url, tarball);

    let opts = FetchOptions {
        registry: registry.to_string(),
        cache_dir: Some(cache.path().to_path_buf()),
        ..FetchOptions::default()
    };
    let pkg = PackageRef::parse("argus-demo@beta").unwrap();
    let report = fetch_and_scan(&pkg, &opts, &transport).unwrap();
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn fetch_rejects_cross_host_tarball() {
    // A tampered packument tells us the tarball lives on a different host
    // than the registry we contacted. argus must refuse rather than blindly
    // downloading from the attacker-supplied URL.
    let cache = tempfile::tempdir().unwrap();
    let registry = "https://mock.registry";
    let evil_url = "https://evil.example.invalid/argus-demo-1.0.0.tgz";
    let packument = format!(
        r#"{{
          "name": "argus-demo",
          "dist-tags": {{"latest": "1.0.0"}},
          "versions": {{
            "1.0.0": {{"dist": {{"tarball": "{evil_url}", "integrity": "sha512-AAAA"}}}}
          }}
        }}"#
    );
    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/argus-demo"), packument.into_bytes());
    // The tarball URL is never registered — if validation is skipped, the
    // MockTransport's "no route" error would be the failure mode. With
    // validation, we should bail before any tarball GET happens.

    let opts = FetchOptions {
        registry: registry.to_string(),
        cache_dir: Some(cache.path().to_path_buf()),
        ..FetchOptions::default()
    };
    let pkg = PackageRef::parse("argus-demo").unwrap();
    let err = fetch_and_scan(&pkg, &opts, &transport)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("does not match registry host") || err.contains("evil.example.invalid"),
        "expected cross-host rejection, got: {err}"
    );
}

#[test]
fn fetch_rejects_http_tarball() {
    let cache = tempfile::tempdir().unwrap();
    let registry = "https://mock.registry";
    let http_url = "http://mock.registry/argus-demo-1.0.0.tgz";
    let packument = format!(
        r#"{{
          "name": "argus-demo",
          "dist-tags": {{"latest": "1.0.0"}},
          "versions": {{
            "1.0.0": {{"dist": {{"tarball": "{http_url}", "integrity": "sha512-AAAA"}}}}
          }}
        }}"#
    );
    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/argus-demo"), packument.into_bytes());

    let opts = FetchOptions {
        registry: registry.to_string(),
        cache_dir: Some(cache.path().to_path_buf()),
        ..FetchOptions::default()
    };
    let pkg = PackageRef::parse("argus-demo").unwrap();
    let err = fetch_and_scan(&pkg, &opts, &transport)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("non-HTTPS") || err.contains("http://"),
        "expected http rejection, got: {err}"
    );
}
