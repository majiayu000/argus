//! End-to-end test for `fetch_and_scan` using a mock transport. No network.
//!
//! Builds a tiny tarball in memory, computes its real SHA-512 + base64
//! integrity string, synthesises a packument JSON pointing at it, and runs
//! the full fetch pipeline against a `MockTransport` that hands back the
//! right bytes for the right URLs.

use argus_core::Decision;
use argus_fetch::{fetch_and_scan, FetchOptions, PackageRef};
use argus_test_support::MockTransport;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use tar::Header;

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
    // Packument has no `dist.attestations` → expect `missing-provenance`
    // (info-level, does not block) and nothing else.
    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(rule_ids, vec!["missing-provenance"], "got: {rule_ids:?}");
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

// ---------- provenance integration tests (#10) ----------

/// Build an attestations JSON document whose subject sha512 matches `sha512_hex`.
fn fake_attestations_json(subject_name: &str, sha512_hex: &str) -> Vec<u8> {
    use base64::Engine as _;
    let stmt = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{ "name": subject_name, "digest": { "sha512": sha512_hex } }],
        "predicate": {
            "buildDefinition": { "buildType": "https://github.com/actions/runner/v1" }
        }
    });
    let payload_b64 =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&stmt).unwrap());
    serde_json::json!({
        "attestations": [{
            "predicateType": "https://slsa.dev/provenance/v1",
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
                "dsseEnvelope": { "payload": payload_b64 }
            }
        }]
    })
    .to_string()
    .into_bytes()
}

fn malformed_statement_attestations_json() -> Vec<u8> {
    let payload_b64 = STANDARD.encode(br#"{"not":"a statement"}"#);
    serde_json::json!({
        "attestations": [{
            "predicateType": "https://slsa.dev/provenance/v1",
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
                "dsseEnvelope": { "payload": payload_b64 }
            }
        }]
    })
    .to_string()
    .into_bytes()
}

fn sha512_hex(bytes: &[u8]) -> String {
    let d = Sha512::digest(bytes);
    let mut s = String::with_capacity(d.len() * 2);
    for b in d {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[test]
fn fetch_provenance_subject_matches_records_info_finding() {
    let cache = tempfile::tempdir().unwrap();
    let registry = "https://mock.registry";
    let tarball = make_targz(&[(
        "package/package.json",
        br#"{"name":"argus-demo","version":"1.0.0"}"#,
    )]);
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let tarball_hex = sha512_hex(&tarball);
    let tarball_url = format!("{registry}/argus-demo/-/argus-demo-1.0.0.tgz");
    let attestations_url = format!("{registry}/-/npm/v1/attestations/argus-demo@1.0.0");
    let packument = format!(
        r#"{{
          "name": "argus-demo",
          "dist-tags": {{"latest": "1.0.0"}},
          "versions": {{
            "1.0.0": {{"dist": {{
              "tarball": "{tarball_url}",
              "integrity": "{integrity}",
              "attestations": {{"url": "{attestations_url}"}}
            }}}}
          }}
        }}"#
    );
    let attestations = fake_attestations_json("pkg:npm/argus-demo@1.0.0", &tarball_hex);

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/argus-demo"), packument.into_bytes());
    transport.insert(&tarball_url, tarball);
    transport.insert(&attestations_url, attestations);

    let opts = FetchOptions {
        registry: registry.to_string(),
        cache_dir: Some(cache.path().to_path_buf()),
        ..FetchOptions::default()
    };
    let pkg = PackageRef::parse("argus-demo").unwrap();
    let report = fetch_and_scan(&pkg, &opts, &transport).unwrap();
    assert_eq!(report.decision, Decision::Allow);
    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(rule_ids, vec!["provenance-verified-subject"]);
    // Detail should mention the builder we encoded.
    assert!(
        report.findings[0]
            .detail
            .contains("github.com/actions/runner"),
        "detail: {}",
        report.findings[0].detail
    );
}

#[test]
fn fetch_provenance_subject_mismatch_blocks() {
    let cache = tempfile::tempdir().unwrap();
    let registry = "https://mock.registry";
    let tarball = make_targz(&[(
        "package/package.json",
        br#"{"name":"argus-demo","version":"1.0.0"}"#,
    )]);
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let tarball_url = format!("{registry}/argus-demo/-/argus-demo-1.0.0.tgz");
    let attestations_url = format!("{registry}/-/npm/v1/attestations/argus-demo@1.0.0");
    let packument = format!(
        r#"{{
          "name": "argus-demo",
          "dist-tags": {{"latest": "1.0.0"}},
          "versions": {{
            "1.0.0": {{"dist": {{
              "tarball": "{tarball_url}",
              "integrity": "{integrity}",
              "attestations": {{"url": "{attestations_url}"}}
            }}}}
          }}
        }}"#
    );
    // Attestation claims a wrong digest — packument or attestations have
    // been tampered with.
    let fake_digest = "0".repeat(128);
    let attestations = fake_attestations_json("pkg:npm/argus-demo@1.0.0", &fake_digest);

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/argus-demo"), packument.into_bytes());
    transport.insert(&tarball_url, tarball);
    transport.insert(&attestations_url, attestations);

    let opts = FetchOptions {
        registry: registry.to_string(),
        cache_dir: Some(cache.path().to_path_buf()),
        ..FetchOptions::default()
    };
    let pkg = PackageRef::parse("argus-demo").unwrap();
    let report = fetch_and_scan(&pkg, &opts, &transport).unwrap();
    assert_eq!(report.decision, Decision::Block);
    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"provenance-subject-mismatch"),
        "got: {rule_ids:?}"
    );
}

#[test]
fn fetch_provenance_malformed_payload_records_parse_failed() -> anyhow::Result<()> {
    let cache = tempfile::tempdir()?;
    let registry = "https://mock.registry";
    let tarball = make_targz(&[(
        "package/package.json",
        br#"{"name":"argus-demo","version":"1.0.0"}"#,
    )]);
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let tarball_url = format!("{registry}/argus-demo/-/argus-demo-1.0.0.tgz");
    let attestations_url = format!("{registry}/-/npm/v1/attestations/argus-demo@1.0.0");
    let packument = format!(
        r#"{{
          "name": "argus-demo",
          "dist-tags": {{"latest": "1.0.0"}},
          "versions": {{
            "1.0.0": {{"dist": {{
              "tarball": "{tarball_url}",
              "integrity": "{integrity}",
              "attestations": {{"url": "{attestations_url}"}}
            }}}}
          }}
        }}"#
    );

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/argus-demo"), packument.into_bytes());
    transport.insert(&tarball_url, tarball);
    transport.insert(&attestations_url, malformed_statement_attestations_json());

    let opts = FetchOptions {
        registry: registry.to_string(),
        cache_dir: Some(cache.path().to_path_buf()),
        ..FetchOptions::default()
    };
    let pkg = PackageRef::parse("argus-demo")?;
    let report = fetch_and_scan(&pkg, &opts, &transport)?;
    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert_eq!(report.decision, Decision::Block);
    assert!(
        rule_ids.contains(&"provenance-parse-failed"),
        "got: {rule_ids:?}"
    );
    assert!(
        !rule_ids.contains(&"provenance-no-sha512-subject"),
        "got: {rule_ids:?}"
    );
    Ok(())
}
