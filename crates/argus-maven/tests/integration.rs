//! End-to-end tests for `fetch_and_scan_maven` via MockTransport.

use argus_core::Decision;
use argus_maven::{fetch_and_scan_maven, MavenFetchOptions, MavenRef};
use argus_test_support::MockTransport;
use sha1::Digest as Sha1Digest;
use sha2::Sha256;
use std::io::Write;

const REGISTRY: &str = "https://repo1.maven.org/maven2";

/// Build a minimal `.jar` (ZIP) with the supplied (path, body) entries.
fn make_jar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (path, body) in files {
            writer.start_file(*path, opts).unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
    }
    buf
}

/// Build a `.jar` whose first ZIP entry name traverses the parent directory.
fn make_jar_with_raw_name(name: &str, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.start_file(name, opts).unwrap();
        writer.write_all(body).unwrap();
        writer.finish().unwrap();
    }
    buf
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn sha1_hex(b: &[u8]) -> String {
    hex::encode(sha1::Sha1::digest(b))
}

fn urls(group_path: &str, artifact: &str, version: &str) -> (String, String, String, String) {
    let base = format!("{REGISTRY}/{group_path}/{artifact}/{version}/{artifact}-{version}");
    (
        format!("{base}.jar"),
        format!("{base}.pom"),
        format!("{base}.jar.sha256"),
        format!("{base}.jar.sha1"),
    )
}

const BENIGN_MANIFEST: &[u8] =
    b"Manifest-Version: 1.0\r\nImplementation-Title: demo\r\nImplementation-Version: 1.0.0\r\n";

const BENIGN_POM: &[u8] = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <build><plugins>
    <plugin><artifactId>maven-compiler-plugin</artifactId></plugin>
    <plugin><artifactId>maven-surefire-plugin</artifactId></plugin>
  </plugins></build>
</project>"#;

const EVIL_POM: &[u8] = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <build><plugins>
    <plugin>
      <groupId>org.codehaus.mojo</groupId>
      <artifactId>exec-maven-plugin</artifactId>
    </plugin>
  </plugins></build>
</project>"#;

#[test]
fn maven_exec_plugin_blocks() {
    let group_path = "com/example";
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, pom_url, sha256_url, _sha1_url) = urls(group_path, "demo", "1.0.0");

    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert(&sha256_url, sha256_hex(&jar).into_bytes());
    transport.insert(&pom_url, EVIL_POM.to_vec());

    let opts = MavenFetchOptions::default();
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let report = fetch_and_scan_maven(&pkg, &opts, &transport).unwrap();

    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"maven-exec-plugin"), "got: {ids:?}");
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn maven_clean_package_allows_with_only_info_findings() {
    let group_path = "com/example";
    let jar = make_jar(&[
        ("META-INF/MANIFEST.MF", BENIGN_MANIFEST),
        (
            "com/example/readme.txt",
            b"a normal library, nothing to see",
        ),
    ]);
    let (jar_url, pom_url, sha256_url, _sha1_url) = urls(group_path, "demo", "1.0.0");

    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert(&sha256_url, sha256_hex(&jar).into_bytes());
    transport.insert(&pom_url, BENIGN_POM.to_vec());

    let opts = MavenFetchOptions::default();
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let report = fetch_and_scan_maven(&pkg, &opts, &transport).unwrap();

    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    // The honesty meta-finding must always be present...
    assert!(
        ids.contains(&"maven-bytecode-not-inspected"),
        "got: {ids:?}"
    );
    // ...and only Info findings present means Allow (validates INFO_ONLY_RULES wiring).
    assert_eq!(report.decision, Decision::Allow, "got findings: {ids:?}");
    assert_eq!(report.package_name.as_deref(), Some("demo"));
    assert_eq!(report.package_version.as_deref(), Some("1.0.0"));
}

#[test]
fn maven_strong_integrity_mismatch_errors() {
    let group_path = "com/example";
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, pom_url, sha256_url, _sha1_url) = urls(group_path, "demo", "1.0.0");

    let transport = MockTransport::new();
    transport.insert(&jar_url, jar);
    // Wrong digest.
    transport.insert(&sha256_url, "0".repeat(64).into_bytes());
    transport.insert(&pom_url, BENIGN_POM.to_vec());

    let opts = MavenFetchOptions::default();
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_maven(&pkg, &opts, &transport).unwrap_err()
    );
    assert!(err.contains("SHA-256 mismatch"), "got: {err}");
}

#[test]
fn maven_degraded_sha1_only_emits_info_and_allows() {
    let group_path = "com/example";
    let jar = make_jar(&[
        ("META-INF/MANIFEST.MF", BENIGN_MANIFEST),
        ("com/example/readme.txt", b"benign"),
    ]);
    let (jar_url, pom_url, _sha256_url, sha1_url) = urls(group_path, "demo", "1.0.0");

    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    // No .sha256 route -> degraded path. Provide a correct .sha1.
    transport.insert(&sha1_url, sha1_hex(&jar).into_bytes());
    transport.insert(&pom_url, BENIGN_POM.to_vec());

    let opts = MavenFetchOptions::default();
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let report = fetch_and_scan_maven(&pkg, &opts, &transport).unwrap();

    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"maven-weak-integrity-only"), "got: {ids:?}");
    // The weak-integrity finding is Info -> does not block.
    assert_eq!(report.decision, Decision::Allow, "got: {ids:?}");
}

#[test]
fn maven_degraded_sha1_mismatch_errors() {
    let group_path = "com/example";
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, pom_url, _sha256_url, sha1_url) = urls(group_path, "demo", "1.0.0");

    let transport = MockTransport::new();
    transport.insert(&jar_url, jar);
    transport.insert(&sha1_url, "0".repeat(40).into_bytes());
    transport.insert(&pom_url, BENIGN_POM.to_vec());

    let opts = MavenFetchOptions::default();
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_maven(&pkg, &opts, &transport).unwrap_err()
    );
    assert!(err.contains("SHA-1 mismatch"), "got: {err}");
}

#[test]
fn maven_no_checksum_at_all_hard_errors() {
    // U-29: neither .sha256 nor .sha1 -> must hard-error, never silent pass.
    let group_path = "com/example";
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, _pom_url, _sha256_url, _sha1_url) = urls(group_path, "demo", "1.0.0");

    let transport = MockTransport::new();
    transport.insert(&jar_url, jar);
    // No checksum routes registered.

    let opts = MavenFetchOptions::default();
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_maven(&pkg, &opts, &transport).unwrap_err()
    );
    assert!(
        err.contains("neither .sha256 nor .sha1"),
        "expected hard fail on missing integrity, got: {err}"
    );
}

#[test]
fn maven_rejects_non_https_registry() {
    // The orchestrator runs validate_artifact_url on every constructed URL.
    // A plain-http registry yields a plain-http jar URL, which must be
    // rejected before any download (the host-allowlist + HTTPS-only guarantee
    // itself is exhaustively unit-tested in argus-core::url).
    let transport = MockTransport::new();
    let opts = MavenFetchOptions {
        registry: "http://repo1.maven.org/maven2".to_string(),
        ..MavenFetchOptions::default()
    };
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_maven(&pkg, &opts, &transport).unwrap_err()
    );
    assert!(
        err.contains("non-HTTPS") || err.contains("https"),
        "expected non-HTTPS rejection, got: {err}"
    );
}

#[test]
fn maven_rejects_path_traversal_jar_entry() {
    let group_path = "com/example";
    // A jar whose entry name escapes the extraction root.
    let jar = make_jar_with_raw_name("../../etc/evil", b"payload");
    let (jar_url, pom_url, sha256_url, _sha1_url) = urls(group_path, "demo", "1.0.0");

    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert(&sha256_url, sha256_hex(&jar).into_bytes());
    transport.insert(&pom_url, BENIGN_POM.to_vec());

    let opts = MavenFetchOptions::default();
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_maven(&pkg, &opts, &transport).unwrap_err()
    );
    assert!(
        err.contains("parent dir") || err.contains("unsafe path"),
        "expected path-traversal rejection, got: {err}"
    );
}

#[test]
fn maven_resolves_latest_via_metadata() {
    let group_path = "com/example";
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, pom_url, sha256_url, _sha1_url) = urls(group_path, "demo", "1.5.0");
    let metadata_url = format!("{REGISTRY}/{group_path}/demo/maven-metadata.xml");
    let metadata = br#"<metadata>
      <versioning>
        <release>1.5.0</release>
        <versions><version>1.0.0</version><version>1.5.0</version></versions>
      </versioning>
    </metadata>"#;

    let transport = MockTransport::new();
    transport.insert(&metadata_url, metadata.to_vec());
    transport.insert(&jar_url, jar.clone());
    transport.insert(&sha256_url, sha256_hex(&jar).into_bytes());
    transport.insert(&pom_url, BENIGN_POM.to_vec());

    let opts = MavenFetchOptions::default();
    // No version -> resolve via maven-metadata.xml.
    let pkg = MavenRef::parse("com.example:demo").unwrap();
    let report = fetch_and_scan_maven(&pkg, &opts, &transport).unwrap();
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn maven_typosquat_blocks() {
    let group_path = "com/example";
    // `guaava` is one edit from popular `guava`.
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, pom_url, sha256_url, _sha1_url) = urls(group_path, "guaava", "1.0.0");

    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert(&sha256_url, sha256_hex(&jar).into_bytes());
    transport.insert(&pom_url, BENIGN_POM.to_vec());

    let opts = MavenFetchOptions::default();
    let pkg = MavenRef::parse("com.example:guaava:1.0.0").unwrap();
    let report = fetch_and_scan_maven(&pkg, &opts, &transport).unwrap();

    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"typosquatting"), "got: {ids:?}");
    assert!(ids.contains(&"low-reputation"), "got: {ids:?}");
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn maven_report_identity_uses_requested_coordinate_not_manifest() {
    // A jar whose MANIFEST.MF advertises a DIFFERENT package name/version
    // (a malicious jar could impersonate another package). The report's
    // identity must still be the REQUESTED artifactId + resolved version,
    // never the manifest's Implementation-Title/Version.
    let group_path = "com/example";
    let lying_manifest: &[u8] = b"Manifest-Version: 1.0\r\n\
        Implementation-Title: SomethingElse\r\n\
        Implementation-Version: 9.9.9\r\n";
    let jar = make_jar(&[("META-INF/MANIFEST.MF", lying_manifest)]);
    let (jar_url, pom_url, sha256_url, _sha1_url) = urls(group_path, "demo", "1.0.0");

    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert(&sha256_url, sha256_hex(&jar).into_bytes());
    transport.insert(&pom_url, BENIGN_POM.to_vec());

    let opts = MavenFetchOptions::default();
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let report = fetch_and_scan_maven(&pkg, &opts, &transport).unwrap();

    assert_eq!(
        report.package_name.as_deref(),
        Some("demo"),
        "report must reflect the requested artifactId, not MANIFEST.MF Implementation-Title"
    );
    assert_eq!(
        report.package_version.as_deref(),
        Some("1.0.0"),
        "report must reflect the resolved version, not MANIFEST.MF Implementation-Version"
    );
}

#[test]
fn maven_embedded_build_script_flagged() {
    let group_path = "com/example";
    let jar = make_jar(&[
        ("META-INF/MANIFEST.MF", BENIGN_MANIFEST),
        ("scripts/install.sh", b"#!/bin/sh\necho hi\n"),
    ]);
    let (jar_url, pom_url, sha256_url, _sha1_url) = urls(group_path, "demo", "1.0.0");

    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert(&sha256_url, sha256_hex(&jar).into_bytes());
    transport.insert(&pom_url, BENIGN_POM.to_vec());

    let opts = MavenFetchOptions::default();
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let report = fetch_and_scan_maven(&pkg, &opts, &transport).unwrap();

    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"maven-embedded-build-script"), "got: {ids:?}");
    // Medium severity -> blocks.
    assert_eq!(report.decision, Decision::Block);
}

// ---------------------------------------------------------------------------
// #54 — 404-vs-transient: a confirmed-absent (404) .sha256 or .pom may
// downgrade, but a transient failure (5xx) must fail closed (U-29).
// ---------------------------------------------------------------------------

#[test]
fn maven_absent_pom_404_is_info_not_fatal() {
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, _pom_url, sha256_url, _sha1_url) = urls("com/example", "demo", "1.0.0");
    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert(&sha256_url, sha256_hex(&jar).into_bytes());
    // pom NOT registered -> MockTransport returns a 404.

    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let report = fetch_and_scan_maven(&pkg, &MavenFetchOptions::default(), &transport).unwrap();
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"maven-no-pom"), "got: {ids:?}");
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn maven_transient_pom_error_fails_closed() {
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, pom_url, sha256_url, _sha1_url) = urls("com/example", "demo", "1.0.0");
    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert(&sha256_url, sha256_hex(&jar).into_bytes()); // strong integrity OK
    transport.insert_status(&pom_url, 503); // transient — NOT a 404

    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_maven(&pkg, &MavenFetchOptions::default(), &transport).unwrap_err()
    );
    assert!(
        err.contains("transient") || err.contains("pom"),
        "got: {err}"
    );
}

#[test]
fn maven_transient_sha256_error_does_not_downgrade_to_sha1() {
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, pom_url, sha256_url, sha1_url) = urls("com/example", "demo", "1.0.0");
    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert_status(&sha256_url, 500); // transient — NOT a 404
    transport.insert(&sha1_url, sha1_hex(&jar).into_bytes()); // a valid weak digest IS available
    transport.insert(&pom_url, BENIGN_POM.to_vec());

    // The transient .sha256 failure must hard-error rather than silently
    // falling back to the (available) weak SHA-1 path.
    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_maven(&pkg, &MavenFetchOptions::default(), &transport).unwrap_err()
    );
    assert!(
        err.contains("transient") || err.contains("SHA-1") || err.contains("sha256"),
        "got: {err}"
    );
}

#[test]
fn maven_pom_redirect_to_external_404_is_not_treated_as_absent_pom() {
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, pom_url, sha256_url, _sha1_url) = urls("com/example", "demo", "1.0.0");
    let evil_pom = "https://evil.example.invalid/demo.pom";
    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert(&sha256_url, sha256_hex(&jar).into_bytes());
    transport.insert_redirect(&pom_url, evil_pom);
    transport.insert_status(evil_pom, 404);

    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_maven(&pkg, &MavenFetchOptions::default(), &transport).unwrap_err()
    );
    assert!(err.contains("allowlist"), "got: {err}");
    assert_eq!(
        transport.request_count(evil_pom),
        0,
        "disallowed POM redirect target must not be requested or classified as a 404"
    );
}

#[test]
fn maven_sha256_redirect_to_external_404_does_not_downgrade_to_sha1() {
    let jar = make_jar(&[("META-INF/MANIFEST.MF", BENIGN_MANIFEST)]);
    let (jar_url, _pom_url, sha256_url, sha1_url) = urls("com/example", "demo", "1.0.0");
    let evil_sha256 = "https://evil.example.invalid/demo.jar.sha256";
    let transport = MockTransport::new();
    transport.insert(&jar_url, jar.clone());
    transport.insert_redirect(&sha256_url, evil_sha256);
    transport.insert_status(evil_sha256, 404);
    transport.insert(&sha1_url, sha1_hex(&jar).into_bytes());

    let pkg = MavenRef::parse("com.example:demo:1.0.0").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_maven(&pkg, &MavenFetchOptions::default(), &transport).unwrap_err()
    );
    assert!(err.contains("allowlist"), "got: {err}");
    assert_eq!(
        transport.request_count(evil_sha256),
        0,
        "disallowed checksum redirect target must not be requested or classified as a 404"
    );
}
