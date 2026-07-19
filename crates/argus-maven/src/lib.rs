//! Maven Central ecosystem support for argus.
//!
//! Maven Central is a STATIC FILE TREE (no JSON packument API). Version
//! resolution parses `maven-metadata.xml`; the artifact is a `.jar` (ZIP of
//! compiled `.class` bytecode); the build manifest `pom.xml` is fetched
//! standalone alongside the jar.
//!
//! # Integrity (honest, U-29)
//!
//! Maven Central's universal per-artifact digest is `.jar.sha1` (SHA-1),
//! which is weak (SEC-06). `.jar.sha256` exists for newer artifacts but is
//! not universal. Strategy:
//!
//! 1. Fetch `<jar>.sha256`; if present, verify with the strong shared
//!    [`verify_sha256_hex`] helper.
//! 2. If `.sha256` is absent, DO NOT silently treat SHA-1 as strong: emit an
//!    Info `maven-weak-integrity-only` finding (visible per U-29) and verify
//!    `.jar.sha1` for corruption detection only.
//!
//! # Fundamental gap (must be stated)
//!
//! A `.jar` is compiled JVM bytecode. argus inspects ONLY textual/structured
//! surfaces (MANIFEST.MF, pom.xml, embedded text/scripts). It CANNOT detect
//! malware living in `.class` bytecode (malicious static initializers,
//! reflection, runtime classloading). A clean report means "no dangerous
//! build-plugin declarations or embedded text payloads were found", NOT "the
//! bytecode is safe". `maven-bytecode-not-inspected` (Info) is emitted
//! unconditionally to keep that explicit. There is no Sigstore/provenance
//! layer on Maven Central (gap).

use anyhow::{bail, Context, Result};
use argus_core::url::{host_of, validate_artifact_url, verify_sha256_hex};
use argus_core::{Ecosystem, Finding, PackageCoordinate, ScanReport, Severity};
use sha1::{Digest, Sha1};
use std::path::PathBuf;

mod metadata;
mod rules;
mod scan;

pub use argus_core::ArtifactScan;
use argus_fetch::is_not_found;
pub use argus_fetch::{HttpTransport, Transport};
pub use metadata::{
    parse_maven_metadata, parse_pom_plugins, resolve_version, MavenMetadata, MavenRef, PomPlugins,
};
pub use rules::POPULAR_MAVEN_ARTIFACTS;
pub use scan::{parse_jar_manifest, scan_maven_jar, JarManifest};

/// Maven Central + its mirrors live under `*.maven.org`. The default
/// registry host is `repo1.maven.org`; the suffix entry accepts the
/// documented mirror hosts on the same family. If an artifact 302s to a
/// foreign CDN (e.g. cloudfront), `validate_artifact_url` rejects it and
/// surfaces the host — an intentional fail-closed, not a silent allow.
const MAVEN_CDN_ALLOWLIST: &[&str] = &[".maven.org"];

/// Cap for the `maven-metadata.xml` body (static, tiny — but popular
/// artifacts with thousands of versions can still be a few MB).
const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct MavenFetchOptions {
    pub registry: String,
    pub cache_dir: Option<PathBuf>,
    pub max_artifact_bytes: u64,
    pub max_extracted_bytes: u64,
}

impl Default for MavenFetchOptions {
    fn default() -> Self {
        Self {
            registry: "https://repo1.maven.org/maven2".to_string(),
            cache_dir: None,
            max_artifact_bytes: 200 * 1024 * 1024,
            max_extracted_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Top-level entry. Resolves the version (via maven-metadata.xml unless an
/// explicit version is given), validates + downloads the jar, verifies its
/// checksum, extracts + scans it, fetches + scans the standalone pom.xml,
/// and returns one merged `ScanReport`.
pub fn fetch_and_scan_maven(
    pkg: &MavenRef,
    opts: &MavenFetchOptions,
    transport: &dyn Transport,
) -> Result<ScanReport> {
    let registry = opts.registry.trim_end_matches('/').to_string();
    let registry_host = host_of(&registry)
        .with_context(|| format!("registry URL has no parseable host: {}", opts.registry))?;
    let group_path = pkg.group_path();

    // 1. Resolve version. If explicit, trust it; else fetch maven-metadata.xml.
    let version = match pkg.version.as_deref() {
        Some(v) => v.to_string(),
        None => {
            let metadata_url = format!(
                "{registry}/{group_path}/{}/maven-metadata.xml",
                pkg.artifact
            );
            validate_artifact_url(&metadata_url, &registry_host, MAVEN_CDN_ALLOWLIST)?;
            let bytes = transport
                .get_redirect_checked(&metadata_url, MAX_METADATA_BYTES, &|u| {
                    validate_artifact_url(u, &registry_host, MAVEN_CDN_ALLOWLIST)
                })
                .with_context(|| format!("fetch maven-metadata {metadata_url}"))?;
            let xml = String::from_utf8_lossy(&bytes);
            resolve_version(&xml, None)
                .with_context(|| format!("resolve latest version for {}", pkg.artifact))?
        }
    };
    let coordinate = PackageCoordinate::new(
        Ecosystem::Maven,
        format!("{}:{}", pkg.group, pkg.artifact),
        version.clone(),
    )
    .context("normalize Maven registry coordinate")?;

    let base = format!(
        "{registry}/{group_path}/{}/{version}/{}-{version}",
        pkg.artifact, pkg.artifact
    );
    let jar_url = format!("{base}.jar");
    let pom_url = format!("{base}.pom");
    let sha256_url = format!("{jar_url}.sha256");
    let sha1_url = format!("{jar_url}.sha1");

    // 2. Download the jar (validate the URL first).
    validate_artifact_url(&jar_url, &registry_host, MAVEN_CDN_ALLOWLIST)?;
    let jar_bytes = transport
        .get_redirect_checked(&jar_url, opts.max_artifact_bytes, &|u| {
            validate_artifact_url(u, &registry_host, MAVEN_CDN_ALLOWLIST)
        })
        .with_context(|| format!("download jar {jar_url}"))?;

    // 3. Integrity. Prefer SHA-256; fall back to SHA-1 with a visible finding.
    let mut integrity_findings: Vec<Finding> = Vec::new();
    verify_jar_integrity(
        &jar_bytes,
        &sha256_url,
        &sha1_url,
        &registry_host,
        transport,
        &mut integrity_findings,
    )
    .with_context(|| format!("verify integrity of {jar_url}"))?;

    // 4. Set up scratch dir + extract/scan the jar.
    let extract_root = match &opts.cache_dir {
        Some(parent) => {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create cache dir {}", parent.display()))?;
            tempfile::tempdir_in(parent).context("create extract scratch dir under cache_dir")?
        }
        None => tempfile::tempdir().context("create private extract scratch dir")?,
    };
    let jar_dir = extract_root.path().join("jar");
    std::fs::create_dir_all(&jar_dir).with_context(|| format!("mkdir {}", jar_dir.display()))?;

    let scan = scan_maven_jar(&jar_bytes, &jar_dir, opts.max_extracted_bytes)
        .with_context(|| format!("scan jar {jar_url}"))?;

    let mut all_findings: Vec<Finding> = scan.findings;
    all_findings.extend(integrity_findings);

    // 5. Fetch + parse the standalone pom.xml for dangerous build plugins.
    //    The pom is best-effort: a 404 (some artifacts ship only a jar) is
    //    NOT a hard error, but a transport error other than "no route" we
    //    propagate. We treat a missing pom as "no plugin findings" — the
    //    jar's own surfaces still drove the scan.
    validate_artifact_url(&pom_url, &registry_host, MAVEN_CDN_ALLOWLIST)?;
    match transport.get_redirect_checked(&pom_url, opts.max_artifact_bytes, &|u| {
        validate_artifact_url(u, &registry_host, MAVEN_CDN_ALLOWLIST)
    }) {
        Ok(pom_bytes) => {
            let pom_xml = String::from_utf8_lossy(&pom_bytes);
            let plugins =
                parse_pom_plugins(&pom_xml).with_context(|| format!("parse pom {pom_url}"))?;
            push_pom_plugin_findings(&plugins, &mut all_findings);
        }
        Err(e) if is_not_found(&e) => {
            // A *confirmed absent* (404) standalone pom is unusual but not
            // dangerous — surface it as Info (U-29 visibility); the integrity
            // gate already ran on the jar.
            all_findings.push(finding(
                "maven-no-pom",
                Severity::Info,
                format!("standalone pom.xml absent (404) at {pom_url}"),
            ));
        }
        Err(e) => {
            // A transient failure (timeout / 5xx / TLS) is NOT proof the pom is
            // absent. Skipping the plugin scan here would let a package whose
            // pom declares exec-maven-plugin/antrun/Groovy slip through, so we
            // fail closed rather than downgrade (U-29).
            return Err(e).with_context(|| {
                format!("fetch standalone pom {pom_url} (transient failure — refusing to skip plugin scan)")
            });
        }
    }

    // 6. Name-based rules (typosquatting) on the artifactId.
    rules::push_name_findings(&pkg.artifact, &mut all_findings);

    // 7. Identity. The report's package_name/version MUST reflect the
    //    REQUESTED Maven coordinate (artifactId + resolved version), never the
    //    jar's MANIFEST.MF Implementation-Title/Version. A malicious jar can
    //    set those manifest fields to an unrelated package name; trusting them
    //    here would let the report misrepresent what was actually scanned. The
    //    manifest-derived `scan.name`/`scan.version` already drive in-jar
    //    findings and are not the artifact's identity.
    let decision = argus_rules::derive_decision_from_findings(&all_findings);

    Ok(ScanReport {
        artifact: argus_core::ArtifactKind::PackageDir,
        path: extract_root.path().to_path_buf(),
        package_name: Some(pkg.artifact.clone()),
        package_version: Some(version),
        decision,
        findings: all_findings,
        coordinate: Some(coordinate),
        intelligence: None,
    })
}

/// Verify the downloaded jar bytes against the registry's checksum.
///
/// Strong path: `.jar.sha256` present -> `verify_sha256_hex`. Degraded path:
/// `.sha256` absent -> emit `maven-weak-integrity-only` (Info) and verify
/// `.jar.sha1` for corruption detection. If BOTH are absent we hard-error
/// (U-29: never a silent pass).
fn verify_jar_integrity(
    jar_bytes: &[u8],
    sha256_url: &str,
    sha1_url: &str,
    registry_host: &str,
    transport: &dyn Transport,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    validate_artifact_url(sha256_url, registry_host, MAVEN_CDN_ALLOWLIST)?;
    // Checksum files are tiny; cap at 4 KiB (hex digest + optional filename).
    const CHECKSUM_CAP: u64 = 4 * 1024;

    match transport.get_redirect_checked(sha256_url, CHECKSUM_CAP, &|u| {
        validate_artifact_url(u, registry_host, MAVEN_CDN_ALLOWLIST)
    }) {
        Ok(sha256_body) => {
            let expected = first_hex_token(&String::from_utf8_lossy(&sha256_body));
            verify_sha256_hex(jar_bytes, &expected)
                .with_context(|| "verify SHA-256 of jar".to_string())?;
            return Ok(());
        }
        // A *transient* failure fetching the strong checksum must NOT silently
        // drop us onto the weak SHA-1 path — that would degrade strong
        // integrity on a timeout/5xx. Fail closed (U-29). Only a confirmed 404
        // (the .sha256 genuinely does not exist for this artifact) falls
        // through to the documented degraded path below.
        Err(e) if !is_not_found(&e) => {
            return Err(e).with_context(|| {
                format!("fetch {sha256_url} (transient — refusing to downgrade to weak SHA-1)")
            });
        }
        Err(_) => {}
    }

    // Degraded path: .sha256 confirmed absent (404). Try .sha1 for corruption
    // detection only.
    validate_artifact_url(sha1_url, registry_host, MAVEN_CDN_ALLOWLIST)?;
    let sha1_body = transport
        .get_redirect_checked(sha1_url, CHECKSUM_CAP, &|u| {
            validate_artifact_url(u, registry_host, MAVEN_CDN_ALLOWLIST)
        })
        .map_err(|e| {
            anyhow::anyhow!(
                "neither .sha256 nor .sha1 checksum available for jar (no strong or weak \
                 integrity digest); refusing to claim a verified download: {e}"
            )
        })?;
    let expected_sha1 = first_hex_token(&String::from_utf8_lossy(&sha1_body));
    verify_sha1_hex(jar_bytes, &expected_sha1).context("verify SHA-1 of jar")?;

    findings.push(finding(
        "maven-weak-integrity-only",
        Severity::Info,
        "only a weak SHA-1 checksum was available (no .sha256); the download was \
         checked for corruption but SHA-1 is not tamper-resistant (SEC-06)",
    ));
    Ok(())
}

/// Verify the SHA-1 digest of `bytes` matches `expected_hex`. Used ONLY on
/// the degraded path, paired with a visible `maven-weak-integrity-only`
/// finding — never presented as a strong integrity guarantee.
fn verify_sha1_hex(bytes: &[u8], expected_hex: &str) -> Result<()> {
    if expected_hex.is_empty() {
        bail!("expected SHA-1 is empty — registry did not advertise an integrity digest");
    }
    let expected = hex::decode(expected_hex)
        .with_context(|| format!("decode expected SHA-1 hex `{expected_hex}`"))?;
    let actual = Sha1::digest(bytes);
    if actual.as_slice() == expected.as_slice() {
        Ok(())
    } else {
        bail!(
            "SHA-1 mismatch for {} downloaded bytes (expected `{expected_hex}`)",
            bytes.len()
        )
    }
}

/// Maven checksum files are usually a bare hex digest, but some tools append
/// ` <filename>`. Take the first whitespace-delimited token.
fn first_hex_token(s: &str) -> String {
    s.split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Translate detected dangerous build plugins into findings.
fn push_pom_plugin_findings(plugins: &PomPlugins, findings: &mut Vec<Finding>) {
    if plugins.exec_plugin {
        findings.push(finding(
            "maven-exec-plugin",
            Severity::High,
            "pom.xml declares exec-maven-plugin (build-time arbitrary command/Java execution)",
        ));
    }
    if plugins.antrun_plugin {
        findings.push(finding(
            "maven-antrun-plugin",
            Severity::High,
            "pom.xml declares maven-antrun-plugin (build-time arbitrary Ant task execution)",
        ));
    }
    if plugins.groovy_plugin {
        findings.push(finding(
            "maven-build-script-plugin",
            Severity::High,
            "pom.xml declares a Groovy build plugin (build-time scripting)",
        ));
    }
}

/// Build a Finding with the given rule_id/severity/detail and no location.
pub(crate) fn finding(rule: &str, sev: Severity, detail: impl Into<String>) -> Finding {
    Finding::new(rule, sev, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_hex_token_strips_filename() {
        assert_eq!(first_hex_token("abc123\n"), "abc123");
        assert_eq!(first_hex_token("ABC123  guava.jar\n"), "abc123");
        assert_eq!(first_hex_token(""), "");
    }

    #[test]
    fn verify_sha1_matches_and_mismatches() {
        let b = b"hello world";
        let h = hex::encode(Sha1::digest(b));
        verify_sha1_hex(b, &h).unwrap();
        assert!(verify_sha1_hex(b, &"0".repeat(40)).is_err());
        assert!(verify_sha1_hex(b, "").is_err());
    }

    #[test]
    fn pom_plugin_findings_map_correctly() {
        let mut f = Vec::new();
        push_pom_plugin_findings(
            &PomPlugins {
                exec_plugin: true,
                antrun_plugin: false,
                groovy_plugin: true,
            },
            &mut f,
        );
        let ids: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(ids.contains(&"maven-exec-plugin"));
        assert!(ids.contains(&"maven-build-script-plugin"));
        assert!(!ids.contains(&"maven-antrun-plugin"));
    }
}
