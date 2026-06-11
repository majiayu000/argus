//! Packagist / Composer (PHP) ecosystem scanner for argus.
//!
//! Fetches a Composer package from repo.packagist.org (p2 metadata),
//! downloads the ZIP artifact, verifies SHA-1 integrity (the only digest
//! Packagist advertises), safe-extracts, scans `composer.json` lifecycle
//! scripts and PHP source files.
//!
//! # Integrity caveat
//! Packagist `dist.shasum` is SHA-1, not SHA-256. SHA-1 provides corruption
//! detection and second-preimage resistance against non-adversarial registries,
//! but NOT collision resistance against a determined registry-level attacker.
//! This is documented and disclosed — it is a property of the Packagist
//! ecosystem, not of argus. When `dist.shasum` is absent, a High-severity
//! `unverified-artifact-integrity` finding is emitted per U-29.

use anyhow::{Context, Result};
use argus_core::url::{host_of, validate_artifact_url};
use argus_core::{Finding, ScanReport};
use std::path::PathBuf;

mod metadata;
mod rules;
mod scan;

pub use argus_core::ArtifactScan;
pub use argus_fetch::{HttpTransport, Transport};
pub use metadata::{resolve_version, ComposerManifest, ComposerPackument, ComposerRef};
pub use scan::scan_composer_zip;

/// Composer dist artifacts come from GitHub/GitLab/Bitbucket CDNs, not from
/// repo.packagist.org itself. The allowlist covers those well-known code-
/// hosting platforms.
const COMPOSER_DIST_ALLOWLIST: &[&str] = &[
    ".github.com",
    ".githubusercontent.com",
    "codeload.github.com",
    ".gitlab.com",
    ".bitbucket.org",
];

/// Cap for the p2 metadata JSON body.
const MAX_PACKUMENT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ComposerFetchOptions {
    pub registry: String,
    pub cache_dir: Option<PathBuf>,
    pub max_artifact_bytes: u64,
    pub max_extracted_bytes: u64,
}

impl Default for ComposerFetchOptions {
    fn default() -> Self {
        Self {
            registry: "https://repo.packagist.org".to_string(),
            cache_dir: None,
            max_artifact_bytes: 200 * 1024 * 1024,
            max_extracted_bytes: 500 * 1024 * 1024,
        }
    }
}

/// Top-level entry: resolve, download ZIP, verify SHA-1 (or emit High finding
/// when absent), safe-extract, scan.
pub fn fetch_and_scan_composer(
    pkg: &ComposerRef,
    opts: &ComposerFetchOptions,
    transport: &dyn Transport,
) -> Result<ScanReport> {
    let registry_host = host_of(&opts.registry)
        .with_context(|| format!("registry URL has no parseable host: {}", opts.registry))?;

    // --- 1. Fetch p2 metadata ---
    let meta_url = format!(
        "{}/p2/{}/{}.json",
        opts.registry.trim_end_matches('/'),
        pkg.vendor,
        pkg.package,
    );
    let meta_bytes = transport
        .get(&meta_url, MAX_PACKUMENT_BYTES)
        .with_context(|| format!("fetch Composer p2 metadata {meta_url}"))?;
    let packument: ComposerPackument = serde_json::from_slice(&meta_bytes)
        .with_context(|| format!("parse Composer p2 metadata {meta_url}"))?;

    // --- 2. Resolve version ---
    let full_name = format!("{}/{}", pkg.vendor, pkg.package);
    let version_obj = resolve_version(&packument, &full_name, pkg.version.as_deref())
        .with_context(|| format!("resolve version for {full_name}"))?;

    let resolved_version = version_obj.version.clone();
    let dist = version_obj.dist.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Composer package {full_name}@{resolved_version} has no dist — VCS-only packages \
             are not supported"
        )
    })?;

    if dist.dist_type.as_deref() != Some("zip") {
        anyhow::bail!(
            "Composer package {full_name}@{resolved_version} dist.type={:?} — only zip is \
             supported",
            dist.dist_type
        );
    }

    let dist_url = dist.url.as_deref().ok_or_else(|| {
        anyhow::anyhow!("Composer package {full_name}@{resolved_version} dist.url is absent")
    })?;

    // Validate the dist URL against the CDN allowlist (not the registry host).
    validate_artifact_url(dist_url, &registry_host, COMPOSER_DIST_ALLOWLIST)
        .with_context(|| format!("validate dist URL {dist_url}"))?;

    // --- 3. Download ZIP ---
    let zip_bytes = transport
        .get_redirect_checked(dist_url, opts.max_artifact_bytes, &|u| {
            validate_artifact_url(u, &registry_host, COMPOSER_DIST_ALLOWLIST)
        })
        .with_context(|| format!("download Composer zip {dist_url}"))?;

    // --- 4. Integrity check ---
    let mut extra_findings: Vec<Finding> = Vec::new();
    match dist.shasum.as_deref() {
        Some(sha) if !sha.is_empty() => {
            argus_core::url::verify_sha1_hex(&zip_bytes, sha).with_context(|| {
                format!(
                    "verify SHA-1 of {full_name}@{resolved_version} ({} bytes)",
                    zip_bytes.len()
                )
            })?;
        }
        _ => {
            // Absent or empty shasum: U-29 — emit High finding, do NOT silently allow.
            extra_findings.push(Finding::new(
                "unverified-artifact-integrity",
                argus_core::Severity::High,
                format!(
                    "Composer package {full_name}@{resolved_version} has no dist.shasum — \
                     artifact integrity cannot be verified (SHA-1 absent from Packagist metadata)"
                ),
            ));
        }
    }

    // --- 5. Extract and scan ---
    let extract_root = match &opts.cache_dir {
        Some(parent) => {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create cache dir {}", parent.display()))?;
            tempfile::tempdir_in(parent).context("create extract scratch dir under cache_dir")?
        }
        None => tempfile::tempdir().context("create private extract scratch dir")?,
    };

    let mut report = scan::scan_composer_zip(
        &zip_bytes,
        extract_root.path(),
        opts.max_extracted_bytes,
        version_obj,
    )
    .context("scan extracted Composer zip")?;

    // Name-based (typosquatting) findings.
    rules::push_name_findings(&full_name, &mut report.findings);

    // Integrity findings come after content findings.
    report.findings.extend(extra_findings);

    report.decision = argus_rules::derive_decision_from_findings(&report.findings);
    if report.package_name.is_none() {
        report.package_name = Some(full_name);
    }
    if report.package_version.is_none() {
        report.package_version = Some(resolved_version);
    }
    Ok(report)
}

pub(crate) fn finding(rule: &str, sev: argus_core::Severity, detail: impl Into<String>) -> Finding {
    Finding::new(rule, sev, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain() {
        let r = ComposerRef::parse("vendor/package").unwrap();
        assert_eq!(r.vendor, "vendor");
        assert_eq!(r.package, "package");
        assert_eq!(r.version, None);
    }

    #[test]
    fn parse_with_version() {
        let r = ComposerRef::parse("guzzlehttp/guzzle@7.8.1").unwrap();
        assert_eq!(r.vendor, "guzzlehttp");
        assert_eq!(r.package, "guzzle");
        assert_eq!(r.version.as_deref(), Some("7.8.1"));
    }

    #[test]
    fn parse_dev_version() {
        let r = ComposerRef::parse("vendor/pkg@dev-main").unwrap();
        assert_eq!(r.version.as_deref(), Some("dev-main"));
    }

    #[test]
    fn parse_rejects_no_slash() {
        assert!(ComposerRef::parse("packagewithoutslash").is_err());
        assert!(ComposerRef::parse("packagewithoutslash@1.0").is_err());
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(ComposerRef::parse("").is_err());
        assert!(ComposerRef::parse("/").is_err());
        assert!(ComposerRef::parse("vendor/").is_err());
        assert!(ComposerRef::parse("/package").is_err());
    }

    #[test]
    fn validate_artifact_accepts_github() {
        validate_artifact_url(
            "https://codeload.github.com/vendor/pkg/legacy.zip/refs/tags/1.0",
            "repo.packagist.org",
            COMPOSER_DIST_ALLOWLIST,
        )
        .unwrap();
    }

    #[test]
    fn validate_artifact_rejects_http() {
        assert!(validate_artifact_url(
            "http://codeload.github.com/vendor/pkg/legacy.zip",
            "repo.packagist.org",
            COMPOSER_DIST_ALLOWLIST,
        )
        .is_err());
    }

    #[test]
    fn validate_artifact_rejects_unknown_host() {
        assert!(validate_artifact_url(
            "https://evil.example.invalid/pkg.zip",
            "repo.packagist.org",
            COMPOSER_DIST_ALLOWLIST,
        )
        .is_err());
    }
}
