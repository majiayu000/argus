//! crates.io ecosystem support for argus.
//!
//! Semantic notes vs npm and PyPI:
//!
//! - crates.io has no install hook in the npm sense. The closest analog
//!   is `build.rs`: it runs at `cargo build` time with the user's
//!   environment, before any of the package's normal API is touched. A
//!   compromised `build.rs` is the canonical attack vector (TrapDoor's
//!   crates.io half, May 2026).
//! - Proc-macro crates run at the consumer's compile time, full Rust
//!   semantics. We flag procmacro-shaped manifests as elevated-risk.
//! - Integrity is SHA-256 hex of the `.crate` blob, advertised in the
//!   JSON API's `checksum` field.

use anyhow::{anyhow, bail, Context, Result};
use argus_core::url::{host_of, validate_artifact_url, verify_sha256_hex};
use argus_core::{canonicalize_package_name, Ecosystem, Finding, PackageCoordinate, ScanReport};
use std::path::PathBuf;

mod metadata;
mod rules;
mod scan;

pub use argus_core::ArtifactScan;
pub use argus_fetch::{HttpTransport, Transport};
pub use metadata::{resolve_version, CrateVersion, CratesPackument};
pub use rules::POPULAR_CRATES;
pub use scan::scan_crate_archive;

/// crates.io serves `.crate` archives from `*.crates.io` (canonically
/// `static.crates.io`). The subdomain-suffix entry accepts every
/// legitimate registry CDN host.
const CRATES_CDN_ALLOWLIST: &[&str] = &[".crates.io"];

/// Cap for the crates.io JSON packument body. Real crate metadata is a
/// few hundred KB at most.
const MAX_PACKUMENT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CrateRef {
    pub name: String,
    pub version: Option<String>,
}

impl CrateRef {
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty crate spec");
        }
        let (name, version) = match spec.split_once('@') {
            Some((n, v)) => (n, Some(v)),
            None => (spec, None),
        };
        if name.is_empty() {
            bail!("empty crate name: {spec}");
        }
        if let Some(v) = version {
            if v.is_empty() {
                bail!("empty version after `@`: {spec}");
            }
        }
        Ok(CrateRef {
            name: name.to_string(),
            version: version.map(str::to_string),
        })
    }
}

#[derive(Debug, Clone)]
pub struct CratesFetchOptions {
    pub registry: String,
    pub cache_dir: Option<PathBuf>,
    pub max_artifact_bytes: u64,
    pub max_extracted_bytes: u64,
}

impl Default for CratesFetchOptions {
    fn default() -> Self {
        Self {
            registry: "https://crates.io".to_string(),
            cache_dir: None,
            max_artifact_bytes: 100 * 1024 * 1024,
            max_extracted_bytes: 500 * 1024 * 1024,
        }
    }
}

/// Top-level entry: resolve, download `.crate`, verify SHA-256, safe-extract,
/// scan.
pub fn fetch_and_scan_crate(
    pkg: &CrateRef,
    opts: &CratesFetchOptions,
    transport: &dyn Transport,
) -> Result<ScanReport> {
    let registry_host = host_of(&opts.registry)
        .with_context(|| format!("registry URL has no parseable host: {}", opts.registry))?;
    let packument_url = format!(
        "{}/api/v1/crates/{}",
        opts.registry.trim_end_matches('/'),
        pkg.name
    );
    let bytes = transport
        .get(&packument_url, MAX_PACKUMENT_BYTES)
        .with_context(|| format!("fetch crates.io packument {packument_url}"))?;
    let packument: CratesPackument = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse crates.io packument {packument_url}"))?;
    let requested_name = canonicalize_package_name(Ecosystem::CratesIo, &pkg.name)
        .context("normalize requested crates.io package name")?;
    let registry_name = canonicalize_package_name(Ecosystem::CratesIo, &packument.crate_meta.name)
        .context("normalize crates.io registry metadata package name")?;
    if requested_name != registry_name {
        bail!(
            "crates.io registry package identity mismatch: requested `{}` but metadata names `{}`",
            pkg.name,
            packument.crate_meta.name
        );
    }

    let version = resolve_version(&packument, pkg.version.as_deref())
        .with_context(|| format!("resolve version for {}", pkg.name))?;
    let coordinate = PackageCoordinate::new(
        Ecosystem::CratesIo,
        packument.crate_meta.name.clone(),
        version.clone(),
    )
    .context("normalize crates.io registry coordinate")?;
    let ver_meta = packument
        .versions
        .iter()
        .find(|v| v.num == version)
        .ok_or_else(|| {
            anyhow!(
                "version `{version}` not present in crates.io packument for {}",
                pkg.name
            )
        })?;

    // crates.io serves .crate blobs from `static.crates.io` after a 302
    // redirect. We let ureq follow it, then verify the SHA-256 ourselves.
    let download_url = format!(
        "{}{}",
        opts.registry.trim_end_matches('/'),
        ver_meta.dl_path
    );
    validate_artifact_url(&download_url, &registry_host, CRATES_CDN_ALLOWLIST)?;

    let crate_bytes = transport
        .get_redirect_checked(&download_url, opts.max_artifact_bytes, &|u| {
            validate_artifact_url(u, &registry_host, CRATES_CDN_ALLOWLIST)
        })
        .with_context(|| format!("download .crate {download_url}"))?;
    verify_sha256_hex(&crate_bytes, &ver_meta.checksum).with_context(|| {
        format!(
            "verify SHA-256 of {}-{version}.crate ({} bytes)",
            pkg.name,
            crate_bytes.len()
        )
    })?;

    let extract_root = match &opts.cache_dir {
        Some(parent) => {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create cache dir {}", parent.display()))?;
            tempfile::tempdir_in(parent).context("create extract scratch dir under cache_dir")?
        }
        None => tempfile::tempdir().context("create private extract scratch dir")?,
    };

    let mut report =
        scan_crate_archive(&crate_bytes, extract_root.path(), opts.max_extracted_bytes)
            .context("scan extracted .crate")?;

    // Name-based rules apply to the user-supplied package name.
    rules::push_name_findings(&pkg.name, &mut report.findings);

    report.decision = argus_rules::derive_decision_from_findings(&report.findings);
    if report.package_name.is_none() {
        report.package_name = Some(pkg.name.clone());
    }
    if report.package_version.is_none() {
        report.package_version = Some(version);
    }
    report.coordinate = Some(coordinate);
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
        let p = CrateRef::parse("serde").unwrap();
        assert_eq!(p.name, "serde");
        assert_eq!(p.version, None);
    }

    #[test]
    fn parse_with_version() {
        let p = CrateRef::parse("tokio@1.40.0").unwrap();
        assert_eq!(p.name, "tokio");
        assert_eq!(p.version.as_deref(), Some("1.40.0"));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(CrateRef::parse("").is_err());
        assert!(CrateRef::parse("serde@").is_err());
        assert!(CrateRef::parse("@1.0").is_err());
    }

    #[test]
    fn validate_artifact_accepts_static_crates_io() {
        validate_artifact_url(
            "https://static.crates.io/crates/serde/serde-1.0.0.crate",
            "crates.io",
            CRATES_CDN_ALLOWLIST,
        )
        .unwrap();
    }

    #[test]
    fn validate_artifact_rejects_http() {
        assert!(validate_artifact_url(
            "http://static.crates.io/crates/serde/x.crate",
            "crates.io",
            CRATES_CDN_ALLOWLIST,
        )
        .is_err());
    }

    #[test]
    fn validate_artifact_rejects_random_host() {
        assert!(validate_artifact_url(
            "https://evil.example.invalid/serde-1.0.0.crate",
            "crates.io",
            CRATES_CDN_ALLOWLIST,
        )
        .is_err());
    }
}
