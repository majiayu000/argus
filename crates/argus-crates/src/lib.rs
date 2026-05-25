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
use argus_core::{Finding, ScanReport};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

mod metadata;
mod rules;
mod scan;

pub use argus_fetch::{HttpTransport, Transport};
pub use metadata::{resolve_version, CrateVersion, CratesPackument};
pub use rules::POPULAR_CRATES;
pub use scan::scan_crate_archive;

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

    let version = resolve_version(&packument, pkg.version.as_deref())
        .with_context(|| format!("resolve version for {}", pkg.name))?;
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
    validate_artifact_url(&download_url, &registry_host)?;

    let crate_bytes = transport
        .get(&download_url, opts.max_artifact_bytes)
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
    Ok(report)
}

fn host_of(url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| anyhow!("URL has no http(s) scheme: {url}"))?;
    let end = rest.find('/').unwrap_or(rest.len());
    let host = rest[..end].to_ascii_lowercase();
    if host.is_empty() {
        bail!("URL has empty host: {url}");
    }
    Ok(host)
}

/// Accept the registry host plus `static.crates.io` (and subdomains of
/// `.crates.io`) for `.crate` file delivery. Same idea as PyPI's
/// `files.pythonhosted.org` allowance.
fn validate_artifact_url(art_url: &str, registry_host: &str) -> Result<()> {
    if !art_url.starts_with("https://") {
        bail!("refusing non-HTTPS .crate URL `{art_url}`");
    }
    let host = host_of(art_url)?;
    if host == registry_host || host == "static.crates.io" || host.ends_with(".crates.io") {
        return Ok(());
    }
    bail!(
        ".crate host `{host}` is neither the registry host `{registry_host}` nor a known crates.io CDN (URL {art_url})"
    );
}

fn verify_sha256_hex(bytes: &[u8], expected_hex: &str) -> Result<()> {
    if expected_hex.is_empty() {
        bail!("expected SHA-256 is empty — crates.io did not advertise a checksum");
    }
    let expected = hex::decode(expected_hex)
        .with_context(|| format!("decode expected SHA-256 hex `{expected_hex}`"))?;
    let actual = Sha256::digest(bytes);
    use subtle::ConstantTimeEq;
    if bool::from(actual.as_slice().ct_eq(&expected)) {
        Ok(())
    } else {
        Err(anyhow!(
            "SHA-256 mismatch for {} downloaded bytes (expected `{expected_hex}`)",
            bytes.len()
        ))
    }
}

/// Internal scan-result shape. Returned from `scan_crate_archive` so the
/// caller can decorate it with name + version metadata before producing
/// the final `ScanReport`.
pub struct ArtifactScan {
    pub findings: Vec<Finding>,
    pub name: Option<String>,
    pub version: Option<String>,
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
        )
        .unwrap();
    }

    #[test]
    fn validate_artifact_rejects_http() {
        assert!(
            validate_artifact_url("http://static.crates.io/crates/serde/x.crate", "crates.io")
                .is_err()
        );
    }

    #[test]
    fn validate_artifact_rejects_random_host() {
        assert!(validate_artifact_url(
            "https://evil.example.invalid/serde-1.0.0.crate",
            "crates.io"
        )
        .is_err());
    }

    #[test]
    fn sha256_roundtrip() {
        let b = b"argus";
        let h = hex::encode(Sha256::digest(b));
        verify_sha256_hex(b, &h).unwrap();
        let mut tampered = b.to_vec();
        tampered[0] ^= 0x01;
        assert!(verify_sha256_hex(&tampered, &h).is_err());
    }
}
