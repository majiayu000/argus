//! Fetch an npm package by name (and optional version), verify its tarball
//! integrity, extract it under a scratch directory, and run argus-rules
//! against the extracted source.
//!
//! No lifecycle script ever runs: this crate does not call `npm`, `tar
//! --to-command`, or any post-extract hook.

use anyhow::{anyhow, bail, Context, Result};
use argus_core::ScanReport;
use std::path::PathBuf;

mod extract;
mod integrity;
mod packument;
mod transport;

pub use extract::extract_tarball;
pub use integrity::{parse_ssri, verify_ssri};
pub use packument::{resolve_version, Packument};
pub use transport::{HttpTransport, Transport};

/// Reference to one npm package + optional version constraint.
///
/// `version` is one of:
/// - `None` — resolve `dist-tags.latest`
/// - `Some("1.2.3")` — exact match against `versions["1.2.3"]`
/// - `Some("beta")` — match against `dist-tags["beta"]`
#[derive(Debug, Clone)]
pub struct PackageRef {
    pub name: String,
    pub version: Option<String>,
}

impl PackageRef {
    /// Parse `chalk` or `chalk@5.3.0` or `@types/node@20.10.0`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty package spec");
        }
        // Scoped: `@scope/name[@version]`
        if let Some(rest) = spec.strip_prefix('@') {
            // Find the `@` that separates name from version, which must appear
            // *after* the `/` that ends the scope.
            let slash = rest
                .find('/')
                .ok_or_else(|| anyhow!("scoped package missing `/`: {spec}"))?;
            let after_slash = &rest[slash + 1..];
            let (pkg_part, version) = split_version(after_slash);
            let name = format!("@{}/{pkg_part}", &rest[..slash]);
            return Ok(PackageRef {
                name,
                version: version.map(str::to_string),
            });
        }
        let (name, version) = split_version(spec);
        Ok(PackageRef {
            name: name.to_string(),
            version: version.map(str::to_string),
        })
    }
}

fn split_version(s: &str) -> (&str, Option<&str>) {
    match s.find('@') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

/// Knobs for `fetch_and_scan`. Defaults match the SPEC §15 Phase 1 settings.
#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub registry: String,
    pub cache_dir: PathBuf,
    /// Hard cap on the downloaded tarball size in bytes. Default 100 MiB.
    pub max_tarball_bytes: u64,
    /// Hard cap on the total uncompressed extracted size. Default 500 MiB.
    pub max_extracted_bytes: u64,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            registry: "https://registry.npmjs.org".to_string(),
            cache_dir: std::env::temp_dir().join("argus"),
            max_tarball_bytes: 100 * 1024 * 1024,
            max_extracted_bytes: 500 * 1024 * 1024,
        }
    }
}

/// Top-level entry: resolve, download, verify, extract, scan.
///
/// `transport` is abstracted so integration tests can inject mock bytes
/// without spinning up an HTTP server.
pub fn fetch_and_scan(
    pkg: &PackageRef,
    opts: &FetchOptions,
    transport: &dyn Transport,
) -> Result<ScanReport> {
    // 1. Fetch packument.
    let packument_url = format!(
        "{}/{}",
        opts.registry.trim_end_matches('/'),
        url_encode_pkg(&pkg.name)
    );
    let packument_bytes = transport
        .get(&packument_url)
        .with_context(|| format!("fetch packument {packument_url}"))?;
    let packument: Packument = serde_json::from_slice(&packument_bytes)
        .with_context(|| format!("parse packument {packument_url}"))?;

    // 2. Resolve version.
    let version = resolve_version(&packument, pkg.version.as_deref())
        .with_context(|| format!("resolve version for {}", pkg.name))?;
    let dist = packument
        .versions
        .get(&version)
        .ok_or_else(|| {
            anyhow!(
                "version `{version}` not present in packument for {}",
                pkg.name
            )
        })?
        .dist
        .clone();

    // 3. Download tarball.
    let tarball_bytes = transport
        .get(&dist.tarball)
        .with_context(|| format!("download tarball {}", dist.tarball))?;
    if tarball_bytes.len() as u64 > opts.max_tarball_bytes {
        bail!(
            "tarball size {} exceeds cap {}",
            tarball_bytes.len(),
            opts.max_tarball_bytes
        );
    }

    // 4. Verify integrity.
    verify_ssri(&tarball_bytes, &dist.integrity).with_context(|| {
        format!(
            "verify integrity of {} ({} bytes)",
            pkg.name,
            tarball_bytes.len()
        )
    })?;

    // 5. Extract into a scratch dir under cache_dir.
    std::fs::create_dir_all(&opts.cache_dir)
        .with_context(|| format!("create argus cache dir at {}", opts.cache_dir.display()))?;
    let extract_root =
        tempfile::tempdir_in(&opts.cache_dir).context("create extract scratch dir")?;
    let pkg_dir = extract_tarball(
        &tarball_bytes,
        extract_root.path(),
        opts.max_extracted_bytes,
    )
    .context("safe-extract tarball")?;

    // 6. Scan with existing rules.
    let report = argus_rules::scan_package_dir(&pkg_dir).context("scan extracted package")?;
    Ok(report)
}

/// npm registry URL-encodes only the `/` in scoped names; everything else is
/// already path-safe. Keep it explicit so we don't ship a full URL encoder.
fn url_encode_pkg(name: &str) -> String {
    name.replace('/', "%2F")
}
