//! RubyGems ecosystem support for argus.
//!
//! Mirrors the shape of `argus-pypi` / `argus-crates`, but RubyGems has two
//! structural differences from those ecosystems:
//!
//! - A `.gem` is a NESTED archive: a PLAIN (non-gzipped) ustar tar whose
//!   members include `metadata.gz` (the YAML gemspec) and `data.tar.gz` (a
//!   gzipped tar of the real files). `argus_fetch::extract_tarball` cannot
//!   open the plain-tar outer container, so [`scan::read_gem_member`] reads
//!   outer members into capped in-memory buffers and only the inner
//!   `data.tar.gz` is handed to `extract_tarball`, reused intact. See
//!   `scan.rs` for the safety discipline.
//! - The build-time execution surface is `extconf.rb` (run via `mkmf` at
//!   `gem install`), the analog of pypi `setup.py` / npm `postinstall`.
//!
//! Integrity is the registry-advertised hex SHA-256 of the `.gem` bytes,
//! verified with the shared `argus_core::url::verify_sha256_hex`. The inner
//! `checksums.yaml.gz` is self-referential (an attacker who repacks the gem
//! also rewrites it) and is therefore NOT a trust anchor; it is out of scope
//! for v1. See the design doc's integrity section.
//!
//! No Ruby code is ever executed by argus.

use anyhow::{bail, Context, Result};
use argus_core::url::{host_of, validate_artifact_url, verify_sha256_hex};
use argus_core::{Finding, ScanReport, Severity};
use std::path::PathBuf;

mod metadata;
mod rules;
mod scan;

pub use argus_core::ArtifactScan;
pub use argus_fetch::{HttpTransport, Transport};
pub use metadata::{resolve_version, GemVersion};
pub use rules::POPULAR_RUBY_GEMS;
pub use scan::{parse_gemspec_extensions, parse_gemspec_name_version, read_gem_member, scan_gem};

/// RubyGems serves both metadata and `.gem` downloads from `rubygems.org`
/// itself, so the CDN allowlist is empty. If a future mirror uses a distinct
/// download host (e.g. a Fastly CNAME with its own hostname), add it here.
const RUBYGEMS_CDN_ALLOWLIST: &[&str] = &[];

/// Cap for the version-list JSON body. RubyGems version lists for popular
/// gems (rails/activesupport) are large but well under this.
const MAX_VERSIONS_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct GemRef {
    pub name: String,
    pub version: Option<String>,
}

impl GemRef {
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty RubyGems package spec");
        }
        let (name, version) = match spec.split_once('@') {
            Some((n, v)) => (n, Some(v)),
            None => (spec, None),
        };
        if name.is_empty() {
            bail!("empty RubyGems package name: {spec}");
        }
        if let Some(v) = version {
            if v.is_empty() {
                bail!("empty version after `@`: {spec}");
            }
        }
        Ok(GemRef {
            name: name.to_string(),
            version: version.map(str::to_string),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GemFetchOptions {
    pub registry: String,
    pub cache_dir: Option<PathBuf>,
    pub max_artifact_bytes: u64,
    pub max_extracted_bytes: u64,
}

impl Default for GemFetchOptions {
    fn default() -> Self {
        Self {
            registry: "https://rubygems.org".to_string(),
            cache_dir: None,
            max_artifact_bytes: 200 * 1024 * 1024,
            max_extracted_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Top-level entry. Resolves the version + its SHA-256, downloads + verifies
/// + parses the `.gem`, and returns one `ScanReport`.
pub fn fetch_and_scan_gems(
    pkg: &GemRef,
    opts: &GemFetchOptions,
    transport: &dyn Transport,
) -> Result<ScanReport> {
    // 1. Fetch the version list and resolve the requested version + sha.
    let registry = opts.registry.trim_end_matches('/');
    let registry_host = host_of(registry)
        .with_context(|| format!("registry URL has no parseable host: {}", opts.registry))?;
    let versions_url = format!("{registry}/api/v1/versions/{}.json", pkg.name);
    // Defense-in-depth: validate the metadata URL host too, not only the
    // download URL.
    validate_artifact_url(&versions_url, &registry_host, RUBYGEMS_CDN_ALLOWLIST)
        .with_context(|| format!("validate RubyGems versions URL {versions_url}"))?;
    let bytes = transport
        .get(&versions_url, MAX_VERSIONS_BYTES)
        .with_context(|| format!("fetch RubyGems version list {versions_url}"))?;
    let versions: Vec<GemVersion> = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse RubyGems version list {versions_url}"))?;

    let (version, sha) = resolve_version(&versions, &pkg.name, pkg.version.as_deref())
        .with_context(|| format!("resolve version for {}", pkg.name))?;

    // 2. Build + validate the download URL.
    let download_url = format!("{registry}/downloads/{}-{version}.gem", pkg.name);
    validate_artifact_url(&download_url, &registry_host, RUBYGEMS_CDN_ALLOWLIST)
        .with_context(|| format!("validate RubyGems download URL {download_url}"))?;

    // 3. Download + verify SHA-256. verify_sha256_hex hard-errors on empty
    //    hex (U-29: an absent digest is a failure, never a silent skip).
    let gem_bytes = transport
        .get(&download_url, opts.max_artifact_bytes)
        .with_context(|| format!("download .gem {download_url}"))?;
    verify_sha256_hex(&gem_bytes, &sha).with_context(|| {
        format!(
            "verify SHA-256 of {}-{version}.gem ({} bytes)",
            pkg.name,
            gem_bytes.len()
        )
    })?;

    // 4. Set up the scratch dir.
    let extract_root = match &opts.cache_dir {
        Some(parent) => {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create cache dir {}", parent.display()))?;
            tempfile::tempdir_in(parent).context("create extract scratch dir under cache_dir")?
        }
        None => tempfile::tempdir().context("create private extract scratch dir")?,
    };
    let art_dir = extract_root.path().join("gem");
    std::fs::create_dir_all(&art_dir).with_context(|| format!("mkdir {}", art_dir.display()))?;

    // 5. Parse + scan the nested archive.
    let scanned = scan_gem(&gem_bytes, &art_dir, opts.max_extracted_bytes)
        .with_context(|| format!("scan .gem {}-{version}", pkg.name))?;
    let mut all_findings: Vec<Finding> = scanned.findings;

    // 6. Name-based rules (typosquatting) on the gem name itself.
    rules::push_name_findings(&pkg.name, &mut all_findings);

    let decision = argus_rules::derive_decision_from_findings(&all_findings);

    Ok(ScanReport {
        artifact: argus_core::ArtifactKind::PackageDir,
        path: extract_root.path().to_path_buf(),
        package_name: scanned.name.or_else(|| Some(pkg.name.clone())),
        package_version: scanned.version.or(Some(version)),
        decision,
        findings: all_findings,
    })
}

/// Build a Finding with the given rule_id/severity/detail and no location.
pub(crate) fn finding(rule: &str, sev: Severity, detail: impl Into<String>) -> Finding {
    Finding::new(rule, sev, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain() {
        let p = GemRef::parse("nokogiri").unwrap();
        assert_eq!(p.name, "nokogiri");
        assert_eq!(p.version, None);
    }

    #[test]
    fn parse_with_version() {
        let p = GemRef::parse("rails@7.1.0").unwrap();
        assert_eq!(p.name, "rails");
        assert_eq!(p.version.as_deref(), Some("7.1.0"));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(GemRef::parse("").is_err());
        assert!(GemRef::parse("rails@").is_err());
        assert!(GemRef::parse("@1.0").is_err());
    }

    #[test]
    fn validate_download_accepts_registry_host() {
        validate_artifact_url::<&str>(
            "https://rubygems.org/downloads/rails-7.1.0.gem",
            "rubygems.org",
            RUBYGEMS_CDN_ALLOWLIST,
        )
        .unwrap();
    }

    #[test]
    fn validate_download_rejects_http_downgrade() {
        assert!(validate_artifact_url::<&str>(
            "http://rubygems.org/downloads/rails-7.1.0.gem",
            "rubygems.org",
            RUBYGEMS_CDN_ALLOWLIST,
        )
        .is_err());
    }

    #[test]
    fn validate_download_rejects_foreign_host() {
        assert!(validate_artifact_url::<&str>(
            "https://evil.example.invalid/downloads/rails-7.1.0.gem",
            "rubygems.org",
            RUBYGEMS_CDN_ALLOWLIST,
        )
        .is_err());
    }
}
