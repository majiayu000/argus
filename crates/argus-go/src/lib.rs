//! Go module ecosystem support for argus.
//!
//! Mirrors the shape of `argus-pypi` / `argus-crates` but speaks the
//! GOPROXY module-proxy protocol (<https://go.dev/ref/mod#goproxy-protocol>).
//!
//! Key semantic differences from npm/PyPI/crates.io:
//!
//! - **Single artifact format.** A Go module ships exactly one artifact:
//!   the module `.zip` at `<base>/<esc-mod>/@v/<esc-ver>.zip`. There is no
//!   sdist/wheel choice, so no format-preference enum.
//! - **No install-time script.** Go has no `postinstall`/`setup.py`. The
//!   import-time execution surface (`func init()`, package-level `var`
//!   initializers) is the closest analog; see `rules` + `scan`.
//! - **Integrity is dirhash `h1:`, NOT a SHA-256 over the zip bytes.** The
//!   proxy advertises the `h1:` checksum at `.../@v/<ver>.ziphash`. We
//!   recompute it independently from the extracted file tree and compare
//!   in constant time. See [`dirhash`] for the full algorithm and the
//!   documented limitation (we do not yet cross-check sum.golang.org's
//!   signed transparency log).
//! - **Pure source.** Module zips contain only source files, so the
//!   scanner can read everything it needs (unlike bytecode ecosystems).
//!
//! No Go code is ever executed by argus. Every file is treated as opaque
//! text or bytes.

use anyhow::{bail, Context, Result};
use argus_core::url::{host_of, validate_artifact_url};
use argus_core::{ArtifactKind, Finding, ScanReport};
use std::path::PathBuf;

pub mod dirhash;
mod metadata;
mod rules;
mod scan;

pub use argus_core::ArtifactScan;
pub use argus_fetch::{HttpTransport, Transport};
pub use metadata::{escape_module_path, parse_go_mod_module, resolve_version, GoModInfo};
pub use rules::POPULAR_GO_MODULES;
pub use scan::{extract_module_zip, scan_extracted_module, ExtractedModule};

/// proxy.golang.org serves both metadata AND the module zip from the same
/// host, so the CDN allowlist is empty: only the registry host itself is
/// accepted. (Contrast with PyPI's `.pythonhosted.org` CDN suffix.)
const GO_PROXY_CDN_ALLOWLIST: &[&str] = &[];

/// Cap for the small GOPROXY metadata bodies (`@latest`, `.info`,
/// `.ziphash`, `.mod`). These are tiny; 16 MiB is generous headroom.
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct GoModuleRef {
    pub module_path: String,
    pub version: Option<String>,
}

impl GoModuleRef {
    /// Parse `<module-path>` or `<module-path>@<version>`.
    ///
    /// Go module paths never contain `@`, so splitting on `@` is
    /// unambiguous. We use the same `split_once('@')` pattern as
    /// `PypiPackageRef`/`CrateRef` for consistency.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty Go module spec");
        }
        let (path, version) = match spec.split_once('@') {
            Some((p, v)) => (p, Some(v)),
            None => (spec, None),
        };
        if path.is_empty() {
            bail!("empty Go module path: {spec}");
        }
        if let Some(v) = version {
            if v.is_empty() {
                bail!("empty version after `@`: {spec}");
            }
        }
        Ok(GoModuleRef {
            module_path: path.to_string(),
            version: version.map(str::to_string),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GoFetchOptions {
    pub registry: String,
    pub cache_dir: Option<PathBuf>,
    pub max_artifact_bytes: u64,
    pub max_extracted_bytes: u64,
}

impl Default for GoFetchOptions {
    fn default() -> Self {
        Self {
            registry: "https://proxy.golang.org".to_string(),
            cache_dir: None,
            max_artifact_bytes: 200 * 1024 * 1024,
            max_extracted_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Top-level entry. Resolves the version, downloads the module zip,
/// verifies the dirhash `h1:` against the proxy `.ziphash`, extracts, and
/// scans the Go sources.
pub fn fetch_and_scan_go(
    pkg: &GoModuleRef,
    opts: &GoFetchOptions,
    transport: &dyn Transport,
) -> Result<ScanReport> {
    let registry = opts.registry.trim_end_matches('/');
    let registry_host = host_of(registry)
        .with_context(|| format!("registry URL has no parseable host: {}", opts.registry))?;
    let esc_mod = escape_module_path(&pkg.module_path);

    // 1. Resolve version. Explicit version is used as-is; None hits @latest.
    let version = match &pkg.version {
        Some(v) => resolve_version(
            &GoModInfo {
                version: String::new(),
            },
            Some(v),
        )?,
        None => {
            let latest_url = format!("{registry}/{esc_mod}/@latest");
            let bytes = transport
                .get(&latest_url, MAX_METADATA_BYTES)
                .with_context(|| format!("fetch GOPROXY @latest {latest_url}"))?;
            let latest: GoModInfo = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse GOPROXY @latest {latest_url}"))?;
            resolve_version(&latest, None)?
        }
    };
    let esc_ver = escape_module_path(&version);

    // 2. Build + validate the zip and ziphash URLs (host allowlist).
    let zip_url = format!("{registry}/{esc_mod}/@v/{esc_ver}.zip");
    let ziphash_url = format!("{registry}/{esc_mod}/@v/{esc_ver}.ziphash");
    validate_artifact_url(&zip_url, &registry_host, GO_PROXY_CDN_ALLOWLIST)
        .with_context(|| format!("validate module zip URL {zip_url}"))?;
    validate_artifact_url(&ziphash_url, &registry_host, GO_PROXY_CDN_ALLOWLIST)
        .with_context(|| format!("validate ziphash URL {ziphash_url}"))?;

    // 3. Try to fetch the proxy-advertised checksum. The documented GOPROXY
    //    protocol only requires list/latest/info/mod/zip; `.ziphash` is NOT a
    //    mandated endpoint (Go authenticates the locally-computed hash via
    //    go.sum / the checksum database). A compliant proxy may therefore
    //    404 it. We must not abort the whole scan in that case — but we also
    //    never silently skip integrity (U-29): an absent/unparseable checksum
    //    becomes a visible `go-integrity-unverified` finding below. A
    //    checksum that IS advertised but does NOT match still hard-fails.
    let expected_h1: Option<String> = match transport.get(&ziphash_url, MAX_METADATA_BYTES) {
        Ok(bytes) => dirhash::parse_ziphash(&bytes).ok(),
        Err(_) => None,
    };

    // 4. Download the module zip.
    let zip_bytes = transport
        .get(&zip_url, opts.max_artifact_bytes)
        .with_context(|| format!("download module zip {zip_url}"))?;

    // 5. Safe-extract into memory (path/symlink/size guards) and recompute
    //    the dirhash over the exact bytes.
    let module = extract_module_zip(&zip_bytes, opts.max_extracted_bytes)
        .with_context(|| format!("safe-extract Go module zip {zip_url}"))?;
    let recomputed_h1 = dirhash::compute_h1(module.files());

    // 6. Scan the extracted sources.
    let mut scan_result = scan_extracted_module(&module);
    let mut all_findings: Vec<Finding> = std::mem::take(&mut scan_result.findings);

    // 6b. Integrity verdict. A present checksum that mismatches is a hard
    //     error (tamper). An absent/unparseable one is surfaced as an
    //     Info finding (in INFO_ONLY_RULES) so a quirky/private proxy does
    //     not break scanning while the unverified state stays visible.
    match &expected_h1 {
        Some(expected) => {
            dirhash::verify_h1(&recomputed_h1, expected).with_context(|| {
                format!(
                    "verify module checksum for {}@{version} ({} files)",
                    pkg.module_path,
                    module.files().len()
                )
            })?;
        }
        None => {
            all_findings.push(finding(
                "go-integrity-unverified",
                argus_core::Severity::Info,
                format!(
                    "GOPROXY served no usable .ziphash for {}@{version}; module bytes could not be authenticated against go.sum/the checksum database (recomputed {recomputed_h1})",
                    pkg.module_path
                ),
            ));
        }
    }

    // 7. Name-based rules (typosquatting) on the module path.
    rules::push_name_findings(&pkg.module_path, &mut all_findings);

    let decision = argus_rules::derive_decision_from_findings(&all_findings);

    Ok(ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: opts
            .cache_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("{}@{version}", pkg.module_path))),
        package_name: scan_result.name.or_else(|| Some(pkg.module_path.clone())),
        package_version: Some(version),
        decision,
        findings: all_findings,
    })
}

/// Build a Finding with the given rule_id/severity/detail and no location.
pub(crate) fn finding(rule: &str, sev: argus_core::Severity, detail: impl Into<String>) -> Finding {
    Finding::new(rule, sev, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain() {
        let p = GoModuleRef::parse("github.com/sirupsen/logrus").unwrap();
        assert_eq!(p.module_path, "github.com/sirupsen/logrus");
        assert_eq!(p.version, None);
    }

    #[test]
    fn parse_with_version() {
        let p = GoModuleRef::parse("github.com/sirupsen/logrus@v1.9.3").unwrap();
        assert_eq!(p.module_path, "github.com/sirupsen/logrus");
        assert_eq!(p.version.as_deref(), Some("v1.9.3"));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(GoModuleRef::parse("").is_err());
        assert!(GoModuleRef::parse("github.com/x@").is_err());
        assert!(GoModuleRef::parse("@v1.0.0").is_err());
    }

    #[test]
    fn validate_artifact_rejects_random_host() {
        assert!(validate_artifact_url(
            "https://evil.example.invalid/foo/@v/v1.0.0.zip",
            "proxy.golang.org",
            GO_PROXY_CDN_ALLOWLIST,
        )
        .is_err());
    }

    #[test]
    fn validate_artifact_accepts_registry_host() {
        validate_artifact_url(
            "https://proxy.golang.org/github.com/x/@v/v1.0.0.zip",
            "proxy.golang.org",
            GO_PROXY_CDN_ALLOWLIST,
        )
        .unwrap();
    }
}
