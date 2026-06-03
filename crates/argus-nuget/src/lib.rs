//! NuGet (.NET) ecosystem support for argus.
//!
//! A `.nupkg` is a ZIP archive (Open Packaging Conventions). argus fetches
//! it from the NuGet v3 **flat container**, scans the install/build trigger
//! surface, and reports.
//!
//! # Integrity (read this — U-29 disclosure)
//!
//! Unlike PyPI and crates.io, the standard NuGet v3 resolution path exposes
//! **no per-artifact content digest**. The flat-container `index.json`
//! returns only a versions array, and the registration leaf returns the
//! download URL + metadata but no hash. The SHA-512 `packageHash` lives
//! ONLY in the **catalog leaf**, a separate document reachable via the
//! registration leaf's `catalogEntry.@id`. argus follows that extra hop and
//! verifies the SHA-512 when available (the strong path). When the catalog
//! entry 404s or omits `packageHash`, argus does **not** fake a pass: it
//! emits an Info `nuget-integrity-unverifiable` finding and records the
//! reason in the report, so a clean verdict is never mistaken for a
//! content-verified one.
//!
//! # Known gaps (not stubbed — honestly absent)
//!
//! - **Author/repository signing** (the PKCS#7 `.signature.p7s` inside the
//!   `.nupkg`) is the real cryptographic integrity primitive. Verifying it
//!   needs a full CMS + X.509 chain validator and is OUT OF SCOPE. argus
//!   does NOT claim signature verification.
//! - **Compiled-DLL blind spot**: most real NuGet malware ships as a
//!   compiled managed assembly under `lib/`. argus treats DLLs as binary
//!   and does NOT decompile MSIL. argus detects the install/build *trigger*
//!   surface (`*.ps1` hooks, MSBuild `.targets`/`.props`) and text-file
//!   content rules — a clean scan does NOT mean the DLL is safe.
//! - **Version normalization** is partial (lowercase + strip `+build`);
//!   full NuGet version equivalence is not implemented.

use anyhow::{bail, Context, Result};
use argus_core::url::{host_of, validate_artifact_url};
use argus_core::{ArtifactKind, Finding, ScanReport, Severity};
use std::path::PathBuf;

mod metadata;
mod rules;
mod scan;

pub use argus_fetch::{HttpTransport, Transport};
pub use metadata::{
    normalize_version, resolve_version, verify_sha512_b64, CatalogLeaf, FlatContainerIndex,
    RegistrationLeaf,
};
pub use rules::POPULAR_NUGET_PACKAGES;
pub use scan::{scan_extracted_nupkg, scan_nuget_archive, NupkgScan};

/// The flat-container download host for nuget.org is the registry host
/// itself (`api.nuget.org/v3-flatcontainer/...`), and argus constructs that
/// URL locally, so the CDN allowlist is empty (tightest). Catalog leaf URLs
/// returned by the registry are validated against this same allowlist
/// before being fetched.
const NUGET_CDN_ALLOWLIST: &[&str] = &[];

/// Cap for NuGet JSON metadata bodies (index/registration/catalog).
const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct NugetRef {
    pub name: String,
    pub version: Option<String>,
}

impl NugetRef {
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty NuGet package spec");
        }
        let (name, version) = match spec.split_once('@') {
            Some((n, v)) => (n, Some(v)),
            None => (spec, None),
        };
        if name.is_empty() {
            bail!("empty NuGet package name: {spec}");
        }
        if let Some(v) = version {
            if v.is_empty() {
                bail!("empty version after `@`: {spec}");
            }
        }
        Ok(NugetRef {
            name: name.to_string(),
            version: version.map(str::to_string),
        })
    }
}

#[derive(Debug, Clone)]
pub struct NugetFetchOptions {
    pub registry: String,
    pub cache_dir: Option<PathBuf>,
    pub max_artifact_bytes: u64,
    pub max_extracted_bytes: u64,
}

impl Default for NugetFetchOptions {
    fn default() -> Self {
        Self {
            registry: "https://api.nuget.org".to_string(),
            cache_dir: None,
            max_artifact_bytes: 200 * 1024 * 1024,
            max_extracted_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Top-level entry: resolve version, download `.nupkg`, verify catalog
/// SHA-512 (best-effort, U-29-visible), safe-extract, scan.
pub fn fetch_and_scan_nuget(
    pkg: &NugetRef,
    opts: &NugetFetchOptions,
    transport: &dyn Transport,
) -> Result<ScanReport> {
    let registry = opts.registry.trim_end_matches('/');
    let registry_host = host_of(&opts.registry)
        .with_context(|| format!("registry URL has no parseable host: {}", opts.registry))?;
    let lower_id = pkg.name.to_ascii_lowercase();

    // 1. Flat-container index → versions.
    let index_url = format!("{registry}/v3-flatcontainer/{lower_id}/index.json");
    let index_bytes = transport
        .get(&index_url, MAX_METADATA_BYTES)
        .with_context(|| format!("fetch NuGet flat-container index {index_url}"))?;
    let index: FlatContainerIndex = serde_json::from_slice(&index_bytes)
        .with_context(|| format!("parse NuGet flat-container index {index_url}"))?;

    // 2. Resolve version.
    let version = resolve_version(&index, pkg.version.as_deref())
        .with_context(|| format!("resolve version for {}", pkg.name))?;
    let lower_version = normalize_version(&version);

    // 3. Construct + validate the download URL (predictable, built locally).
    let download_url = format!(
        "{registry}/v3-flatcontainer/{lower_id}/{lower_version}/{lower_id}.{lower_version}.nupkg"
    );
    validate_artifact_url(&download_url, &registry_host, NUGET_CDN_ALLOWLIST)?;

    // 4. Download the artifact bytes.
    let nupkg_bytes = transport
        .get(&download_url, opts.max_artifact_bytes)
        .with_context(|| format!("download .nupkg {download_url}"))?;

    // 5. Integrity (option A): follow registration → catalog → packageHash.
    //    On the strong path we verify SHA-512 and hard-error on mismatch.
    //    When the catalog hop is unavailable we emit a visible Info finding
    //    rather than faking a verified result (U-29).
    let mut findings: Vec<Finding> = Vec::new();
    match resolve_catalog_hash(
        registry,
        &registry_host,
        &lower_id,
        &lower_version,
        transport,
    ) {
        Ok(Some((hash_b64, algo))) => {
            if algo.eq_ignore_ascii_case("SHA512") {
                verify_sha512_b64(&nupkg_bytes, &hash_b64).with_context(|| {
                    format!(
                        "verify SHA-512 of {lower_id}.{lower_version}.nupkg ({} bytes)",
                        nupkg_bytes.len()
                    )
                })?;
            } else {
                findings.push(Finding::new(
                    "nuget-integrity-unverifiable",
                    Severity::Info,
                    format!(
                        "catalog packageHashAlgorithm `{algo}` is not SHA512; content digest not verified"
                    ),
                ));
            }
        }
        Ok(None) => {
            findings.push(Finding::new(
                "nuget-integrity-unverifiable",
                Severity::Info,
                "NuGet catalog entry did not advertise a packageHash; content digest not verified (transport TLS + host pin only)"
                    .to_string(),
            ));
        }
        Err(e) => {
            findings.push(Finding::new(
                "nuget-integrity-unverifiable",
                Severity::Info,
                format!(
                    "NuGet catalog hop unavailable ({e:#}); content digest not verified (transport TLS + host pin only)"
                ),
            ));
        }
    }

    // 6. Safe-extract + scan.
    let extract_root = match &opts.cache_dir {
        Some(parent) => {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create cache dir {}", parent.display()))?;
            tempfile::tempdir_in(parent).context("create extract scratch dir under cache_dir")?
        }
        None => tempfile::tempdir().context("create private extract scratch dir")?,
    };
    let scan = scan_nuget_archive(&nupkg_bytes, extract_root.path(), opts.max_extracted_bytes)
        .context("scan extracted .nupkg")?;
    findings.extend(scan.findings);

    // 7. Name-based rules on the user-supplied id.
    rules::push_name_findings(&pkg.name, &mut findings);

    let decision = argus_rules::derive_decision_from_findings(&findings);

    Ok(ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: extract_root.path().to_path_buf(),
        package_name: scan.name.or_else(|| Some(pkg.name.clone())),
        package_version: scan.version.or(Some(version)),
        decision,
        findings,
    })
}

/// Follow the registration leaf → `catalogEntry.@id` → catalog leaf and
/// return `(packageHash_b64, algorithm)` if present. Returns `Ok(None)`
/// when the catalog entry exists but omits `packageHash`. Any transport or
/// parse failure is an `Err` and is surfaced to the caller as an Info
/// finding — never silently swallowed (U-17 / U-29).
fn resolve_catalog_hash(
    registry: &str,
    registry_host: &str,
    lower_id: &str,
    lower_version: &str,
    transport: &dyn Transport,
) -> Result<Option<(String, String)>> {
    let registration_url =
        format!("{registry}/v3/registration5-gz-semver2/{lower_id}/{lower_version}.json");
    let reg_bytes = transport
        .get(&registration_url, MAX_METADATA_BYTES)
        .with_context(|| format!("fetch NuGet registration leaf {registration_url}"))?;
    let reg: RegistrationLeaf = serde_json::from_slice(&reg_bytes)
        .with_context(|| format!("parse NuGet registration leaf {registration_url}"))?;

    let catalog_url = reg.catalog_entry.id;
    // The catalog @id is registry-controlled; validate its host before fetch.
    validate_artifact_url(&catalog_url, registry_host, NUGET_CDN_ALLOWLIST)
        .with_context(|| format!("validate catalog entry URL {catalog_url}"))?;

    let catalog_bytes = transport
        .get(&catalog_url, MAX_METADATA_BYTES)
        .with_context(|| format!("fetch NuGet catalog leaf {catalog_url}"))?;
    let catalog: CatalogLeaf = serde_json::from_slice(&catalog_bytes)
        .with_context(|| format!("parse NuGet catalog leaf {catalog_url}"))?;

    match (catalog.package_hash, catalog.package_hash_algorithm) {
        (Some(h), Some(a)) if !h.trim().is_empty() => Ok(Some((h, a))),
        _ => Ok(None),
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
    fn parse_plain() {
        let p = NugetRef::parse("Newtonsoft.Json").unwrap();
        assert_eq!(p.name, "Newtonsoft.Json");
        assert_eq!(p.version, None);
    }

    #[test]
    fn parse_with_version() {
        let p = NugetRef::parse("Serilog@3.1.1").unwrap();
        assert_eq!(p.name, "Serilog");
        assert_eq!(p.version.as_deref(), Some("3.1.1"));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(NugetRef::parse("").is_err());
        assert!(NugetRef::parse("Serilog@").is_err());
        assert!(NugetRef::parse("@1.0").is_err());
    }

    #[test]
    fn validate_artifact_accepts_registry_host() {
        validate_artifact_url::<&str>(
            "https://api.nuget.org/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg",
            "api.nuget.org",
            NUGET_CDN_ALLOWLIST,
        )
        .unwrap();
    }

    #[test]
    fn validate_artifact_rejects_http() {
        assert!(validate_artifact_url::<&str>(
            "http://api.nuget.org/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg",
            "api.nuget.org",
            NUGET_CDN_ALLOWLIST,
        )
        .is_err());
    }

    #[test]
    fn validate_artifact_rejects_random_host() {
        assert!(validate_artifact_url::<&str>(
            "https://evil.example.invalid/foo.nupkg",
            "api.nuget.org",
            NUGET_CDN_ALLOWLIST,
        )
        .is_err());
    }
}
