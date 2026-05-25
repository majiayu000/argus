//! Fetch an npm package by name (and optional version), verify its tarball
//! integrity, extract it under a scratch directory, and run argus-rules
//! against the extracted source.
//!
//! No lifecycle script ever runs: this crate does not call `npm`, `tar
//! --to-command`, or any post-extract hook.

use anyhow::{anyhow, bail, Context, Result};
use argus_core::url::{host_of, validate_artifact_url};
use argus_core::{Finding, ScanReport, Severity};
use sha2::{Digest, Sha512};
use std::path::PathBuf;

mod extract;
mod integrity;
mod packument;
mod provenance;
mod transport;

pub use extract::extract_tarball;
pub use integrity::{parse_ssri, verify_ssri};
pub use packument::{resolve_version, Packument};
pub use provenance::{check_subject_digest, parse_attestations, AttestationSummary, SubjectCheck};
pub use transport::{HttpTransport, Transport};

/// Cap for the packument JSON body. Real packuments are hundreds of KB; we
/// leave headroom for very-popular packages without letting a hostile server
/// stream gigabytes of JSON into RAM (review H-2).
const MAX_PACKUMENT_BYTES: u64 = 32 * 1024 * 1024;

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
    ///
    /// Rejects empty scope (`@/x`), empty name (`@scope/`), and empty version
    /// (`chalk@`). Without these checks, downstream lookups produce confusing
    /// "version `` not present" errors instead of saying what is actually
    /// wrong with the input.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty package spec");
        }
        // Scoped: `@scope/name[@version]`
        if let Some(rest) = spec.strip_prefix('@') {
            let slash = rest
                .find('/')
                .ok_or_else(|| anyhow!("scoped package missing `/`: {spec}"))?;
            let scope = &rest[..slash];
            if scope.is_empty() {
                bail!("scoped package has empty scope: {spec}");
            }
            let after_slash = &rest[slash + 1..];
            let (pkg_part, version) = split_version(after_slash);
            if pkg_part.is_empty() {
                bail!("scoped package has empty name: {spec}");
            }
            check_version(version)?;
            return Ok(PackageRef {
                name: format!("@{scope}/{pkg_part}"),
                version: version.map(str::to_string),
            });
        }
        let (name, version) = split_version(spec);
        if name.is_empty() {
            bail!("empty package name: {spec}");
        }
        check_version(version)?;
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

fn check_version(v: Option<&str>) -> Result<()> {
    if matches!(v, Some(s) if s.is_empty()) {
        bail!("package spec ends with `@` but version is empty");
    }
    Ok(())
}

/// Knobs for `fetch_and_scan`. Defaults match the SPEC §15 Phase 1 settings.
#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub registry: String,
    /// Optional persistent scratch parent. When `None`, every fetch uses a
    /// fresh private temp dir (mode 0700 on Unix), eliminating the multi-user
    /// race the review called out (M-3). Cache reuse arrives in M2.
    pub cache_dir: Option<PathBuf>,
    /// Hard cap on the downloaded tarball size in bytes. Default 100 MiB.
    pub max_tarball_bytes: u64,
    /// Hard cap on the total uncompressed extracted size. Default 500 MiB.
    pub max_extracted_bytes: u64,
    /// Additional hosts the tarball URL may resolve to. The registry host is
    /// always accepted; this list lets operators name CDN or storage hosts
    /// that legitimately serve tarballs for a custom registry. Empty by
    /// default — public npm tarballs live on the same host as the
    /// packument.
    pub tarball_host_allowlist: Vec<String>,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            registry: "https://registry.npmjs.org".to_string(),
            cache_dir: None,
            max_tarball_bytes: 100 * 1024 * 1024,
            max_extracted_bytes: 500 * 1024 * 1024,
            tarball_host_allowlist: Vec::new(),
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
    let registry_host = host_of(&opts.registry)
        .with_context(|| format!("registry URL has no parseable host: {}", opts.registry))?;
    let packument_url = format!(
        "{}/{}",
        opts.registry.trim_end_matches('/'),
        url_encode_pkg(&pkg.name)
    );
    let packument_bytes = transport
        .get(&packument_url, MAX_PACKUMENT_BYTES)
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

    // 3. Validate the tarball URL the registry handed us. The packument is
    //    attacker-influenceable (compromised registry, MITM, or a rogue
    //    mirror), so we refuse anything other than HTTPS on the same host as
    //    the registry. Operators with multi-host setups can extend this
    //    later; defaulting closed is the right behaviour for an MVP.
    validate_artifact_url(&dist.tarball, &registry_host, &opts.tarball_host_allowlist)?;

    // 4. Download tarball under a streaming cap.
    let tarball_bytes = transport
        .get(&dist.tarball, opts.max_tarball_bytes)
        .with_context(|| format!("download tarball {}", dist.tarball))?;

    // 5. Verify integrity (strongest declared algorithm only).
    verify_ssri(&tarball_bytes, &dist.integrity).with_context(|| {
        format!(
            "verify integrity of {} ({} bytes)",
            pkg.name,
            tarball_bytes.len()
        )
    })?;

    // 6. Extract into a fresh scratch dir. When `cache_dir` is set we honour
    //    it (for power users / persistent caches); otherwise we use a private
    //    system temp dir so two local users cannot race on `/tmp/argus`.
    let extract_root = match &opts.cache_dir {
        Some(parent) => {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create cache dir {}", parent.display()))?;
            tempfile::tempdir_in(parent).context("create extract scratch dir under cache_dir")?
        }
        None => tempfile::tempdir().context("create private extract scratch dir")?,
    };
    let pkg_dir = extract_tarball(
        &tarball_bytes,
        extract_root.path(),
        opts.max_extracted_bytes,
    )
    .context("safe-extract tarball")?;

    // 7. Scan with existing rules.
    let mut report = argus_rules::scan_package_dir(&pkg_dir).context("scan extracted package")?;

    // 8. Provenance cross-check. We compute the tarball SHA-512 (already
    //    proved equal to `dist.integrity` in step 5), fetch the attestations
    //    bundle if one is advertised, and verify that an attestation subject
    //    digest agrees with the bytes we hold. This catches a tampered
    //    packument where attestations point at the wrong artifact. Full
    //    Sigstore signature verification — catching forged attestations —
    //    is the M2 follow-up tracked in #10-followup.
    let tarball_sha512_hex = hex_sha512(&tarball_bytes);
    let provenance_findings = check_provenance(
        &dist.attestations,
        &tarball_sha512_hex,
        &registry_host,
        &opts.tarball_host_allowlist,
        transport,
    );
    report.findings.extend(provenance_findings);
    report.decision = argus_rules::derive_decision_from_findings(&report.findings);

    Ok(report)
}

fn hex_sha512(bytes: &[u8]) -> String {
    let digest = Sha512::digest(bytes);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Resolve the attestations URL (if any) and produce findings describing
/// the provenance state. Never returns an error: provenance is layered on
/// top of the existing decision, and a fetch failure becomes a finding,
/// not a hard error that hides the rest of the scan.
fn check_provenance(
    attestations: &Option<packument::AttestationsRef>,
    tarball_sha512_hex: &str,
    registry_host: &str,
    allowlist: &[String],
    transport: &dyn Transport,
) -> Vec<Finding> {
    let Some(att_ref) = attestations else {
        return vec![Finding::new(
            "missing-provenance",
            Severity::Info,
            "package was not published with `npm publish --provenance`; no OIDC attestation to cross-check",
        )];
    };

    // Same-host / HTTPS / allowlist guard as we apply to tarballs.
    if let Err(e) = validate_artifact_url(&att_ref.url, registry_host, allowlist) {
        return vec![Finding::new(
            "provenance-fetch-blocked",
            Severity::High,
            format!("attestations URL rejected by host/scheme guard: {e}"),
        )];
    }

    let bytes = match transport.get(&att_ref.url, MAX_PACKUMENT_BYTES) {
        Ok(b) => b,
        Err(e) => {
            return vec![Finding::new(
                "provenance-fetch-failed",
                Severity::High,
                format!("could not fetch attestations from {}: {e}", att_ref.url),
            )];
        }
    };

    let summaries = match parse_attestations(&bytes) {
        Ok(s) => s,
        Err(e) => {
            return vec![Finding::new(
                "provenance-parse-failed",
                Severity::High,
                format!("attestations document is unparseable: {e}"),
            )];
        }
    };

    match check_subject_digest(&summaries, tarball_sha512_hex) {
        SubjectCheck::Matched {
            subject_name,
            predicate_type,
            builder_id,
        } => {
            let detail = match builder_id {
                Some(b) => format!(
                    "OIDC attestation subject `{subject_name}` (`{predicate_type}`) matches the downloaded tarball; builder `{b}` — signature NOT cryptographically verified (see #10-followup)"
                ),
                None => format!(
                    "OIDC attestation subject `{subject_name}` (`{predicate_type}`) matches the downloaded tarball; signature NOT cryptographically verified (see #10-followup)"
                ),
            };
            vec![Finding::new("provenance-verified-subject", Severity::Info, detail)]
        }
        SubjectCheck::Mismatch { expected, actual_hex } => {
            vec![Finding::new(
                "provenance-subject-mismatch",
                Severity::Critical,
                format!(
                    "attestations claim digest(s) {expected:?} but downloaded tarball is sha512:{actual_hex} — packument or attestations have been tampered with"
                ),
            )]
        }
        SubjectCheck::NoSha512Subject => vec![Finding::new(
            "provenance-no-sha512-subject",
            Severity::Medium,
            "attestations were present but none carried a sha512 subject digest; nothing to cross-check",
        )],
    }
}

/// npm registry URL-encodes only the `/` in scoped names; everything else is
/// already path-safe. Keep it explicit so we don't ship a full URL encoder.
fn url_encode_pkg(name: &str) -> String {
    name.replace('/', "%2F")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain() {
        let p = PackageRef::parse("chalk").unwrap();
        assert_eq!(p.name, "chalk");
        assert_eq!(p.version, None);
    }

    #[test]
    fn parse_plain_with_version() {
        let p = PackageRef::parse("chalk@5.3.0").unwrap();
        assert_eq!(p.name, "chalk");
        assert_eq!(p.version.as_deref(), Some("5.3.0"));
    }

    #[test]
    fn parse_scoped_with_version() {
        let p = PackageRef::parse("@types/node@20.10.0").unwrap();
        assert_eq!(p.name, "@types/node");
        assert_eq!(p.version.as_deref(), Some("20.10.0"));
    }

    #[test]
    fn parse_rejects_empty_version() {
        assert!(PackageRef::parse("chalk@").is_err());
        assert!(PackageRef::parse("@types/node@").is_err());
    }

    #[test]
    fn parse_rejects_empty_scope_and_name() {
        assert!(PackageRef::parse("@/name").is_err());
        assert!(PackageRef::parse("@scope/").is_err());
        assert!(PackageRef::parse("@scope/@1.0").is_err()); // empty name before @
        assert!(PackageRef::parse("").is_err());
        assert!(PackageRef::parse("   ").is_err());
    }

}
