//! PyPI ecosystem support for argus.
//!
//! Mirrors the shape of `argus-fetch` but for the Python Package Index.
//! Crucial semantic differences from npm:
//!
//! - **sdist** (`.tar.gz` containing `setup.py`) executes Python code on
//!   `pip install`. This is the strongest analog to npm's `postinstall`.
//! - **wheel** (`.whl`, a ZIP archive) does not execute on install but
//!   runs Python at import time. The risk surface there is `__init__.py`
//!   and any top-level `*.py` file the consumer imports.
//! - Integrity is SHA-256 (hex) over the artifact bytes, advertised in
//!   the JSON API's `digests.sha256` field. MD5 is also present; we
//!   explicitly refuse it as weak.
//!
//! No Python code is ever executed by argus. The scanner treats every
//! file as opaque text or bytes.

use anyhow::{anyhow, bail, Context, Result};
use argus_core::url::{host_of, validate_artifact_url, verify_sha256_hex};
use argus_core::{
    canonicalize_package_name, Ecosystem, Finding, PackageCoordinate, ScanReport, Severity,
};
use std::path::{Path, PathBuf};

mod metadata;
mod rules;
mod sdist;
mod wheel;

pub use argus_core::ArtifactScan;
pub use argus_transport::{HttpTransport, Transport};
pub use metadata::{resolve_version, PypiPackument, PypiUrl};

/// PyPI serves package files from `*.pythonhosted.org` (canonically
/// `files.pythonhosted.org`), not from `pypi.org`. The subdomain-suffix
/// entry accepts every legitimate Warehouse CDN host.
const PYPI_CDN_ALLOWLIST: &[&str] = &[".pythonhosted.org"];
pub use sdist::{
    scan_extracted_sdist, scan_extracted_sdist_with_rules,
    scan_extracted_sdist_with_rules_and_context, scan_sdist_dir, scan_sdist_dir_with_rules,
    scan_sdist_dir_with_rules_and_context,
};
pub use wheel::{scan_wheel_zip, scan_wheel_zip_with_rules, scan_wheel_zip_with_rules_and_context};

/// Cap for the PyPI JSON packument body. Real PyPI packuments are large
/// (Django ships ~5 MB of versions/releases history), so we allow a bit
/// more headroom than npm.
const MAX_PACKUMENT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferredFormat {
    Sdist,
    Wheel,
    Both,
}

#[derive(Debug, Clone)]
pub struct PypiPackageRef {
    pub name: String,
    pub version: Option<String>,
}

impl PypiPackageRef {
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty PyPI package spec");
        }
        let (name, version) = match spec.split_once('@') {
            Some((n, v)) => (n, Some(v)),
            None => (spec, None),
        };
        if name.is_empty() {
            bail!("empty PyPI package name: {spec}");
        }
        if let Some(v) = version {
            if v.is_empty() {
                bail!("empty version after `@`: {spec}");
            }
        }
        Ok(PypiPackageRef {
            name: name.to_string(),
            version: version.map(str::to_string),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PypiFetchOptions {
    pub registry: String,
    pub cache_dir: Option<PathBuf>,
    pub max_artifact_bytes: u64,
    pub max_extracted_bytes: u64,
    pub prefer: PreferredFormat,
}

impl Default for PypiFetchOptions {
    fn default() -> Self {
        Self {
            registry: "https://pypi.org".to_string(),
            cache_dir: None,
            max_artifact_bytes: 200 * 1024 * 1024,
            max_extracted_bytes: 1024 * 1024 * 1024,
            prefer: PreferredFormat::Both,
        }
    }
}

/// Top-level entry. Resolves the version, picks one or both artifact
/// formats per `opts.prefer`, downloads + verifies + extracts each, and
/// returns one merged `ScanReport`.
pub fn fetch_and_scan_pypi(
    pkg: &PypiPackageRef,
    opts: &PypiFetchOptions,
    transport: &dyn Transport,
) -> Result<ScanReport> {
    let rules = argus_rules::RuleSession::builtin()?;
    fetch_and_scan_pypi_with_rules(pkg, opts, transport, &rules)
}

pub fn fetch_and_scan_pypi_with_rules(
    pkg: &PypiPackageRef,
    opts: &PypiFetchOptions,
    transport: &dyn Transport,
    rules: &argus_rules::RuleSession,
) -> Result<ScanReport> {
    let execution = argus_core::ExecutionContext::serial()?;
    fetch_and_scan_pypi_with_rules_and_context(pkg, opts, transport, rules, &execution)
}

pub fn fetch_and_scan_pypi_with_rules_and_context(
    pkg: &PypiPackageRef,
    opts: &PypiFetchOptions,
    transport: &dyn Transport,
    rules: &argus_rules::RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<ScanReport> {
    // 1. Fetch packument.
    let registry_host = host_of(&opts.registry)
        .with_context(|| format!("registry URL has no parseable host: {}", opts.registry))?;
    let packument_url = format!(
        "{}/pypi/{}/json",
        opts.registry.trim_end_matches('/'),
        pkg.name
    );
    let bytes = transport
        .get(&packument_url, MAX_PACKUMENT_BYTES)
        .with_context(|| format!("fetch PyPI packument {packument_url}"))?;
    let packument: PypiPackument = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse PyPI packument {packument_url}"))?;
    let requested_name = canonicalize_package_name(Ecosystem::PyPi, &pkg.name)
        .context("normalize requested PyPI package name")?;
    let registry_name = canonicalize_package_name(Ecosystem::PyPi, &packument.info.name)
        .context("normalize PyPI registry metadata package name")?;
    if requested_name != registry_name {
        bail!(
            "PyPI registry package identity mismatch: requested `{}` but metadata names `{}`",
            pkg.name,
            packument.info.name
        );
    }

    // 2. Resolve version.
    let version = resolve_version(&packument, pkg.version.as_deref())
        .with_context(|| format!("resolve version for {}", pkg.name))?;
    let coordinate = PackageCoordinate::new(
        Ecosystem::PyPi,
        packument.info.name.clone(),
        version.clone(),
    )
    .context("normalize PyPI registry coordinate")?;
    let urls = packument.releases.get(&version).ok_or_else(|| {
        anyhow!(
            "version `{version}` not present in PyPI packument for {}",
            pkg.name
        )
    })?;
    if urls.is_empty() {
        bail!(
            "version `{version}` has no published artifacts on PyPI for {}",
            pkg.name
        );
    }

    // 3. Pick artifact(s) per preference.
    let mut artifacts: Vec<&PypiUrl> = Vec::new();
    let sdist = urls.iter().find(|u| u.packagetype == "sdist");
    let wheel = urls.iter().find(|u| u.packagetype == "bdist_wheel");
    match opts.prefer {
        PreferredFormat::Sdist => {
            if let Some(s) = sdist {
                artifacts.push(s);
            }
        }
        PreferredFormat::Wheel => {
            if let Some(w) = wheel {
                artifacts.push(w);
            }
        }
        PreferredFormat::Both => {
            if let Some(s) = sdist {
                artifacts.push(s);
            }
            if let Some(w) = wheel {
                artifacts.push(w);
            }
        }
    }
    if artifacts.is_empty() {
        bail!(
            "no {:?} artifact for {}@{version} on PyPI",
            opts.prefer,
            pkg.name
        );
    }

    // 4. Set up the scratch dir once. Each artifact gets its own subdir.
    let extract_root = match &opts.cache_dir {
        Some(parent) => {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create cache dir {}", parent.display()))?;
            tempfile::tempdir_in(parent).context("create extract scratch dir under cache_dir")?
        }
        None => tempfile::tempdir().context("create private extract scratch dir")?,
    };

    // 5. For each artifact: validate URL, download, verify SHA-256, extract, scan.
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut last_name: Option<String> = None;
    let mut last_version: Option<String> = None;
    let mut external_budget = argus_rules::ExternalScanBudget::default();
    for (index, art) in artifacts.iter().enumerate() {
        validate_artifact_filename(&art.filename)
            .with_context(|| format!("invalid PyPI artifact filename {:?}", art.filename))?;
        validate_artifact_url(&art.url, &registry_host, PYPI_CDN_ALLOWLIST)?;
        let artifact_kind = match art.packagetype.as_str() {
            "sdist" => "sdist",
            "bdist_wheel" => "wheel",
            other => bail!("unsupported PyPI packagetype: {other}"),
        };
        let bytes = transport
            .get_redirect_checked(&art.url, opts.max_artifact_bytes, &|u| {
                validate_artifact_url(u, &registry_host, PYPI_CDN_ALLOWLIST)
            })
            .with_context(|| format!("download artifact {}", art.url))?;
        verify_sha256_hex(&bytes, &art.digests.sha256).with_context(|| {
            format!("verify SHA-256 of {} ({} bytes)", art.filename, bytes.len())
        })?;

        let art_dir = extract_root
            .path()
            .join(format!("artifact-{index}-{artifact_kind}"));
        std::fs::create_dir_all(&art_dir)
            .with_context(|| format!("mkdir {}", art_dir.display()))?;
        let (findings, name, version_str) = match artifact_kind {
            "sdist" => {
                let report = sdist::scan_sdist_dir_with_rules_budget_and_context(
                    &bytes,
                    &art_dir,
                    opts.max_extracted_bytes,
                    rules,
                    execution,
                    &mut external_budget,
                )
                .with_context(|| format!("scan sdist {}", art.filename))?;
                (report.findings, report.name, report.version)
            }
            "wheel" => {
                let report = wheel::scan_wheel_zip_with_rules_budget_and_context(
                    &bytes,
                    &art_dir,
                    opts.max_extracted_bytes,
                    rules,
                    execution,
                    &mut external_budget,
                )
                .with_context(|| format!("scan wheel {}", art.filename))?;
                (report.findings, report.name, report.version)
            }
            _ => unreachable!("artifact_kind is normalized above"),
        };
        all_findings.extend(findings);
        if name.is_some() {
            last_name = name;
        }
        if version_str.is_some() {
            last_version = version_str;
        }
    }

    // 6. Run name-based rules (typosquatting) on the package name itself.
    rules.push_typosquat_findings(Ecosystem::PyPi, &pkg.name, "PyPI name", &mut all_findings)?;

    let decision = argus_rules::derive_decision_from_findings(&all_findings);

    let mut report = ScanReport {
        artifact: argus_core::ArtifactKind::PackageDir,
        // Registry coordinate, never the random extraction TempDir: the
        // path feeds text/JSON/SARIF output and fingerprints (see the
        // matching invariant in argus-fetch).
        path: PathBuf::from(format!("{}@{version}", coordinate.canonical_name)),
        package_name: last_name.or_else(|| Some(pkg.name.clone())),
        package_version: last_version.or(Some(version)),
        decision,
        findings: all_findings,
        coordinate: Some(coordinate),
        intelligence: None,
        rules: None,
    };
    rules.validate_external_limits(&report.findings)?;
    rules.finalize_package(&mut report);
    Ok(report)
}

fn validate_artifact_filename(filename: &str) -> Result<()> {
    if filename.is_empty() {
        bail!("empty filename");
    }
    if filename.contains('/') || filename.contains('\\') {
        bail!("filename must not contain path separators");
    }
    if filename == "." || filename == ".." {
        bail!("filename must not be `.` or `..`");
    }
    if Path::new(filename).is_absolute() {
        bail!("absolute filename");
    }
    Ok(())
}

/// Build a Finding with the given rule_id/severity/detail and no location.
pub(crate) fn finding(rule: &str, sev: Severity, detail: impl Into<String>) -> Finding {
    Finding::new(rule, sev, detail)
}

/// [`argus_pipeline::EcosystemFetcher`] entry point for PyPI.
pub struct PypiFetcher;

impl argus_pipeline::EcosystemFetcher for PypiFetcher {
    fn ecosystem(&self) -> argus_core::Ecosystem {
        argus_core::Ecosystem::PyPi
    }

    fn default_registry(&self) -> &'static str {
        "https://pypi.org"
    }

    fn fetch_and_scan(
        &self,
        spec: &str,
        opts: &argus_pipeline::CommonFetchOptions,
        transport: &dyn Transport,
        rules: &argus_rules::RuleSession,
    ) -> anyhow::Result<argus_core::ScanReport> {
        let execution = argus_core::ExecutionContext::serial()?;
        self.fetch_and_scan_with_context(spec, opts, transport, rules, &execution)
    }

    fn fetch_and_scan_with_context(
        &self,
        spec: &str,
        opts: &argus_pipeline::CommonFetchOptions,
        transport: &dyn Transport,
        rules: &argus_rules::RuleSession,
        execution: &argus_core::ExecutionContext,
    ) -> anyhow::Result<argus_core::ScanReport> {
        let pkg = PypiPackageRef::parse(spec)?;
        let opts = PypiFetchOptions {
            registry: opts.registry.clone(),
            cache_dir: opts.cache_dir.clone(),
            ..PypiFetchOptions::default()
        };
        fetch_and_scan_pypi_with_rules_and_context(&pkg, &opts, transport, rules, execution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain() {
        let p = PypiPackageRef::parse("requests").unwrap();
        assert_eq!(p.name, "requests");
        assert_eq!(p.version, None);
    }

    #[test]
    fn parse_with_version() {
        let p = PypiPackageRef::parse("django@5.0.0").unwrap();
        assert_eq!(p.name, "django");
        assert_eq!(p.version.as_deref(), Some("5.0.0"));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(PypiPackageRef::parse("").is_err());
        assert!(PypiPackageRef::parse("requests@").is_err());
        assert!(PypiPackageRef::parse("@1.0").is_err());
    }

    #[test]
    fn validate_artifact_accepts_pythonhosted() {
        validate_artifact_url(
            "https://files.pythonhosted.org/packages/foo/bar.tar.gz",
            "pypi.org",
            PYPI_CDN_ALLOWLIST,
        )
        .unwrap();
    }

    #[test]
    fn validate_artifact_rejects_http() {
        assert!(validate_artifact_url(
            "http://files.pythonhosted.org/foo.tar.gz",
            "pypi.org",
            PYPI_CDN_ALLOWLIST,
        )
        .is_err());
    }

    #[test]
    fn validate_artifact_rejects_random_host() {
        assert!(validate_artifact_url(
            "https://evil.example.invalid/foo.tar.gz",
            "pypi.org",
            PYPI_CDN_ALLOWLIST,
        )
        .is_err());
    }

    #[test]
    fn validate_artifact_filename_rejects_paths() {
        assert!(validate_artifact_filename("../evil.tar.gz").is_err());
        assert!(validate_artifact_filename("/tmp/evil.tar.gz").is_err());
        assert!(validate_artifact_filename("nested/evil.tar.gz").is_err());
        assert!(validate_artifact_filename("nested\\evil.tar.gz").is_err());
        assert!(validate_artifact_filename(".").is_err());
        assert!(validate_artifact_filename("..").is_err());
    }

    #[test]
    fn validate_artifact_filename_accepts_basename() {
        assert!(validate_artifact_filename("demo-1.0.0.tar.gz").is_ok());
        assert!(validate_artifact_filename("demo-1.0.0-py3-none-any.whl").is_ok());
    }
}
