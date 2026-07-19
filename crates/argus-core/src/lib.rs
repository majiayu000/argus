//! Core types for argus.
//!
//! A scan over a package directory or lockfile produces a [`ScanReport`].
//! Each report carries a list of [`Finding`]s and a derived [`Decision`].
//!
//! Shared URL + integrity helpers live in [`url`]; the per-artifact
//! intermediate scan shape lives in [`scan`].

pub mod scan;
pub mod url;

pub use scan::ArtifactScan;

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Final decision for a scanned artifact.
///
/// Per SPEC §10, an unknown high-risk artifact must require explicit
/// approval; only allowlisted patterns may downgrade a lifecycle-script
/// finding from `Block` to `AllowWithApproval`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Block,
    AllowWithApproval,
    Allow,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Block => "block",
            Decision::AllowWithApproval => "allow-with-approval",
            Decision::Allow => "allow",
        }
    }
}

/// Severity attached to a [`Finding`]. Used by report renderers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// One rule match against a scanned artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub detail: String,
    /// Path the finding was sourced from (relative to artifact root).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Declarative capability manifest entry for agent-surface scans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// Machine-readable evidence locations, usually `file:line`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<String>>,
    /// Statically resolved network host for `net_egress` capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_host: Option<String>,
}

impl Finding {
    pub fn new(rule_id: &str, severity: Severity, detail: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity,
            detail: detail.into(),
            location: None,
            capability: None,
            evidence: None,
            resolved_host: None,
        }
    }

    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    pub fn with_capability(
        mut self,
        capability: impl Into<String>,
        evidence: Vec<String>,
        resolved_host: Option<String>,
    ) -> Self {
        self.capability = Some(capability.into());
        if !evidence.is_empty() {
            self.evidence = Some(evidence);
        }
        self.resolved_host = resolved_host;
        self
    }
}

/// What kind of artifact was scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    PackageDir,
    Lockfile,
    /// Agent-facing surface: MCP configs, skills, hooks, instruction files.
    AgentSurface,
}

/// Package ecosystem names supported by the shared intelligence coordinate.
///
/// The serialized values intentionally match the exact OSV ecosystem strings.
/// Their capitalization and punctuation are not uniform, so every variant is
/// renamed explicitly rather than through a blanket serde casing rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "PyPI")]
    PyPi,
    #[serde(rename = "crates.io")]
    CratesIo,
    #[serde(rename = "Go")]
    Go,
    #[serde(rename = "NuGet")]
    NuGet,
    #[serde(rename = "Maven")]
    Maven,
    #[serde(rename = "RubyGems")]
    RubyGems,
    #[serde(rename = "Packagist")]
    Packagist,
}

impl Ecosystem {
    pub fn osv_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPi => "PyPI",
            Self::CratesIo => "crates.io",
            Self::Go => "Go",
            Self::NuGet => "NuGet",
            Self::Maven => "Maven",
            Self::RubyGems => "RubyGems",
            Self::Packagist => "Packagist",
        }
    }

    fn purl_type(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPi => "pypi",
            Self::CratesIo => "cargo",
            Self::Go => "golang",
            Self::NuGet => "nuget",
            Self::Maven => "maven",
            Self::RubyGems => "gem",
            Self::Packagist => "composer",
        }
    }
}

/// Registry-selected package identity, normalized without losing its display
/// values. The purl is derived from the canonical fields and is never used as
/// the source of identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageCoordinate {
    pub ecosystem: Ecosystem,
    pub canonical_name: String,
    pub version: String,
    pub purl: String,
    pub original_ecosystem: String,
    pub original_name: String,
    pub original_version: String,
}

impl PackageCoordinate {
    pub fn new(
        ecosystem: Ecosystem,
        original_name: impl Into<String>,
        original_version: impl Into<String>,
    ) -> Result<Self> {
        let original_name = original_name.into();
        let original_version = original_version.into();
        validate_coordinate_text("package version", &original_version)?;

        let canonical_name = canonicalize_package_name(ecosystem, &original_name)?;
        let purl = build_purl(ecosystem, &canonical_name, &original_version)?;

        let coordinate = Self {
            ecosystem,
            canonical_name,
            version: original_version.clone(),
            purl,
            original_ecosystem: ecosystem.osv_name().to_string(),
            original_name,
            original_version,
        };
        coordinate.validate()?;
        Ok(coordinate)
    }

    /// Revalidate a deserialized or directly constructed coordinate.
    ///
    /// `PackageCoordinate` remains a public report DTO, so callers may obtain
    /// one without [`PackageCoordinate::new`]. Consumers at a trust boundary
    /// must call this method before matching on its canonical fields.
    pub fn validate(&self) -> Result<()> {
        validate_coordinate_text("package version", &self.original_version)?;
        if self.original_ecosystem != self.ecosystem.osv_name() {
            bail!(
                "original ecosystem `{}` does not match `{}`",
                self.original_ecosystem,
                self.ecosystem.osv_name()
            );
        }
        let canonical_name =
            canonicalize_package_name(self.ecosystem, self.original_name.as_str())?;
        if self.canonical_name != canonical_name {
            bail!(
                "canonical package name `{}` does not match normalized original name `{canonical_name}`",
                self.canonical_name
            );
        }
        if self.version != self.original_version {
            bail!(
                "package version `{}` does not match original version `{}`",
                self.version,
                self.original_version
            );
        }
        let purl = build_purl(self.ecosystem, &canonical_name, &self.original_version)?;
        if self.purl != purl {
            bail!(
                "package purl `{}` does not match derived purl `{purl}`",
                self.purl
            );
        }
        Ok(())
    }
}

fn validate_coordinate_text(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{field} must not be empty");
    }
    if value.chars().any(char::is_control) {
        bail!("{field} must not contain control characters");
    }
    Ok(())
}

/// Validate and normalize an ecosystem package name through the same contract
/// used by [`PackageCoordinate::new`].
pub fn canonicalize_package_name(ecosystem: Ecosystem, name: &str) -> Result<String> {
    validate_coordinate_text("package name", name)?;
    match ecosystem {
        Ecosystem::Npm => {
            validate_ascii_package_name(ecosystem, name)?;
            if let Some(scoped) = name.strip_prefix('@') {
                let (scope, package) = scoped
                    .split_once('/')
                    .ok_or_else(|| anyhow::anyhow!("scoped npm name must contain `/`"))?;
                if scope.is_empty() || package.is_empty() || package.contains('/') {
                    bail!("scoped npm name must be `@scope/name` with exactly one `/`");
                }
                validate_ascii_name_component("npm scope", scope, "-._~")?;
                validate_ascii_name_component("npm package", package, "-._~")?;
            } else {
                if name.contains('/') {
                    bail!("unscoped npm name must not contain `/`");
                }
                validate_ascii_name_component("npm package", name, "-._~")?;
            }
            Ok(name.to_ascii_lowercase())
        }
        Ecosystem::CratesIo => {
            validate_ascii_package_name(ecosystem, name)?;
            validate_ascii_name_component("crates.io package", name, "-_")?;
            Ok(name.to_ascii_lowercase())
        }
        Ecosystem::NuGet => {
            validate_ascii_package_name(ecosystem, name)?;
            validate_ascii_name_component("NuGet package", name, "-._")?;
            Ok(name.to_ascii_lowercase())
        }
        Ecosystem::Packagist => {
            validate_ascii_package_name(ecosystem, name)?;
            let (vendor, package) = name
                .split_once('/')
                .ok_or_else(|| anyhow::anyhow!("Packagist name must be `vendor/package`"))?;
            if vendor.is_empty() || package.is_empty() || package.contains('/') {
                bail!("Packagist name must contain exactly one non-empty `/` separator");
            }
            validate_ascii_name_component("Packagist vendor", vendor, "-._")?;
            validate_ascii_name_component("Packagist package", package, "-._")?;
            Ok(name.to_ascii_lowercase())
        }
        Ecosystem::PyPi => {
            validate_ascii_package_name(ecosystem, name)?;
            if !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                bail!(
                    "PyPI package name must contain only ASCII letters, digits, `-`, `_`, or `.`"
                );
            }
            let first = name.as_bytes().first().copied();
            let last = name.as_bytes().last().copied();
            if !first.is_some_and(|byte| byte.is_ascii_alphanumeric())
                || !last.is_some_and(|byte| byte.is_ascii_alphanumeric())
            {
                bail!("PyPI package name must start and end with an ASCII letter or digit");
            }
            Ok(normalize_pep503_name(name))
        }
        Ecosystem::Maven => {
            let (group, artifact) = name
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("Maven name must be `group_id:artifact_id`"))?;
            if group.is_empty() || artifact.is_empty() || artifact.contains(':') {
                bail!("Maven name must contain exactly one non-empty `:` separator");
            }
            Ok(name.to_string())
        }
        Ecosystem::Go | Ecosystem::RubyGems => Ok(name.to_string()),
    }
}

fn validate_ascii_package_name(ecosystem: Ecosystem, name: &str) -> Result<()> {
    if !name.is_ascii() {
        bail!(
            "{} package name must contain ASCII characters only",
            ecosystem.osv_name()
        );
    }
    Ok(())
}

fn validate_ascii_name_component(field: &str, value: &str, punctuation: &str) -> Result<()> {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || punctuation.as_bytes().contains(&byte))
    {
        return Ok(());
    }
    bail!("{field} contains a character outside its ASCII package-name grammar")
}

fn normalize_pep503_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !separator {
                normalized.push('-');
                separator = true;
            }
        } else {
            normalized.extend(character.to_lowercase());
            separator = false;
        }
    }
    normalized
}

fn build_purl(ecosystem: Ecosystem, name: &str, version: &str) -> Result<String> {
    let (namespace, package_name) = match ecosystem {
        Ecosystem::Npm if name.starts_with('@') => {
            let (scope, package) = name
                .split_once('/')
                .ok_or_else(|| anyhow::anyhow!("scoped npm name must contain `/`"))?;
            if package.is_empty() || package.contains('/') {
                bail!("scoped npm name must contain exactly one non-empty package segment");
            }
            (Some(scope), package)
        }
        Ecosystem::Npm => {
            if name.contains('/') {
                bail!("unscoped npm name must not contain `/`");
            }
            (None, name)
        }
        Ecosystem::Maven => {
            let (group, artifact) = name
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("Maven name must be `group_id:artifact_id`"))?;
            if group.is_empty() || artifact.is_empty() || artifact.contains(':') {
                bail!("Maven name must contain exactly one non-empty `:` separator");
            }
            (Some(group), artifact)
        }
        Ecosystem::Go | Ecosystem::Packagist => match name.rsplit_once('/') {
            Some((namespace, package)) if !namespace.is_empty() && !package.is_empty() => {
                (Some(namespace), package)
            }
            _ if ecosystem == Ecosystem::Packagist => {
                bail!("Packagist name must be `vendor/package`")
            }
            _ => (None, name),
        },
        _ => (None, name),
    };

    let encoded_name = encode_purl_component(package_name);
    let encoded_version = encode_purl_component(version);
    let namespace = namespace
        .map(|value| {
            value
                .split('/')
                .map(encode_purl_component)
                .collect::<Vec<_>>()
                .join("/")
        })
        .filter(|value| !value.is_empty());

    Ok(match namespace {
        Some(namespace) => format!(
            "pkg:{}/{namespace}/{encoded_name}@{encoded_version}",
            ecosystem.purl_type()
        ),
        None => format!(
            "pkg:{}/{encoded_name}@{encoded_version}",
            ecosystem.purl_type()
        ),
    })
}

fn encode_purl_component(value: &str) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            write!(encoded, "%{byte:02X}").expect("writing a purl to String cannot fail");
        }
    }
    encoded
}

/// Whether the selected malicious-package snapshot matched the coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelMatchStatus {
    Matched,
    NoMatch,
}

/// Audit metadata for the exact malicious-package snapshot used by a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntelSnapshotStatus {
    pub source: String,
    pub revision: String,
    pub imported_at: DateTime<Utc>,
    pub age_seconds: u64,
    pub archive_sha256: String,
    pub records_sha256: String,
    pub snapshot_sha256: String,
    pub status: IntelMatchStatus,
}

impl IntelSnapshotStatus {
    /// Compute snapshot age once at scan start. A snapshot timestamp in the
    /// future is invalid input, not a zero-age fallback.
    pub fn age_seconds(imported_at: DateTime<Utc>, scan_started_at: DateTime<Utc>) -> Result<u64> {
        let seconds = scan_started_at
            .signed_duration_since(imported_at)
            .num_seconds();
        if seconds < 0 {
            bail!("snapshot imported_at {imported_at} is later than scan start {scan_started_at}");
        }
        Ok(seconds as u64)
    }
}

/// Final report after running all rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub artifact: ArtifactKind,
    pub path: PathBuf,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub decision: Decision,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinate: Option<PackageCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intelligence: Option<IntelSnapshotStatus>,
}

impl ScanReport {
    /// Return the unique set of rule ids that fired, in the order they appear.
    pub fn rule_ids(&self) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for f in &self.findings {
            if seen.insert(f.rule_id.clone()) {
                out.push(f.rule_id.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_serializes_kebab_case() {
        assert_eq!(
            serde_json::to_string(&Decision::AllowWithApproval).unwrap(),
            "\"allow-with-approval\""
        );
    }

    #[test]
    fn rule_ids_dedups_in_order() {
        let report = ScanReport {
            artifact: ArtifactKind::PackageDir,
            path: PathBuf::from("/tmp/x"),
            package_name: None,
            package_version: None,
            decision: Decision::Block,
            findings: vec![
                Finding::new("lifecycle-script", Severity::High, "preinstall"),
                Finding::new("remote-download", Severity::High, "curl"),
                Finding::new("lifecycle-script", Severity::High, "postinstall"),
            ],
            coordinate: None,
            intelligence: None,
        };
        assert_eq!(
            report.rule_ids(),
            vec!["lifecycle-script", "remote-download"]
        );
    }

    #[test]
    fn coordinate_matrix() {
        let cases = [
            (
                Ecosystem::Npm,
                "@Scope/Demo",
                "@scope/demo",
                "pkg:npm/%40scope/demo@1.2.3",
                "\"npm\"",
            ),
            (
                Ecosystem::PyPi,
                "Demo_pkg.Name",
                "demo-pkg-name",
                "pkg:pypi/demo-pkg-name@1.2.3",
                "\"PyPI\"",
            ),
            (
                Ecosystem::CratesIo,
                "Demo_Pkg",
                "demo_pkg",
                "pkg:cargo/demo_pkg@1.2.3",
                "\"crates.io\"",
            ),
            (
                Ecosystem::Go,
                "github.com/Owner/Repo",
                "github.com/Owner/Repo",
                "pkg:golang/github.com/Owner/Repo@v1.2.3",
                "\"Go\"",
            ),
            (
                Ecosystem::NuGet,
                "Clean.Pkg",
                "clean.pkg",
                "pkg:nuget/clean.pkg@1.2.3",
                "\"NuGet\"",
            ),
            (
                Ecosystem::Maven,
                "Com.Example:Demo",
                "Com.Example:Demo",
                "pkg:maven/Com.Example/Demo@1.2.3",
                "\"Maven\"",
            ),
            (
                Ecosystem::RubyGems,
                "Demo_Gem",
                "Demo_Gem",
                "pkg:gem/Demo_Gem@1.2.3",
                "\"RubyGems\"",
            ),
            (
                Ecosystem::Packagist,
                "Vendor/Package",
                "vendor/package",
                "pkg:composer/vendor/package@1.2.3",
                "\"Packagist\"",
            ),
        ];

        for (ecosystem, original_name, canonical_name, expected_purl, serialized) in cases {
            let version = if ecosystem == Ecosystem::Go {
                "v1.2.3"
            } else {
                "1.2.3"
            };
            let coordinate =
                PackageCoordinate::new(ecosystem, original_name, version).expect("coordinate");
            assert_eq!(coordinate.canonical_name, canonical_name);
            assert_eq!(coordinate.version, version);
            assert_eq!(coordinate.purl, expected_purl);
            assert_eq!(coordinate.original_ecosystem, ecosystem.osv_name());
            assert_eq!(coordinate.original_name, original_name);
            assert_eq!(coordinate.original_version, version);
            assert_eq!(serde_json::to_string(&ecosystem).unwrap(), serialized);
        }

        let crate_dash = PackageCoordinate::new(Ecosystem::CratesIo, "demo-pkg", "1.0.0").unwrap();
        let crate_underscore =
            PackageCoordinate::new(Ecosystem::CratesIo, "demo_pkg", "1.0.0").unwrap();
        assert_ne!(crate_dash, crate_underscore);

        let npm = PackageCoordinate::new(Ecosystem::Npm, "demo", "1.0.0").unwrap();
        let pypi = PackageCoordinate::new(Ecosystem::PyPi, "demo", "1.0.0").unwrap();
        assert_ne!(npm, pypi, "cross-ecosystem names must never merge");

        assert!(PackageCoordinate::new(Ecosystem::Npm, "", "1.0.0").is_err());
        assert!(PackageCoordinate::new(Ecosystem::Npm, "demo", "").is_err());
        assert!(PackageCoordinate::new(Ecosystem::Npm, "de\u{0}mo", "1.0.0").is_err());
        assert!(PackageCoordinate::new(Ecosystem::Npm, "demo", "1.0\n.0").is_err());
        assert!(canonicalize_package_name(Ecosystem::Npm, "démø").is_err());
        assert!(canonicalize_package_name(Ecosystem::CratesIo, "craté").is_err());
        assert!(canonicalize_package_name(Ecosystem::NuGet, "NúGet.Package").is_err());
        assert!(canonicalize_package_name(Ecosystem::PyPi, "pÿpi").is_err());
        assert!(canonicalize_package_name(Ecosystem::Npm, "@scope/name/extra").is_err());
        assert!(canonicalize_package_name(Ecosystem::Maven, "group:artifact:extra").is_err());
        assert!(canonicalize_package_name(Ecosystem::Packagist, "vendor/package/extra").is_err());

        let mut inconsistent =
            PackageCoordinate::new(Ecosystem::Npm, "@scope/demo", "1.0.0").unwrap();
        inconsistent.canonical_name = "@scope/other".to_string();
        assert!(inconsistent.validate().is_err());
        inconsistent.canonical_name = "@scope/demo".to_string();
        inconsistent.purl = "pkg:npm/%40scope/other@1.0.0".to_string();
        assert!(inconsistent.validate().is_err());
    }

    #[test]
    fn intelligence_status() {
        use chrono::TimeZone as _;

        let imported_at = Utc.with_ymd_and_hms(2026, 7, 19, 1, 2, 3).single().unwrap();
        let scan_started_at = Utc.with_ymd_and_hms(2026, 7, 19, 1, 4, 8).single().unwrap();
        let age_seconds = IntelSnapshotStatus::age_seconds(imported_at, scan_started_at).unwrap();
        assert_eq!(age_seconds, 125);
        assert_eq!(
            IntelSnapshotStatus::age_seconds(imported_at, imported_at).unwrap(),
            0
        );
        assert!(IntelSnapshotStatus::age_seconds(scan_started_at, imported_at).is_err());

        let status = IntelSnapshotStatus {
            source: "https://github.com/ossf/malicious-packages".to_string(),
            revision: "a".repeat(40),
            imported_at,
            age_seconds,
            archive_sha256: "b".repeat(64),
            records_sha256: "c".repeat(64),
            snapshot_sha256: "d".repeat(64),
            status: IntelMatchStatus::NoMatch,
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["status"], "no_match");
        assert_eq!(json["age_seconds"], 125);

        let report = ScanReport {
            artifact: ArtifactKind::PackageDir,
            path: PathBuf::from("/tmp/demo"),
            package_name: Some("demo".to_string()),
            package_version: Some("1.0.0".to_string()),
            decision: Decision::Allow,
            findings: Vec::new(),
            coordinate: None,
            intelligence: None,
        };
        let report_json = serde_json::to_value(report).unwrap();
        assert!(report_json.get("coordinate").is_none());
        assert!(report_json.get("intelligence").is_none());
    }
}
