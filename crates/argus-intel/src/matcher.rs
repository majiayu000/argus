use crate::gem_version::GemVersion;
use crate::go_version::GoVersion;
use crate::maven_version::MavenVersion;
use crate::normalize::ecosystem_from_osv;
use crate::snapshot::{load_snapshot, SnapshotEnvelope, SnapshotEvent, SnapshotRange};
use anyhow::{bail, Context, Result};
use argus_core::{
    Ecosystem, Finding, IntelMatchStatus, IntelSnapshotStatus, PackageCoordinate, Severity,
};
use pep440_rs::Version as Pep440Version;
use semver::Version;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

pub const RULE_KNOWN_MALICIOUS: &str = "known-malicious-package";

#[derive(Debug, Clone)]
struct IndexedAffected {
    advisory_id: String,
    aliases: Vec<String>,
    exact_versions: Vec<String>,
    ranges: Vec<SnapshotRange>,
}

#[derive(Debug)]
pub struct IntelDatabase {
    snapshot: SnapshotEnvelope,
    index: BTreeMap<(Ecosystem, String), Vec<IndexedAffected>>,
}

#[derive(Debug)]
pub struct MatchResult {
    pub findings: Vec<Finding>,
    pub status: IntelMatchStatus,
}

impl IntelDatabase {
    pub fn load(path: &Path) -> Result<Self> {
        let snapshot = load_snapshot(path)?;
        let mut index = BTreeMap::<(Ecosystem, String), Vec<IndexedAffected>>::new();
        for record in &snapshot.records {
            if record.withdrawn.is_some() {
                continue;
            }
            for affected in &record.affected {
                let ecosystem = ecosystem_from_osv(&affected.ecosystem)
                    .ok_or_else(|| anyhow::anyhow!("verified snapshot ecosystem disappeared"))?;
                index
                    .entry((ecosystem, affected.canonical_name.clone()))
                    .or_default()
                    .push(IndexedAffected {
                        advisory_id: record.advisory_id.clone(),
                        aliases: record.aliases.clone(),
                        exact_versions: affected.exact_versions.clone(),
                        ranges: affected.ranges.clone(),
                    });
            }
        }
        for affected in index.values_mut() {
            affected.sort_by(|left, right| left.advisory_id.cmp(&right.advisory_id));
        }
        Ok(Self { snapshot, index })
    }

    pub fn match_coordinate(&self, coordinate: &PackageCoordinate) -> Result<MatchResult> {
        coordinate
            .validate()
            .context("validate package coordinate before intelligence matching")?;
        parse_version(coordinate.ecosystem, &coordinate.version)
            .context("validate scan coordinate version")?;
        let Some(candidates) = self
            .index
            .get(&(coordinate.ecosystem, coordinate.canonical_name.clone()))
        else {
            return Ok(MatchResult {
                findings: Vec::new(),
                status: IntelMatchStatus::NoMatch,
            });
        };
        let mut findings = Vec::new();
        for affected in candidates {
            if let Some(basis) = version_matches(
                coordinate.ecosystem,
                &coordinate.version,
                &affected.exact_versions,
                &affected.ranges,
            )? {
                let aliases = affected.aliases.join(",");
                let mut finding = Finding::new(
                    RULE_KNOWN_MALICIOUS,
                    Severity::Critical,
                    format!(
                        "OpenSSF advisory {} identifies {}@{} as malicious",
                        affected.advisory_id, coordinate.canonical_name, coordinate.version
                    ),
                );
                finding.evidence = Some(vec![
                    format!("advisory={}", affected.advisory_id),
                    format!("aliases={aliases}"),
                    format!("source_revision={}", self.snapshot.revision),
                    format!(
                        "coordinate={}::{}@{}",
                        coordinate.ecosystem.osv_name(),
                        coordinate.canonical_name,
                        coordinate.version
                    ),
                    format!(
                        "original_coordinate={}::{}@{}",
                        coordinate.original_ecosystem,
                        coordinate.original_name,
                        coordinate.original_version
                    ),
                    format!("match_basis={basis}"),
                ]);
                findings.push(finding);
            }
        }
        let status = if findings.is_empty() {
            IntelMatchStatus::NoMatch
        } else {
            IntelMatchStatus::Matched
        };
        Ok(MatchResult { findings, status })
    }

    pub fn status(
        &self,
        scan_started_at: chrono::DateTime<chrono::Utc>,
        status: IntelMatchStatus,
    ) -> Result<IntelSnapshotStatus> {
        Ok(IntelSnapshotStatus {
            source: self.snapshot.source.clone(),
            revision: self.snapshot.revision.clone(),
            imported_at: self.snapshot.imported_at,
            age_seconds: IntelSnapshotStatus::age_seconds(
                self.snapshot.imported_at,
                scan_started_at,
            )?,
            archive_sha256: self.snapshot.archive_sha256.clone(),
            records_sha256: self.snapshot.records_sha256.clone(),
            snapshot_sha256: self.snapshot.snapshot_sha256.clone(),
            status,
        })
    }

    pub fn snapshot(&self) -> &SnapshotEnvelope {
        &self.snapshot
    }
}

fn version_matches(
    ecosystem: Ecosystem,
    candidate: &str,
    exact_versions: &[String],
    ranges: &[SnapshotRange],
) -> Result<Option<String>> {
    for exact in exact_versions {
        if compare_versions(ecosystem, candidate, exact)? == Ordering::Equal {
            return Ok(Some(format!("exact:{exact}")));
        }
    }
    for range in ranges {
        let mut start: Option<&str> = None;
        for event in &range.events {
            if let Some(introduced) = event.introduced.as_deref() {
                start = Some(introduced);
                continue;
            }
            let introduced = start
                .take()
                .ok_or_else(|| anyhow::anyhow!("verified range lost introduced"))?;
            if interval_contains(ecosystem, candidate, introduced, event)? {
                return Ok(Some(interval_evidence(introduced, event)));
            }
        }
        if let Some(introduced) = start {
            if introduced == "0"
                || compare_versions(ecosystem, candidate, introduced)? != Ordering::Less
            {
                return Ok(Some(format!("range:[{introduced},infinity)")));
            }
        }
    }
    Ok(None)
}

fn interval_contains(
    ecosystem: Ecosystem,
    candidate: &str,
    introduced: &str,
    closing: &SnapshotEvent,
) -> Result<bool> {
    let after_start =
        introduced == "0" || compare_versions(ecosystem, candidate, introduced)? != Ordering::Less;
    let (end, inclusive) = if let Some(value) = closing.fixed.as_deref() {
        (value, false)
    } else if let Some(value) = closing.limit.as_deref() {
        (value, false)
    } else if let Some(value) = closing.last_affected.as_deref() {
        (value, true)
    } else {
        bail!("range closing event has no closing field");
    };
    let end_order = compare_versions(ecosystem, candidate, end)?;
    Ok(after_start && (end_order == Ordering::Less || (inclusive && end_order == Ordering::Equal)))
}

fn interval_evidence(introduced: &str, closing: &SnapshotEvent) -> String {
    if let Some(end) = &closing.fixed {
        format!("range:[{introduced},{end}) fixed")
    } else if let Some(end) = &closing.limit {
        format!("range:[{introduced},{end}) limit")
    } else {
        format!(
            "range:[{introduced},{}] last_affected",
            closing.last_affected.as_deref().unwrap_or("")
        )
    }
}

pub(crate) fn parse_version(ecosystem: Ecosystem, raw: &str) -> Result<()> {
    if raw.is_empty() || raw.chars().any(char::is_control) {
        bail!("package version is empty or contains control characters");
    }
    match ecosystem {
        Ecosystem::Npm | Ecosystem::CratesIo => {
            Version::parse(raw).with_context(|| format!("parse strict SemVer `{raw}`"))?;
        }
        Ecosystem::Go => drop(GoVersion::parse(raw)?),
        Ecosystem::PyPi => drop(parse_pep440(raw)?),
        Ecosystem::NuGet => drop(NugetVersion::parse(raw)?),
        Ecosystem::Maven => drop(MavenVersion::parse(raw)?),
        Ecosystem::RubyGems => drop(GemVersion::parse(raw)?),
        Ecosystem::Packagist => drop(ComposerVersion::parse(raw)?),
    }
    Ok(())
}

pub(crate) fn compare_versions(ecosystem: Ecosystem, left: &str, right: &str) -> Result<Ordering> {
    Ok(match ecosystem {
        Ecosystem::Npm | Ecosystem::CratesIo => Version::parse(left)?.cmp(&Version::parse(right)?),
        Ecosystem::Go => GoVersion::parse(left)?.cmp(&GoVersion::parse(right)?),
        Ecosystem::PyPi => parse_pep440(left)?.cmp(&parse_pep440(right)?),
        Ecosystem::NuGet => NugetVersion::parse(left)?.cmp(&NugetVersion::parse(right)?),
        Ecosystem::Maven => MavenVersion::parse(left)?.cmp(&MavenVersion::parse(right)?),
        Ecosystem::RubyGems => GemVersion::parse(left)?.cmp(&GemVersion::parse(right)?),
        Ecosystem::Packagist => ComposerVersion::parse(left)?.cmp(&ComposerVersion::parse(right)?),
    })
}

fn parse_pep440(raw: &str) -> Result<Pep440Version> {
    raw.parse::<Pep440Version>()
        .with_context(|| format!("parse PEP 440 version `{raw}`"))
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum Identifier {
    Numeric(u64),
    Text(String),
}

fn parse_identifiers(raw: &str) -> Result<Vec<Identifier>> {
    raw.split('.')
        .map(|part| {
            if part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                bail!("invalid version qualifier `{part}`");
            }
            Ok(part.parse::<u64>().map_or_else(
                |_| Identifier::Text(part.to_ascii_lowercase()),
                Identifier::Numeric,
            ))
        })
        .collect()
}

fn cmp_identifiers(left: &[Identifier], right: &[Identifier]) -> Ordering {
    for (a, b) in left.iter().zip(right) {
        let order = match (a, b) {
            (Identifier::Numeric(a), Identifier::Numeric(b)) => a.cmp(b),
            (Identifier::Numeric(_), Identifier::Text(_)) => Ordering::Less,
            (Identifier::Text(_), Identifier::Numeric(_)) => Ordering::Greater,
            (Identifier::Text(a), Identifier::Text(b)) => a.cmp(b),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

#[derive(Debug, Eq, PartialEq)]
struct NugetVersion {
    release: Vec<u64>,
    prerelease: Option<Vec<Identifier>>,
}

impl NugetVersion {
    fn parse(raw: &str) -> Result<Self> {
        let public = raw.split('+').next().unwrap_or(raw);
        let (release, prerelease) = public
            .split_once('-')
            .map_or((public, None), |(release, pre)| (release, Some(pre)));
        let release = release
            .split('.')
            .map(|part| part.parse::<u64>().context("parse NuGet numeric segment"))
            .collect::<Result<Vec<_>>>()?;
        if release.is_empty() || release.len() > 4 {
            bail!("NuGet version must have one to four numeric segments");
        }
        let prerelease = prerelease.map(parse_identifiers).transpose()?;
        if prerelease.as_ref().is_some_and(Vec::is_empty) {
            bail!("NuGet prerelease is empty");
        }
        Ok(Self {
            release,
            prerelease,
        })
    }
}

impl Ord for NugetVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_padded(&self.release, &other.release).then_with(|| {
            match (&self.prerelease, &other.prerelease) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(left), Some(right)) => cmp_identifiers(left, right),
            }
        })
    }
}

impl PartialOrd for NugetVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ComposerVersion {
    release: Vec<u64>,
    stability: (u8, u64),
}

impl ComposerVersion {
    fn parse(raw: &str) -> Result<Self> {
        let value = raw.trim().trim_start_matches('v').to_ascii_lowercase();
        if value.starts_with("dev-") || value.ends_with("-dev") {
            bail!("Composer branch/dev versions are not comparable in malicious ranges");
        }
        let public = value.split('+').next().unwrap_or(&value);
        let split = public
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(public.len());
        let release_raw = public[..split].trim_end_matches('.');
        if release_raw.is_empty() || release_raw.split('.').any(str::is_empty) {
            bail!("Composer version has invalid release segments");
        }
        let release = release_raw
            .split('.')
            .map(|part| {
                part.parse::<u64>()
                    .context("parse Composer release segment")
            })
            .collect::<Result<Vec<_>>>()?;
        if release.len() > 4 {
            bail!("Composer normalized version has more than four release segments");
        }
        let suffix = public[split..].trim_matches(['.', '-', '_']);
        let stability = if suffix.is_empty() {
            (5, 0)
        } else {
            let letters = suffix.bytes().take_while(u8::is_ascii_alphabetic).count();
            let label = &suffix[..letters];
            let number_raw = suffix[letters..].trim_matches(['.', '-', '_']);
            let number = if number_raw.is_empty() {
                0
            } else {
                number_raw
                    .parse::<u64>()
                    .context("parse Composer qualifier")?
            };
            let rank = match label {
                "dev" => 0,
                "alpha" | "a" => 1,
                "beta" | "b" => 2,
                "rc" => 3,
                "patch" | "pl" | "p" => 6,
                _ => bail!("unsupported Composer stability `{label}`"),
            };
            (rank, number)
        };
        Ok(Self { release, stability })
    }
}

impl Ord for ComposerVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_padded(&self.release, &other.release).then_with(|| self.stability.cmp(&other.stability))
    }
}

impl PartialOrd for ComposerVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn cmp_padded(left: &[u64], right: &[u64]) -> Ordering {
    let length = left.len().max(right.len());
    (0..length)
        .map(|index| {
            left.get(index)
                .copied()
                .unwrap_or(0)
                .cmp(&right.get(index).copied().unwrap_or(0))
        })
        .find(|order| *order != Ordering::Equal)
        .unwrap_or(Ordering::Equal)
}
