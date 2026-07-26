use crate::snapshot::{load_snapshot, SnapshotEnvelope, SnapshotEvent, SnapshotRange};
use anyhow::{bail, Context, Result};
use argus_core::{
    Ecosystem, Finding, IntelMatchStatus, IntelSnapshotStatus, PackageCoordinate, Severity,
};
use argus_osv_schema::{compare_versions, ecosystem_from_osv, parse_version};
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
