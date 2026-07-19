use crate::model::{NormalizedAdvisory, OsvError, OsvErrorKind};
use crate::resolver::ResolvedSnapshot;
use crate::severity::SeverityLevel;
use argus_core::{
    Decision, Finding, Severity, VulnerabilityAdvisoryEvidence, VulnerabilityQueryEvidence,
    VulnerabilityQueryStatus, VulnerabilitySourceMode, VULNERABILITY_QUERY_EVIDENCE_VERSION,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use std::collections::BTreeSet;

pub const MAX_REPORT_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityReport {
    pub decision: Decision,
    pub findings: Vec<Finding>,
    pub evidence: VulnerabilityQueryEvidence,
    pub advisories: Vec<NormalizedAdvisory>,
}

pub trait ReportBuilder {
    fn build(&self, snapshot: &ResolvedSnapshot) -> Result<VulnerabilityReport, OsvError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OsvReportBuilder {
    fail_on_severity: Option<SeverityLevel>,
}

impl OsvReportBuilder {
    pub fn new(fail_on_severity: Option<SeverityLevel>) -> Result<Self, OsvError> {
        if fail_on_severity
            .is_some_and(|level| matches!(level, SeverityLevel::Unknown | SeverityLevel::None))
        {
            return Err(OsvError::new(
                OsvErrorKind::InvalidInput,
                "fail_on_severity must be low, medium, high, or critical",
            ));
        }
        Ok(Self { fail_on_severity })
    }
}

impl ReportBuilder for OsvReportBuilder {
    fn build(&self, snapshot: &ResolvedSnapshot) -> Result<VulnerabilityReport, OsvError> {
        validate_resolved_snapshot(snapshot)?;
        let mut advisories = snapshot
            .results
            .iter()
            .flat_map(|result| result.advisories.iter().cloned())
            .collect::<Vec<_>>();
        advisories.sort_by(|left, right| {
            (&left.coordinate, &left.primary_id).cmp(&(&right.coordinate, &right.primary_id))
        });
        let mut findings =
            Vec::with_capacity(advisories.len() + usize::from(snapshot.authorized_stale));
        let mut evidence = Vec::with_capacity(advisories.len());
        let mut blocked = false;
        for advisory in &advisories {
            let is_blocking = self
                .fail_on_severity
                .is_some_and(|threshold| advisory.severity.level >= threshold);
            blocked |= is_blocking;
            let mut finding = Finding::new(
                "known-vulnerability",
                if is_blocking {
                    Severity::High
                } else {
                    Severity::Medium
                },
                format!(
                    "{} affects {} at exact version {}; OSV severity is {}",
                    advisory.primary_id,
                    advisory.coordinate.canonical_name,
                    advisory.coordinate.version,
                    normalized_level_name(advisory.severity.level)
                ),
            );
            if !advisory.evidence.locators.is_empty() {
                finding.evidence = Some(advisory.evidence.locators.clone());
            }
            findings.push(finding);
            evidence.push(advisory_evidence(advisory)?);
        }
        if snapshot.authorized_stale {
            findings.push(Finding::new(
                "vulnerability-data-stale",
                Severity::Medium,
                "complete vulnerability result uses explicitly authorized stale cache data",
            ));
        }
        let (oldest_fetched_at, newest_fetched_at, maximum_age_seconds) = freshness(snapshot)?;
        let status = if snapshot.authorized_stale {
            VulnerabilityQueryStatus::CompleteStale
        } else if advisories.is_empty() {
            VulnerabilityQueryStatus::CompleteNoMatch
        } else {
            VulnerabilityQueryStatus::CompleteWithFindings
        };
        let report = VulnerabilityReport {
            decision: if blocked {
                Decision::Block
            } else if findings.is_empty() {
                Decision::Allow
            } else {
                Decision::AllowWithApproval
            },
            findings,
            evidence: VulnerabilityQueryEvidence {
                version: VULNERABILITY_QUERY_EVIDENCE_VERSION,
                status,
                source_mode: snapshot.source_mode,
                queried_coordinates: snapshot.coordinates.queries.len(),
                excluded_local_records: snapshot.coordinates.excluded_local_records,
                active_advisories: advisories.len(),
                oldest_fetched_at,
                newest_fetched_at,
                maximum_age_seconds,
                advisories: evidence,
            },
            advisories,
        };
        let size = serde_json_canonicalizer::to_vec(&report)
            .map_err(|error| {
                OsvError::new(
                    OsvErrorKind::Internal,
                    format!("canonicalize vulnerability report: {error}"),
                )
            })?
            .len();
        if size > MAX_REPORT_EVIDENCE_BYTES {
            return Err(OsvError::new(
                OsvErrorKind::ResourceLimit,
                format!(
                    "vulnerability finding and evidence bytes {size} exceed maximum {MAX_REPORT_EVIDENCE_BYTES}"
                ),
            ));
        }
        Ok(report)
    }
}

fn validate_resolved_snapshot(snapshot: &ResolvedSnapshot) -> Result<(), OsvError> {
    snapshot.coordinates.validate()?;
    if snapshot.results.len() != snapshot.coordinates.queries.len() {
        return Err(OsvError::incomplete(
            "resolved snapshot has missing coordinate results",
        ));
    }
    if snapshot.authorized_stale != (snapshot.source_mode == VulnerabilitySourceMode::OfflineStale)
    {
        return Err(OsvError::incomplete(
            "stale authorization does not match the snapshot source mode",
        ));
    }
    let expected_sources = match snapshot.source_mode {
        VulnerabilitySourceMode::Network => Some((true, false)),
        VulnerabilitySourceMode::Cache
        | VulnerabilitySourceMode::OfflineFresh
        | VulnerabilitySourceMode::OfflineStale => Some((false, true)),
        VulnerabilitySourceMode::Mixed => None,
    };
    let mut saw_network = false;
    let mut saw_cache = false;
    for (query, result) in snapshot.coordinates.queries.iter().zip(&snapshot.results) {
        if query != &result.query {
            return Err(OsvError::incomplete(
                "resolved snapshot result order does not match coordinates",
            ));
        }
        if result.fetched_at > snapshot.resolved_at {
            return Err(OsvError::incomplete(
                "resolved snapshot fetched_at is in the future",
            ));
        }
        saw_network |= result.source == crate::resolver::CoordinateSource::Network;
        saw_cache |= result.source == crate::resolver::CoordinateSource::Cache;
        let summary_ids = result
            .query_summaries
            .iter()
            .map(|summary| summary.primary_id.as_str())
            .collect::<BTreeSet<_>>();
        let advisory_ids = result
            .advisories
            .iter()
            .map(|advisory| advisory.primary_id.as_str())
            .collect::<BTreeSet<_>>();
        if summary_ids.len() != result.query_summaries.len() || summary_ids != advisory_ids {
            return Err(OsvError::incomplete(
                "resolved query summaries do not match hydrated advisories",
            ));
        }
        for advisory in &result.advisories {
            if advisory.coordinate != query.coordinate
                || advisory.evidence.locators != query.locators
                || advisory.evidence.affected.is_empty()
            {
                return Err(OsvError::incomplete(
                    "resolved advisory is not bound to its complete coordinate evidence",
                ));
            }
        }
        if result
            .advisories
            .windows(2)
            .any(|pair| pair[0].primary_id >= pair[1].primary_id)
        {
            return Err(OsvError::incomplete(
                "resolved advisories are not sorted with unique primary IDs",
            ));
        }
    }
    if let Some((network, cache)) = expected_sources {
        if !snapshot.results.is_empty() && (saw_network != network || saw_cache != cache) {
            return Err(OsvError::incomplete(
                "coordinate sources do not match the snapshot source mode",
            ));
        }
    } else if !(saw_network && saw_cache) {
        return Err(OsvError::incomplete(
            "mixed snapshot does not contain both cache and network results",
        ));
    }
    Ok(())
}

fn advisory_evidence(
    advisory: &NormalizedAdvisory,
) -> Result<VulnerabilityAdvisoryEvidence, OsvError> {
    let matched_ranges = advisory
        .evidence
        .affected
        .iter()
        .map(|affected| {
            let bytes = serde_json_canonicalizer::to_vec(affected).map_err(|error| {
                OsvError::new(
                    OsvErrorKind::Internal,
                    format!("canonicalize matched affected evidence: {error}"),
                )
            })?;
            String::from_utf8(bytes).map_err(|error| {
                OsvError::new(
                    OsvErrorKind::Internal,
                    format!("matched affected evidence is not UTF-8: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let severity = advisory.severity.evidence.first();
    Ok(VulnerabilityAdvisoryEvidence {
        coordinate: advisory.coordinate.clone(),
        primary_id: advisory.primary_id.clone(),
        aliases: advisory.aliases.clone(),
        locators: advisory.evidence.locators.clone(),
        matched_ranges,
        severity_type: severity.map(|value| value.severity_type.clone()),
        severity_score: severity.map(|value| value.score.clone()),
        normalized_severity: normalized_level_name(advisory.severity.level).to_string(),
        batch_summary_modified: advisory.batch_summary_modified.clone(),
        detail_modified: advisory.detail_modified.clone(),
        database_modified: advisory
            .database_modified
            .to_rfc3339_opts(SecondsFormat::AutoSi, true),
        source_url: advisory.source_url.clone(),
    })
}

fn freshness(snapshot: &ResolvedSnapshot) -> Result<(DateTime<Utc>, DateTime<Utc>, u64), OsvError> {
    let oldest = snapshot
        .results
        .iter()
        .map(|result| result.fetched_at)
        .min()
        .unwrap_or(snapshot.resolved_at);
    let newest = snapshot
        .results
        .iter()
        .map(|result| result.fetched_at)
        .max()
        .unwrap_or(snapshot.resolved_at);
    let age = snapshot
        .resolved_at
        .signed_duration_since(oldest)
        .to_std()
        .map_err(|_| OsvError::incomplete("resolved snapshot freshness is in the future"))?;
    let seconds = age
        .as_secs()
        .checked_add(u64::from(age.subsec_nanos() != 0))
        .ok_or_else(|| OsvError::limit("resolved snapshot freshness seconds overflowed"))?;
    Ok((oldest, newest, seconds))
}

fn normalized_level_name(level: SeverityLevel) -> &'static str {
    match level {
        SeverityLevel::Unknown => "unknown",
        SeverityLevel::None => "none",
        SeverityLevel::Low => "low",
        SeverityLevel::Medium => "medium",
        SeverityLevel::High => "high",
        SeverityLevel::Critical => "critical",
    }
}
