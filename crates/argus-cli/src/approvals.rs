use anyhow::{bail, ensure, Context, Result};
use argus_core::rules::{policy, RulePolicy};
use argus_core::{Decision, Ecosystem, ScanReport};
use argus_lockfile::LockfileScanTarget;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const MAX_LEDGER_BYTES: usize = 16 * 1024 * 1024;
const MAX_REASON_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalLedger {
    schema_version: u8,
    approvals: Vec<ApprovalRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalRecord {
    purl: String,
    algorithm: String,
    digest: String,
    capability: String,
    reason: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovalAssessment {
    pub(crate) purl: String,
    pub(crate) artifact: PathBuf,
    pub(crate) complete: bool,
    pub(crate) applied: Vec<AppliedApproval>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppliedApproval {
    algorithm: String,
    digest: String,
    capability: String,
    reason: String,
    expires_at: DateTime<Utc>,
}

pub(crate) fn load_and_assess(
    path: &Path,
    reports: &[ScanReport],
    targets: &[LockfileScanTarget],
    scan_started_at: DateTime<Utc>,
) -> Result<Vec<ApprovalAssessment>> {
    let raw = argus_core::fs::read_bounded_utf8_regular_file(path, MAX_LEDGER_BYTES)
        .with_context(|| format!("read approval ledger {}", path.display()))?;
    let ledger: ApprovalLedger = serde_json::from_str(&raw)
        .with_context(|| format!("parse approval ledger {}", path.display()))?;
    ensure!(
        ledger.schema_version == 1,
        "approval ledger schemaVersion must be 1"
    );
    validate_records(&ledger.approvals, scan_started_at)?;

    reports
        .iter()
        .filter(|report| report.decision == Decision::AllowWithApproval)
        .map(|report| assess_report(report, targets, &ledger.approvals))
        .collect()
}

fn validate_records(records: &[ApprovalRecord], scan_started_at: DateTime<Utc>) -> Result<()> {
    let mut identities = BTreeSet::new();
    for record in records {
        ensure!(
            !record.purl.trim().is_empty(),
            "approval purl must not be empty"
        );
        ensure!(
            !record.algorithm.trim().is_empty() && !record.digest.trim().is_empty(),
            "approval digest binding must not be empty"
        );
        ensure!(
            !record.capability.trim().is_empty(),
            "approval capability must not be empty"
        );
        ensure!(
            !record.reason.trim().is_empty() && record.reason.len() <= MAX_REASON_BYTES,
            "approval reason must contain 1..={MAX_REASON_BYTES} bytes"
        );
        ensure!(
            record.expires_at > scan_started_at,
            "approval for {} / {} is expired",
            record.purl,
            record.capability
        );
        ensure!(
            identities.insert((
                record.purl.as_str(),
                record.algorithm.as_str(),
                record.digest.as_str(),
                record.capability.as_str(),
            )),
            "duplicate approval binding for {} / {}",
            record.purl,
            record.capability
        );
    }
    Ok(())
}

fn assess_report(
    report: &ScanReport,
    targets: &[LockfileScanTarget],
    records: &[ApprovalRecord],
) -> Result<ApprovalAssessment> {
    let coordinate = report
        .coordinate
        .as_ref()
        .context("approval requires a resolved package coordinate")?;
    if !matches!(
        coordinate.ecosystem,
        Ecosystem::Npm | Ecosystem::PyPi | Ecosystem::CratesIo
    ) {
        bail!(
            "dependency approvals are not available for {} until its lockfile digest is verified against downloaded bytes",
            coordinate.original_ecosystem
        );
    }
    let target = targets
        .iter()
        .find(|target| target.coordinate.as_ref() == Some(coordinate))
        .with_context(|| format!("approval has no lockfile target for {}", coordinate.purl))?;
    let required = report
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                policy(&finding.rule_id),
                RulePolicy::ApprovalOnly | RulePolicy::DowngradeSafe
            )
        })
        .collect::<Vec<_>>();
    ensure!(
        !required.is_empty(),
        "approval decision for {} has no approval-scoped findings",
        coordinate.purl
    );

    let mut applied = Vec::new();
    let mut capabilities = BTreeSet::new();
    for finding in required {
        let capability = finding.capability.as_deref().unwrap_or(&finding.rule_id);
        if !capabilities.insert(capability) {
            continue;
        }
        let matched = records.iter().find(|record| {
            record.purl == coordinate.purl
                && record.capability == capability
                && target.expected_integrity.iter().any(|integrity| {
                    integrity.algorithm.as_deref() == Some(record.algorithm.as_str())
                        && integrity.value.as_deref() == Some(record.digest.as_str())
                })
        });
        if let Some(record) = matched {
            applied.push(AppliedApproval {
                algorithm: record.algorithm.clone(),
                digest: record.digest.clone(),
                capability: record.capability.clone(),
                reason: record.reason.clone(),
                expires_at: record.expires_at,
            });
        }
    }
    Ok(ApprovalAssessment {
        purl: coordinate.purl.clone(),
        artifact: report.path.clone(),
        complete: applied.len() == capabilities.len(),
        applied,
    })
}

pub(crate) fn effective_decision(
    report: &ScanReport,
    assessments: &[ApprovalAssessment],
) -> Decision {
    if report.decision != Decision::AllowWithApproval {
        return report.decision;
    }
    let approved = report.coordinate.as_ref().is_some_and(|coordinate| {
        assessments.iter().any(|assessment| {
            assessment.purl == coordinate.purl
                && assessment.artifact == report.path
                && assessment.complete
        })
    });
    if approved {
        Decision::Allow
    } else {
        Decision::AllowWithApproval
    }
}
