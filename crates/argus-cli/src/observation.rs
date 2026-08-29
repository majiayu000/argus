use crate::lockfile_scan::LockfileScanOutcome;
use anyhow::{bail, Context, Result};
use argus_core::{Decision, Finding, PackageCoordinate};
use argus_lockfile::{IntegrityEvidence, LockfileScanTarget};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObservationExport<'a> {
    schema_version: u8,
    generated_at: DateTime<Utc>,
    lockfile: &'a Path,
    decision: Decision,
    artifacts: Vec<ObservedArtifact<'a>>,
    suggested_ci_controls: SuggestedCiControls,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObservedArtifact<'a> {
    coordinate: &'a PackageCoordinate,
    expected_integrity: &'a [IntegrityEvidence],
    decision: Decision,
    findings: &'a [Finding],
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct SuggestedCiControls {
    network: &'static str,
    secrets: &'static str,
    filesystem: &'static str,
    process: &'static str,
}

pub(crate) fn export(
    path: &Path,
    outcome: &LockfileScanOutcome,
    targets: &[LockfileScanTarget],
    generated_at: DateTime<Utc>,
) -> Result<()> {
    let artifacts = outcome
        .reports
        .iter()
        .filter(|report| report.decision != Decision::Allow)
        .map(|report| {
            let coordinate = report.coordinate.as_ref().ok_or_else(|| {
                anyhow::anyhow!("observation export requires a resolved package coordinate")
            })?;
            let target = targets
                .iter()
                .find(|target| target.coordinate.as_ref() == Some(coordinate))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "observation export has no lockfile target for {}",
                        coordinate.purl
                    )
                })?;
            if target.expected_integrity.is_empty() {
                bail!(
                    "observation export refuses unbound artifact {} without lockfile integrity",
                    coordinate.purl
                );
            }
            Ok(ObservedArtifact {
                coordinate,
                expected_integrity: &target.expected_integrity,
                decision: report.decision,
                findings: &report.findings,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let document = ObservationExport {
        schema_version: 1,
        generated_at,
        lockfile: &outcome.lockfile,
        decision: outcome.decision,
        artifacts,
        suggested_ci_controls: SuggestedCiControls {
            network: "deny",
            secrets: "none",
            filesystem: "read-only",
            process: "isolated-no-host-tools",
        },
    };
    let mut bytes = serde_json::to_vec_pretty(&document).context("serialize observation export")?;
    bytes.push(b'\n');
    argus_core::fs::atomic_write_bytes(path, &bytes, ".argus-observation-")
        .with_context(|| format!("write observation export {}", path.display()))
}
