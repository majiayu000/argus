//! Rule-session matching and report finalization shared by agent scan modes.

use crate::{AgentScanOutcome, SurfaceFile};
use anyhow::{Context, Result};
use argus_core::{ArtifactKind, Finding, ScanReport};
use argus_rules::RuleSession;
use std::path::Path;

pub(super) fn scan_files(
    rules: &RuleSession,
    files: &[SurfaceFile],
    findings: &mut Vec<Finding>,
) -> Result<()> {
    for file in files {
        rules
            .scan_bytes(&file.rel, file.content.as_bytes(), findings)
            .with_context(|| format!("run external rules on agent surface `{}`", file.rel))?;
    }
    rules.validate_external_limits(findings)?;
    Ok(())
}

pub(super) fn report(path: &Path, findings: Vec<Finding>, rules: &RuleSession) -> ScanReport {
    let mut report = ScanReport {
        artifact: ArtifactKind::AgentSurface,
        path: path.to_path_buf(),
        package_name: None,
        package_version: None,
        decision: argus_core::Decision::Allow,
        findings,
        coordinate: None,
        intelligence: None,
        rules: None,
    };
    rules.finalize_agent(&mut report);
    report
}

pub(super) fn incomplete(
    path: &Path,
    semantic: Vec<Finding>,
    inventory: Vec<Finding>,
    error: anyhow::Error,
    rules: &RuleSession,
) -> AgentScanOutcome {
    let findings = semantic.into_iter().chain(inventory).collect();
    let mut report = report(path, findings, rules);
    report.decision = argus_core::Decision::Block;
    AgentScanOutcome {
        report,
        operational_error: Some(error),
        snapshot_entry_count: None,
    }
}
