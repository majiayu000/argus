//! Rule-session matching and report finalization shared by agent scan modes.

use crate::{AgentScanOutcome, SurfaceFile};
use anyhow::{Context, Result};
use argus_core::{ArtifactKind, Finding, ScanReport};
use argus_rules::RuleSession;
use std::path::Path;

#[cfg(test)]
pub(super) fn scan_files(
    rules: &RuleSession,
    files: &[SurfaceFile],
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let execution = argus_core::ExecutionContext::serial()
        .context("build serial agent rule execution context")?;
    scan_files_with_context(rules, files, findings, &execution)
}

pub(super) fn scan_files_with_context(
    rules: &RuleSession,
    files: &[SurfaceFile],
    findings: &mut Vec<Finding>,
    execution: &argus_core::ExecutionContext,
) -> Result<()> {
    rules
        .scan_virtual_inputs_with_context(
            files.len(),
            files
                .iter()
                .map(|file| (file.rel.as_str(), file.content.as_bytes())),
            findings,
            execution,
        )
        .context("run external rules on agent surfaces")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SurfaceKind;
    use std::fs;

    fn external_session() -> RuleSession {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("rules.yaml"),
            "schema_version: 1\nrules:\n  - { id: \"agent-bounded-external\", description: \"bounded\", policy_class: blocking, default_severity: low, help_uri: \"https://example.test/agent-bounded\", languages: [markdown], matcher: { kind: literal, pattern: \"never-match\" } }\n",
        )
        .unwrap();
        RuleSession::load(Some(temp.path()), &[]).unwrap()
    }

    fn surfaces(count: usize) -> Vec<SurfaceFile> {
        (0..count)
            .map(|index| SurfaceFile {
                rel: format!("{index:05}.md"),
                content: String::new(),
                kind: SurfaceKind::Instruction,
            })
            .collect()
    }

    #[test]
    fn external_surface_count_accepts_limit_and_rejects_plus_one() {
        let rules = external_session();
        scan_files(
            &rules,
            &surfaces(argus_rules::MAX_EXTERNAL_SCAN_FILES),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(scan_files(
            &rules,
            &surfaces(argus_rules::MAX_EXTERNAL_SCAN_FILES + 1),
            &mut Vec::new(),
        )
        .is_err());
    }
}
