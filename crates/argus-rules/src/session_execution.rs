//! Context-aware external-rule surface execution.

use crate::session::{
    has_relevant_language, read_bounded, RuleSession, MAX_EXTERNAL_EVIDENCE_BYTES,
    MAX_EXTERNAL_FINDINGS, MAX_EXTERNAL_INPUT_BYTES, MAX_EXTERNAL_SCAN_FILES,
};
use anyhow::{bail, Context, Result};
use argus_core::{ExecutionContext, Finding};
use std::path::{Path, PathBuf};

enum ExternalScanInput<'a> {
    File(PathBuf),
    Virtual(&'a [u8]),
}

/// Artifact-scoped external-rule resource accounting.
///
/// Callers that scan one artifact through multiple directories or virtual
/// surfaces must share one instance. Legacy one-shot APIs create a fresh
/// budget for compatibility.
#[derive(Debug, Default)]
pub struct ExternalScanBudget {
    input_count: usize,
    finding_count: usize,
    evidence_bytes: usize,
}

impl ExternalScanBudget {
    fn checked_input_total(&self, phase_inputs: usize) -> Result<usize> {
        let total = self
            .input_count
            .checked_add(phase_inputs)
            .ok_or_else(|| anyhow::anyhow!("external-rule input count overflow"))?;
        if total > MAX_EXTERNAL_SCAN_FILES {
            bail!("external-rule scan exceeds {MAX_EXTERNAL_SCAN_FILES} inputs");
        }
        Ok(total)
    }
}

impl RuleSession {
    pub fn scan_directory_with_context(
        &self,
        root: &Path,
        findings: &mut Vec<Finding>,
        execution: &ExecutionContext,
    ) -> Result<()> {
        let mut budget = ExternalScanBudget::default();
        self.scan_directory_with_budget_and_context(root, findings, execution, &mut budget)
    }

    pub fn scan_directory_with_budget_and_context(
        &self,
        root: &Path,
        findings: &mut Vec<Finding>,
        execution: &ExecutionContext,
        budget: &mut ExternalScanBudget,
    ) -> Result<()> {
        self.scan_directory_with_virtual_inputs_and_budget_and_context(
            root,
            0,
            std::iter::empty::<(String, &[u8])>(),
            findings,
            execution,
            budget,
        )
    }

    pub fn scan_directory_with_virtual_inputs_and_context<'a>(
        &self,
        root: &Path,
        virtual_input_count: usize,
        virtual_inputs: impl IntoIterator<Item = (String, &'a [u8])>,
        findings: &mut Vec<Finding>,
        execution: &ExecutionContext,
    ) -> Result<()> {
        let mut budget = ExternalScanBudget::default();
        self.scan_directory_with_virtual_inputs_and_budget_and_context(
            root,
            virtual_input_count,
            virtual_inputs,
            findings,
            execution,
            &mut budget,
        )
    }

    pub fn scan_directory_with_virtual_inputs_and_budget_and_context<'a>(
        &self,
        root: &Path,
        virtual_input_count: usize,
        virtual_inputs: impl IntoIterator<Item = (String, &'a [u8])>,
        findings: &mut Vec<Finding>,
        execution: &ExecutionContext,
        budget: &mut ExternalScanBudget,
    ) -> Result<()> {
        if !self.has_enabled_external_rules() {
            return Ok(());
        }
        let mut inputs = Vec::new();
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = entry
                .with_context(|| format!("walk external-rule scan root {}", root.display()))?;
            if entry.file_type().is_file() {
                let rel = entry
                    .path()
                    .strip_prefix(root)
                    .context("derive external-rule relative path")?
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("external-rule path is not valid UTF-8"))?
                    .replace('\\', "/");
                inputs.push((rel, ExternalScanInput::File(entry.path().to_path_buf())));
                if inputs.len() > MAX_EXTERNAL_SCAN_FILES {
                    bail!("external-rule scan exceeds {MAX_EXTERNAL_SCAN_FILES} inputs");
                }
            }
        }
        let phase_input_count = inputs
            .len()
            .checked_add(virtual_input_count)
            .ok_or_else(|| anyhow::anyhow!("external-rule input count overflow"))?;
        budget.checked_input_total(phase_input_count)?;
        let collection_limit = virtual_input_count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("external-rule virtual input count overflow"))?;
        let virtual_inputs = virtual_inputs
            .into_iter()
            .take(collection_limit)
            .collect::<Vec<_>>();
        if virtual_inputs.len() != virtual_input_count {
            bail!("external-rule virtual input count does not match declared count");
        }
        inputs.extend(
            virtual_inputs
                .into_iter()
                .map(|(rel, bytes)| (rel, ExternalScanInput::Virtual(bytes))),
        );
        self.scan_inputs_with_context(inputs, findings, execution, budget)
    }

    pub fn scan_virtual_inputs_with_context<'a>(
        &self,
        input_count: usize,
        inputs: impl IntoIterator<Item = (&'a str, &'a [u8])>,
        findings: &mut Vec<Finding>,
        execution: &ExecutionContext,
    ) -> Result<()> {
        let mut budget = ExternalScanBudget::default();
        self.scan_virtual_inputs_with_budget_and_context(
            input_count,
            inputs,
            findings,
            execution,
            &mut budget,
        )
    }

    pub fn scan_virtual_inputs_with_budget_and_context<'a>(
        &self,
        input_count: usize,
        inputs: impl IntoIterator<Item = (&'a str, &'a [u8])>,
        findings: &mut Vec<Finding>,
        execution: &ExecutionContext,
        budget: &mut ExternalScanBudget,
    ) -> Result<()> {
        if !self.has_enabled_external_rules() {
            return Ok(());
        }
        budget.checked_input_total(input_count)?;
        let collection_limit = input_count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("external-rule virtual input count overflow"))?;
        let inputs = inputs
            .into_iter()
            .take(collection_limit)
            .map(|(rel, bytes)| (rel.to_string(), ExternalScanInput::Virtual(bytes)))
            .collect::<Vec<_>>();
        if inputs.len() != input_count {
            bail!("external-rule virtual input count does not match declared count");
        }
        self.scan_inputs_with_context(inputs, findings, execution, budget)
    }

    fn scan_inputs_with_context(
        &self,
        mut inputs: Vec<(String, ExternalScanInput<'_>)>,
        findings: &mut Vec<Finding>,
        execution: &ExecutionContext,
        budget: &mut ExternalScanBudget,
    ) -> Result<()> {
        inputs.sort_by(|left, right| left.0.cmp(&right.0));
        let next_input_count = budget.checked_input_total(inputs.len())?;
        let mut staged_findings = Vec::new();
        let mut evidence_bytes = 0usize;
        execution.execute_ordered(
            &inputs,
            None,
            |_index, (rel, input)| {
                if let ExternalScanInput::Virtual(bytes) = input {
                    if bytes.len() > MAX_EXTERNAL_INPUT_BYTES {
                        bail!(
                            "external-rule input `{rel}` exceeds \
                             {MAX_EXTERNAL_INPUT_BYTES} bytes"
                        );
                    }
                }
                if !has_relevant_language(self, rel) {
                    return Ok(Vec::new());
                }
                let owned;
                let bytes = match input {
                    ExternalScanInput::File(path) => {
                        owned = read_bounded(path, MAX_EXTERNAL_INPUT_BYTES)
                            .with_context(|| format!("read external-rule input `{rel}`"))?;
                        owned.as_slice()
                    }
                    ExternalScanInput::Virtual(bytes) => *bytes,
                };
                let mut per_input = Vec::new();
                self.scan_bytes(rel, bytes, &mut per_input)?;
                Ok(per_input)
            },
            |_index, mut per_input| {
                let next_findings = staged_findings
                    .len()
                    .checked_add(per_input.len())
                    .ok_or_else(|| anyhow::anyhow!("external-rule finding count overflow"))?;
                let artifact_findings = budget
                    .finding_count
                    .checked_add(next_findings)
                    .ok_or_else(|| anyhow::anyhow!("external-rule finding count overflow"))?;
                if artifact_findings > MAX_EXTERNAL_FINDINGS {
                    bail!("external-rule findings exceed {MAX_EXTERNAL_FINDINGS}");
                }
                for evidence in per_input
                    .iter()
                    .filter_map(|finding| finding.evidence.as_ref())
                    .flatten()
                {
                    evidence_bytes =
                        evidence_bytes.checked_add(evidence.len()).ok_or_else(|| {
                            anyhow::anyhow!("external-rule evidence byte count overflow")
                        })?;
                    if evidence_bytes > MAX_EXTERNAL_EVIDENCE_BYTES {
                        bail!("external-rule evidence exceeds {MAX_EXTERNAL_EVIDENCE_BYTES} bytes");
                    }
                }
                let artifact_evidence = budget
                    .evidence_bytes
                    .checked_add(evidence_bytes)
                    .ok_or_else(|| anyhow::anyhow!("external-rule evidence byte count overflow"))?;
                if artifact_evidence > MAX_EXTERNAL_EVIDENCE_BYTES {
                    bail!("external-rule evidence exceeds {MAX_EXTERNAL_EVIDENCE_BYTES} bytes");
                }
                staged_findings.append(&mut per_input);
                Ok(())
            },
        )?;
        budget.input_count = next_input_count;
        budget.finding_count = budget
            .finding_count
            .checked_add(staged_findings.len())
            .ok_or_else(|| anyhow::anyhow!("external-rule finding count overflow"))?;
        budget.evidence_bytes = budget
            .evidence_bytes
            .checked_add(evidence_bytes)
            .ok_or_else(|| anyhow::anyhow!("external-rule evidence byte count overflow"))?;
        findings.append(&mut staged_findings);
        Ok(())
    }
}
