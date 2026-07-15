//! Optional semantic-judge protocol for agent-surface scans.
//!
//! The deterministic scanner owns request construction, size limits, response
//! validation, and decision derivation. A caller-provided judge only transports
//! the versioned JSON request to an explicitly configured external service.

use crate::{SurfaceFile, SurfaceKind};
use anyhow::{bail, Context, Result};
use argus_core::{Decision, Finding, ScanReport, Severity};
use serde::{Deserialize, Serialize};

pub const REQUEST_SCHEMA_VERSION: u8 = 1;
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RATIONALE_BYTES: usize = 4 * 1024;
pub const RULE_LLM_INTENT_JUDGE: &str = "llm-intent-judge";

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmJudgeInstruction {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmJudgeRequest {
    pub schema_version: u8,
    pub instruction_files: Vec<LlmJudgeInstruction>,
    pub deterministic_report: ScanReport,
}

impl LlmJudgeRequest {
    pub(crate) fn from_scan(files: &[SurfaceFile], report: &ScanReport) -> Result<Self> {
        let request = Self {
            schema_version: REQUEST_SCHEMA_VERSION,
            instruction_files: files
                .iter()
                .filter(|file| file.kind == SurfaceKind::Instruction)
                .map(|file| LlmJudgeInstruction {
                    path: file.rel.clone(),
                    content: file.content.clone(),
                })
                .collect(),
            deterministic_report: report.clone(),
        };
        let encoded = serde_json::to_vec(&request).context("serialize LLM judge request")?;
        if encoded.len() > MAX_REQUEST_BYTES {
            bail!(
                "LLM judge request is {} bytes, exceeding the {} byte limit",
                encoded.len(),
                MAX_REQUEST_BYTES
            );
        }
        Ok(request)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmJudgeResponse {
    pub schema_version: u8,
    pub decision: Decision,
    pub rationale: String,
}

impl LlmJudgeResponse {
    pub fn new(decision: Decision, rationale: impl Into<String>) -> Self {
        Self {
            schema_version: REQUEST_SCHEMA_VERSION,
            decision,
            rationale: rationale.into(),
        }
    }

    pub(crate) fn into_finding(self) -> Result<Finding> {
        if self.schema_version != REQUEST_SCHEMA_VERSION {
            bail!(
                "unsupported LLM judge response schema_version {}; expected {}",
                self.schema_version,
                REQUEST_SCHEMA_VERSION
            );
        }
        let rationale = self.rationale.trim();
        if rationale.is_empty() {
            bail!("LLM judge response rationale must not be empty");
        }
        if rationale.len() > MAX_RATIONALE_BYTES {
            bail!(
                "LLM judge response rationale is {} bytes, exceeding the {} byte limit",
                rationale.len(),
                MAX_RATIONALE_BYTES
            );
        }
        let severity = match self.decision {
            Decision::Allow => Severity::Info,
            Decision::AllowWithApproval => Severity::Medium,
            Decision::Block => Severity::High,
        };
        Ok(Finding::new(
            RULE_LLM_INTENT_JUDGE,
            severity,
            format!(
                "external semantic judge recommended {}: {rationale}",
                self.decision.as_str()
            ),
        ))
    }
}

pub trait LlmJudge {
    fn judge(&self, request: &LlmJudgeRequest) -> Result<LlmJudgeResponse>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::ArtifactKind;
    use std::path::PathBuf;

    #[test]
    fn response_rejects_unknown_fields() {
        let error = serde_json::from_str::<LlmJudgeResponse>(
            r#"{"schema_version":1,"decision":"allow","rationale":"ok","extra":true}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn response_rejects_unknown_decision() {
        let error = serde_json::from_str::<LlmJudgeResponse>(
            r#"{"schema_version":1,"decision":"review","rationale":"ok"}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown variant"), "{error}");
    }

    #[test]
    fn response_validation_rejects_bad_schema_and_rationale() {
        let mut response = LlmJudgeResponse::new(Decision::Allow, "ok");
        response.schema_version = 2;
        assert!(response.into_finding().is_err());

        assert!(LlmJudgeResponse::new(Decision::Allow, "   ")
            .into_finding()
            .is_err());
        assert!(
            LlmJudgeResponse::new(Decision::Allow, "x".repeat(MAX_RATIONALE_BYTES + 1))
                .into_finding()
                .is_err()
        );
    }

    #[test]
    fn decision_maps_to_non_downgrading_severity() {
        for (decision, severity) in [
            (Decision::Allow, Severity::Info),
            (Decision::AllowWithApproval, Severity::Medium),
            (Decision::Block, Severity::High),
        ] {
            let finding = LlmJudgeResponse::new(decision, "reviewed")
                .into_finding()
                .unwrap();
            assert_eq!(finding.severity, severity);
        }
    }

    #[test]
    fn request_rejects_oversized_instruction_payload() {
        let files: Vec<SurfaceFile> = (0..5)
            .map(|index| SurfaceFile {
                rel: format!("skill-{index}/SKILL.md"),
                content: "x".repeat(900_000),
                kind: SurfaceKind::Instruction,
            })
            .collect();
        let report = ScanReport {
            artifact: ArtifactKind::AgentSurface,
            path: PathBuf::from("."),
            package_name: None,
            package_version: None,
            decision: Decision::Allow,
            findings: Vec::new(),
        };
        let error = LlmJudgeRequest::from_scan(&files, &report).unwrap_err();
        assert!(error.to_string().contains("exceeding"), "{error:#}");
    }
}
