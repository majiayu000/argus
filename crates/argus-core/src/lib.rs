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
}

impl Finding {
    pub fn new(rule_id: &str, severity: Severity, detail: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity,
            detail: detail.into(),
            location: None,
        }
    }

    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }
}

/// What kind of artifact was scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    PackageDir,
    Lockfile,
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
        };
        assert_eq!(
            report.rule_ids(),
            vec!["lifecycle-script", "remote-download"]
        );
    }
}
