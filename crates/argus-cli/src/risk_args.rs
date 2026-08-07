//! Opt-in weighted risk scoring flags (GH-146).
//!
//! Scoring is opt-in, and that is a deliberate contract choice rather than
//! caution for its own sake. The default decision path is policy-driven and
//! every existing consumer's exit codes depend on it. Switching that default
//! to a scored decision is a behaviour change for everyone, and GH-146 states
//! the precondition for making it: the weights cannot be calibrated until the
//! labeled benchmark in GH-145 exists. Shipping the machinery now, off by
//! default, lets the score be inspected and thresholds tuned without silently
//! re-deciding anyone's builds.

use anyhow::{Context, Result};
use argus_core::rules::{RiskScore, RiskThresholds};
use argus_core::{RiskReport, ScanReport};

#[derive(clap::Args, Debug, Clone)]
pub(crate) struct RiskArgs {
    /// Compute a weighted risk score from finding severities and report the
    /// score plus each rule's contribution. Does not change the decision
    /// unless `--risk-decides` is also passed.
    #[arg(long = "risk-scoring")]
    risk_scoring: bool,
    /// Let the risk score decide, replacing the policy-driven decision.
    #[arg(long = "risk-decides", requires = "risk_scoring")]
    risk_decides: bool,
    /// Score at or above which the decision becomes allow-with-approval.
    #[arg(
        long = "risk-approval-threshold",
        value_name = "BASIS_POINTS",
        requires = "risk_scoring"
    )]
    approval_threshold: Option<u64>,
    /// Score at or above which the decision becomes block.
    #[arg(
        long = "risk-block-threshold",
        value_name = "BASIS_POINTS",
        requires = "risk_scoring"
    )]
    block_threshold: Option<u64>,
}

impl RiskArgs {
    /// Attach a risk assessment to the report when scoring was requested.
    ///
    /// With `--risk-decides` the scored decision replaces the policy-driven
    /// one; otherwise the score is reported alongside the unchanged decision
    /// so an operator can compare the two before trusting it.
    pub(crate) fn apply(&self, report: &mut ScanReport) -> Result<()> {
        if !self.risk_scoring {
            return Ok(());
        }
        let thresholds = self.thresholds()?;
        let assessment = argus_core::rules::assess_by_severity(&report.findings, thresholds)
            .map_err(|error| anyhow::anyhow!("{error}"))
            .context("assess weighted risk")?;
        if self.risk_decides {
            report.decision = assessment.decision;
        }
        report.risk = Some(RiskReport::from(assessment));
        Ok(())
    }

    fn thresholds(&self) -> Result<RiskThresholds> {
        let defaults = argus_core::rules::default_thresholds();
        let approval = self
            .approval_threshold
            .map_or(defaults.approval(), RiskScore::new);
        let block = self
            .block_threshold
            .map_or(defaults.block(), RiskScore::new);
        RiskThresholds::new(approval, block)
            .map_err(|error| anyhow::anyhow!("{error}"))
            .context("validate risk thresholds")
    }
}

/// Render the risk section of a text report.
pub(crate) fn render_text(risk: &RiskReport) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    let _ = writeln!(
        output,
        "risk score: {} (approval >= {}, block >= {})",
        risk.score, risk.approval_threshold, risk.block_threshold
    );
    for contribution in &risk.contributions {
        let _ = writeln!(
            output,
            "  {} +{} (weight {} x confidence {})",
            contribution.rule_id, contribution.score, contribution.weight, contribution.confidence
        );
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::{ArtifactKind, Decision, Finding, Severity};

    fn args(scoring: bool, decides: bool, approval: Option<u64>, block: Option<u64>) -> RiskArgs {
        RiskArgs {
            risk_scoring: scoring,
            risk_decides: decides,
            approval_threshold: approval,
            block_threshold: block,
        }
    }

    fn report(decision: Decision, findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            artifact: ArtifactKind::PackageDir,
            path: "demo".into(),
            package_name: Some("demo".to_string()),
            package_version: None,
            decision,
            findings,
            coordinate: None,
            intelligence: None,
            rules: None,
            vulnerability: None,
            risk: None,
        }
    }

    #[test]
    fn scoring_off_leaves_the_report_untouched() {
        let mut scan = report(
            Decision::Allow,
            vec![Finding::new("r", Severity::Critical, "d")],
        );
        args(false, false, None, None)
            .apply(&mut scan)
            .expect("no-op succeeds");
        assert!(scan.risk.is_none());
        assert_eq!(scan.decision, Decision::Allow);
    }

    #[test]
    fn scoring_reports_without_changing_the_decision_by_default() {
        // The point of the default: an operator can compare the scored verdict
        // against the policy-driven one before trusting uncalibrated weights.
        let mut scan = report(
            Decision::Allow,
            vec![Finding::new("r", Severity::Critical, "d")],
        );
        args(true, false, None, None)
            .apply(&mut scan)
            .expect("scoring succeeds");

        let risk = scan.risk.as_ref().expect("risk attached");
        assert_eq!(risk.score, 10_000);
        assert_eq!(risk.decision, Decision::Block);
        // Reported, not applied.
        assert_eq!(scan.decision, Decision::Allow);
    }

    #[test]
    fn risk_decides_replaces_the_decision() {
        let mut scan = report(
            Decision::Allow,
            vec![Finding::new("r", Severity::Critical, "d")],
        );
        args(true, true, None, None)
            .apply(&mut scan)
            .expect("scoring succeeds");
        assert_eq!(scan.decision, Decision::Block);
    }

    #[test]
    fn contributions_name_every_rule_that_scored() {
        let mut scan = report(
            Decision::Allow,
            vec![
                Finding::new("typosquatting", Severity::High, "d"),
                Finding::new("lifecycle-script", Severity::Medium, "d"),
            ],
        );
        args(true, false, None, None)
            .apply(&mut scan)
            .expect("scoring succeeds");

        let risk = scan.risk.expect("risk attached");
        let ids: Vec<&str> = risk
            .contributions
            .iter()
            .map(|contribution| contribution.rule_id.as_str())
            .collect();
        assert_eq!(ids, ["lifecycle-script", "typosquatting"]);
        assert_eq!(risk.score, 9_000);
    }

    #[test]
    fn custom_thresholds_are_honoured_and_reported() {
        let mut scan = report(Decision::Allow, vec![Finding::new("r", Severity::Low, "d")]);
        args(true, true, Some(500), Some(1_000))
            .apply(&mut scan)
            .expect("scoring succeeds");

        let risk = scan.risk.as_ref().expect("risk attached");
        assert_eq!(risk.approval_threshold, 500);
        assert_eq!(risk.block_threshold, 1_000);
        assert_eq!(scan.decision, Decision::Block);
    }

    #[test]
    fn inverted_thresholds_fail_closed() {
        let mut scan = report(Decision::Allow, Vec::new());
        let error = args(true, false, Some(9_000), Some(1_000))
            .apply(&mut scan)
            .expect_err("inverted thresholds must be rejected");
        assert!(
            format!("{error:#}").contains("threshold"),
            "unexpected error: {error:#}"
        );
        // Nothing partially applied.
        assert!(scan.risk.is_none());
    }

    #[test]
    fn equal_thresholds_fail_closed() {
        let mut scan = report(Decision::Allow, Vec::new());
        assert!(args(true, false, Some(3_000), Some(3_000))
            .apply(&mut scan)
            .is_err());
    }

    #[test]
    fn text_rendering_shows_the_score_and_its_working() {
        let mut scan = report(
            Decision::Allow,
            vec![Finding::new("typosquatting", Severity::High, "d")],
        );
        args(true, false, None, None)
            .apply(&mut scan)
            .expect("scoring succeeds");

        let text = render_text(scan.risk.as_ref().expect("risk attached"));
        assert!(text.contains("risk score: 6000"));
        assert!(text.contains("approval >= 3000"));
        assert!(text.contains("block >= 6000"));
        assert!(text.contains("typosquatting +6000"));
    }
}
