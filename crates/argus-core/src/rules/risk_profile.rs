//! The severity-derived risk profile (GH-146).
//!
//! [`super::risk`] is a pure contract: it takes weight and confidence
//! resolvers and refuses to invent either. This module supplies the one
//! profile that can be justified **without** the labeled benchmark from
//! GH-145.
//!
//! # Why severity, and why not per-rule weights
//!
//! GH-146's complaint is that the decision is rule-id set algebra in which a
//! `Low` finding and a `Critical` finding are interchangeable. Severity is not
//! a number this module invents — every detector already assigns it, it is
//! part of the rule catalog contract, and it is already surfaced in every
//! report. Letting it drive a score uses information the system has.
//!
//! Per-rule weights are different. "`typosquatting` is worth 0.8 and
//! `lifecycle-script` 0.3" is a claim about real-world outcomes, and there is
//! no measurement behind it yet. GH-146 says so directly: the labeled
//! benchmark must come first or the weights cannot be calibrated. So this
//! profile deliberately ships none.
//!
//! # Confidence is wired but not calibrated
//!
//! Every finding is assessed at full confidence. That is the honest value:
//! there is no per-rule confidence measurement, and a proxy (evidence
//! presence, match count) would encode detector implementation details as if
//! they were a probability. The dimension exists in the contract so GH-145's
//! results can populate it without an API change.
//!
//! # Default thresholds reproduce the severity profile
//!
//! At the default thresholds a *single* finding produces exactly the decision
//! [`super::AggregationProfile::SeverityDriven`] would, so enabling scoring is
//! not a surprise. The difference appears with multiple findings: two
//! independent Medium-risk behaviours accumulate to a block, where set algebra
//! saw one "medium bucket" and stopped. That accumulation is the actual
//! improvement, and it needs no calibration to justify.

use super::risk::{
    Confidence, RiskAssessment, RiskAssessmentError, RiskScore, RiskThresholds, RuleWeight,
};
use crate::{Finding, Severity};

/// Weight for a severity, in basis points.
///
/// The spacing is ordinal, not a calibrated magnitude: it encodes
/// "Critical outranks High outranks Medium outranks Low", plus the property
/// that two Mediums reach the block threshold and two Lows do not. Anything
/// finer requires GH-145.
pub fn severity_weight_basis_points(severity: Severity) -> u32 {
    match severity {
        Severity::Critical => 10_000,
        Severity::High => 6_000,
        Severity::Medium => 3_000,
        Severity::Low => 1_000,
        // Info findings are disclosures, not risk. They stay visible in the
        // report and contribute nothing to the score.
        Severity::Info => 0,
    }
}

/// Default approval threshold: one Medium finding.
pub const DEFAULT_APPROVAL_THRESHOLD: u64 = 3_000;

/// Default block threshold: one High finding, or two Mediums.
pub const DEFAULT_BLOCK_THRESHOLD: u64 = 6_000;

/// The default thresholds as a validated pair.
pub fn default_thresholds() -> RiskThresholds {
    RiskThresholds::new(
        RiskScore::new(DEFAULT_APPROVAL_THRESHOLD),
        RiskScore::new(DEFAULT_BLOCK_THRESHOLD),
    )
    // vibeguard-disable-next-line RS-03 -- DEFAULT_APPROVAL_THRESHOLD < DEFAULT_BLOCK_THRESHOLD by construction
    .expect("default approval threshold is below the default block threshold")
}

/// Assess findings using severity-derived weights at full confidence.
///
/// Returns the score, the decision the thresholds imply, and the per-rule
/// contributions that produced it, so a report can show its work rather than
/// asserting a verdict.
pub fn assess_by_severity(
    findings: &[Finding],
    thresholds: RiskThresholds,
) -> Result<RiskAssessment, RiskAssessmentError> {
    let weights = severity_weights(findings);
    super::risk::assess(
        findings,
        thresholds,
        |rule_id| weights.get(rule_id).copied(),
        |_finding| Some(Confidence::max()),
    )
}

/// Highest severity observed per rule id, as a weight.
///
/// The assessment contract de-duplicates by rule id, so the weight must also
/// be per-rule. When one rule fired at several severities the highest one
/// decides: a rule that produced a Critical observation is not made cheaper by
/// also having produced an Info one.
fn severity_weights(findings: &[Finding]) -> std::collections::BTreeMap<String, RuleWeight> {
    let mut weights: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for finding in findings {
        let basis_points = severity_weight_basis_points(finding.severity);
        weights
            .entry(finding.rule_id.clone())
            .and_modify(|current| *current = (*current).max(basis_points))
            .or_insert(basis_points);
    }
    weights
        .into_iter()
        .map(|(rule_id, points)| {
            // vibeguard-disable-next-line RS-03 -- severity weights are at most BASIS_POINTS
            let weight = RuleWeight::new(points).expect("severity weight is bounded");
            (rule_id, weight)
        })
        .collect()
}

#[cfg(test)]
mod tests;
