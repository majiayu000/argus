//! Fixed-point risk assessment primitives.
//!
//! This module is intentionally not wired into scan aggregation. Callers must
//! provide both the rule-weight and finding-confidence resolvers; there are no
//! implicit or built-in weights here. Scores are represented as integer basis
//! points, making assessment deterministic across platforms and input order.

use crate::{Decision, Finding};
use std::{collections::BTreeMap, error::Error, fmt};

/// Number of basis points in one whole value.
pub const BASIS_POINTS: u32 = 10_000;

/// A validated confidence value in the inclusive range 0..=10,000 basis
/// points. The caller owns the confidence policy (for example, detector
/// calibration or an audit resolver).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Confidence(u32);

impl Confidence {
    pub fn new(basis_points: u32) -> Result<Self, RiskAssessmentError> {
        if basis_points <= BASIS_POINTS {
            Ok(Self(basis_points))
        } else {
            Err(RiskAssessmentError::InvalidConfidence { basis_points })
        }
    }

    pub fn from_basis_points(basis_points: u32) -> Result<Self, RiskAssessmentError> {
        Self::new(basis_points)
    }

    pub const fn zero() -> Self {
        Self(0)
    }

    pub const fn max() -> Self {
        Self(BASIS_POINTS)
    }

    pub const fn basis_points(self) -> u32 {
        self.0
    }

    pub const fn bps(self) -> u32 {
        self.basis_points()
    }
}

/// A validated rule weight in the inclusive range 0..=10,000 basis points.
/// A zero weight is explicit and differs from a missing weight resolver entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleWeight(u32);

impl RuleWeight {
    pub fn new(basis_points: u32) -> Result<Self, RiskAssessmentError> {
        if basis_points <= BASIS_POINTS {
            Ok(Self(basis_points))
        } else {
            Err(RiskAssessmentError::InvalidRuleWeight { basis_points })
        }
    }

    pub fn from_basis_points(basis_points: u32) -> Result<Self, RiskAssessmentError> {
        Self::new(basis_points)
    }

    pub const fn zero() -> Self {
        Self(0)
    }

    pub const fn max() -> Self {
        Self(BASIS_POINTS)
    }

    pub const fn basis_points(self) -> u32 {
        self.0
    }

    pub const fn bps(self) -> u32 {
        self.basis_points()
    }
}

/// An integer risk score. Scores are additive basis-point contributions and
/// are therefore not capped at 10,000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RiskScore(u64);

impl RiskScore {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn zero() -> Self {
        Self(0)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Thresholds for the three decisions. A score below `approval` allows;
/// scores at or above `approval` but below `block` require approval; scores at
/// or above `block` are blocked. `approval < block` is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskThresholds {
    approval: RiskScore,
    block: RiskScore,
}

impl RiskThresholds {
    pub fn new(approval: RiskScore, block: RiskScore) -> Result<Self, RiskAssessmentError> {
        if approval < block {
            Ok(Self { approval, block })
        } else {
            Err(RiskAssessmentError::InvalidThresholds { approval, block })
        }
    }

    pub const fn approval(self) -> RiskScore {
        self.approval
    }

    pub const fn block(self) -> RiskScore {
        self.block
    }

    fn validate(self) -> Result<Self, RiskAssessmentError> {
        if self.approval < self.block {
            Ok(self)
        } else {
            Err(RiskAssessmentError::InvalidThresholds {
                approval: self.approval,
                block: self.block,
            })
        }
    }
}

/// One deterministic, de-duplicated contribution to an assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskContribution {
    pub rule_id: String,
    pub weight: RuleWeight,
    pub confidence: Confidence,
    /// `floor(weight * confidence / 10_000)`, i.e. truncation toward zero.
    /// Both operands are bounded at 10,000, so their `u64` product is at most
    /// 100,000,000 and cannot overflow.
    pub score: RiskScore,
}

/// Result of assessing findings against caller-provided resolvers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAssessment {
    pub score: RiskScore,
    pub decision: Decision,
    pub thresholds: RiskThresholds,
    pub contributions: Vec<RiskContribution>,
}

/// Errors are explicit so unknown or unweighted rules cannot silently become
/// zero-risk observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskAssessmentError {
    InvalidConfidence {
        basis_points: u32,
    },
    InvalidRuleWeight {
        basis_points: u32,
    },
    InvalidThresholds {
        approval: RiskScore,
        block: RiskScore,
    },
    MissingWeight {
        rule_id: String,
    },
    MissingConfidence {
        rule_id: String,
    },
    ScoreOverflow {
        rule_id: String,
    },
}

impl fmt::Display for RiskAssessmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfidence { basis_points } => {
                write!(
                    f,
                    "confidence {basis_points} exceeds {BASIS_POINTS} basis points"
                )
            }
            Self::InvalidRuleWeight { basis_points } => {
                write!(
                    f,
                    "rule weight {basis_points} exceeds {BASIS_POINTS} basis points"
                )
            }
            Self::InvalidThresholds { approval, block } => write!(
                f,
                "approval threshold {} must be lower than block threshold {}",
                approval.value(),
                block.value()
            ),
            Self::MissingWeight { rule_id } => {
                write!(f, "missing risk weight for rule `{rule_id}`")
            }
            Self::MissingConfidence { rule_id } => {
                write!(f, "missing risk confidence for rule `{rule_id}`")
            }
            Self::ScoreOverflow { rule_id } => {
                write!(f, "risk score overflow while adding rule `{rule_id}`")
            }
        }
    }
}

impl Error for RiskAssessmentError {}

/// Engine with explicit caller-owned rule weight and confidence resolvers.
pub struct RiskEngine<W, C> {
    thresholds: RiskThresholds,
    weight_for: W,
    confidence_for: C,
}

impl<W, C> RiskEngine<W, C>
where
    W: Fn(&str) -> Option<RuleWeight>,
    C: Fn(&Finding) -> Option<Confidence>,
{
    pub fn new(thresholds: RiskThresholds, weight_for: W, confidence_for: C) -> Self {
        Self {
            thresholds,
            weight_for,
            confidence_for,
        }
    }

    pub fn assess(&self, findings: &[Finding]) -> Result<RiskAssessment, RiskAssessmentError> {
        assess(
            findings,
            self.thresholds,
            &self.weight_for,
            &self.confidence_for,
        )
    }
}

/// Alias emphasizing that this is an assessment engine, not the existing
/// [`super::aggregate`] runtime policy path.
pub type RiskAssessmentEngine<W, C> = RiskEngine<W, C>;

/// Assess findings using explicit resolvers. Duplicate findings are
/// conservatively de-duplicated by `rule_id` (there is no reliable observation
/// key in v1) and retain the maximum confidence for that rule. Contributions
/// are returned in lexicographic rule-id order. Each contribution uses
/// `floor(weight * confidence / 10_000)` (truncation toward zero; values are
/// non-negative), and the bounded operands make the multiplication safe in
/// `u64`.
pub fn assess<W, C>(
    findings: &[Finding],
    thresholds: RiskThresholds,
    weight_for: W,
    confidence_for: C,
) -> Result<RiskAssessment, RiskAssessmentError>
where
    W: Fn(&str) -> Option<RuleWeight>,
    C: Fn(&Finding) -> Option<Confidence>,
{
    let thresholds = thresholds.validate()?;
    let mut findings_by_rule: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        findings_by_rule
            .entry(finding.rule_id.clone())
            .or_default()
            .push(finding);
    }

    let mut contributions = Vec::with_capacity(findings_by_rule.len());
    let mut total = RiskScore::zero();
    for (rule_id, mut observations) in findings_by_rule {
        // The resolver is caller-owned and should be pure. Sorting the
        // observations also gives it a stable invocation order if a resolver
        // tracks calls internally.
        observations.sort_by_key(|finding| {
            (
                finding.detail.as_str(),
                finding.location.as_deref(),
                finding.capability.as_deref(),
                finding.evidence.as_deref(),
                finding.resolved_host.as_deref(),
            )
        });
        let mut confidence = None;
        for finding in observations {
            let resolved =
                confidence_for(finding).ok_or_else(|| RiskAssessmentError::MissingConfidence {
                    rule_id: rule_id.clone(),
                })?;
            confidence =
                Some(confidence.map_or(resolved, |current: Confidence| current.max(resolved)));
        }
        let confidence = confidence.unwrap_or(Confidence::zero());
        let weight = weight_for(&rule_id).ok_or_else(|| RiskAssessmentError::MissingWeight {
            rule_id: rule_id.clone(),
        })?;
        let contribution = RiskScore::new(
            (u64::from(weight.basis_points()) * u64::from(confidence.basis_points()))
                / u64::from(BASIS_POINTS),
        );
        total =
            total
                .checked_add(contribution)
                .ok_or_else(|| RiskAssessmentError::ScoreOverflow {
                    rule_id: rule_id.clone(),
                })?;
        contributions.push(RiskContribution {
            rule_id,
            weight,
            confidence,
            score: contribution,
        });
    }

    let decision = if total < thresholds.approval {
        Decision::Allow
    } else if total < thresholds.block {
        Decision::AllowWithApproval
    } else {
        Decision::Block
    };
    Ok(RiskAssessment {
        score: total,
        decision,
        thresholds,
        contributions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thresholds() -> RiskThresholds {
        RiskThresholds::new(RiskScore::new(50), RiskScore::new(100)).unwrap()
    }

    fn finding(rule_id: &str) -> Finding {
        Finding::new(rule_id, crate::Severity::High, "test")
    }

    #[test]
    fn validates_ranges_and_threshold_boundaries() {
        assert!(Confidence::new(BASIS_POINTS).is_ok());
        assert!(Confidence::new(BASIS_POINTS + 1).is_err());
        assert!(RuleWeight::new(BASIS_POINTS).is_ok());
        assert!(RuleWeight::new(BASIS_POINTS + 1).is_err());
        assert!(RiskThresholds::new(RiskScore::new(10), RiskScore::new(10)).is_err());
        assert!(RiskThresholds::new(RiskScore::new(11), RiskScore::new(10)).is_err());

        let assessment = assess(
            &[finding("a")],
            thresholds(),
            |_| Some(RuleWeight::new(BASIS_POINTS).unwrap()),
            |_| Some(Confidence::new(500).unwrap()),
        )
        .unwrap();
        assert_eq!(assessment.score, RiskScore::new(500));
        assert_eq!(assessment.decision, Decision::Block);

        let at_approval = assess(
            &[finding("a")],
            thresholds(),
            |_| Some(RuleWeight::new(BASIS_POINTS).unwrap()),
            |_| Some(Confidence::new(50).unwrap()),
        )
        .unwrap();
        assert_eq!(at_approval.score, thresholds().approval());
        assert_eq!(at_approval.decision, Decision::AllowWithApproval);

        let at_block = assess(
            &[finding("a")],
            thresholds(),
            |_| Some(RuleWeight::new(BASIS_POINTS).unwrap()),
            |_| Some(Confidence::new(100).unwrap()),
        )
        .unwrap();
        assert_eq!(at_block.score, thresholds().block());
        assert_eq!(at_block.decision, Decision::Block);
    }

    #[test]
    fn deduplicates_max_confidence_and_is_input_order_independent() {
        let first = vec![
            finding("z"),
            Finding::new("a", crate::Severity::High, "low").at("a-low"),
            Finding::new("a", crate::Severity::High, "high").at("a-high"),
        ];
        let second = vec![
            Finding::new("a", crate::Severity::High, "high").at("a-high"),
            finding("z"),
            Finding::new("a", crate::Severity::High, "low").at("a-low"),
        ];
        let result = |items: &[Finding]| {
            assess(
                items,
                thresholds(),
                |id| Some(RuleWeight::new(if id == "a" { 500 } else { 1000 }).unwrap()),
                |finding| match finding.detail.as_str() {
                    "low" => Some(Confidence::new(1000).unwrap()),
                    "high" => Some(Confidence::new(9999).unwrap()),
                    _ => Some(Confidence::new(500).unwrap()),
                },
            )
            .unwrap()
        };
        let a = result(&first);
        let b = result(&second);
        assert_eq!(a, b);
        assert_eq!(a.contributions.len(), 2);
        assert_eq!(a.contributions[0].rule_id, "a");
        assert_eq!(
            a.contributions[0].confidence,
            Confidence::new(9999).unwrap()
        );
        assert_eq!(a.contributions[0].score, RiskScore::new(499));
    }

    #[test]
    fn fractional_contributions_floor_and_freeze_decisions() {
        let floor_thresholds = RiskThresholds::new(RiskScore::new(1), RiskScore::new(2)).unwrap();
        let below_approval = assess(
            &[finding("fractional")],
            floor_thresholds,
            |_| Some(RuleWeight::new(1).unwrap()),
            |_| Some(Confidence::new(9999).unwrap()),
        )
        .unwrap();
        assert_eq!(below_approval.score, RiskScore::zero());
        assert_eq!(below_approval.decision, Decision::Allow);

        let threshold_edge =
            RiskThresholds::new(RiskScore::new(9999), RiskScore::new(10000)).unwrap();
        let at_approval = assess(
            &[finding("fractional")],
            threshold_edge,
            |_| Some(RuleWeight::max()),
            |_| Some(Confidence::new(9999).unwrap()),
        )
        .unwrap();
        assert_eq!(at_approval.score, RiskScore::new(9999));
        assert_eq!(at_approval.decision, Decision::AllowWithApproval);
    }

    #[test]
    fn score_addition_is_checked_at_u64_boundary() {
        assert_eq!(
            RiskScore::new(u64::MAX).checked_add(RiskScore::new(1)),
            None
        );
        assert_eq!(
            RiskScore::new(u64::MAX - 1).checked_add(RiskScore::new(1)),
            Some(RiskScore::new(u64::MAX))
        );
    }

    #[test]
    fn missing_resolvers_are_typed_errors_and_empty_is_stable() {
        let missing_weight = assess(
            &[finding("unknown")],
            thresholds(),
            |_| None,
            |_| Some(Confidence::new(1).unwrap()),
        )
        .unwrap_err();
        assert!(matches!(
            missing_weight,
            RiskAssessmentError::MissingWeight { .. }
        ));
        let missing_confidence = assess(
            &[finding("known")],
            thresholds(),
            |_| Some(RuleWeight::new(1).unwrap()),
            |_| None,
        )
        .unwrap_err();
        assert!(matches!(
            missing_confidence,
            RiskAssessmentError::MissingConfidence { .. }
        ));

        let a_missing_confidence = vec![finding("z"), finding("a")];
        let z_missing_weight = |items: &[Finding]| {
            assess(
                items,
                thresholds(),
                |id| (id == "a").then(|| RuleWeight::new(1).unwrap()),
                |finding| (finding.rule_id == "a").then(|| Confidence::new(1).unwrap()),
            )
            .unwrap_err()
        };
        assert!(matches!(
            z_missing_weight(&a_missing_confidence),
            RiskAssessmentError::MissingConfidence { ref rule_id } if rule_id == "z"
        ));
        assert!(matches!(
            z_missing_weight(&a_missing_confidence.into_iter().rev().collect::<Vec<_>>()),
            RiskAssessmentError::MissingConfidence { ref rule_id } if rule_id == "z"
        ));

        let a_missing_weight = vec![finding("a"), finding("z")];
        let missing_weight_first = |items: &[Finding]| {
            assess(
                items,
                thresholds(),
                |_| None,
                |_| Some(Confidence::new(1).unwrap()),
            )
            .unwrap_err()
        };
        assert!(matches!(
            missing_weight_first(&a_missing_weight),
            RiskAssessmentError::MissingWeight { ref rule_id } if rule_id == "a"
        ));
        assert!(matches!(
            missing_weight_first(&a_missing_weight.into_iter().rev().collect::<Vec<_>>()),
            RiskAssessmentError::MissingWeight { ref rule_id } if rule_id == "a"
        ));

        let empty = assess(&[], thresholds(), |_| None, |_| None).unwrap();
        assert_eq!(empty.score, RiskScore::zero());
        assert_eq!(empty.decision, Decision::Allow);
        assert!(empty.contributions.is_empty());
    }
}
