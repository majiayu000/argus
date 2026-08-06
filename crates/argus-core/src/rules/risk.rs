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
}

/// Thresholds for the three decisions. A score below `approval` allows;
/// scores at or above `approval` but below `block` require approval; scores at
/// or above `block` are blocked. `approval < block` is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskThresholds {
    pub approval: RiskScore,
    pub block: RiskScore,
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
/// are returned in lexicographic rule-id order.
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
    let mut confidence_by_rule: BTreeMap<String, Confidence> = BTreeMap::new();
    for finding in findings {
        let confidence =
            confidence_for(finding).ok_or_else(|| RiskAssessmentError::MissingConfidence {
                rule_id: finding.rule_id.clone(),
            })?;
        confidence_by_rule
            .entry(finding.rule_id.clone())
            .and_modify(|existing| *existing = (*existing).max(confidence))
            .or_insert(confidence);
    }

    let mut contributions = Vec::with_capacity(confidence_by_rule.len());
    let mut total = RiskScore::zero();
    for (rule_id, confidence) in confidence_by_rule {
        let weight = weight_for(&rule_id).ok_or_else(|| RiskAssessmentError::MissingWeight {
            rule_id: rule_id.clone(),
        })?;
        let contribution = RiskScore::new(
            (u64::from(weight.basis_points()) * u64::from(confidence.basis_points()))
                / u64::from(BASIS_POINTS),
        );
        total = RiskScore::new(total.value().checked_add(contribution.value()).ok_or_else(
            || RiskAssessmentError::ScoreOverflow {
                rule_id: rule_id.clone(),
            },
        )?);
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
        let first = vec![finding("z"), finding("a"), finding("a")];
        let second = vec![finding("a"), finding("z"), finding("a")];
        let result = |items: &[Finding]| {
            assess(
                items,
                thresholds(),
                |id| Some(RuleWeight::new(if id == "a" { 500 } else { 1000 }).unwrap()),
                |finding| {
                    Some(Confidence::new(if finding.rule_id == "a" { 1000 } else { 500 }).unwrap())
                },
            )
            .unwrap()
        };
        let a = result(&first);
        let b = result(&second);
        assert_eq!(a, b);
        assert_eq!(a.contributions.len(), 2);
        assert_eq!(a.contributions[0].rule_id, "a");
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

        let empty = assess(&[], thresholds(), |_| None, |_| None).unwrap();
        assert_eq!(empty.score, RiskScore::zero());
        assert_eq!(empty.decision, Decision::Allow);
        assert!(empty.contributions.is_empty());
    }
}
