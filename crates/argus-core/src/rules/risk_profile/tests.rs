use super::*;
use crate::rules::risk::RiskScore;
use crate::{Decision, Finding};

fn finding(rule_id: &str, severity: Severity) -> Finding {
    Finding::new(rule_id, severity, "test finding")
}

fn assess(findings: &[Finding]) -> RiskAssessment {
    assess_by_severity(findings, default_thresholds()).expect("assessment succeeds")
}

// ---------------------------------------------------------------------------
// The GH-146 complaint: Low and Critical must stop being interchangeable.
// ---------------------------------------------------------------------------

#[test]
fn severity_changes_the_score_and_the_decision() {
    assert_eq!(
        assess(&[finding("r", Severity::Low)]).decision,
        Decision::Allow
    );
    assert_eq!(
        assess(&[finding("r", Severity::Medium)]).decision,
        Decision::AllowWithApproval
    );
    assert_eq!(
        assess(&[finding("r", Severity::High)]).decision,
        Decision::Block
    );
    assert_eq!(
        assess(&[finding("r", Severity::Critical)]).decision,
        Decision::Block
    );

    // The scores are ordered, not merely the decisions.
    let scores: Vec<u64> = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]
    .iter()
    .map(|severity| assess(&[finding("r", *severity)]).score.value())
    .collect();
    assert!(
        scores.windows(2).all(|pair| pair[0] < pair[1]),
        "scores must be strictly increasing in severity: {scores:?}"
    );
}

#[test]
fn single_finding_decisions_match_the_severity_driven_profile() {
    // Enabling scoring must not surprise anyone: for one finding it reproduces
    // exactly what `AggregationProfile::SeverityDriven` already decided.
    for (severity, expected) in [
        (Severity::Critical, Decision::Block),
        (Severity::High, Decision::Block),
        (Severity::Medium, Decision::AllowWithApproval),
        (Severity::Low, Decision::Allow),
        (Severity::Info, Decision::Allow),
    ] {
        let findings = [finding("r", severity)];
        assert_eq!(
            assess(&findings).decision,
            expected,
            "severity {severity:?} disagreed with the severity profile"
        );
        assert_eq!(crate::rules::aggregate_severity_driven(&findings), expected);
    }
}

// ---------------------------------------------------------------------------
// Accumulation is the actual improvement over set algebra.
// ---------------------------------------------------------------------------

#[test]
fn independent_medium_risks_accumulate_into_a_block() {
    // Set algebra saw "the medium bucket is non-empty" and stopped. Two
    // distinct medium-risk behaviours are worse than one.
    let two_mediums = [
        finding("obfuscated-source", Severity::Medium),
        finding("lifecycle-script", Severity::Medium),
    ];
    assert_eq!(assess(&two_mediums).decision, Decision::Block);
    // The pre-existing severity profile stops at approval for the same input.
    assert_eq!(
        crate::rules::aggregate_severity_driven(&two_mediums),
        Decision::AllowWithApproval
    );
}

#[test]
fn low_risks_do_not_accumulate_into_a_block_as_easily() {
    let two_lows = [
        finding("rule-a", Severity::Low),
        finding("rule-b", Severity::Low),
    ];
    assert_eq!(assess(&two_lows).decision, Decision::Allow);

    let four_lows = [
        finding("rule-a", Severity::Low),
        finding("rule-b", Severity::Low),
        finding("rule-c", Severity::Low),
        finding("rule-d", Severity::Low),
    ];
    assert_eq!(assess(&four_lows).decision, Decision::AllowWithApproval);
}

#[test]
fn repeated_observations_of_one_rule_count_once() {
    // The contract de-duplicates by rule id: a rule that fires on 50 files is
    // one risk, not 50. Otherwise a noisy detector could block anything.
    let many = vec![finding("credential-access", Severity::Medium); 50];
    assert_eq!(
        assess(&many).decision,
        Decision::AllowWithApproval,
        "repeated observations of one rule must not accumulate"
    );
    assert_eq!(assess(&many).contributions.len(), 1);
}

#[test]
fn a_rules_highest_severity_decides_its_weight() {
    // The same rule firing at Info elsewhere must not discount its Critical.
    let mixed = [
        finding("proc-macro-network", Severity::Info),
        finding("proc-macro-network", Severity::Critical),
    ];
    assert_eq!(assess(&mixed).decision, Decision::Block);
    assert_eq!(
        assess(&mixed).score.value(),
        severity_weight_basis_points(Severity::Critical) as u64
    );
}

// ---------------------------------------------------------------------------
// Info is a disclosure, not risk.
// ---------------------------------------------------------------------------

#[test]
fn info_findings_contribute_zero_but_stay_visible() {
    let infos = [
        finding("maven-bytecode-not-inspected", Severity::Info),
        finding("go-integrity-unverified", Severity::Info),
    ];
    let assessment = assess(&infos);
    assert_eq!(assessment.decision, Decision::Allow);
    assert_eq!(assessment.score.value(), 0);
    // Still enumerated: a zero contribution is a statement, not an omission.
    assert_eq!(assessment.contributions.len(), 2);
    assert!(assessment
        .contributions
        .iter()
        .all(|contribution| contribution.score.value() == 0));
}

#[test]
fn no_findings_scores_zero_and_allows() {
    let assessment = assess(&[]);
    assert_eq!(assessment.score.value(), 0);
    assert_eq!(assessment.decision, Decision::Allow);
    assert!(assessment.contributions.is_empty());
}

// ---------------------------------------------------------------------------
// Determinism and thresholds.
// ---------------------------------------------------------------------------

#[test]
fn contributions_are_deterministic_regardless_of_finding_order() {
    let forward = [
        finding("z-rule", Severity::High),
        finding("a-rule", Severity::Low),
        finding("m-rule", Severity::Medium),
    ];
    let reversed: Vec<Finding> = forward.iter().rev().cloned().collect();

    let left = assess(&forward);
    let right = assess(&reversed);
    assert_eq!(left.score, right.score);
    assert_eq!(left.decision, right.decision);
    let ids: Vec<&str> = left
        .contributions
        .iter()
        .map(|contribution| contribution.rule_id.as_str())
        .collect();
    assert_eq!(ids, ["a-rule", "m-rule", "z-rule"]);
}

#[test]
fn custom_thresholds_move_the_boundaries() {
    let strict =
        RiskThresholds::new(RiskScore::new(500), RiskScore::new(1_000)).expect("valid thresholds");
    // A single Low is 1,000 basis points, which now blocks.
    assert_eq!(
        assess_by_severity(&[finding("r", Severity::Low)], strict)
            .expect("assessment succeeds")
            .decision,
        Decision::Block
    );

    let lenient = RiskThresholds::new(RiskScore::new(20_000), RiskScore::new(30_000))
        .expect("valid thresholds");
    assert_eq!(
        assess_by_severity(&[finding("r", Severity::Critical)], lenient)
            .expect("assessment succeeds")
            .decision,
        Decision::Allow
    );
}

#[test]
fn thresholds_are_inclusive_at_the_boundary() {
    let assessment = assess(&[finding("r", Severity::Medium)]);
    assert_eq!(assessment.score.value(), DEFAULT_APPROVAL_THRESHOLD);
    assert_eq!(assessment.decision, Decision::AllowWithApproval);

    let block = assess(&[finding("r", Severity::High)]);
    assert_eq!(block.score.value(), DEFAULT_BLOCK_THRESHOLD);
    assert_eq!(block.decision, Decision::Block);
}

#[test]
fn default_thresholds_are_ordered() {
    let thresholds = default_thresholds();
    assert!(thresholds.approval() < thresholds.block());
}
