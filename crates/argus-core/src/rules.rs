//! Central rule metadata, policy aggregation, and effective-rule APIs.
//!
//! Built-in metadata has exactly one source: the versioned YAML document
//! embedded by [`catalog::EMBEDDED_RULE_CATALOG_YAML`]. Detector
//! implementations remain in their owning crates and are represented by a
//! typed `builtin` matcher rather than being mis-described as regular
//! expressions.

mod catalog;
mod effective;

pub use catalog::{
    CatalogError, CatalogOrigin, DefaultSeverity, HelpUri, MatcherKind, RuleCatalog, RuleDef,
    RuleId, RuleMatcher, RuleParameters, EMBEDDED_RULE_CATALOG_YAML, MAX_CATALOG_BYTES,
    MAX_CATALOG_RULES, MAX_DESCRIPTION_BYTES, MAX_MATCHER_BYTES, MAX_RULE_ID_BYTES,
    RULE_CATALOG_SCHEMA_VERSION,
};
pub use effective::{
    AppliedRuleOverride, DisabledRule, EffectiveRule, EffectiveRuleSet, RuleOverride,
    RuleOverrideAction, RuleSetDigest,
};

use std::sync::OnceLock;

/// Decision-policy class of a rule. Severity overrides never mutate this
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulePolicy {
    /// Structural signal that carries no policy weight at `Severity::Info`.
    InfoOnly,
    /// Bounded anomaly that requires explicit human approval when it is the
    /// only policy-weighted evidence.
    ApprovalOnly,
    /// Native-build signal that may participate in the existing bounded
    /// downgrade path.
    DowngradeSafe,
    /// Any policy-weighted occurrence pushes a package decision to Block.
    Blocking,
}

static BUILTIN_CATALOG: OnceLock<Result<RuleCatalog, CatalogError>> = OnceLock::new();

/// Validate and return the embedded built-in catalog.
///
/// Callers that own startup should propagate this error. Legacy lookup
/// helpers below panic rather than silently falling back when the embedded
/// catalog is invalid.
pub fn builtin_catalog() -> Result<&'static RuleCatalog, CatalogError> {
    match BUILTIN_CATALOG.get_or_init(|| {
        RuleCatalog::parse_yaml(EMBEDDED_RULE_CATALOG_YAML, CatalogOrigin::EmbeddedBuiltin)
    }) {
        Ok(catalog) => Ok(catalog),
        Err(error) => Err(error.clone()),
    }
}

fn required_builtin_catalog() -> &'static RuleCatalog {
    builtin_catalog().unwrap_or_else(|error| panic!("invalid embedded rule catalog: {error}"))
}

/// Look up a rule definition by id.
pub fn rule_def(id: &str) -> Option<&'static RuleDef> {
    required_builtin_catalog().get(id)
}

/// All built-in definitions in deterministic rule-id order.
pub fn all_rules() -> &'static [RuleDef] {
    required_builtin_catalog().rules()
}

/// Decision-policy class for a rule id. Unregistered ids fail closed.
pub fn policy(id: &str) -> RulePolicy {
    rule_def(id).map_or(RulePolicy::Blocking, |rule| rule.policy_class)
}

/// How findings are folded into a [`crate::Decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationProfile {
    /// Package scans use immutable policy classes.
    PolicyDriven,
    /// Agent-surface scans use emitted severity.
    SeverityDriven,
}

pub fn aggregate(findings: &[crate::Finding], profile: AggregationProfile) -> crate::Decision {
    match profile {
        AggregationProfile::PolicyDriven => aggregate_policy_driven(findings),
        AggregationProfile::SeverityDriven => aggregate_severity_driven(findings),
    }
}

fn aggregate_policy_driven(findings: &[crate::Finding]) -> crate::Decision {
    use crate::{Decision, Severity};
    use std::collections::BTreeSet;

    if findings.is_empty() {
        return Decision::Allow;
    }
    let decision_ids: BTreeSet<&str> = findings
        .iter()
        .filter(|finding| {
            finding.severity != Severity::Info || policy(&finding.rule_id) != RulePolicy::InfoOnly
        })
        .map(|finding| finding.rule_id.as_str())
        .collect();
    if decision_ids.is_empty() {
        return Decision::Allow;
    }
    let residual_ids: BTreeSet<&str> = decision_ids
        .iter()
        .copied()
        .filter(|id| policy(id) != RulePolicy::ApprovalOnly)
        .collect();
    if residual_ids.is_empty() {
        return Decision::AllowWithApproval;
    }
    let has_native_build = residual_ids.contains("known-native-build-pattern");
    let has_high_risk = residual_ids
        .iter()
        .any(|id| policy(id) != RulePolicy::DowngradeSafe);
    if has_native_build && !has_high_risk {
        Decision::AllowWithApproval
    } else {
        Decision::Block
    }
}

fn aggregate_severity_driven(findings: &[crate::Finding]) -> crate::Decision {
    use crate::{Decision, Severity};

    let mut has_medium = false;
    for finding in findings {
        match finding.severity {
            Severity::Critical | Severity::High => return Decision::Block,
            Severity::Medium => has_medium = true,
            Severity::Low | Severity::Info => {}
        }
    }
    if has_medium {
        Decision::AllowWithApproval
    } else {
        Decision::Allow
    }
}

#[cfg(test)]
mod tests;
