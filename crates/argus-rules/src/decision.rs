//! Decision derivation from accumulated findings.
//!
//! Rule of thumb (SPEC §10): any high-risk finding blocks. Two downgrade
//! paths exist:
//!
//! - **Allow** when every finding is purely informational (e.g.
//!   `missing-provenance` on a package that simply was not published with
//!   OIDC). These rules carry no policy weight on their own.
//! - **AllowWithApproval** when the only non-info findings are a
//!   `lifecycle-script` paired with a `known-native-build-pattern`.
//!   esbuild, sharp, fsevents and similar legitimate native-build packages
//!   land here. A human reviewer still has to opt in before install.

use crate::PackageContext;
use argus_core::{Decision, Finding};
use std::collections::BTreeSet;

/// Rules that never push the decision toward block on their own.
/// `missing-provenance` is a recommendation, not a verdict — many packages
/// predate OIDC publishing.
const INFO_ONLY_RULES: &[&str] = &["missing-provenance", "provenance-verified-subject"];

/// Rules that, when paired with `known-native-build-pattern`, drop the
/// decision from Block to AllowWithApproval.
const DOWNGRADE_SAFE_RULES: &[&str] = &["lifecycle-script", "known-native-build-pattern"];

pub fn derive(_ctx: &PackageContext, findings: &[Finding]) -> Decision {
    derive_from_findings(findings)
}

/// Standalone form used by `argus-fetch` after it appends provenance
/// findings to the report produced by `scan_package_dir`. Identical
/// semantics to [`derive`] — split off so callers that don't have a
/// `PackageContext` can still recompute the decision.
pub fn derive_from_findings(findings: &[Finding]) -> Decision {
    let ids: BTreeSet<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    if ids.is_empty() {
        return Decision::Allow;
    }

    // Strip pure-info rules; they do not influence the decision.
    let decision_ids: BTreeSet<&str> = ids
        .iter()
        .copied()
        .filter(|id| !INFO_ONLY_RULES.contains(id))
        .collect();

    if decision_ids.is_empty() {
        return Decision::Allow;
    }

    let has_native_build = decision_ids.contains("known-native-build-pattern");
    let has_high_risk = decision_ids
        .iter()
        .any(|id| !DOWNGRADE_SAFE_RULES.contains(id));

    if has_native_build && !has_high_risk {
        Decision::AllowWithApproval
    } else {
        Decision::Block
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::Severity;

    fn f(rule: &str) -> Finding {
        Finding::new(rule, Severity::High, "x")
    }

    #[test]
    fn empty_is_allow() {
        assert_eq!(derive_from_findings(&[]), Decision::Allow);
    }

    #[test]
    fn only_missing_provenance_is_allow() {
        assert_eq!(
            derive_from_findings(&[Finding::new("missing-provenance", Severity::Info, "")]),
            Decision::Allow
        );
    }

    #[test]
    fn provenance_verified_subject_alone_is_allow() {
        assert_eq!(
            derive_from_findings(&[Finding::new(
                "provenance-verified-subject",
                Severity::Info,
                ""
            )]),
            Decision::Allow
        );
    }

    #[test]
    fn provenance_subject_mismatch_blocks() {
        assert_eq!(
            derive_from_findings(&[f("provenance-subject-mismatch")]),
            Decision::Block
        );
    }

    #[test]
    fn lifecycle_plus_native_build_plus_provenance_ok_is_approval() {
        let findings = vec![
            f("lifecycle-script"),
            Finding::new("known-native-build-pattern", Severity::Info, ""),
            Finding::new("provenance-verified-subject", Severity::Info, ""),
        ];
        assert_eq!(derive_from_findings(&findings), Decision::AllowWithApproval);
    }

    #[test]
    fn high_risk_rule_still_blocks_even_with_provenance_ok() {
        let findings = vec![
            f("remote-download"),
            Finding::new("provenance-verified-subject", Severity::Info, ""),
        ];
        assert_eq!(derive_from_findings(&findings), Decision::Block);
    }
}
