//! Decision derivation from accumulated findings. The actual fold lives
//! in `argus_core::rules::aggregate` (PolicyDriven profile); this module
//! keeps the package-facing API and its regression tests.
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
use argus_core::rules::{aggregate, AggregationProfile};
use argus_core::{Decision, Finding};

pub fn derive(_ctx: &PackageContext, findings: &[Finding]) -> Decision {
    derive_from_findings(findings)
}

/// Standalone form used by `argus-fetch` after it appends provenance
/// findings to the report produced by `scan_package_dir`. Identical
/// semantics to [`derive`] — split off so callers that don't have a
/// `PackageContext` can still recompute the decision.
pub fn derive_from_findings(findings: &[Finding]) -> Decision {
    aggregate(findings, AggregationProfile::PolicyDriven)
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
    fn sigstore_info_only_findings_are_allow() {
        let findings = [
            Finding::new("provenance-signature-verified", Severity::Info, ""),
            Finding::new("provenance-signature-untrusted-issuer", Severity::Info, ""),
            Finding::new("provenance-signature-unverified", Severity::Info, ""),
        ];
        assert_eq!(derive_from_findings(&findings), Decision::Allow);
    }

    #[test]
    fn high_severity_info_only_rule_still_blocks() {
        assert_eq!(
            derive_from_findings(&[Finding::new(
                "provenance-signature-unverified",
                Severity::High,
                ""
            )]),
            Decision::Block
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

    #[test]
    fn anomaly_decision_requires_approval_for_closed_anomaly_set() {
        let findings = [
            Finding::new("version-shape-anomaly", Severity::Medium, ""),
            Finding::new("rapid-publish-window", Severity::Medium, ""),
            Finding::new("missing-provenance", Severity::Info, ""),
        ];
        assert_eq!(derive_from_findings(&findings), Decision::AllowWithApproval);
    }

    #[test]
    fn anomaly_decision_unassessed_set_is_allow() {
        let findings = [
            Finding::new("npm-version-shape-unassessed", Severity::Info, ""),
            Finding::new("npm-rapid-publish-unassessed", Severity::Info, ""),
        ];
        assert_eq!(derive_from_findings(&findings), Decision::Allow);
    }

    #[test]
    fn anomaly_decision_preserves_native_build_approval() {
        let findings = [
            f("lifecycle-script"),
            Finding::new("known-native-build-pattern", Severity::Info, ""),
            Finding::new("version-shape-anomaly", Severity::Medium, ""),
        ];
        assert_eq!(derive_from_findings(&findings), Decision::AllowWithApproval);
    }

    #[test]
    fn anomaly_decision_never_overrides_residual_block() {
        let findings = [
            f("remote-download"),
            Finding::new("rapid-publish-window", Severity::Medium, ""),
        ];
        assert_eq!(derive_from_findings(&findings), Decision::Block);
    }

    #[test]
    fn lockfile_info_and_weak_decisions_match_policy_contract() {
        assert_eq!(
            derive_from_findings(&[Finding::new(
                "lockfile-integrity-unavailable",
                Severity::Info,
                ""
            )]),
            Decision::Allow
        );
        assert_eq!(
            derive_from_findings(&[Finding::new(
                "lockfile-integrity-weak",
                Severity::Medium,
                ""
            )]),
            Decision::AllowWithApproval
        );
        assert_eq!(
            derive_from_findings(&[
                Finding::new("lockfile-integrity-weak", Severity::Medium, ""),
                Finding::new("lockfile-integrity-invalid", Severity::Critical, "")
            ]),
            Decision::Block
        );
    }
}
