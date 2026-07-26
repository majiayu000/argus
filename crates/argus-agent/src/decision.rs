//! Decision derivation for agent-surface scans. The actual fold lives in
//! `argus_core::rules::aggregate` (SeverityDriven profile: no native-build
//! allowlist; Critical/High block, Medium requires approval).

use argus_core::rules::{aggregate, AggregationProfile};
use argus_core::{Decision, Finding};

pub fn derive(findings: &[Finding]) -> Decision {
    aggregate(findings, AggregationProfile::SeverityDriven)
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::Severity;

    #[test]
    fn severity_maps_to_decision() {
        let critical = Finding::new("AGT-01", Severity::Critical, "x");
        let medium = Finding::new("AGT-05", Severity::Medium, "x");
        let info = Finding::new("AGT-05", Severity::Info, "x");
        assert_eq!(derive(&[critical, medium.clone()]), Decision::Block);
        assert_eq!(derive(&[medium]), Decision::AllowWithApproval);
        assert_eq!(derive(&[info]), Decision::Allow);
        assert_eq!(derive(&[]), Decision::Allow);
    }
}
