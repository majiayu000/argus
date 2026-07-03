//! Decision derivation for agent-surface scans. Simpler than the package
//! path: there is no native-build allowlist. Any critical or high finding
//! blocks; medium requires approval; otherwise allow.

use argus_core::{Decision, Finding, Severity};

pub fn derive(findings: &[Finding]) -> Decision {
    let mut has_medium = false;
    for f in findings {
        match f.severity {
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
mod tests {
    use super::*;

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
