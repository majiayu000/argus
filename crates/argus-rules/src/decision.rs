//! Decision derivation from accumulated findings.
//!
//! Rule of thumb (SPEC §10): any high-risk finding blocks. The only
//! downgrade allowed at this milestone is the recognised native-build
//! pattern, which moves a `lifecycle-script` from `Block` to
//! `AllowWithApproval`.

use crate::PackageContext;
use argus_core::{Decision, Finding};
use std::collections::BTreeSet;

const DOWNGRADE_SAFE_RULES: &[&str] = &["lifecycle-script", "known-native-build-pattern"];

pub fn derive(_ctx: &PackageContext, findings: &[Finding]) -> Decision {
    let ids: BTreeSet<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    if ids.is_empty() {
        return Decision::Allow;
    }

    let has_native_build = ids.contains("known-native-build-pattern");
    let has_high_risk = ids.iter().any(|id| !DOWNGRADE_SAFE_RULES.contains(id));

    if has_native_build && !has_high_risk {
        Decision::AllowWithApproval
    } else {
        Decision::Block
    }
}
