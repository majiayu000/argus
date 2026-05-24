//! Binary-file detection. Fires when the package bundles native artifacts
//! that would be loaded or executed at install/runtime.

use crate::{has_native_bin_ext, PackageContext};
use safepm_core::{Finding, Severity};

pub fn run(ctx: &PackageContext, findings: &mut Vec<Finding>) {
    let mut matched: Vec<String> = Vec::new();

    for rel in &ctx.binary_files {
        matched.push(rel.clone());
    }
    for file in &ctx.text_files {
        if has_native_bin_ext(&file.rel) {
            matched.push(file.rel.clone());
        }
    }

    matched.sort();
    matched.dedup();

    for rel in matched {
        findings.push(
            Finding::new(
                "binary-file",
                Severity::High,
                "package ships a native binary artifact",
            )
            .at(&rel),
        );
    }
}
