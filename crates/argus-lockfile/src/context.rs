//! Context-aware lockfile evaluation boundary.

use crate::{
    ensure_canonical_output_size, policy::evaluate, BoundedInput, ParseOutput, PolicyError,
    PolicyOptions,
};
use argus_core::{ExecutionContext, ScanReport};
use argus_rules::RuleSession;
use std::path::Path;

/// Carry the invocation context through the lockfile path.
///
/// One bounded lockfile has no useful local parallel unit; OSV work after
/// coordinate collection reuses this same context at the caller.
pub fn evaluate_with_rules_and_context(
    output: &ParseOutput,
    path: &Path,
    options: &PolicyOptions,
    input: &BoundedInput<'_>,
    rules: &RuleSession,
    _execution: &ExecutionContext,
) -> Result<ScanReport, PolicyError> {
    let mut report = evaluate(output, path, options)?;
    rules
        .scan_bytes(input.path_label(), input.bytes(), &mut report.findings)
        .map_err(|error| PolicyError::RuleExecution(error.to_string()))?;
    rules
        .validate_external_limits(&report.findings)
        .map_err(|error| PolicyError::RuleExecution(error.to_string()))?;
    rules.finalize_package(&mut report);
    let canonical = serde_json_canonicalizer::to_vec(&report.findings)
        .map_err(|error| PolicyError::Canonicalization(error.to_string()))?;
    ensure_canonical_output_size(canonical.len()).map_err(PolicyError::CanonicalOutputLimit)?;
    Ok(report)
}
