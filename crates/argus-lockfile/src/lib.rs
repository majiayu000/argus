//! Bounded, deterministic parsing contracts for supported dependency lockfiles.
//!
//! This crate is deliberately static: callers provide bytes and a path label,
//! and no parser can invoke a process, transport, or package manager.

mod bounds;
mod context;
mod detect;
mod model;
pub mod parsers;
pub mod policy;
mod scan_targets;

pub use bounds::{
    ensure_canonical_output_size, ensure_record_count, parse_json, parse_toml, parse_yaml,
    BoundedInput, ScalarBudget, MAX_CANONICAL_OUTPUT_BYTES, MAX_INPUT_BYTES, MAX_NESTING_DEPTH,
    MAX_RECORDS, MAX_SCALAR_BYTES, MAX_SCALAR_COUNT,
};
pub use context::evaluate_with_rules_and_context;
pub use detect::{detect_format, DetectionRequest, FormatHint};
pub use model::{
    Coverage, DetectedLockfile, FormatVersion, IntegrityEvidence, IntegrityState, LockfileError,
    LockfileFormat, NormalizedDependency, NormalizedSource, ParseOutput, SourceKind,
};
pub use parsers::{parser_for, LockfileParser};
pub use policy::{evaluate, evaluate_with_rules, PolicyError, PolicyOptions};
pub use scan_targets::{
    build_scan_targets, diff_lockfile_scan_targets, diff_scan_targets, scan_targets,
    LockfileScanConstraint, LockfileScanDelta, LockfileScanOccurrence, LockfileScanTarget,
    LockfileScanTargetChange, LockfileScanTargetClass, LockfileScanTargetKind,
};

/// Detect and fully parse one lockfile through the frozen parser contract.
pub fn parse_lockfile(
    input: &BoundedInput<'_>,
    request: DetectionRequest<'_>,
) -> Result<ParseOutput, LockfileError> {
    let detected = detect_format(input, request)?;
    parser_for(detected.format).parse(input, &detected)
}
