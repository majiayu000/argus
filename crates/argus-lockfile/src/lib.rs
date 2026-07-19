//! Bounded, deterministic parsing contracts for supported dependency lockfiles.
//!
//! This crate is deliberately static: callers provide bytes and a path label,
//! and no parser can invoke a process, transport, or package manager.

mod bounds;
mod detect;
mod model;
pub mod parsers;
pub mod policy;

pub use bounds::{
    ensure_canonical_output_size, ensure_record_count, parse_json, parse_toml, parse_yaml,
    BoundedInput, ScalarBudget, MAX_CANONICAL_OUTPUT_BYTES, MAX_INPUT_BYTES, MAX_NESTING_DEPTH,
    MAX_RECORDS, MAX_SCALAR_BYTES, MAX_SCALAR_COUNT,
};
pub use detect::{detect_format, DetectionRequest, FormatHint};
pub use model::{
    Coverage, DetectedLockfile, FormatVersion, IntegrityEvidence, IntegrityState, LockfileError,
    LockfileFormat, NormalizedDependency, NormalizedSource, ParseOutput, SourceKind,
};
pub use parsers::{parser_for, LockfileParser};
pub use policy::{evaluate, PolicyError, PolicyOptions};

/// Detect and fully parse one lockfile through the frozen parser contract.
pub fn parse_lockfile(
    input: &BoundedInput<'_>,
    request: DetectionRequest<'_>,
) -> Result<ParseOutput, LockfileError> {
    let detected = detect_format(input, request)?;
    parser_for(detected.format).parse(input, &detected)
}
