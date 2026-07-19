//! Bounded OSV query models and resolver boundaries.

pub mod cache;
pub mod client;
pub mod model;
pub mod normalize;
pub mod report;
pub mod resolver;
pub mod severity;

pub use model::{
    AdvisoryEvidence, AdvisoryReference, AffectedEvidence, CoordinateQuery, CoordinateSet,
    NormalizedAdvisory, OsvError, OsvErrorKind, RangeEvidence,
};
pub use normalize::{collect_lockfile_coordinates, normalize_advisory};
pub use severity::{
    normalize_severities, NormalizedSeverity, SeverityEvidence, SeverityLevel, SeveritySource,
};
