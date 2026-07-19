//! Bounded import and offline matching for the OpenSSF malicious-packages data set.
//!
//! Import is the only network-capable path in this crate. [`IntelDatabase::load`]
//! and matching operate exclusively on a previously verified local snapshot.

mod gem_version;
mod go_version;
mod import;
mod matcher;
mod maven_version;
mod normalize;
mod osv;
mod osv_profile;
mod snapshot;
mod version_number;

pub use import::{
    archive_url, import_snapshot, ArchiveTransport, DownloadMetadata, HttpArchiveTransport,
    ImportLimits, ImportOutcome, ImportRequest, CANONICAL_SOURCE,
};
pub use matcher::{IntelDatabase, MatchResult, RULE_KNOWN_MALICIOUS};
pub use osv::{
    match_osv_affected, parse_osv_record, validate_osv_coordinate, OsvAffected, OsvAffectedMatch,
    OsvEvent, OsvIntervalMatch, OsvPackage, OsvRange, OsvRangeMatch, OsvRecord, OsvReference,
    OsvSeverity, SUPPORTED_SCHEMA_VERSIONS,
};
pub use snapshot::{
    load_snapshot, AtomicCleanupState, AtomicWriteOutcome, SnapshotEnvelope, SnapshotRecord,
    SnapshotRecordCounts,
};
