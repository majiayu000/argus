//! Bounded import and offline matching for the OpenSSF malicious-packages data set.
//!
//! Import is the only network-capable path in this crate. [`IntelDatabase::load`]
//! and matching operate exclusively on a previously verified local snapshot.

mod import;
mod matcher;
mod normalize;
mod snapshot;

pub use import::{
    archive_url, import_snapshot, ArchiveTransport, DownloadMetadata, HttpArchiveTransport,
    ImportLimits, ImportOutcome, ImportRequest, CANONICAL_SOURCE,
};
pub use matcher::{IntelDatabase, MatchResult, RULE_KNOWN_MALICIOUS};
pub use snapshot::{
    load_snapshot, AtomicCleanupState, AtomicWriteOutcome, SnapshotEnvelope, SnapshotRecord,
    SnapshotRecordCounts,
};
