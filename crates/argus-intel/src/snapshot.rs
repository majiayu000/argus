use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[cfg(unix)]
#[path = "atomic_unix.rs"]
mod atomic_unix;

pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;
const MAX_SNAPSHOT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEnvelope {
    pub format_version: u32,
    pub source: String,
    pub revision: String,
    pub schema_versions: Vec<String>,
    pub archive_sha256: String,
    pub records_sha256: String,
    pub imported_at: DateTime<Utc>,
    pub records: Vec<SnapshotRecord>,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotRecordCounts {
    pub active_records: usize,
    pub withdrawn_records: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicCleanupState {
    Pending,
    DurabilityUncertain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicWriteOutcome {
    Committed,
    CommittedWithCleanupWarning {
        backup_name: String,
        state: AtomicCleanupState,
        cause: String,
    },
}

impl SnapshotEnvelope {
    pub fn record_counts(&self) -> SnapshotRecordCounts {
        let withdrawn_records = self
            .records
            .iter()
            .filter(|record| record.withdrawn.is_some())
            .count();
        SnapshotRecordCounts {
            active_records: self.records.len() - withdrawn_records,
            withdrawn_records,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRecord {
    pub advisory_id: String,
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<DateTime<Utc>>,
    pub affected: Vec<SnapshotAffected>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotAffected {
    pub ecosystem: String,
    pub original_ecosystem: String,
    pub canonical_name: String,
    pub original_name: String,
    pub exact_versions: Vec<String>,
    pub ranges: Vec<SnapshotRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRange {
    pub range_type: String,
    pub events: Vec<SnapshotEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
}

#[derive(Serialize)]
struct SnapshotPayload<'a> {
    format_version: u32,
    source: &'a str,
    revision: &'a str,
    schema_versions: &'a [String],
    archive_sha256: &'a str,
    records_sha256: &'a str,
    imported_at: DateTime<Utc>,
    records: &'a [SnapshotRecord],
}

pub(crate) fn records_bytes(records: &[SnapshotRecord]) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(&records).context("canonicalize snapshot records")
}

pub(crate) fn records_digest(records: &[SnapshotRecord]) -> Result<String> {
    Ok(hex::encode(Sha256::digest(records_bytes(records)?)))
}

fn payload_bytes(snapshot: &SnapshotEnvelope) -> Result<Vec<u8>> {
    let payload = SnapshotPayload {
        format_version: snapshot.format_version,
        source: &snapshot.source,
        revision: &snapshot.revision,
        schema_versions: &snapshot.schema_versions,
        archive_sha256: &snapshot.archive_sha256,
        records_sha256: &snapshot.records_sha256,
        imported_at: snapshot.imported_at,
        records: &snapshot.records,
    };
    serde_json_canonicalizer::to_vec(&payload).context("canonicalize snapshot payload")
}

pub(crate) fn snapshot_digest(snapshot: &SnapshotEnvelope) -> Result<String> {
    Ok(hex::encode(Sha256::digest(payload_bytes(snapshot)?)))
}

pub(crate) fn finalize_snapshot(mut snapshot: SnapshotEnvelope) -> Result<SnapshotEnvelope> {
    snapshot.records_sha256 = records_digest(&snapshot.records)?;
    snapshot.snapshot_sha256 = snapshot_digest(&snapshot)?;
    Ok(snapshot)
}

#[cfg(unix)]
pub fn load_snapshot(path: &Path) -> Result<SnapshotEnvelope> {
    let (file, length) = atomic_unix::open_snapshot(path)?;
    if length > MAX_SNAPSHOT_BYTES {
        bail!(
            "snapshot {} exceeds {} byte limit",
            path.display(),
            MAX_SNAPSHOT_BYTES
        );
    }
    let snapshot: SnapshotEnvelope = serde_json::from_reader(file)
        .with_context(|| format!("parse snapshot {}", path.display()))?;
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

#[cfg(not(unix))]
pub fn load_snapshot(path: &Path) -> Result<SnapshotEnvelope> {
    bail!(
        "secure intelligence snapshot loading is unsupported on non-Unix platform for {}",
        path.display()
    )
}

pub(crate) fn validate_snapshot(snapshot: &SnapshotEnvelope) -> Result<()> {
    if snapshot.format_version != SNAPSHOT_FORMAT_VERSION {
        bail!(
            "unsupported intelligence snapshot format version {}",
            snapshot.format_version
        );
    }
    crate::import::validate_source_revision(&snapshot.source, &snapshot.revision)?;
    if snapshot.schema_versions.is_empty()
        || snapshot
            .schema_versions
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        bail!("snapshot schema_versions must be non-empty, sorted, and unique");
    }
    for schema in &snapshot.schema_versions {
        if !crate::osv::SUPPORTED_SCHEMA_VERSIONS.contains(&schema.as_str()) {
            bail!("snapshot contains unsupported OSV schema `{schema}`");
        }
    }
    validate_digest("archive_sha256", &snapshot.archive_sha256)?;
    validate_digest("records_sha256", &snapshot.records_sha256)?;
    validate_digest("snapshot_sha256", &snapshot.snapshot_sha256)?;
    let actual_records = records_digest(&snapshot.records)?;
    if actual_records != snapshot.records_sha256 {
        bail!("snapshot records SHA-256 mismatch");
    }
    let actual_snapshot = snapshot_digest(snapshot)?;
    if actual_snapshot != snapshot.snapshot_sha256 {
        bail!("snapshot envelope SHA-256 mismatch");
    }
    crate::normalize::validate_normalized_records(&snapshot.records)
}

fn validate_digest(label: &str, digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn write_atomic(path: &Path, snapshot: &SnapshotEnvelope) -> Result<AtomicWriteOutcome> {
    atomic_unix::write_atomic(path, snapshot)
}

#[cfg(not(unix))]
pub(crate) fn write_atomic(
    path: &Path,
    _snapshot: &SnapshotEnvelope,
) -> Result<AtomicWriteOutcome> {
    bail!(
        "secure atomic intelligence snapshot replacement is unsupported on non-Unix platform for {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::CANONICAL_SOURCE;
    use chrono::TimeZone;

    fn snapshot_with_record() -> SnapshotEnvelope {
        finalize_snapshot(SnapshotEnvelope {
            format_version: SNAPSHOT_FORMAT_VERSION,
            source: CANONICAL_SOURCE.to_string(),
            revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
            schema_versions: vec!["1.7.4".to_string()],
            archive_sha256: "0".repeat(64),
            records_sha256: String::new(),
            imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            records: vec![SnapshotRecord {
                advisory_id: "MAL-SNAPSHOT-INVARIANT".to_string(),
                aliases: vec!["CVE-2026-1".to_string()],
                withdrawn: None,
                affected: vec![SnapshotAffected {
                    ecosystem: "npm".to_string(),
                    original_ecosystem: "npm".to_string(),
                    canonical_name: "demo".to_string(),
                    original_name: "demo".to_string(),
                    exact_versions: vec!["1.0.0".to_string()],
                    ranges: Vec::new(),
                }],
            }],
            snapshot_sha256: String::new(),
        })
        .unwrap()
    }

    #[test]
    fn snapshot_rejects_empty_affected_and_invalid_alias_text() {
        let mut empty_affected = snapshot_with_record();
        empty_affected.records[0].affected.clear();
        let empty_affected = finalize_snapshot(empty_affected).unwrap();
        assert!(validate_snapshot(&empty_affected)
            .unwrap_err()
            .to_string()
            .contains("no affected packages"));

        let mut invalid_alias = snapshot_with_record();
        invalid_alias.records[0].aliases = vec!["bad\nalias".to_string()];
        let invalid_alias = finalize_snapshot(invalid_alias).unwrap();
        assert!(validate_snapshot(&invalid_alias)
            .unwrap_err()
            .to_string()
            .contains("control character"));
    }
}
