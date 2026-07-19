use crate::model::{
    canonical_query_coordinate, parse_modified, query_identity, CoordinateQuery, CoordinateSet,
    NormalizedAdvisory, OsvError, OsvErrorKind, MAX_ID_BYTES,
};
use crate::normalize::validate_normalized_advisory;
use argus_core::PackageCoordinate;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const CACHE_FILE_NAME: &str = "cache-v1.json";
pub const CACHE_LOCK_NAME: &str = ".lock";
pub const CACHE_API_VERSION: &str = "osv-v1";
pub const CACHE_SCHEMA_SET_ID: &str = "argus-osv-schema-2026-07-09-v1";
pub const CACHE_FORMAT_VERSION: u32 = 1;
pub const MAX_CACHE_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_CACHE_ENTRIES: usize = 100_000;
pub const MAX_AGE_SECONDS: u64 = 2_592_000;

pub trait CacheStore {
    fn read(&self, cache_dir: &Path) -> Result<Option<Vec<u8>>, OsvError>;
    fn replace(&self, cache_dir: &Path, canonical_envelope: &[u8]) -> Result<(), OsvError>;
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheQuerySummary {
    pub primary_id: String,
    pub modified: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheEntry {
    pub coordinate: PackageCoordinate,
    pub fetched_at: DateTime<Utc>,
    pub query_summaries: Vec<CacheQuerySummary>,
    pub advisories: Vec<NormalizedAdvisory>,
    pub response_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheEnvelope {
    pub version: u32,
    pub generation: u64,
    pub api_version: String,
    pub schema_set_id: String,
    pub entries: BTreeMap<String, CacheEntry>,
    pub content_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheLookup {
    pub hits: BTreeMap<String, CacheEntry>,
    pub refresh: Vec<CoordinateQuery>,
    pub authorized_stale: bool,
}
pub fn coordinate_cache_key(coordinate: &PackageCoordinate) -> Result<String, OsvError> {
    coordinate
        .validate()
        .map_err(|error| cache_error(format!("invalid cache coordinate: {error}")))?;
    let identity = canonical_bytes(&query_identity(coordinate), "cache coordinate")?;
    let identity = String::from_utf8(identity)
        .map_err(|error| cache_error(format!("canonical coordinate is not UTF-8: {error}")))?;
    Ok(format!(
        "{CACHE_API_VERSION}:{CACHE_SCHEMA_SET_ID}:{identity}"
    ))
}

pub fn finalize_entry(mut entry: CacheEntry) -> Result<CacheEntry, OsvError> {
    normalize_entry(&mut entry)?;
    entry.response_sha256 = response_digest(&entry)?;
    Ok(entry)
}

pub fn finalize_envelope(mut envelope: CacheEnvelope) -> Result<CacheEnvelope, OsvError> {
    validate_envelope_shape(&envelope)?;
    envelope
        .entries
        .iter()
        .try_for_each(|(key, entry)| validate_entry(key, entry))?;
    envelope.content_sha256 = content_digest(&envelope)?;
    ensure_cache_size(canonical_bytes(&envelope, "cache envelope")?.len())?;
    Ok(envelope)
}

pub fn encode_envelope(envelope: &CacheEnvelope) -> Result<Vec<u8>, OsvError> {
    validate_envelope(envelope)?;
    let bytes = canonical_bytes(envelope, "cache envelope")?;
    ensure_cache_size(bytes.len())?;
    Ok(bytes)
}

pub fn decode_envelope(bytes: &[u8], now: DateTime<Utc>) -> Result<CacheEnvelope, OsvError> {
    ensure_cache_size(bytes.len())?;
    let envelope: CacheEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| cache_error(format!("parse cache envelope: {error}")))?;
    validate_envelope(&envelope)?;
    if envelope
        .entries
        .values()
        .any(|entry| entry.fetched_at > now)
    {
        return Err(cache_error("cache entry fetched_at is in the future"));
    }
    Ok(envelope)
}

pub fn ensure_cache_size(size: usize) -> Result<(), OsvError> {
    ensure_limit("cache envelope bytes", size, MAX_CACHE_BYTES)
}
pub fn ensure_entry_count(count: usize) -> Result<(), OsvError> {
    ensure_limit("cache entry count", count, MAX_CACHE_ENTRIES)
}

fn ensure_limit(label: &str, actual: usize, maximum: usize) -> Result<(), OsvError> {
    if actual > maximum {
        return Err(OsvError::new(
            OsvErrorKind::ResourceLimit,
            format!("{label} {actual} exceeds maximum {maximum}"),
        ));
    }
    Ok(())
}
pub fn merge_envelope(
    existing: Option<CacheEnvelope>,
    incoming: impl IntoIterator<Item = CacheEntry>,
    now: DateTime<Utc>,
) -> Result<CacheEnvelope, OsvError> {
    let mut envelope = match existing {
        Some(envelope) => {
            validate_envelope(&envelope)?;
            if envelope
                .entries
                .values()
                .any(|entry| entry.fetched_at > now)
            {
                return Err(cache_error("cache entry fetched_at is in the future"));
            }
            envelope
        }
        None => CacheEnvelope {
            version: CACHE_FORMAT_VERSION,
            generation: 0,
            api_version: CACHE_API_VERSION.to_string(),
            schema_set_id: CACHE_SCHEMA_SET_ID.to_string(),
            entries: BTreeMap::new(),
            content_sha256: String::new(),
        },
    };
    for raw_entry in incoming {
        let entry = finalize_entry(raw_entry)?;
        if entry.fetched_at > now {
            return Err(cache_error(
                "incoming cache entry fetched_at is in the future",
            ));
        }
        let key = coordinate_cache_key(&entry.coordinate)?;
        match envelope.entries.get(&key) {
            Some(current) if current.fetched_at > entry.fetched_at => {}
            Some(current) if current.fetched_at == entry.fetched_at => {
                if current.response_sha256 != entry.response_sha256 {
                    return Err(cache_error(
                        "same-time cache entries have conflicting response digests",
                    ));
                }
            }
            _ => {
                envelope.entries.insert(key, entry);
            }
        }
    }
    ensure_entry_count(envelope.entries.len())?;
    envelope.generation = envelope
        .generation
        .checked_add(1)
        .ok_or_else(|| cache_error("cache generation overflowed"))?;
    finalize_envelope(envelope)
}

pub fn lookup_cache(
    envelope: Option<&CacheEnvelope>,
    coordinates: &CoordinateSet,
    now: DateTime<Utc>,
    max_age_seconds: u64,
    offline: bool,
    allow_stale: bool,
) -> Result<CacheLookup, OsvError> {
    coordinates.validate()?;
    if max_age_seconds > MAX_AGE_SECONDS {
        return Err(OsvError::new(
            OsvErrorKind::InvalidInput,
            format!("max_age_seconds exceeds maximum {MAX_AGE_SECONDS}"),
        ));
    }
    if allow_stale && !offline {
        return Err(OsvError::new(
            OsvErrorKind::InvalidInput,
            "allow_stale requires offline mode",
        ));
    }
    if let Some(envelope) = envelope {
        validate_envelope(envelope)?;
    }
    let mut hits = BTreeMap::new();
    let mut refresh = Vec::new();
    let mut authorized_stale = false;
    for query in &coordinates.queries {
        let key = coordinate_cache_key(&query.coordinate)?;
        let Some(entry) = envelope.and_then(|value| value.entries.get(&key)) else {
            if offline {
                return Err(cache_error("offline cache is missing a queried coordinate"));
            }
            refresh.push(query.clone());
            continue;
        };
        let age = now.signed_duration_since(entry.fetched_at);
        if age < chrono::TimeDelta::zero() {
            return Err(cache_error("cache entry fetched_at is in the future"));
        }
        if age <= chrono::TimeDelta::seconds(max_age_seconds as i64) {
            hits.insert(key, entry.clone());
        } else if offline && allow_stale {
            authorized_stale = true;
            hits.insert(key, entry.clone());
        } else if offline {
            return Err(cache_error(
                "offline cache contains an unauthorized stale entry",
            ));
        } else {
            refresh.push(query.clone());
        }
    }
    Ok(CacheLookup {
        hits,
        refresh,
        authorized_stale,
    })
}
fn normalize_entry(entry: &mut CacheEntry) -> Result<(), OsvError> {
    let identity = query_identity(&entry.coordinate);
    if entry
        .advisories
        .iter()
        .any(|advisory| query_identity(&advisory.coordinate) != identity)
    {
        return Err(cache_error(
            "cached advisory coordinate does not match cache entry",
        ));
    }
    entry.coordinate = canonical_query_coordinate(&entry.coordinate)
        .map_err(|error| cache_error(format!("invalid entry coordinate: {error}")))?;
    for advisory in &mut entry.advisories {
        advisory.coordinate = entry.coordinate.clone();
        advisory.evidence.locators.clear();
    }
    entry.query_summaries.sort();
    if entry
        .query_summaries
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(cache_error("duplicate query summary in cache entry"));
    }
    entry.advisories.sort_by(|left, right| {
        (&left.primary_id, &left.coordinate).cmp(&(&right.primary_id, &right.coordinate))
    });
    if entry
        .advisories
        .windows(2)
        .any(|pair| pair[0].primary_id == pair[1].primary_id)
    {
        return Err(cache_error("duplicate advisory primary ID in cache entry"));
    }
    Ok(())
}
fn validate_entry(key: &str, entry: &CacheEntry) -> Result<(), OsvError> {
    if coordinate_cache_key(&entry.coordinate)? != key {
        return Err(cache_error("cache key does not match entry coordinate"));
    }
    let mut normalized = entry.clone();
    normalize_entry(&mut normalized)?;
    if &normalized != entry {
        return Err(cache_error("cache entry is not in canonical order"));
    }
    let mut summaries = BTreeMap::new();
    for summary in &entry.query_summaries {
        validate_text(
            "query summary primary ID",
            &summary.primary_id,
            MAX_ID_BYTES,
        )?;
        parse_modified(&summary.modified)
            .map_err(|error| cache_error(format!("invalid query summary modified: {error}")))?;
        if summaries
            .insert(summary.primary_id.as_str(), summary.modified.as_str())
            .is_some()
        {
            return Err(cache_error("duplicate query summary primary ID"));
        }
    }
    let mut advisory_ids = BTreeSet::new();
    for advisory in &entry.advisories {
        if advisory.coordinate != entry.coordinate || !advisory.evidence.locators.is_empty() {
            return Err(cache_error(
                "cached advisory coordinate does not match cache entry",
            ));
        }
        validate_text("advisory primary ID", &advisory.primary_id, MAX_ID_BYTES)?;
        if advisory.evidence.affected.is_empty()
            || advisory.evidence.affected.iter().any(|affected| {
                affected.exact_versions.is_empty() && affected.ranges.is_empty()
                    || affected
                        .ranges
                        .iter()
                        .any(|range| range.affected_index != affected.affected_index)
            })
        {
            return Err(cache_error(
                "cached advisory has no matching affected evidence",
            ));
        }
        if !advisory_ids.insert(advisory.primary_id.as_str()) {
            return Err(cache_error("duplicate advisory primary ID"));
        }
        let summary_modified = summaries
            .get(advisory.primary_id.as_str())
            .ok_or_else(|| cache_error("cached advisory has no query summary"))?;
        validate_normalized_advisory(advisory, summary_modified)
            .map_err(|error| cache_error(format!("revalidate cached advisory: {error}")))?;
    }
    if summaries.keys().copied().collect::<BTreeSet<_>>() != advisory_ids {
        return Err(cache_error(
            "query summaries and hydrated advisories do not have identical IDs",
        ));
    }
    validate_digest("response_sha256", &entry.response_sha256)?;
    if response_digest(entry)? != entry.response_sha256 {
        return Err(cache_error("cache entry response digest mismatch"));
    }
    Ok(())
}

fn validate_envelope(envelope: &CacheEnvelope) -> Result<(), OsvError> {
    validate_envelope_shape(envelope)?;
    envelope
        .entries
        .iter()
        .try_for_each(|(key, entry)| validate_entry(key, entry))?;
    validate_digest("content_sha256", &envelope.content_sha256)?;
    if content_digest(envelope)? != envelope.content_sha256 {
        return Err(cache_error("cache envelope content digest mismatch"));
    }
    Ok(())
}
fn validate_envelope_shape(envelope: &CacheEnvelope) -> Result<(), OsvError> {
    if envelope.version != CACHE_FORMAT_VERSION
        || envelope.api_version != CACHE_API_VERSION
        || envelope.schema_set_id != CACHE_SCHEMA_SET_ID
    {
        return Err(cache_error("unsupported cache envelope identity"));
    }
    ensure_entry_count(envelope.entries.len())
}
#[derive(Serialize)]
struct ResponseDomain<'a> {
    query_summaries: &'a [CacheQuerySummary],
    advisories: &'a [NormalizedAdvisory],
}

fn response_digest(entry: &CacheEntry) -> Result<String, OsvError> {
    digest(&ResponseDomain {
        query_summaries: &entry.query_summaries,
        advisories: &entry.advisories,
    })
}
#[derive(Serialize)]
struct ContentDomain<'a> {
    version: u32,
    generation: u64,
    api_version: &'a str,
    schema_set_id: &'a str,
    entries: &'a BTreeMap<String, CacheEntry>,
}

fn content_digest(envelope: &CacheEnvelope) -> Result<String, OsvError> {
    digest(&ContentDomain {
        version: envelope.version,
        generation: envelope.generation,
        api_version: &envelope.api_version,
        schema_set_id: &envelope.schema_set_id,
        entries: &envelope.entries,
    })
}

fn digest(value: &impl Serialize) -> Result<String, OsvError> {
    Ok(hex::encode(Sha256::digest(canonical_bytes(
        value,
        "cache digest domain",
    )?)))
}

fn canonical_bytes(value: &impl Serialize, label: &str) -> Result<Vec<u8>, OsvError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| cache_error(format!("canonicalize {label}: {error}")))
}
fn validate_digest(label: &str, digest: &str) -> Result<(), OsvError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(cache_error(format!("{label} is not lowercase SHA-256")));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, maximum: usize) -> Result<(), OsvError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(cache_error(format!("{label} is invalid")));
    }
    Ok(())
}
fn cache_error(detail: impl Into<String>) -> OsvError {
    OsvError::new(OsvErrorKind::Cache, detail)
}

#[derive(Debug, Clone, Copy)]
pub enum CacheHookPoint<'a> {
    BeforeComponentOpen { index: usize, name: &'a str },
    AfterFinalDirectoryOpen,
    BeforeTargetOpen,
    BeforeRename,
    BeforeDirectorySync,
}

pub trait CacheHooks: Send + Sync {
    fn at(&self, _point: CacheHookPoint<'_>) -> Result<(), OsvError> {
        Ok(())
    }
}

struct NoopHooks;
impl CacheHooks for NoopHooks {}
#[derive(Clone)]
pub struct SecureCache {
    trusted_root: PathBuf,
    hooks: Arc<dyn CacheHooks>,
}

impl SecureCache {
    pub fn new(trusted_root: impl Into<PathBuf>) -> Self {
        Self {
            trusted_root: trusted_root.into(),
            hooks: Arc::new(NoopHooks),
        }
    }

    pub fn with_hooks(trusted_root: impl Into<PathBuf>, hooks: Arc<dyn CacheHooks>) -> Self {
        Self {
            trusted_root: trusted_root.into(),
            hooks,
        }
    }
    pub fn load_at(
        &self,
        cache_dir: &Path,
        now: DateTime<Utc>,
    ) -> Result<Option<CacheEnvelope>, OsvError> {
        self.with_locked_directory(cache_dir, false, |directory| {
            unix::read_target(directory, &*self.hooks)?
                .map(|bytes| decode_envelope(&bytes, now))
                .transpose()
        })
    }
    pub fn commit(
        &self,
        cache_dir: &Path,
        entries: impl IntoIterator<Item = CacheEntry>,
        now: DateTime<Utc>,
    ) -> Result<CacheEnvelope, OsvError> {
        let entries = entries.into_iter().collect::<Vec<_>>();
        self.with_locked_directory(cache_dir, true, |directory| {
            let existing = unix::read_target(directory, &*self.hooks)?
                .map(|bytes| decode_envelope(&bytes, now))
                .transpose()?;
            let merged = merge_envelope(existing, entries, now)?;
            let bytes = encode_envelope(&merged)?;
            unix::write_target(directory, &bytes, &*self.hooks)?;
            Ok(merged)
        })
    }

    #[cfg(unix)]
    fn with_locked_directory<T>(
        &self,
        cache_dir: &Path,
        exclusive: bool,
        operation: impl FnOnce(&rustix::fd::OwnedFd) -> Result<T, OsvError>,
    ) -> Result<T, OsvError> {
        let directory = unix::open_cache_directory(&self.trusted_root, cache_dir, &*self.hooks)?;
        self.hooks.at(CacheHookPoint::AfterFinalDirectoryOpen)?;
        let lock = unix::open_lock(&directory)?;
        unix::lock(&lock, exclusive)?;
        operation(&directory)
    }
    #[cfg(not(unix))]
    fn with_locked_directory<T>(
        &self,
        _cache_dir: &Path,
        _exclusive: bool,
        _operation: impl FnOnce(&()) -> Result<T, OsvError>,
    ) -> Result<T, OsvError> {
        Err(cache_error(
            "secure OSV cache is unsupported on this platform",
        ))
    }
}

impl CacheStore for SecureCache {
    fn read(&self, cache_dir: &Path) -> Result<Option<Vec<u8>>, OsvError> {
        self.with_locked_directory(cache_dir, false, |directory| {
            let Some(bytes) = unix::read_target(directory, &*self.hooks)? else {
                return Ok(None);
            };
            let envelope = decode_envelope(&bytes, Utc::now())?;
            encode_envelope(&envelope).map(Some)
        })
    }
    fn replace(&self, cache_dir: &Path, canonical_envelope: &[u8]) -> Result<(), OsvError> {
        let envelope = decode_envelope(canonical_envelope, Utc::now())?;
        if encode_envelope(&envelope)? != canonical_envelope {
            return Err(cache_error(
                "replacement cache bytes are not RFC 8785 canonical",
            ));
        }
        self.with_locked_directory(cache_dir, true, |directory| {
            unix::read_target(directory, &*self.hooks)?;
            unix::write_target(directory, canonical_envelope, &*self.hooks)
        })
    }
}
#[cfg(not(unix))]
mod unix {
    use super::*;
    fn unsupported<T>() -> Result<T, OsvError> {
        Err(cache_error(
            "secure OSV cache is unsupported on this platform",
        ))
    }
    pub(super) fn read_target(_: &(), _: &dyn CacheHooks) -> Result<Option<Vec<u8>>, OsvError> {
        unsupported()
    }
    pub(super) fn write_target(_: &(), _: &[u8], _: &dyn CacheHooks) -> Result<(), OsvError> {
        unsupported()
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fd::OwnedFd;
    use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags};
    use rustix::io::Errno;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::Component;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    pub(super) fn open_cache_directory(
        trusted_root: &Path,
        cache_dir: &Path,
        hooks: &dyn CacheHooks,
    ) -> Result<OwnedFd, OsvError> {
        let mut directory = fs::open(
            trusted_root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| fs_error("open trusted cache root", error))?;
        let relative = if cache_dir.is_absolute() {
            cache_dir
                .strip_prefix(trusted_root)
                .map_err(|_| cache_error("cache directory is outside trusted root"))?
        } else {
            cache_dir
        };
        for (index, component) in relative.components().enumerate() {
            let Component::Normal(name) = component else {
                return Err(cache_error(
                    "cache directory contains a non-normal component",
                ));
            };
            let name_text = name
                .to_str()
                .ok_or_else(|| cache_error("cache directory component is not UTF-8"))?;
            hooks.at(CacheHookPoint::BeforeComponentOpen {
                index,
                name: name_text,
            })?;
            directory = match fs::openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(opened) => opened,
                Err(Errno::NOENT) => {
                    if let Err(error) = fs::mkdirat(&directory, name, Mode::RWXU) {
                        if error != Errno::EXIST {
                            return Err(fs_error("create cache directory", error));
                        }
                    }
                    fs::openat(
                        &directory,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|error| fs_error("open created cache directory", error))?
                }
                Err(error) => return Err(fs_error("open cache directory component", error)),
            };
        }
        let stat =
            fs::fstat(&directory).map_err(|error| fs_error("inspect cache directory", error))?;
        if stat.st_mode & 0o077 != 0 {
            return Err(cache_error("cache directory permissions are not 0700"));
        }
        Ok(directory)
    }

    pub(super) fn open_lock(directory: &OwnedFd) -> Result<OwnedFd, OsvError> {
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let lock = match fs::openat(directory, CACHE_LOCK_NAME, flags, Mode::empty()) {
            Ok(lock) => lock,
            Err(Errno::NOENT) => fs::openat(
                directory,
                CACHE_LOCK_NAME,
                flags | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            )
            .or_else(|error| {
                if error == Errno::EXIST {
                    fs::openat(directory, CACHE_LOCK_NAME, flags, Mode::empty())
                } else {
                    Err(error)
                }
            })
            .map_err(|error| fs_error("create cache lock", error))?,
            Err(error) => return Err(fs_error("open cache lock", error)),
        };
        ensure_regular(&lock, "cache lock")?;
        Ok(lock)
    }

    pub(super) fn lock(lock: &OwnedFd, exclusive: bool) -> Result<(), OsvError> {
        fs::flock(
            lock,
            if exclusive {
                FlockOperation::LockExclusive
            } else {
                FlockOperation::LockShared
            },
        )
        .map_err(|error| fs_error("lock cache", error))
    }

    pub(super) fn read_target(
        directory: &OwnedFd,
        hooks: &dyn CacheHooks,
    ) -> Result<Option<Vec<u8>>, OsvError> {
        hooks.at(CacheHookPoint::BeforeTargetOpen)?;
        let descriptor = match fs::openat(
            directory,
            CACHE_FILE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(fs_error("open cache target", error)),
        };
        ensure_regular(&descriptor, "cache target")?;
        let stat =
            fs::fstat(&descriptor).map_err(|error| fs_error("inspect cache target", error))?;
        let length = usize::try_from(stat.st_size)
            .map_err(|_| cache_error("cache target has invalid length"))?;
        ensure_cache_size(length)?;
        let mut bytes = Vec::with_capacity(length.min(1024 * 1024));
        File::from(descriptor)
            .take((MAX_CACHE_BYTES as u64) + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| fs_error("read cache target", error))?;
        ensure_cache_size(bytes.len())?;
        Ok(Some(bytes))
    }

    pub(super) fn write_target(
        directory: &OwnedFd,
        bytes: &[u8],
        hooks: &dyn CacheHooks,
    ) -> Result<(), OsvError> {
        ensure_cache_size(bytes.len())?;
        reject_non_regular_target(directory)?;
        let temporary_name = format!(
            ".cache-v1.tmp-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let descriptor = fs::openat(
            directory,
            temporary_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| fs_error("create cache temporary", error))?;
        let result = (|| {
            let mut temporary = File::from(descriptor);
            temporary
                .write_all(bytes)
                .map_err(|error| fs_error("write cache temporary", error))?;
            temporary
                .sync_all()
                .map_err(|error| fs_error("fsync cache temporary", error))?;
            drop(temporary);
            hooks.at(CacheHookPoint::BeforeRename)?;
            fs::renameat(
                directory,
                temporary_name.as_str(),
                directory,
                CACHE_FILE_NAME,
            )
            .map_err(|error| fs_error("replace cache target", error))?;
            hooks.at(CacheHookPoint::BeforeDirectorySync)?;
            fs::fsync(directory).map_err(|error| fs_error("fsync cache directory", error))
        })();
        if result.is_err() {
            let _ = fs::unlinkat(directory, temporary_name.as_str(), AtFlags::empty());
        }
        result
    }

    fn reject_non_regular_target(directory: &OwnedFd) -> Result<(), OsvError> {
        match fs::openat(
            directory,
            CACHE_FILE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => ensure_regular(&descriptor, "cache target"),
            Err(Errno::NOENT) => Ok(()),
            Err(error) => Err(fs_error("validate cache target", error)),
        }
    }

    fn ensure_regular(descriptor: &OwnedFd, label: &str) -> Result<(), OsvError> {
        let stat =
            fs::fstat(descriptor).map_err(|error| fs_error("inspect cache object", error))?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            Err(cache_error(format!("{label} is not a regular file")))
        } else if stat.st_mode & 0o077 != 0 {
            Err(cache_error(format!("{label} permissions are not 0600")))
        } else {
            Ok(())
        }
    }

    fn fs_error(stage: &str, error: impl std::fmt::Display) -> OsvError {
        cache_error(format!("{stage} failed for <argus-osv-cache>: {error}"))
    }
}
