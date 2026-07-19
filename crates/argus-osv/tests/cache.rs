#![cfg(unix)]

use argus_core::{Ecosystem, PackageCoordinate};
use argus_osv::cache::{
    coordinate_cache_key, decode_envelope, encode_envelope, ensure_cache_size, ensure_entry_count,
    finalize_entry, lookup_cache, merge_envelope, CacheEntry, CacheEnvelope, CacheHookPoint,
    CacheHooks, CacheQuerySummary, CacheStore, SecureCache, CACHE_FILE_NAME, CACHE_LOCK_NAME,
    MAX_CACHE_BYTES, MAX_CACHE_ENTRIES,
};
use argus_osv::model::{
    AdvisoryEvidence, AffectedEvidence, CoordinateQuery, CoordinateSet, NormalizedAdvisory,
    OsvError, OsvErrorKind,
};
use argus_osv::severity::{NormalizedSeverity, SeverityLevel};
use chrono::{DateTime, TimeZone, Utc};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "argus-osv-{label}-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn time(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 19, 10, 0, second).unwrap()
}

fn coordinate(name: &str) -> PackageCoordinate {
    PackageCoordinate::new(Ecosystem::Npm, name, "1.2.3").unwrap()
}

fn entry(name: &str, advisory_id: &str, fetched_at: DateTime<Utc>) -> CacheEntry {
    let coordinate = coordinate(name);
    let advisory = NormalizedAdvisory {
        coordinate: coordinate.clone(),
        primary_id: advisory_id.to_string(),
        aliases: vec![],
        evidence: AdvisoryEvidence {
            locators: vec!["package-lock.json:1".to_string()],
            affected: vec![AffectedEvidence {
                affected_index: 0,
                exact_versions: vec!["1.2.3".to_string()],
                ranges: vec![],
            }],
        },
        severity: NormalizedSeverity {
            level: SeverityLevel::Unknown,
            base_score: None,
            evidence: vec![],
        },
        references: vec![],
        batch_summary_modified: "2026-07-19T10:00:00Z".to_string(),
        detail_modified: "2026-07-19T10:00:00Z".to_string(),
        database_modified: time(0),
        published: None,
        source_url: format!("https://api.osv.dev/v1/vulns/{advisory_id}"),
    };
    CacheEntry {
        coordinate,
        fetched_at,
        query_summaries: vec![CacheQuerySummary {
            primary_id: advisory_id.to_string(),
            modified: "2026-07-19T10:00:00Z".to_string(),
        }],
        advisories: vec![advisory],
        response_sha256: String::new(),
    }
}

fn query_set(names: &[&str]) -> CoordinateSet {
    CoordinateSet::new(
        names
            .iter()
            .map(|name| CoordinateQuery::new(coordinate(name), Vec::new()).unwrap())
            .collect(),
        0,
    )
    .unwrap()
}

fn noncanonical(envelope: &CacheEnvelope) -> Vec<u8> {
    format!(
        "{{\"content_sha256\":{},\"entries\":{},\"schema_set_id\":{},\
         \"api_version\":{},\"generation\":{},\"version\":{}}}",
        serde_json::to_string(&envelope.content_sha256).unwrap(),
        serde_json::to_string(&envelope.entries).unwrap(),
        serde_json::to_string(&envelope.schema_set_id).unwrap(),
        serde_json::to_string(&envelope.api_version).unwrap(),
        envelope.generation,
        envelope.version
    )
    .into_bytes()
}

#[test]
fn cache_contract_digest_domains_canonical_order_and_bounds() {
    let now = time(5);
    let first = finalize_entry(entry("zeta", "GHSA-Z", time(1))).unwrap();
    let second = finalize_entry(entry("alpha", "GHSA-A", time(2))).unwrap();
    let envelope = merge_envelope(None, [first, second], now).unwrap();
    let bytes = encode_envelope(&envelope).unwrap();
    let decoded = decode_envelope(&bytes, now).unwrap();
    assert_eq!(decoded, envelope);
    assert_eq!(encode_envelope(&decoded).unwrap(), bytes);

    let mut unordered = entry("order", "GHSA-Z", time(1));
    let other = entry("order", "GHSA-A", time(1));
    unordered
        .query_summaries
        .extend(other.query_summaries.clone());
    unordered.advisories.extend(other.advisories.clone());
    let mut reversed = unordered.clone();
    reversed.query_summaries.reverse();
    reversed.advisories.reverse();
    assert_eq!(
        finalize_entry(unordered).unwrap(),
        finalize_entry(reversed).unwrap(),
        "raw response ordering changed canonical cache content"
    );

    let reordered = noncanonical(&envelope);
    assert_ne!(reordered, bytes);
    assert_eq!(decode_envelope(&reordered, now).unwrap(), envelope);
    let error = SecureCache::new("/").replace(Path::new("unused"), &reordered);
    assert!(error.is_err(), "non-canonical replacement was accepted");

    let mut tampered = envelope.clone();
    tampered.entries.values_mut().next().unwrap().fetched_at = time(3);
    assert!(decode_envelope(&serde_json::to_vec(&tampered).unwrap(), now).is_err());
    assert!(ensure_cache_size(MAX_CACHE_BYTES).is_ok());
    assert!(ensure_cache_size(MAX_CACHE_BYTES + 1).is_err());
    assert!(ensure_entry_count(MAX_CACHE_ENTRIES).is_ok());
    assert!(ensure_entry_count(MAX_CACHE_ENTRIES + 1).is_err());
}

#[test]
fn cache_contract_generation_merge_and_same_time_conflict() {
    let now = time(9);
    let initial = merge_envelope(None, [entry("demo", "GHSA-A", time(1))], now).unwrap();
    assert_eq!(initial.generation, 1);
    let older = merge_envelope(
        Some(initial.clone()),
        [entry("demo", "GHSA-OLD", time(0))],
        now,
    )
    .unwrap();
    assert_eq!(older.generation, 2);
    assert_eq!(
        older.entries.values().next().unwrap().advisories[0].primary_id,
        "GHSA-A"
    );
    let idempotent =
        merge_envelope(Some(older.clone()), [entry("demo", "GHSA-A", time(1))], now).unwrap();
    assert_eq!(idempotent.generation, 3);
    let display_equivalent = merge_envelope(
        Some(idempotent.clone()),
        [entry("Demo", "GHSA-A", time(1))],
        now,
    )
    .unwrap();
    assert_eq!(display_equivalent.entries.len(), 1);
    let conflict = merge_envelope(
        Some(display_equivalent),
        [entry("demo", "GHSA-B", time(1))],
        now,
    )
    .unwrap_err();
    assert_eq!(conflict.kind, OsvErrorKind::Cache);
    assert!(conflict.detail.contains("same-time"));
}

#[test]
fn cache_contract_revalidates_keys_advisories_and_future_time() {
    let now = time(5);
    let envelope = merge_envelope(None, [entry("demo", "GHSA-A", time(1))], now).unwrap();

    let mut bad_key = envelope.clone();
    let value = bad_key.entries.pop_first().unwrap().1;
    bad_key.entries.insert("forged".to_string(), value);
    bad_key.content_sha256.clear();
    assert!(argus_osv::cache::finalize_envelope(bad_key).is_err());

    let mut bad_coordinate = envelope.clone();
    let cached = bad_coordinate.entries.values_mut().next().unwrap();
    cached.advisories[0].coordinate = coordinate("other");
    assert!(decode_envelope(&serde_json::to_vec(&bad_coordinate).unwrap(), now).is_err());

    let mut bad_evidence = entry("demo", "GHSA-A", time(1));
    bad_evidence.advisories[0].evidence.affected[0].exact_versions = vec!["9.9.9".to_string()];
    assert!(merge_envelope(None, [bad_evidence], now).is_err());

    let mut bad_batch_raw = entry("demo", "GHSA-A", time(1));
    bad_batch_raw.advisories[0].batch_summary_modified = "2026-07-19T10:00:00.000000Z".to_string();
    assert!(merge_envelope(None, [bad_batch_raw], now).is_err());

    let mut bad_detail_raw = entry("demo", "GHSA-A", time(1));
    bad_detail_raw.advisories[0].detail_modified = "2026-07-19T10:00:01Z".to_string();
    assert!(merge_envelope(None, [bad_detail_raw], now).is_err());

    let mut bad_database_modified = entry("demo", "GHSA-A", time(1));
    bad_database_modified.advisories[0].database_modified = time(1);
    assert!(merge_envelope(None, [bad_database_modified], now).is_err());

    let mut bad_source = entry("demo", "GHSA-A", time(1));
    bad_source.advisories[0].source_url = "https://example.invalid/GHSA-A".to_string();
    assert!(merge_envelope(None, [bad_source], now).is_err());

    let mut bad_severity = entry("demo", "GHSA-A", time(1));
    bad_severity.advisories[0].severity.level = SeverityLevel::Critical;
    assert!(merge_envelope(None, [bad_severity], now).is_err());

    let future = merge_envelope(None, [entry("demo", "GHSA-A", time(9))], time(9)).unwrap();
    assert!(decode_envelope(&encode_envelope(&future).unwrap(), now).is_err());
}

#[test]
fn cache_contract_fresh_offline_and_authorized_stale_matrix() {
    let envelope = merge_envelope(None, [entry("fresh", "GHSA-F", time(4))], time(5)).unwrap();
    let mixed = query_set(&["fresh", "missing"]);
    let online = lookup_cache(Some(&envelope), &mixed, time(5), 1, false, false).unwrap();
    assert_eq!(online.hits.len(), 1);
    assert_eq!(online.refresh.len(), 1);
    assert!(!online.authorized_stale);
    let fractional_stale = lookup_cache(
        Some(&envelope),
        &query_set(&["fresh"]),
        time(5) + chrono::Duration::nanoseconds(1),
        1,
        false,
        false,
    )
    .unwrap();
    assert!(fractional_stale.hits.is_empty());
    assert_eq!(fractional_stale.refresh.len(), 1);
    assert!(lookup_cache(Some(&envelope), &mixed, time(5), 1, true, false).is_err());

    let stale = query_set(&["fresh"]);
    assert!(lookup_cache(Some(&envelope), &stale, time(9), 1, true, false).is_err());
    let authorized = lookup_cache(Some(&envelope), &stale, time(9), 1, true, true).unwrap();
    assert_eq!(authorized.hits.len(), 1);
    assert!(authorized.authorized_stale);
    let refresh = lookup_cache(Some(&envelope), &stale, time(9), 1, false, false).unwrap();
    assert!(refresh.hits.is_empty());
    assert_eq!(refresh.refresh.len(), 1);
    assert!(lookup_cache(Some(&envelope), &stale, time(9), 1, false, true).is_err());
}

#[test]
fn cache_contract_zero_result_is_explicit_and_digest_protected() {
    let zero = CacheEntry {
        coordinate: coordinate("clean"),
        fetched_at: time(1),
        query_summaries: vec![],
        advisories: vec![],
        response_sha256: String::new(),
    };
    let envelope = merge_envelope(None, [zero], time(2)).unwrap();
    let cached = envelope.entries.values().next().unwrap();
    assert!(cached.query_summaries.is_empty());
    assert!(cached.advisories.is_empty());
    assert_eq!(cached.response_sha256.len(), 64);
}

fn prepare_cache(root: &TempRoot) -> SecureCache {
    SecureCache::new(root.path())
}

fn secure_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn cache_contract_static_symlink_and_non_regular_matrix() {
    let now = time(5);

    let parent_root = TempRoot::new("parent-link");
    let outside = TempRoot::new("parent-outside");
    symlink(outside.path(), parent_root.path().join("parent")).unwrap();
    let error = prepare_cache(&parent_root)
        .commit(
            Path::new("parent/cache"),
            [entry("a", "GHSA-A", time(1))],
            now,
        )
        .unwrap_err();
    assert!(error.detail.contains("<argus-osv-cache>"));

    let final_root = TempRoot::new("final-link");
    let final_outside = TempRoot::new("final-outside");
    symlink(final_outside.path(), final_root.path().join("cache")).unwrap();
    assert!(prepare_cache(&final_root)
        .load_at(Path::new("cache"), now)
        .is_err());

    let lock_root = TempRoot::new("lock-link");
    secure_dir(&lock_root.path().join("cache"));
    let lock_outside = lock_root.path().join("outside-lock");
    fs::write(&lock_outside, b"outside").unwrap();
    symlink(
        &lock_outside,
        lock_root.path().join("cache").join(CACHE_LOCK_NAME),
    )
    .unwrap();
    assert!(prepare_cache(&lock_root)
        .load_at(Path::new("cache"), now)
        .is_err());

    let target_root = TempRoot::new("target-link");
    secure_dir(&target_root.path().join("cache"));
    let target_outside = target_root.path().join("outside-target");
    fs::write(&target_outside, b"outside").unwrap();
    symlink(
        &target_outside,
        target_root.path().join("cache").join(CACHE_FILE_NAME),
    )
    .unwrap();
    assert!(prepare_cache(&target_root)
        .load_at(Path::new("cache"), now)
        .is_err());
    assert_eq!(fs::read(&target_outside).unwrap(), b"outside");

    let fifo_root = TempRoot::new("target-dir");
    secure_dir(&fifo_root.path().join("cache"));
    fs::create_dir(fifo_root.path().join("cache").join(CACHE_FILE_NAME)).unwrap();
    assert!(prepare_cache(&fifo_root)
        .load_at(Path::new("cache"), now)
        .is_err());
}

struct BeforeComponentSwap {
    root: PathBuf,
    outside: PathBuf,
    fired: AtomicBool,
}

impl CacheHooks for BeforeComponentSwap {
    fn at(&self, point: CacheHookPoint<'_>) -> Result<(), OsvError> {
        if matches!(point, CacheHookPoint::BeforeComponentOpen { index: 0, .. })
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            fs::rename(self.root.join("parent"), self.root.join("parent-old")).unwrap();
            symlink(&self.outside, self.root.join("parent")).unwrap();
        }
        Ok(())
    }
}

struct AfterFinalSwap {
    root: PathBuf,
    outside: PathBuf,
    fired: AtomicBool,
}

impl CacheHooks for AfterFinalSwap {
    fn at(&self, point: CacheHookPoint<'_>) -> Result<(), OsvError> {
        if matches!(point, CacheHookPoint::AfterFinalDirectoryOpen)
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            fs::rename(self.root.join("cache"), self.root.join("cache-old")).unwrap();
            symlink(&self.outside, self.root.join("cache")).unwrap();
        }
        Ok(())
    }
}

struct BeforeRenameSwap {
    cache: PathBuf,
    outside_file: PathBuf,
}

impl CacheHooks for BeforeRenameSwap {
    fn at(&self, point: CacheHookPoint<'_>) -> Result<(), OsvError> {
        if matches!(point, CacheHookPoint::BeforeRename) {
            symlink(&self.outside_file, self.cache.join(CACHE_FILE_NAME)).unwrap();
        }
        Ok(())
    }
}

struct SymlinkAtHook {
    point: fn(CacheHookPoint<'_>) -> bool,
    cache: PathBuf,
    name: &'static str,
    outside_file: PathBuf,
    fired: AtomicBool,
}

impl CacheHooks for SymlinkAtHook {
    fn at(&self, point: CacheHookPoint<'_>) -> Result<(), OsvError> {
        if (self.point)(point) && !self.fired.swap(true, Ordering::SeqCst) {
            symlink(&self.outside_file, self.cache.join(self.name)).unwrap();
        }
        Ok(())
    }
}

#[test]
fn cache_contract_handle_relative_swap_matrix() {
    let now = time(5);
    let parent_root = TempRoot::new("parent-swap");
    let parent_outside = TempRoot::new("parent-swap-outside");
    fs::create_dir(parent_root.path().join("parent")).unwrap();
    let hooks = Arc::new(BeforeComponentSwap {
        root: parent_root.path().to_path_buf(),
        outside: parent_outside.path().to_path_buf(),
        fired: AtomicBool::new(false),
    });
    let error = SecureCache::with_hooks(parent_root.path(), hooks)
        .commit(
            Path::new("parent/cache"),
            [entry("a", "GHSA-A", time(1))],
            now,
        )
        .unwrap_err();
    assert_eq!(error.kind, OsvErrorKind::Cache);
    assert!(!parent_outside.path().join("cache").exists());

    let final_root = TempRoot::new("final-swap");
    let final_outside = TempRoot::new("final-swap-outside");
    secure_dir(&final_root.path().join("cache"));
    let hooks = Arc::new(AfterFinalSwap {
        root: final_root.path().to_path_buf(),
        outside: final_outside.path().to_path_buf(),
        fired: AtomicBool::new(false),
    });
    SecureCache::with_hooks(final_root.path(), hooks)
        .commit(Path::new("cache"), [entry("a", "GHSA-A", time(1))], now)
        .unwrap();
    assert!(final_root
        .path()
        .join("cache-old")
        .join(CACHE_FILE_NAME)
        .exists());
    assert!(!final_outside.path().join(CACHE_FILE_NAME).exists());

    let rename_root = TempRoot::new("rename-swap");
    secure_dir(&rename_root.path().join("cache"));
    let outside_file = rename_root.path().join("outside");
    fs::write(&outside_file, b"outside").unwrap();
    let hooks = Arc::new(BeforeRenameSwap {
        cache: rename_root.path().join("cache"),
        outside_file: outside_file.clone(),
    });
    SecureCache::with_hooks(rename_root.path(), hooks)
        .commit(Path::new("cache"), [entry("a", "GHSA-A", time(1))], now)
        .unwrap();
    assert_eq!(fs::read(&outside_file).unwrap(), b"outside");
    assert!(
        fs::symlink_metadata(rename_root.path().join("cache").join(CACHE_FILE_NAME))
            .unwrap()
            .file_type()
            .is_file()
    );

    for (label, name, point) in [
        (
            "lock-open-swap",
            CACHE_LOCK_NAME,
            (|point| matches!(point, CacheHookPoint::AfterFinalDirectoryOpen))
                as fn(CacheHookPoint<'_>) -> bool,
        ),
        (
            "target-open-swap",
            CACHE_FILE_NAME,
            (|point| matches!(point, CacheHookPoint::BeforeTargetOpen))
                as fn(CacheHookPoint<'_>) -> bool,
        ),
    ] {
        let root = TempRoot::new(label);
        secure_dir(&root.path().join("cache"));
        let outside_file = root.path().join("outside");
        fs::write(&outside_file, b"outside").unwrap();
        let hooks = Arc::new(SymlinkAtHook {
            point,
            cache: root.path().join("cache"),
            name,
            outside_file: outside_file.clone(),
            fired: AtomicBool::new(false),
        });
        assert!(SecureCache::with_hooks(root.path(), hooks)
            .load_at(Path::new("cache"), now)
            .is_err());
        assert_eq!(fs::read(outside_file).unwrap(), b"outside");
    }
}

struct FailBeforeRename;

impl CacheHooks for FailBeforeRename {
    fn at(&self, point: CacheHookPoint<'_>) -> Result<(), OsvError> {
        if matches!(point, CacheHookPoint::BeforeRename) {
            Err(OsvError::new(OsvErrorKind::Cache, "injected interruption"))
        } else {
            Ok(())
        }
    }
}

struct FailDirectorySync;

impl CacheHooks for FailDirectorySync {
    fn at(&self, point: CacheHookPoint<'_>) -> Result<(), OsvError> {
        if matches!(point, CacheHookPoint::BeforeDirectorySync) {
            Err(OsvError::new(
                OsvErrorKind::Cache,
                "injected directory sync failure",
            ))
        } else {
            Ok(())
        }
    }
}

#[test]
fn cache_contract_interrupted_write_and_network_failure_preserve_cache() {
    let root = TempRoot::new("interrupted");
    let cache = prepare_cache(&root);
    cache
        .commit(Path::new("cache"), [entry("a", "GHSA-A", time(1))], time(5))
        .unwrap();
    let before = fs::read(root.path().join("cache").join(CACHE_FILE_NAME)).unwrap();
    let failing = SecureCache::with_hooks(root.path(), Arc::new(FailBeforeRename));
    assert!(failing
        .commit(Path::new("cache"), [entry("b", "GHSA-B", time(2))], time(5))
        .is_err());
    assert_eq!(
        fs::read(root.path().join("cache").join(CACHE_FILE_NAME)).unwrap(),
        before
    );
    assert!(!fs::read_dir(root.path().join("cache"))
        .unwrap()
        .any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")));

    let envelope = cache.load_at(Path::new("cache"), time(5)).unwrap().unwrap();
    let stale = lookup_cache(
        Some(&envelope),
        &query_set(&["a"]),
        time(9),
        1,
        false,
        false,
    )
    .unwrap();
    assert_eq!(stale.refresh.len(), 1);
    assert_eq!(
        fs::read(root.path().join("cache").join(CACHE_FILE_NAME)).unwrap(),
        before,
        "network refresh failure path mutated cache without commit"
    );

    let failing_sync = SecureCache::with_hooks(root.path(), Arc::new(FailDirectorySync));
    assert!(failing_sync
        .commit(Path::new("cache"), [entry("b", "GHSA-B", time(2))], time(5))
        .is_err());
    assert!(!fs::read_dir(root.path().join("cache"))
        .unwrap()
        .any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")));
}

#[test]
fn cache_concurrency_merges_without_lost_update() {
    let root = TempRoot::new("concurrency");
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for (name, id) in [("a", "GHSA-A"), ("b", "GHSA-B")] {
        let root = root.path().to_path_buf();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            let cache = SecureCache::new(root);
            barrier.wait();
            cache
                .commit(Path::new("cache"), [entry(name, id, time(1))], time(5))
                .unwrap();
        }));
    }
    barrier.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    let envelope = prepare_cache(&root)
        .load_at(Path::new("cache"), time(5))
        .unwrap()
        .unwrap();
    assert_eq!(envelope.entries.len(), 2);
    assert_eq!(envelope.generation, 2);
}

#[test]
fn cache_contract_permissions_and_diagnostics_do_not_leak_paths() {
    let root = TempRoot::new("secret-cache-path");
    let cache_dir = root.path().join("cache");
    secure_dir(&cache_dir);
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let result =
        prepare_cache(&root).commit(Path::new("cache"), [entry("a", "GHSA-A", time(1))], time(5));
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.kind, OsvErrorKind::Cache);
    assert!(error.detail.contains("<argus-osv-cache>"));
    assert!(!error.detail.contains(root.path().to_str().unwrap()));
}

#[test]
fn cache_contract_store_roundtrip_uses_canonical_bytes_and_modes() {
    let root = TempRoot::new("roundtrip");
    let cache = prepare_cache(&root);
    let envelope = cache
        .commit(
            Path::new("new/cache"),
            [entry("a", "GHSA-A", time(1))],
            time(5),
        )
        .unwrap();
    let bytes = cache.read(Path::new("new/cache")).unwrap().unwrap();
    assert_eq!(bytes, encode_envelope(&envelope).unwrap());
    assert_eq!(
        fs::metadata(root.path().join("new"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.path().join("new/cache").join(CACHE_LOCK_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(root.path().join("new/cache").join(CACHE_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let key = coordinate_cache_key(&coordinate("a")).unwrap();
    assert!(envelope.entries.contains_key(&key));
    assert_eq!(
        coordinate_cache_key(&coordinate("A")).unwrap(),
        coordinate_cache_key(&coordinate("a")).unwrap()
    );
}
