#![cfg(unix)]

use argus_core::{
    Decision, Ecosystem, PackageCoordinate, Severity, VulnerabilityQueryStatus,
    VulnerabilitySourceMode,
};
use argus_osv::cache::{SecureCache, CACHE_FILE_NAME};
use argus_osv::client::{OsvTransport, ResponseLimits, TransportResponse};
use argus_osv::report::{OsvReportBuilder, ReportBuilder};
use argus_osv::resolver::{AdvisoryResolver, CoordinateSource, OsvResolver, ResolveRequest};
use argus_osv::severity::SeverityLevel;
use argus_osv::{CoordinateQuery, CoordinateSet, OsvError, OsvErrorKind};
use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "argus-osv-resolver-{label}-{}-{}",
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

struct MockTransport {
    batches: Mutex<VecDeque<Result<Value, OsvError>>>,
    details: Mutex<BTreeMap<String, VecDeque<Result<Value, OsvError>>>>,
}

impl MockTransport {
    fn new(batches: Vec<Value>, details: Vec<(&str, Vec<Value>)>) -> Self {
        Self {
            batches: Mutex::new(batches.into_iter().map(Ok).collect()),
            details: Mutex::new(
                details
                    .into_iter()
                    .map(|(id, values)| {
                        (
                            id.to_string(),
                            values.into_iter().map(Ok).collect::<VecDeque<_>>(),
                        )
                    })
                    .collect(),
            ),
        }
    }

    fn failing(detail: &str) -> Self {
        Self {
            batches: Mutex::new([Err(OsvError::new(OsvErrorKind::Transport, detail))].into()),
            details: Mutex::new(BTreeMap::new()),
        }
    }
}

impl OsvTransport for MockTransport {
    fn post_query_batch(
        &self,
        _body: &[u8],
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        self.batches
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected querybatch request")
            .map(json_response)
    }

    fn get_advisory(
        &self,
        id: &str,
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        self.details
            .lock()
            .unwrap()
            .get_mut(id)
            .and_then(VecDeque::pop_front)
            .expect("unexpected advisory request")
            .map(json_response)
    }
}

fn json_response(value: Value) -> TransportResponse {
    TransportResponse {
        status: 200,
        content_type: Some("application/json".to_string()),
        body: serde_json::to_vec(&value).unwrap(),
    }
}

fn time(second: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 19, 10, 0, 0).unwrap() + Duration::seconds(second)
}

fn query(name: &str, locators: &[&str]) -> CoordinateQuery {
    CoordinateQuery::new(
        PackageCoordinate::new(Ecosystem::Npm, name, "1.2.3").unwrap(),
        locators.iter().map(|value| (*value).to_string()),
    )
    .unwrap()
}

fn coordinates(queries: Vec<CoordinateQuery>) -> CoordinateSet {
    CoordinateSet::new(queries, 2).unwrap()
}

fn make_resolver(root: &TempRoot) -> OsvResolver {
    OsvResolver::new(SecureCache::new(root.path()), "cache")
}

fn request<'a>(
    coordinates: &'a CoordinateSet,
    now: DateTime<Utc>,
    offline: bool,
    allow_stale: bool,
    max_age_seconds: u64,
) -> ResolveRequest<'a> {
    ResolveRequest {
        coordinates,
        offline,
        allow_stale,
        max_age_seconds,
        now,
    }
}

fn batch(results: Vec<Value>) -> Value {
    json!({"results": results})
}

fn result(vulns: Vec<Value>) -> Value {
    json!({"vulns": vulns})
}

fn summary(id: &str) -> Value {
    json!({"id": id, "modified": "2026-07-19T10:00:00Z"})
}

fn advisory(id: &str, names: &[&str], aliases: &[&str], high: bool) -> Value {
    let affected = names
        .iter()
        .map(|name| {
            let mut block = json!({
                "package":{"ecosystem":"npm","name":name},
                "versions":["1.2.3"],
                "ranges":[{
                    "type":"SEMVER",
                    "events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]
                }]
            });
            if high {
                block["severity"] = json!([{
                    "type":"CVSS_V3",
                    "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "source":"NVD"
                }]);
            }
            block
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version":"1.8.0",
        "id":id,
        "modified":"2026-07-19T10:00:00Z",
        "aliases":aliases,
        "affected":affected
    })
}

fn no_match_transport(result_count: usize) -> MockTransport {
    MockTransport::new(
        vec![batch((0..result_count).map(|_| result(vec![])).collect())],
        vec![],
    )
}

#[test]
fn result_states_cover_network_cache_and_offline_fresh_no_match() {
    let root = TempRoot::new("source-basic");
    let resolver = make_resolver(&root);
    let set = coordinates(vec![query("alpha", &["new:2", "new:1"])]);
    let network = resolver
        .resolve(
            request(&set, time(0), false, false, 60),
            Some(&no_match_transport(1)),
        )
        .unwrap();
    assert_eq!(network.source_mode, VulnerabilitySourceMode::Network);
    assert_eq!(network.results[0].source, CoordinateSource::Network);
    let report = OsvReportBuilder::default().build(&network).unwrap();
    assert_eq!(
        report.evidence.status,
        VulnerabilityQueryStatus::CompleteNoMatch
    );
    assert_eq!(report.decision, Decision::Allow);
    assert!(report.findings.is_empty());

    let cached = resolver
        .resolve(request(&set, time(1), false, false, 60), None)
        .unwrap();
    assert_eq!(cached.source_mode, VulnerabilitySourceMode::Cache);
    assert_eq!(cached.results[0].source, CoordinateSource::Cache);
    let offline = resolver
        .resolve(request(&set, time(2), true, false, 60), None)
        .unwrap();
    assert_eq!(offline.source_mode, VulnerabilitySourceMode::OfflineFresh);
    assert_eq!(
        OsvReportBuilder::default()
            .build(&offline)
            .unwrap()
            .evidence
            .queried_coordinates,
        1
    );
}

#[test]
fn source_modes_cover_mixed_and_current_locator_rebinding() {
    let root = TempRoot::new("source-mixed");
    let resolver = make_resolver(&root);
    let initial = coordinates(vec![query("Alpha", &["old:1"])]);
    let seed = MockTransport::new(
        vec![batch(vec![result(vec![summary("GHSA-ALPHA")])])],
        vec![(
            "GHSA-ALPHA",
            vec![advisory("GHSA-ALPHA", &["alpha"], &[], false)],
        )],
    );
    resolver
        .resolve(request(&initial, time(0), false, false, 60), Some(&seed))
        .unwrap();

    let combined = coordinates(vec![
        query("alpha", &["current:2", "current:1"]),
        query("beta", &["beta:1"]),
    ]);
    let mixed = resolver
        .resolve(
            request(
                &combined,
                time(1) + Duration::nanoseconds(1),
                false,
                false,
                60,
            ),
            Some(&no_match_transport(1)),
        )
        .unwrap();
    assert_eq!(mixed.source_mode, VulnerabilitySourceMode::Mixed);
    assert_eq!(
        mixed
            .results
            .iter()
            .map(|value| value.source)
            .collect::<Vec<_>>(),
        [CoordinateSource::Cache, CoordinateSource::Network]
    );
    assert_eq!(
        mixed.results[0].advisories[0].evidence.locators,
        ["current:1", "current:2"]
    );
    let report = OsvReportBuilder::default().build(&mixed).unwrap();
    assert_eq!(report.evidence.source_mode, VulnerabilitySourceMode::Mixed);
    assert_eq!(report.evidence.active_advisories, 1);
    assert_eq!(report.evidence.maximum_age_seconds, 2);
}

#[test]
fn offline_stale_requires_explicit_authorization_and_is_visible() {
    let root = TempRoot::new("offline-stale");
    let resolver = make_resolver(&root);
    let set = coordinates(vec![query("alpha", &["alpha:1"])]);
    resolver
        .resolve(
            request(&set, time(0), false, false, 1),
            Some(&no_match_transport(1)),
        )
        .unwrap();
    assert!(resolver
        .resolve(request(&set, time(10), true, false, 1), None)
        .is_err());
    let stale = resolver
        .resolve(request(&set, time(10), true, true, 1), None)
        .unwrap();
    assert_eq!(stale.source_mode, VulnerabilitySourceMode::OfflineStale);
    let report = OsvReportBuilder::default().build(&stale).unwrap();
    assert_eq!(
        report.evidence.status,
        VulnerabilityQueryStatus::CompleteStale
    );
    assert_eq!(report.decision, Decision::AllowWithApproval);
    assert_eq!(report.findings[0].rule_id, "vulnerability-data-stale");
    assert_eq!(report.findings[0].severity, Severity::Medium);

    let missing = coordinates(vec![query("missing", &[])]);
    assert!(resolver
        .resolve(request(&missing, time(10), true, true, 1), None)
        .is_err());
}

#[test]
fn online_refresh_failure_never_falls_back_or_commits_partial_data() {
    let root = TempRoot::new("refresh-failure");
    let resolver = make_resolver(&root);
    let set = coordinates(vec![query("alpha", &[])]);
    resolver
        .resolve(
            request(&set, time(0), false, false, 1),
            Some(&no_match_transport(1)),
        )
        .unwrap();
    let target = root.path().join("cache").join(CACHE_FILE_NAME);
    let before = fs::read(&target).unwrap();
    let error = resolver
        .resolve(
            request(&set, time(10), false, false, 1),
            Some(&MockTransport::failing("timeout")),
        )
        .unwrap_err();
    assert_eq!(error.kind, OsvErrorKind::Transport);
    assert_eq!(fs::read(&target).unwrap(), before);

    let missing_root = TempRoot::new("missing-failure");
    let missing_resolver = make_resolver(&missing_root);
    assert!(missing_resolver
        .resolve(
            request(&set, time(10), false, false, 1),
            Some(&MockTransport::failing("DNS")),
        )
        .is_err());
    assert!(!missing_root
        .path()
        .join("cache")
        .join(CACHE_FILE_NAME)
        .exists());
}

#[test]
fn advisory_evidence_and_intel_separation_cover_aliases_unknown_and_multi_id() {
    let root = TempRoot::new("advisory-evidence");
    let resolver = make_resolver(&root);
    let set = coordinates(vec![
        query("alpha", &["alpha:2", "alpha:1"]),
        query("beta", &["beta:1"]),
    ]);
    let transport = MockTransport::new(
        vec![batch(vec![
            result(vec![summary("GHSA-SHARED"), summary("GHSA-HIGH")]),
            result(vec![summary("GHSA-SHARED")]),
        ])],
        vec![
            (
                "GHSA-HIGH",
                vec![advisory("GHSA-HIGH", &["alpha"], &["CVE-2"], true)],
            ),
            (
                "GHSA-SHARED",
                vec![advisory(
                    "GHSA-SHARED",
                    &["alpha", "beta"],
                    &["CVE-1", "CVE-1"],
                    false,
                )],
            ),
        ],
    );
    let snapshot = resolver
        .resolve(request(&set, time(0), false, false, 60), Some(&transport))
        .unwrap();
    let approval = OsvReportBuilder::default().build(&snapshot).unwrap();
    assert_eq!(approval.decision, Decision::AllowWithApproval);
    assert_eq!(approval.advisories.len(), 3);
    assert_eq!(approval.evidence.advisories.len(), 3);
    assert!(approval
        .evidence
        .advisories
        .iter()
        .any(|value| value.primary_id == "GHSA-SHARED"
            && value.aliases == ["CVE-1"]
            && value.normalized_severity == "unknown"
            && value.batch_summary_modified == "2026-07-19T10:00:00Z"
            && value.detail_modified == "2026-07-19T10:00:00Z"
            && value.locators == ["alpha:1", "alpha:2"]
            && value.matched_ranges[0].contains("\"exact_versions\":[\"1.2.3\"]")));
    assert!(approval.evidence.advisories.iter().all(|value| value
        .source_url
        .starts_with("https://api.osv.dev/v1/vulns/")));

    let blocked = OsvReportBuilder::new(Some(SeverityLevel::High))
        .unwrap()
        .build(&snapshot)
        .unwrap();
    assert_eq!(blocked.decision, Decision::Block);
    assert_eq!(
        blocked
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::High)
            .count(),
        1
    );
    assert!(blocked
        .findings
        .iter()
        .all(|finding| finding.rule_id == "known-vulnerability"));
    assert!(OsvReportBuilder::new(Some(SeverityLevel::Unknown)).is_err());
}

#[test]
fn nonmatching_or_withdrawn_snapshot_never_commits_or_builds_report() {
    let set = coordinates(vec![query("alpha", &[])]);
    let wrong = advisory("GHSA-RACE", &["other"], &[], false);
    let mut withdrawn = advisory("GHSA-RACE", &["alpha"], &[], false);
    withdrawn["withdrawn"] = json!("2026-07-19T10:00:01Z");
    for detail in [wrong, withdrawn] {
        let root = TempRoot::new("race-no-commit");
        let resolver = make_resolver(&root);
        let transport = MockTransport::new(
            vec![
                batch(vec![result(vec![summary("GHSA-RACE")])]),
                batch(vec![result(vec![summary("GHSA-RACE")])]),
            ],
            vec![("GHSA-RACE", vec![detail.clone(), detail])],
        );
        assert_eq!(
            resolver
                .resolve(request(&set, time(0), false, false, 60), Some(&transport))
                .unwrap_err()
                .kind,
            OsvErrorKind::SnapshotRace
        );
        assert!(!root.path().join("cache").join(CACHE_FILE_NAME).exists());
    }
}

#[test]
fn report_rejects_partial_or_internally_inconsistent_snapshots() {
    let root = TempRoot::new("partial-report");
    let resolver = make_resolver(&root);
    let set = coordinates(vec![query("alpha", &[])]);
    let mut snapshot = resolver
        .resolve(
            request(&set, time(0), false, false, 60),
            Some(&no_match_transport(1)),
        )
        .unwrap();
    let complete = snapshot.clone();
    snapshot.results.clear();
    assert_eq!(
        OsvReportBuilder::default()
            .build(&snapshot)
            .unwrap_err()
            .kind,
        OsvErrorKind::IncompleteAnalysis
    );
    let mut stale_mismatch = complete.clone();
    stale_mismatch.source_mode = VulnerabilitySourceMode::OfflineStale;
    assert!(OsvReportBuilder::default().build(&stale_mismatch).is_err());
    let mut query_mismatch = complete;
    query_mismatch.results[0].query = query("other", &[]);
    assert!(OsvReportBuilder::default().build(&query_mismatch).is_err());
}
