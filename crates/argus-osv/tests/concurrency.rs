use argus_core::{Ecosystem, ExecutionContext, PackageCoordinate, ScanConcurrency};
use argus_osv::client::{
    OsvClient, OsvClock, OsvTransport, ResponseLimits, TransportAttempt, TransportResponse,
};
use argus_osv::{CoordinateQuery, CoordinateSet, OsvError, OsvErrorKind};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};
use std::time::{Duration, Instant};

fn query(name: &str) -> CoordinateQuery {
    CoordinateQuery::new(
        PackageCoordinate::new(Ecosystem::Npm, name, "1.0.0").unwrap(),
        [format!("lock:{name}")],
    )
    .unwrap()
}

fn coordinate_set(count: usize) -> CoordinateSet {
    CoordinateSet::new(
        (0..count)
            .map(|index| query(&format!("package-{index:05}")))
            .collect(),
        0,
    )
    .unwrap()
}

fn execution(jobs: usize) -> ExecutionContext {
    ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap()
}

fn response(value: Value) -> TransportResponse {
    TransportResponse {
        status: 200,
        content_type: Some("application/json".to_string()),
        body: serde_json::to_vec(&value).unwrap(),
    }
}

fn empty_batch(count: usize) -> TransportResponse {
    response(json!({
        "results": (0..count)
            .map(|_| json!({"vulns":[]}))
            .collect::<Vec<_>>()
    }))
}

fn batch_request(body: &[u8]) -> (usize, usize) {
    let value: Value = serde_json::from_slice(body).unwrap();
    let queries = value["queries"].as_array().unwrap();
    let first = queries[0]["package"]["name"].as_str().unwrap();
    let coordinate = first
        .strip_prefix("package-")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    (coordinate / 1_000, queries.len())
}

struct QueryWindowTransport {
    active: AtomicUsize,
    maximum: AtomicUsize,
    calls: Mutex<Vec<usize>>,
    fail_first_window: bool,
    first_window: Barrier,
    first_window_size: usize,
}

impl QueryWindowTransport {
    fn new(fail_first_window: bool, first_window_size: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            fail_first_window,
            first_window: Barrier::new(first_window_size),
            first_window_size,
        }
    }

    fn calls(&self) -> Vec<usize> {
        let mut calls = self.calls.lock().unwrap().clone();
        calls.sort_unstable();
        calls
    }
}

impl OsvTransport for QueryWindowTransport {
    fn post_query_batch(
        &self,
        body: &[u8],
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        let (chunk, count) = batch_request(body);
        self.calls.lock().unwrap().push(chunk);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        if chunk < self.first_window_size {
            self.first_window.wait();
        }
        let delay = if chunk % 2 == 0 { 20 } else { 5 };
        std::thread::sleep(Duration::from_millis(delay));
        self.active.fetch_sub(1, Ordering::SeqCst);
        if self.fail_first_window && chunk < 2 {
            return Err(OsvError::new(
                OsvErrorKind::Transport,
                format!("querybatch-failure-{chunk}"),
            ));
        }
        Ok(empty_batch(count))
    }

    fn get_advisory(
        &self,
        _id: &str,
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        panic!("empty query batches must not request advisory details")
    }
}

#[test]
fn querybatch_windows_obey_jobs_and_osv_cap_with_stable_output() {
    let coordinates = coordinate_set(9_000);
    let expected = coordinates
        .queries
        .iter()
        .map(|query| query.coordinate.canonical_name.clone())
        .collect::<Vec<_>>();
    for (jobs, expected_peak) in [(1, 1), (2, 2), (8, 8), (64, 8)] {
        let transport = QueryWindowTransport::new(false, expected_peak);
        let snapshot = OsvClient::new(&transport)
            .query_with_context(&coordinates, &execution(jobs))
            .unwrap();
        let actual = snapshot
            .queries
            .iter()
            .map(|query| query.query.coordinate.canonical_name.clone())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "jobs={jobs}");
        assert_eq!(
            transport.maximum.load(Ordering::SeqCst),
            expected_peak,
            "jobs={jobs}"
        );
        assert_eq!(transport.calls(), (0..9).collect::<Vec<_>>());
        assert_eq!(snapshot.request_count, 9);
    }
}

#[test]
fn querybatch_failure_is_lowest_index_and_stops_later_windows() {
    let transport = QueryWindowTransport::new(true, 2);
    let error = OsvClient::new(&transport)
        .query_with_context(&coordinate_set(9_000), &execution(2))
        .unwrap_err();
    assert!(error.detail.contains("querybatch-failure-0"), "{error}");
    assert_eq!(transport.calls(), [0, 1]);
}

struct DetailWindowTransport {
    count: usize,
    active: AtomicUsize,
    maximum: AtomicUsize,
    calls: Mutex<Vec<usize>>,
    fail_first_window: bool,
    first_window: Barrier,
    first_window_size: usize,
}

impl DetailWindowTransport {
    fn new(count: usize, fail_first_window: bool, first_window_size: usize) -> Self {
        Self {
            count,
            active: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            fail_first_window,
            first_window: Barrier::new(first_window_size),
            first_window_size,
        }
    }

    fn ids(&self) -> Vec<String> {
        (0..self.count)
            .map(|index| format!("GHSA-{index:02}"))
            .collect()
    }

    fn calls(&self) -> Vec<usize> {
        let mut calls = self.calls.lock().unwrap().clone();
        calls.sort_unstable();
        calls
    }
}

impl OsvTransport for DetailWindowTransport {
    fn post_query_batch(
        &self,
        _body: &[u8],
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        Ok(response(json!({
            "results":[{
                "vulns": self.ids().iter().map(|id| json!({
                    "id": id,
                    "modified": "2026-07-27T00:00:00Z"
                })).collect::<Vec<_>>()
            }]
        })))
    }

    fn get_advisory(
        &self,
        id: &str,
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        let index = id.strip_prefix("GHSA-").unwrap().parse::<usize>().unwrap();
        self.calls.lock().unwrap().push(index);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        if index < self.first_window_size {
            self.first_window.wait();
        }
        let delay = if index % 2 == 0 { 20 } else { 5 };
        std::thread::sleep(Duration::from_millis(delay));
        self.active.fetch_sub(1, Ordering::SeqCst);
        if self.fail_first_window && index < 2 {
            return Err(OsvError::new(
                OsvErrorKind::Transport,
                format!("detail-failure-{index:02}"),
            ));
        }
        Ok(response(json!({
            "schema_version": "1.8.0",
            "id": id,
            "modified": "2026-07-27T00:00:00Z",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "demo"},
                "versions": ["1.0.0"]
            }]
        })))
    }
}

fn one_query() -> CoordinateSet {
    CoordinateSet::new(vec![query("demo")], 0).unwrap()
}

#[test]
fn detail_windows_obey_jobs_and_osv_cap() {
    for (jobs, expected_peak) in [(1, 1), (2, 2), (8, 8), (64, 8)] {
        let transport = DetailWindowTransport::new(9, false, expected_peak);
        let snapshot = OsvClient::new(&transport)
            .query_with_context(&one_query(), &execution(jobs))
            .unwrap();
        assert_eq!(snapshot.queries[0].advisories.len(), 9);
        assert_eq!(
            transport.maximum.load(Ordering::SeqCst),
            expected_peak,
            "jobs={jobs}"
        );
        assert_eq!(transport.calls(), (0..9).collect::<Vec<_>>());
        assert_eq!(snapshot.request_count, 10);
    }
}

#[test]
fn detail_failure_is_lowest_id_and_stops_later_windows() {
    let transport = DetailWindowTransport::new(17, true, 8);
    let error = OsvClient::new(&transport)
        .query_with_context(&one_query(), &execution(8))
        .unwrap_err();
    assert!(error.detail.contains("detail-failure-00"), "{error}");
    assert_eq!(transport.calls(), (0..8).collect::<Vec<_>>());
}

struct AttemptAccountingTransport {
    posts: AtomicUsize,
}

impl OsvTransport for AttemptAccountingTransport {
    fn post_query_batch(
        &self,
        _body: &[u8],
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        Ok(response(json!({
            "results":[{
                "vulns":[{
                    "id":"GHSA-RETRY",
                    "modified":"2026-07-27T00:00:00Z"
                }]
            }]
        })))
    }

    fn get_advisory(
        &self,
        _id: &str,
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        panic!("coordinator must use the attempt-accounting transport API")
    }

    fn get_advisory_attempted(&self, id: &str, _limits: ResponseLimits) -> TransportAttempt {
        TransportAttempt {
            attempts: 3,
            result: Ok(response(json!({
                "schema_version":"1.8.0",
                "id":id,
                "modified":"2026-07-27T00:00:00Z",
                "affected":[{
                    "package":{"ecosystem":"npm","name":"demo"},
                    "versions":["1.0.0"]
                }]
            }))),
        }
    }
}

#[test]
fn detail_attempts_are_counted_while_querybatch_is_one_shot() {
    let transport = AttemptAccountingTransport {
        posts: AtomicUsize::new(0),
    };
    let snapshot = OsvClient::new(&transport)
        .query_with_context(&one_query(), &execution(8))
        .unwrap();
    assert_eq!(transport.posts.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot.request_count, 4);
}

struct FailingPostTransport {
    posts: AtomicUsize,
}

impl OsvTransport for FailingPostTransport {
    fn post_query_batch(
        &self,
        _body: &[u8],
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        Err(OsvError::new(
            OsvErrorKind::Transport,
            "one-shot POST failure",
        ))
    }

    fn get_advisory(
        &self,
        _id: &str,
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        panic!("failed querybatch must not hydrate details")
    }
}

#[test]
fn coordinator_never_retries_querybatch_post() {
    let transport = FailingPostTransport {
        posts: AtomicUsize::new(0),
    };
    let error = OsvClient::new(&transport)
        .query_with_context(&one_query(), &execution(64))
        .unwrap_err();
    assert!(error.detail.contains("one-shot POST failure"));
    assert_eq!(transport.posts.load(Ordering::SeqCst), 1);
}

struct FakeOsvClock {
    elapsed: Mutex<Duration>,
}

impl FakeOsvClock {
    fn new(elapsed: Duration) -> Self {
        Self {
            elapsed: Mutex::new(elapsed),
        }
    }

    fn advance(&self, duration: Duration) {
        *self.elapsed.lock().unwrap() += duration;
    }
}

impl OsvClock for FakeOsvClock {
    fn elapsed(&self, _started: Instant) -> Duration {
        *self.elapsed.lock().unwrap()
    }
}

struct PagingDeadlineTransport<'a> {
    clock: &'a FakeOsvClock,
    timeouts: Mutex<Vec<Duration>>,
}

impl OsvTransport for PagingDeadlineTransport<'_> {
    fn post_query_batch(
        &self,
        _body: &[u8],
        limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        let mut timeouts = self.timeouts.lock().unwrap();
        let call = timeouts.len();
        timeouts.push(limits.request_timeout);
        drop(timeouts);
        self.clock.advance(limits.request_timeout);
        let result = if call == 0 {
            json!({"vulns":[], "next_page_token":"second-page"})
        } else {
            json!({"vulns":[]})
        };
        Ok(response(json!({"results":[result]})))
    }

    fn get_advisory(
        &self,
        _id: &str,
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        panic!("empty pages must not hydrate details")
    }
}

#[test]
fn sequential_query_windows_share_one_operation_deadline() {
    let clock = FakeOsvClock::new(Duration::from_secs(250));
    let transport = PagingDeadlineTransport {
        clock: &clock,
        timeouts: Mutex::new(Vec::new()),
    };
    let error = OsvClient::with_clock(&transport, &clock)
        .query_with_context(&one_query(), &execution(1))
        .unwrap_err();
    assert!(error.detail.contains("300 second timeout"), "{error}");
    assert_eq!(
        *transport.timeouts.lock().unwrap(),
        [Duration::from_secs(30), Duration::from_secs(20)]
    );
}

struct DetailDeadlineTransport<'a> {
    clock: &'a FakeOsvClock,
    detail_timeouts: Mutex<Vec<Duration>>,
}

impl OsvTransport for DetailDeadlineTransport<'_> {
    fn post_query_batch(
        &self,
        _body: &[u8],
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        Ok(response(json!({
            "results":[{
                "vulns":[{
                    "id":"GHSA-DEADLINE",
                    "modified":"2026-07-27T00:00:00Z"
                }]
            }]
        })))
    }

    fn get_advisory(
        &self,
        _id: &str,
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        panic!("attempt-aware path is required")
    }

    fn get_advisory_attempted(&self, id: &str, limits: ResponseLimits) -> TransportAttempt {
        self.detail_timeouts
            .lock()
            .unwrap()
            .push(limits.request_timeout);
        self.clock.advance(limits.request_timeout);
        TransportAttempt {
            attempts: 1,
            result: Ok(response(json!({
                "schema_version":"1.8.0",
                "id":id,
                "modified":"2026-07-27T00:00:00Z",
                "affected":[{
                    "package":{"ecosystem":"npm","name":"demo"},
                    "versions":["1.0.0"]
                }]
            }))),
        }
    }
}

#[test]
fn detail_logical_get_receives_only_operation_remaining() {
    let clock = FakeOsvClock::new(Duration::from_secs(295));
    let transport = DetailDeadlineTransport {
        clock: &clock,
        detail_timeouts: Mutex::new(Vec::new()),
    };
    let error = OsvClient::with_clock(&transport, &clock)
        .query_with_context(&one_query(), &execution(8))
        .unwrap_err();
    assert!(error.detail.contains("300 second timeout"), "{error}");
    assert_eq!(
        *transport.detail_timeouts.lock().unwrap(),
        [Duration::from_secs(5)]
    );
}
