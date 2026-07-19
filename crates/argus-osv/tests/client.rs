use argus_core::{Ecosystem, PackageCoordinate};
use argus_osv::client::{
    HttpsOsvTransport, OsvClient, OsvTransport, ResponseLimits, TransportResponse, CONNECT_TIMEOUT,
    MAX_ASSOCIATIONS, MAX_DETAIL_RESPONSE_BYTES, MAX_ENCODED_REQUEST_BYTES,
    MAX_PAGES_PER_COORDINATE, MAX_PAGE_TOKEN_BYTES, MAX_QUERY_RESPONSE_BYTES, REQUEST_TIMEOUT,
};
use argus_osv::model::MAX_LOCATOR_BYTES;
use argus_osv::{CoordinateQuery, CoordinateSet, OsvError, OsvErrorKind};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
struct MockTransport {
    batches: Mutex<VecDeque<Result<TransportResponse, OsvError>>>,
    details: Mutex<BTreeMap<String, VecDeque<Result<TransportResponse, OsvError>>>>,
    calls: Mutex<Vec<String>>,
}
impl MockTransport {
    fn new(batch_values: Vec<Value>, details: Vec<(&str, Vec<Value>)>) -> Self {
        Self {
            batches: Mutex::new(
                batch_values
                    .into_iter()
                    .map(|value| Ok(json_response(value)))
                    .collect(),
            ),
            details: Mutex::new(
                details
                    .into_iter()
                    .map(|(id, values)| {
                        (
                            id.to_string(),
                            values.into_iter().map(json_response).map(Ok).collect(),
                        )
                    })
                    .collect(),
            ),
            calls: Mutex::new(Vec::new()),
        }
    }
    fn with_batch_response(response: Result<TransportResponse, OsvError>) -> Self {
        Self {
            batches: Mutex::new([response].into()),
            details: Mutex::new(BTreeMap::new()),
            calls: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}
impl OsvTransport for MockTransport {
    fn post_query_batch(
        &self,
        body: &[u8],
        limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        assert_eq!(limits.redirect_limit, 0);
        assert!(!limits.send_credentials);
        assert_eq!(limits.encoded_request_bytes, MAX_ENCODED_REQUEST_BYTES);
        assert_eq!(limits.connect_timeout.as_secs(), 5);
        assert_eq!(limits.request_timeout.as_secs(), 30);
        assert_eq!(limits.decoded_response_bytes, MAX_QUERY_RESPONSE_BYTES);
        let body: Value = serde_json::from_slice(body).unwrap();
        self.calls.lock().unwrap().push(format!(
            "batch:{}",
            body["queries"].as_array().unwrap().len()
        ));
        self.batches
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected batch request")
    }
    fn get_advisory(
        &self,
        percent_encoded_id: &str,
        limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        assert_eq!(limits.redirect_limit, 0);
        assert!(!limits.send_credentials);
        assert_eq!(limits.encoded_request_bytes, MAX_ENCODED_REQUEST_BYTES);
        assert_eq!(limits.connect_timeout.as_secs(), 5);
        assert_eq!(limits.request_timeout.as_secs(), 30);
        assert_eq!(limits.decoded_response_bytes, MAX_DETAIL_RESPONSE_BYTES);
        self.calls
            .lock()
            .unwrap()
            .push(format!("detail:{percent_encoded_id}"));
        self.details
            .lock()
            .unwrap()
            .get_mut(percent_encoded_id)
            .and_then(VecDeque::pop_front)
            .expect("unexpected detail request")
    }
}
struct ConcurrencyTransport {
    inner: MockTransport,
    active: AtomicUsize,
    maximum: AtomicUsize,
}
impl OsvTransport for ConcurrencyTransport {
    fn post_query_batch(
        &self,
        body: &[u8],
        limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        self.inner.post_query_batch(body, limits)
    }
    fn get_advisory(
        &self,
        id: &str,
        limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let response = self.inner.get_advisory(id, limits);
        self.active.fetch_sub(1, Ordering::SeqCst);
        response
    }
}
fn json_response(value: Value) -> TransportResponse {
    TransportResponse {
        status: 200,
        content_type: Some("application/json; charset=utf-8".to_string()),
        body: serde_json::to_vec(&value).unwrap(),
    }
}
fn query(name: &str, version: &str) -> CoordinateQuery {
    CoordinateQuery::new(
        PackageCoordinate::new(Ecosystem::Npm, name, version).unwrap(),
        [format!("package-lock:{name}")],
    )
    .unwrap()
}
fn set(queries: Vec<CoordinateQuery>) -> CoordinateSet {
    CoordinateSet::new(queries, 0).unwrap()
}
fn summary(id: &str, modified: &str) -> Value {
    json!({"id": id, "modified": modified})
}
fn batch(results: Vec<Value>) -> Value {
    json!({"results": results})
}
fn result(vulns: Vec<Value>, token: Option<&str>) -> Value {
    let mut value = json!({"vulns": vulns});
    if let Some(token) = token {
        value["next_page_token"] = json!(token);
    }
    value
}
fn advisory(id: &str, modified: &str, name: &str, version: &str) -> Value {
    json!({
        "schema_version": "1.8.0",
        "id": id,
        "modified": modified,
        "affected": [{
            "package": {"ecosystem": "npm", "name": name},
            "versions": [version]
        }]
    })
}
#[test]
fn batch_transport_aligns_subsets_and_hydrates_unique_ids() {
    let transport = MockTransport::new(
        vec![
            batch(vec![
                result(
                    vec![summary("GHSA-SHARED", "2026-07-19T00:00:00.123456Z")],
                    Some("next-a"),
                ),
                result(
                    vec![summary("GHSA-SHARED", "2026-07-19T00:00:00.123456Z")],
                    None,
                ),
            ]),
            batch(vec![result(
                vec![summary("GHSA-A", "2026-07-19T00:00:01Z")],
                None,
            )]),
        ],
        vec![
            (
                "GHSA-A",
                vec![advisory(
                    "GHSA-A",
                    "2026-07-19T00:00:01.999999999Z",
                    "a",
                    "1.0.0",
                )],
            ),
            (
                "GHSA-SHARED",
                vec![json!({
                    "schema_version": "1.8.0",
                    "id": "GHSA-SHARED",
                    "modified": "2026-07-19T00:00:00.123456789Z",
                    "affected": [
                        {"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]},
                        {"package":{"ecosystem":"npm","name":"b"},"versions":["2.0.0"]}
                    ]
                })],
            ),
        ],
    );
    let snapshot = OsvClient::new(&transport)
        .query(&set(vec![query("b", "2.0.0"), query("a", "1.0.0")]))
        .unwrap();
    assert_eq!(snapshot.queries.len(), 2);
    assert_eq!(snapshot.queries[0].summaries.len(), 2);
    assert_eq!(snapshot.queries[1].summaries.len(), 1);
    let shared = snapshot
        .queries
        .iter()
        .flat_map(|query| &query.advisories)
        .find(|advisory| advisory.primary_id == "GHSA-SHARED")
        .unwrap();
    assert_eq!(shared.batch_summary_modified, "2026-07-19T00:00:00.123456Z");
    assert_eq!(shared.detail_modified, "2026-07-19T00:00:00.123456789Z");
    assert_eq!(
        transport
            .calls()
            .iter()
            .filter(|call| call.as_str() == "detail:GHSA-SHARED")
            .count(),
        1
    );
    assert_eq!(transport.calls()[..2], ["batch:2", "batch:1"]);
}
#[test]
fn snapshot_consistency_retries_only_races_and_succeeds_on_second_round() {
    let transport = MockTransport::new(
        vec![
            batch(vec![result(
                vec![summary("GHSA-RACE", "2026-07-19T00:00:00.000000Z")],
                None,
            )]),
            batch(vec![result(
                vec![summary("GHSA-RACE", "2026-07-19T00:00:01.000000Z")],
                None,
            )]),
        ],
        vec![(
            "GHSA-RACE",
            vec![
                advisory(
                    "GHSA-RACE",
                    "2026-07-19T00:00:00.000001000Z",
                    "demo",
                    "1.0.0",
                ),
                advisory(
                    "GHSA-RACE",
                    "2026-07-19T00:00:01.000000999Z",
                    "demo",
                    "1.0.0",
                ),
            ],
        )],
    );
    let snapshot = OsvClient::new(&transport)
        .query(&set(vec![query("demo", "1.0.0")]))
        .unwrap();
    assert_eq!(snapshot.request_count, 4);
}
#[test]
fn snapshot_consistency_fails_when_second_round_is_still_a_race() {
    let batches = (0..2)
        .map(|_| {
            batch(vec![result(
                vec![summary("GHSA-RACE", "2026-07-19T00:00:00.000000Z")],
                None,
            )])
        })
        .collect();
    let details = (0..2)
        .map(|_| {
            advisory(
                "GHSA-RACE",
                "2026-07-19T00:00:00.000001000Z",
                "demo",
                "1.0.0",
            )
        })
        .collect();
    let transport = MockTransport::new(batches, vec![("GHSA-RACE", details)]);
    assert_eq!(
        OsvClient::new(&transport)
            .query(&set(vec![query("demo", "1.0.0")]))
            .unwrap_err()
            .kind,
        OsvErrorKind::SnapshotRace
    );
    assert_eq!(transport.calls().len(), 4);
}
#[test]
fn withdrawn_and_nonmatch_are_snapshot_races() {
    for detail in [
        json!({
            "schema_version":"1.8.0","id":"GHSA-RACE",
            "modified":"2026-07-19T00:00:00Z",
            "withdrawn":"2026-07-19T00:00:01Z",
            "affected":[{"package":{"ecosystem":"npm","name":"demo"},"versions":["1.0.0"]}]
        }),
        advisory("GHSA-RACE", "2026-07-19T00:00:00Z", "other", "1.0.0"),
    ] {
        let transport = MockTransport::new(
            vec![
                batch(vec![result(
                    vec![summary("GHSA-RACE", "2026-07-19T00:00:00Z")],
                    None,
                )]),
                batch(vec![result(
                    vec![summary("GHSA-RACE", "2026-07-19T00:00:00Z")],
                    None,
                )]),
            ],
            vec![("GHSA-RACE", vec![detail.clone(), detail])],
        );
        assert_eq!(
            OsvClient::new(&transport)
                .query(&set(vec![query("demo", "1.0.0")]))
                .unwrap_err()
                .kind,
            OsvErrorKind::SnapshotRace
        );
    }
}
#[test]
fn malformed_detail_id_and_json_do_not_retry() {
    for detail in [
        advisory("GHSA-WRONG", "2026-07-19T00:00:00Z", "demo", "1.0.0"),
        json!({"id":"GHSA-ONE","modified":"invalid"}),
    ] {
        let transport = MockTransport::new(
            vec![batch(vec![result(
                vec![summary("GHSA-ONE", "2026-07-19T00:00:00Z")],
                None,
            )])],
            vec![("GHSA-ONE", vec![detail])],
        );
        assert_eq!(
            OsvClient::new(&transport)
                .query(&set(vec![query("demo", "1.0.0")]))
                .unwrap_err()
                .kind,
            OsvErrorKind::MalformedResponse
        );
        assert_eq!(transport.calls().len(), 2);
    }
}
#[test]
fn rejects_position_length_token_and_page_failures() {
    let coordinate = set(vec![query("demo", "1.0.0")]);
    let cases = vec![
        vec![batch(vec![])],
        vec![batch(vec![result(vec![], Some(""))])],
        vec![
            batch(vec![result(vec![], Some("same"))]),
            batch(vec![result(vec![], Some("same"))]),
        ],
        (0..MAX_PAGES_PER_COORDINATE)
            .map(|index| batch(vec![result(vec![], Some(&format!("token-{index}")))]))
            .collect(),
        vec![batch(vec![result(
            vec![],
            Some(&"x".repeat(MAX_PAGE_TOKEN_BYTES + 1)),
        )])],
    ];
    for batches in cases {
        let transport = MockTransport::new(batches, vec![]);
        let error = OsvClient::new(&transport).query(&coordinate).unwrap_err();
        assert!(matches!(
            error.kind,
            OsvErrorKind::MalformedResponse | OsvErrorKind::ResourceLimit
        ));
    }
}
#[test]
fn rejects_duplicate_summary_and_modified_interval_conflict() {
    let duplicate = MockTransport::new(
        vec![batch(vec![result(
            vec![
                summary("GHSA-X", "2026-07-19T00:00:00Z"),
                summary("GHSA-X", "2026-07-19T00:00:00Z"),
            ],
            None,
        )])],
        vec![],
    );
    assert_eq!(
        OsvClient::new(&duplicate)
            .query(&set(vec![query("demo", "1.0.0")]))
            .unwrap_err()
            .kind,
        OsvErrorKind::MalformedResponse
    );
    let conflict = MockTransport::new(
        vec![batch(vec![
            result(vec![summary("GHSA-X", "2026-07-19T00:00:00.000000Z")], None),
            result(vec![summary("GHSA-X", "2026-07-19T00:00:00.000001Z")], None),
        ])],
        vec![],
    );
    assert_eq!(
        OsvClient::new(&conflict)
            .query(&set(vec![query("a", "1.0.0"), query("b", "1.0.0")]))
            .unwrap_err()
            .kind,
        OsvErrorKind::MalformedResponse
    );
}
#[test]
fn status_content_type_body_and_transport_failures_are_typed() {
    let mut responses = vec![
        TransportResponse {
            status: 302,
            content_type: Some("application/json".to_string()),
            body: vec![],
        },
        TransportResponse {
            status: 200,
            content_type: Some("text/html".to_string()),
            body: vec![],
        },
        TransportResponse {
            status: 200,
            content_type: None,
            body: vec![],
        },
        TransportResponse {
            status: 200,
            content_type: Some("application/json".to_string()),
            body: vec![b' '; MAX_QUERY_RESPONSE_BYTES + 1],
        },
    ];
    for response in responses.drain(..) {
        let transport = MockTransport::with_batch_response(Ok(response));
        let error = OsvClient::new(&transport)
            .query(&set(vec![query("demo", "1.0.0")]))
            .unwrap_err();
        assert!(matches!(
            error.kind,
            OsvErrorKind::Transport | OsvErrorKind::ResourceLimit
        ));
    }
    for detail in ["TLS", "DNS", "timeout", "body read"] {
        let transport =
            MockTransport::with_batch_response(Err(OsvError::new(OsvErrorKind::Transport, detail)));
        assert_eq!(
            OsvClient::new(&transport)
                .query(&set(vec![query("demo", "1.0.0")]))
                .unwrap_err()
                .kind,
            OsvErrorKind::Transport
        );
    }
}
#[test]
fn detail_body_limit_accepts_equality_and_rejects_plus_one() {
    let summary_batch = || {
        batch(vec![result(
            vec![summary("GHSA-LIMIT", "2026-07-19T00:00:00Z")],
            None,
        )])
    };
    let mut exact = serde_json::to_vec(&advisory(
        "GHSA-LIMIT",
        "2026-07-19T00:00:00Z",
        "demo",
        "1.0.0",
    ))
    .unwrap();
    exact.resize(MAX_DETAIL_RESPONSE_BYTES, b' ');
    for (body, expected) in [
        (exact, None),
        (
            vec![b' '; MAX_DETAIL_RESPONSE_BYTES + 1],
            Some(OsvErrorKind::ResourceLimit),
        ),
    ] {
        let transport = MockTransport {
            batches: Mutex::new([Ok(json_response(summary_batch()))].into()),
            details: Mutex::new(BTreeMap::from([(
                "GHSA-LIMIT".to_string(),
                [Ok(TransportResponse {
                    status: 200,
                    content_type: Some("application/json".to_string()),
                    body,
                })]
                .into(),
            )])),
            calls: Mutex::new(Vec::new()),
        };
        let result = OsvClient::new(&transport).query(&set(vec![query("demo", "1.0.0")]));
        match expected {
            None => assert!(result.is_ok()),
            Some(kind) => assert_eq!(result.unwrap_err().kind, kind),
        }
    }
}
#[test]
fn query_body_uses_stable_batches_of_one_thousand() {
    let queries = (0..1_001)
        .map(|index| query(&format!("package-{index:04}"), "1.0.0"))
        .collect();
    let transport = MockTransport::new(
        vec![
            batch((0..1_000).map(|_| result(vec![], None)).collect()),
            batch(vec![result(vec![], None)]),
        ],
        vec![],
    );
    let snapshot = OsvClient::new(&transport).query(&set(queries)).unwrap();
    assert_eq!(snapshot.queries.len(), 1_001);
    assert_eq!(transport.calls(), ["batch:1000", "batch:1"]);
}
fn canonical_limits(decoded_response_bytes: usize) -> ResponseLimits {
    ResponseLimits {
        encoded_request_bytes: MAX_ENCODED_REQUEST_BYTES,
        decoded_response_bytes,
        connect_timeout: CONNECT_TIMEOUT,
        request_timeout: REQUEST_TIMEOUT,
        redirect_limit: 0,
        send_credentials: false,
    }
}
#[test]
fn production_transport_rejects_oversize_request_and_unsafe_path_without_network() {
    let transport = HttpsOsvTransport::default();
    assert_eq!(
        transport
            .post_query_batch(
                &vec![b'x'; MAX_ENCODED_REQUEST_BYTES + 1],
                canonical_limits(MAX_QUERY_RESPONSE_BYTES),
            )
            .unwrap_err()
            .kind,
        OsvErrorKind::ResourceLimit
    );
    assert_eq!(
        transport
            .get_advisory("../escape", canonical_limits(MAX_DETAIL_RESPONSE_BYTES))
            .unwrap_err()
            .kind,
        OsvErrorKind::MalformedResponse
    );
}
#[test]
fn malformed_batch_and_detail_shapes_fail_without_retry() {
    let malformed_batch = MockTransport::with_batch_response(Ok(TransportResponse {
        status: 200,
        content_type: Some("application/json".to_string()),
        body: b"{".to_vec(),
    }));
    assert_eq!(
        OsvClient::new(&malformed_batch)
            .query(&set(vec![query("demo", "1.0.0")]))
            .unwrap_err()
            .kind,
        OsvErrorKind::MalformedResponse
    );
    let transport = MockTransport::new(
        vec![batch(vec![result(
            vec![summary("GHSA-BAD", "2026-07-19T00:00:00Z")],
            None,
        )])],
        vec![(
            "GHSA-BAD",
            vec![json!({
                "id":"GHSA-BAD",
                "modified":"2026-07-19T00:00:00Z",
                "affected":[]
            })],
        )],
    );
    assert_eq!(
        OsvClient::new(&transport)
            .query(&set(vec![query("demo", "1.0.0")]))
            .unwrap_err()
            .kind,
        OsvErrorKind::MalformedResponse
    );
    assert_eq!(transport.calls().len(), 2);
}
#[test]
fn encoded_request_limit_is_enforced_before_transport() {
    let version = format!("1.0.0-{}", "a".repeat(1_018));
    let queries = (0..1_000)
        .map(|index| {
            let suffix = format!("{index:04}");
            query(
                &format!("{}{}", "x".repeat(4_096 - suffix.len()), suffix),
                &version,
            )
        })
        .collect();
    let transport = MockTransport::new(vec![], vec![]);
    assert_eq!(
        OsvClient::new(&transport)
            .query(&set(queries))
            .unwrap_err()
            .kind,
        OsvErrorKind::ResourceLimit
    );
    assert!(transport.calls().is_empty());
}
#[test]
fn unique_advisory_and_association_limits_fail_before_hydration() {
    let unique = (0..20_001)
        .map(|index| summary(&format!("GHSA-{index:05}"), "2026-07-19T00:00:00Z"))
        .collect();
    let transport = MockTransport::new(vec![batch(vec![result(unique, None)])], vec![]);
    assert_eq!(
        OsvClient::new(&transport)
            .query(&set(vec![query("demo", "1.0.0")]))
            .unwrap_err()
            .kind,
        OsvErrorKind::ResourceLimit
    );
    let per_coordinate = MAX_ASSOCIATIONS / 1_000 + 1;
    let result_value = || {
        result(
            (0..per_coordinate)
                .map(|id| summary(&format!("GHSA-{id:03}"), "2026-07-19T00:00:00Z"))
                .collect(),
            None,
        )
    };
    let queries = (0..1_000)
        .map(|index| query(&format!("package-{index:04}"), "1.0.0"))
        .collect();
    let transport = MockTransport::new(
        vec![batch((0..1_000).map(|_| result_value()).collect())],
        vec![],
    );
    assert_eq!(
        OsvClient::new(&transport)
            .query(&set(queries))
            .unwrap_err()
            .kind,
        OsvErrorKind::ResourceLimit
    );
}
#[test]
fn rejects_invalid_ids_timestamps_and_nullable_closed_fields() {
    for body in [
        batch(vec![result(
            vec![summary("", "2026-07-19T00:00:00Z")],
            None,
        )]),
        batch(vec![result(
            vec![summary("GHSA-X", "2026-07-19T00:00:00+00:00")],
            None,
        )]),
        batch(vec![result(
            vec![summary("GHSA-X", "2026-07-19T00:00:00.1234567890Z")],
            None,
        )]),
        batch(vec![result(
            vec![summary("GHSA-X", "2026-07-19T00:00:00.Z")],
            None,
        )]),
        batch(vec![result(
            vec![summary("GHSA-X", "2026-13-19T00:00:00Z")],
            None,
        )]),
        json!({"results":[{"vulns":null}]}),
        json!({"results":[{"next_page_token":null}]}),
        json!({"results":[{"unknown":true}]}),
    ] {
        let transport = MockTransport::new(vec![body], vec![]);
        assert!(OsvClient::new(&transport)
            .query(&set(vec![query("demo", "1.0.0")]))
            .is_err());
    }
}
#[test]
fn malformed_detail_body_and_missing_modified_fail_closed() {
    for body in [b"{".to_vec(), br#"{"id":"GHSA-BAD"}"#.to_vec()] {
        let transport = MockTransport {
            batches: Mutex::new(
                [Ok(json_response(batch(vec![result(
                    vec![summary("GHSA-BAD", "2026-07-19T00:00:00Z")],
                    None,
                )])))]
                .into(),
            ),
            details: Mutex::new(BTreeMap::from([(
                "GHSA-BAD".to_string(),
                [Ok(TransportResponse {
                    status: 200,
                    content_type: Some("application/json".to_string()),
                    body,
                })]
                .into(),
            )])),
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(
            OsvClient::new(&transport)
                .query(&set(vec![query("demo", "1.0.0")]))
                .unwrap_err()
                .kind,
            OsvErrorKind::MalformedResponse
        );
    }
}
#[test]
fn advisory_ids_are_percent_encoded_for_the_fixed_detail_path() {
    let transport = MockTransport::new(
        vec![batch(vec![result(
            vec![summary("GHSA:ENCODED", "2026-07-19T00:00:00Z")],
            None,
        )])],
        vec![(
            "GHSA%3AENCODED",
            vec![advisory(
                "GHSA:ENCODED",
                "2026-07-19T00:00:00Z",
                "demo",
                "1.0.0",
            )],
        )],
    );
    assert_eq!(
        OsvClient::new(&transport)
            .query(&set(vec![query("demo", "1.0.0")]))
            .unwrap_err()
            .kind,
        OsvErrorKind::MalformedResponse
    );
    assert_eq!(transport.calls()[1], "detail:GHSA%3AENCODED");
}
#[test]
fn detail_hydration_never_exceeds_eight_concurrent_requests() {
    let ids = [
        "GHSA-0", "GHSA-1", "GHSA-2", "GHSA-3", "GHSA-4", "GHSA-5", "GHSA-6", "GHSA-7", "GHSA-8",
    ];
    let inner = MockTransport::new(
        vec![batch(vec![result(
            ids.iter()
                .map(|id| summary(id, "2026-07-19T00:00:00Z"))
                .collect(),
            None,
        )])],
        ids.iter()
            .map(|id| {
                (
                    *id,
                    vec![advisory(id, "2026-07-19T00:00:00Z", "demo", "1.0.0")],
                )
            })
            .collect(),
    );
    let transport = ConcurrencyTransport {
        inner,
        active: AtomicUsize::new(0),
        maximum: AtomicUsize::new(0),
    };
    OsvClient::new(&transport)
        .query(&set(vec![query("demo", "1.0.0")]))
        .unwrap();
    assert_eq!(transport.maximum.load(Ordering::SeqCst), 8);
}
#[test]
fn aggregate_known_evidence_limit_fails_before_network() {
    let prefix = "x".repeat(MAX_LOCATOR_BYTES - 6);
    let locators = (0..8_200)
        .map(|index| format!("{index:05}:{prefix}"))
        .collect();
    let coordinates = CoordinateSet {
        queries: vec![CoordinateQuery {
            coordinate: PackageCoordinate::new(Ecosystem::Npm, "demo", "1.0.0").unwrap(),
            locators,
        }],
        excluded_local_records: 0,
    };
    let transport = MockTransport::new(vec![], vec![]);
    let reject = |coordinates: &CoordinateSet, expected| {
        let error = OsvClient::new(&transport).query(coordinates).unwrap_err();
        assert_eq!(error.kind, expected);
    };
    reject(&coordinates, OsvErrorKind::ResourceLimit);
    for version in ["${revision}", "1.2.3-${changelist}"] {
        let coordinates = CoordinateSet {
            queries: vec![CoordinateQuery {
                coordinate: PackageCoordinate::new(Ecosystem::Maven, "org.example:demo", version)
                    .unwrap(),
                locators: vec![],
            }],
            excluded_local_records: 0,
        };
        reject(&coordinates, OsvErrorKind::InvalidInput);
    }
    assert!(transport.calls().is_empty());
}
