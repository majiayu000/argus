use super::*;
use argus_core::{Ecosystem, PackageCoordinate};

const MODIFIED: &str = "2026-07-27T00:00:00Z";

fn state(name: &str) -> QueryState {
    QueryState::new(
        CoordinateQuery::new(
            PackageCoordinate::new(Ecosystem::Npm, name, "1.0.0").unwrap(),
            Vec::new(),
        )
        .unwrap(),
    )
}

fn summary(id: impl Into<String>) -> BatchSummary {
    BatchSummary {
        id: id.into(),
        modified: MODIFIED.to_string(),
    }
}

#[test]
fn encoded_query_body_accepts_exact_limit_and_rejects_plus_one() {
    let mut states = (0..MAX_BATCH_QUERIES)
        .map(|index| state(&format!("package-{index:04}")))
        .collect::<Vec<_>>();
    let indices = (0..states.len()).collect::<Vec<_>>();
    let baseline = encode_batch_request(&indices, &states).unwrap().len();
    let mut remaining = MAX_ENCODED_REQUEST_BYTES - baseline;
    for query_state in &mut states {
        let name = &mut query_state.query.coordinate.canonical_name;
        let available = crate::model::MAX_PACKAGE_NAME_BYTES - name.len();
        let add = available.min(remaining);
        name.push_str(&"a".repeat(add));
        remaining -= add;
        if remaining == 0 {
            break;
        }
    }
    for query_state in &mut states {
        let version = &mut query_state.query.coordinate.version;
        let available = crate::model::MAX_PACKAGE_VERSION_BYTES - version.len();
        let add = available.min(remaining);
        version.push_str(&"a".repeat(add));
        remaining -= add;
        if remaining == 0 {
            break;
        }
    }
    assert_eq!(remaining, 0, "coordinate name capacity must reach 4 MiB");
    assert_eq!(
        encode_batch_request(&indices, &states).unwrap().len(),
        MAX_ENCODED_REQUEST_BYTES
    );
    states[MAX_BATCH_QUERIES - 1]
        .query
        .coordinate
        .version
        .push('a');
    assert_eq!(
        encode_batch_request(&indices, &states).unwrap_err().kind,
        OsvErrorKind::ResourceLimit
    );
}

#[test]
fn query_response_body_accepts_exact_limit_and_rejects_plus_one() {
    let response = |length| TransportResponse {
        status: 200,
        content_type: Some("application/json".to_string()),
        body: vec![b' '; length],
    };
    assert_eq!(
        validate_response(
            response(MAX_QUERY_RESPONSE_BYTES),
            MAX_QUERY_RESPONSE_BYTES,
            "querybatch",
        )
        .unwrap()
        .len(),
        MAX_QUERY_RESPONSE_BYTES
    );
    assert_eq!(
        validate_response(
            response(MAX_QUERY_RESPONSE_BYTES + 1),
            MAX_QUERY_RESPONSE_BYTES,
            "querybatch",
        )
        .unwrap_err()
        .kind,
        OsvErrorKind::ResourceLimit
    );
}

#[test]
fn total_decoded_and_request_budgets_cover_equality_plus_one_and_overflow() {
    let mut decoded = OperationBudget {
        requests: 0,
        decoded_bytes: MAX_TOTAL_DECODED_BYTES - 1,
    };
    decoded.observe_bytes(1).unwrap();
    assert_eq!(decoded.decoded_bytes, MAX_TOTAL_DECODED_BYTES);
    assert_eq!(
        decoded.observe_bytes(1).unwrap_err().kind,
        OsvErrorKind::ResourceLimit
    );
    decoded.decoded_bytes = usize::MAX;
    assert_eq!(
        decoded.observe_bytes(1).unwrap_err().detail,
        "decoded byte count overflowed"
    );

    for jobs in [1, 2, 8, 64] {
        let mut requests = OperationBudget {
            requests: MAX_HTTP_REQUESTS - 1,
            decoded_bytes: 0,
        };
        requests.reserve_requests(1).unwrap();
        assert_eq!(requests.requests, MAX_HTTP_REQUESTS, "jobs={jobs}");
        assert_eq!(
            requests.reserve_requests(1).unwrap_err().kind,
            OsvErrorKind::ResourceLimit,
            "jobs={jobs}"
        );
    }
    let overflow = OperationBudget {
        requests: usize::MAX,
        decoded_bytes: 0,
    };
    assert_eq!(
        overflow.ensure_request_capacity(1).unwrap_err().detail,
        "HTTP request count overflowed"
    );
}

#[test]
fn page_count_accepts_last_page_and_rejects_a_required_extra_page() {
    let mut complete = vec![state("complete")];
    complete[0].pages = MAX_PAGES_PER_COORDINATE - 1;
    process_batch_result(
        0,
        BatchResult {
            vulns: Vec::new(),
            next_page_token: None,
        },
        &mut complete,
        &mut BTreeMap::new(),
        &mut 0,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(complete[0].pages, MAX_PAGES_PER_COORDINATE);

    let mut extra = vec![state("extra")];
    extra[0].pages = MAX_PAGES_PER_COORDINATE - 1;
    assert_eq!(
        process_batch_result(
            0,
            BatchResult {
                vulns: Vec::new(),
                next_page_token: Some("page-17".to_string()),
            },
            &mut extra,
            &mut BTreeMap::new(),
            &mut 0,
            &mut Vec::new(),
        )
        .unwrap_err()
        .kind,
        OsvErrorKind::ResourceLimit
    );
}

#[test]
fn association_count_accepts_exact_limit_and_rejects_plus_one_and_overflow() {
    let mut states = vec![state("associations")];
    let mut intervals = BTreeMap::new();
    let mut next = Vec::new();
    let mut count = MAX_ASSOCIATIONS - 1;
    process_batch_result(
        0,
        BatchResult {
            vulns: vec![summary("GHSA-EXACT")],
            next_page_token: None,
        },
        &mut states,
        &mut intervals,
        &mut count,
        &mut next,
    )
    .unwrap();
    assert_eq!(count, MAX_ASSOCIATIONS);
    assert_eq!(
        process_batch_result(
            0,
            BatchResult {
                vulns: vec![summary("GHSA-PLUS-ONE")],
                next_page_token: None,
            },
            &mut states,
            &mut intervals,
            &mut count,
            &mut next,
        )
        .unwrap_err()
        .kind,
        OsvErrorKind::ResourceLimit
    );

    count = usize::MAX;
    assert_eq!(
        process_batch_result(
            0,
            BatchResult {
                vulns: vec![summary("GHSA-OVERFLOW")],
                next_page_token: None,
            },
            &mut states,
            &mut intervals,
            &mut count,
            &mut next,
        )
        .unwrap_err()
        .detail,
        "summary association count overflowed"
    );
}

#[test]
fn unique_advisory_count_accepts_exact_limit_and_rejects_plus_one() {
    ensure_unique_advisory_count(MAX_UNIQUE_ADVISORY_IDS).unwrap();
    assert_eq!(
        ensure_unique_advisory_count(MAX_UNIQUE_ADVISORY_IDS + 1)
            .unwrap_err()
            .kind,
        OsvErrorKind::ResourceLimit
    );
}
