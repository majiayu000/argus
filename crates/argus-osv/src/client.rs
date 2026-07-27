use crate::coordinator::OsvCoordinator;
use crate::model::{
    modified_intervals_overlap, parse_modified, CoordinateQuery, CoordinateSet, ModifiedInterval,
    NormalizedAdvisory, OsvError, OsvErrorKind, MAX_ID_BYTES,
};
use crate::normalize::normalize_advisory;
pub use crate::transport::{
    HttpsOsvTransport, OsvTransport, ResponseLimits, TransportAttempt, TransportResponse,
    CONNECT_TIMEOUT, REQUEST_TIMEOUT,
};
use argus_core::ExecutionContext;
use argus_osv_schema::parse_osv_record;
use argus_transport::GET_MAX_ATTEMPTS;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

pub const MAX_BATCH_QUERIES: usize = 1_000;
pub const MAX_PAGE_TOKEN_BYTES: usize = 4 * 1024;
pub const MAX_PAGES_PER_COORDINATE: usize = 16;
pub const MAX_ASSOCIATIONS: usize = 100_000;
pub const MAX_UNIQUE_ADVISORY_IDS: usize = 20_000;
pub const MAX_HTTP_REQUESTS: usize = 25_000;
pub const MAX_OSV_IN_FLIGHT: usize = 8;
pub const MAX_DETAIL_CONCURRENCY: usize = MAX_OSV_IN_FLIGHT;
pub const MAX_ENCODED_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_QUERY_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DETAIL_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TOTAL_DECODED_BYTES: usize = 512 * 1024 * 1024;
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuerySummary {
    pub primary_id: String,
    pub modified: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuerySnapshot {
    pub query: CoordinateQuery,
    pub summaries: Vec<QuerySummary>,
    pub advisories: Vec<NormalizedAdvisory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteSnapshot {
    pub queries: Vec<QuerySnapshot>,
    pub request_count: usize,
    pub total_decoded_bytes: usize,
}

pub trait OsvClock: Send + Sync {
    fn elapsed(&self, started: Instant) -> Duration;
}

struct SystemOsvClock;

impl OsvClock for SystemOsvClock {
    fn elapsed(&self, started: Instant) -> Duration {
        started.elapsed()
    }
}

static SYSTEM_OSV_CLOCK: SystemOsvClock = SystemOsvClock;

pub struct OsvClient<'a> {
    transport: &'a dyn OsvTransport,
    clock: &'a dyn OsvClock,
}

impl<'a> OsvClient<'a> {
    pub fn new(transport: &'a dyn OsvTransport) -> Self {
        Self {
            transport,
            clock: &SYSTEM_OSV_CLOCK,
        }
    }

    pub fn with_clock(transport: &'a dyn OsvTransport, clock: &'a dyn OsvClock) -> Self {
        Self { transport, clock }
    }

    pub fn query(&self, coordinates: &CoordinateSet) -> Result<CompleteSnapshot, OsvError> {
        let execution = ExecutionContext::serial().map_err(|error| {
            OsvError::new(
                OsvErrorKind::Internal,
                format!("construct serial OSV execution context: {error}"),
            )
        })?;
        self.query_with_context(coordinates, &execution)
    }

    pub fn query_with_context(
        &self,
        coordinates: &CoordinateSet,
        execution: &ExecutionContext,
    ) -> Result<CompleteSnapshot, OsvError> {
        coordinates.validate()?;
        let started = Instant::now();
        let mut budget = OperationBudget::default();
        let first = self.query_round(coordinates, execution, started, &mut budget);
        let mut snapshot = match first {
            Err(error) if error.kind == OsvErrorKind::SnapshotRace => {
                self.query_round(coordinates, execution, started, &mut budget)?
            }
            result => result?,
        };
        snapshot.request_count = budget.requests;
        snapshot.total_decoded_bytes = budget.decoded_bytes;
        Ok(snapshot)
    }

    fn query_round(
        &self,
        coordinates: &CoordinateSet,
        execution: &ExecutionContext,
        started: Instant,
        budget: &mut OperationBudget,
    ) -> Result<CompleteSnapshot, OsvError> {
        let coordinator = OsvCoordinator::new(execution);
        let mut states = coordinates
            .queries
            .iter()
            .cloned()
            .map(QueryState::new)
            .collect::<Vec<_>>();
        let mut pending = (0..states.len()).collect::<Vec<_>>();
        let mut intervals = BTreeMap::<String, Vec<ModifiedInterval>>::new();
        let mut association_count = 0usize;

        while !pending.is_empty() {
            let mut next_pending = Vec::new();
            let chunks = pending.chunks(MAX_BATCH_QUERIES).collect::<Vec<_>>();
            for window in chunks.chunks(coordinator.window_size()) {
                self.ensure_operation_time(started)?;
                let work = window
                    .iter()
                    .map(|indices| {
                        Ok(BatchWork {
                            indices: (*indices).to_vec(),
                            body: encode_batch_request(indices, &states)?,
                        })
                    })
                    .collect::<Result<Vec<_>, OsvError>>()?;
                budget.reserve_requests(work.len())?;
                let outcomes = coordinator.execute_window(&work, |_, item| {
                    let operation_remaining = self.operation_remaining(started)?;
                    let response = self.transport.post_query_batch(
                        &item.body,
                        response_limits(MAX_QUERY_RESPONSE_BYTES, operation_remaining),
                    )?;
                    let body = validate_response(response, MAX_QUERY_RESPONSE_BYTES, "querybatch")?;
                    let decoded_bytes = body.len();
                    let response =
                        serde_json::from_slice::<BatchResponse>(&body).map_err(|error| {
                            OsvError::new(
                                OsvErrorKind::MalformedResponse,
                                format!("parse querybatch JSON: {error}"),
                            )
                        })?;
                    Ok(BatchOutcome {
                        decoded_bytes,
                        response,
                    })
                })?;
                self.ensure_operation_time(started)?;
                for (item, outcome) in work.into_iter().zip(outcomes) {
                    budget.observe_bytes(outcome.decoded_bytes)?;
                    if outcome.response.results.len() != item.indices.len() {
                        return Err(OsvError::new(
                            OsvErrorKind::MalformedResponse,
                            format!(
                                "querybatch returned {} results for {} positional queries",
                                outcome.response.results.len(),
                                item.indices.len()
                            ),
                        ));
                    }
                    for (index, result) in item.indices.into_iter().zip(outcome.response.results) {
                        process_batch_result(
                            index,
                            result,
                            &mut states,
                            &mut intervals,
                            &mut association_count,
                            &mut next_pending,
                        )?;
                    }
                }
            }
            pending = next_pending;
        }

        ensure_unique_advisory_count(intervals.len())?;
        let details = self.hydrate_details(intervals.keys(), &coordinator, started, budget)?;
        let mut queries = Vec::with_capacity(states.len());
        for state in states {
            let mut advisories = Vec::with_capacity(state.summaries.len());
            for summary in &state.summaries {
                let (record, raw_modified) = details.get(&summary.primary_id).ok_or_else(|| {
                    OsvError::new(
                        OsvErrorKind::Internal,
                        format!("missing hydrated advisory `{}`", summary.primary_id),
                    )
                })?;
                let detail_instant = parse_modified(raw_modified)?.start;
                if !intervals[&summary.primary_id]
                    .iter()
                    .all(|interval| interval.contains(detail_instant))
                {
                    return Err(OsvError::new(
                        OsvErrorKind::SnapshotRace,
                        format!(
                            "detail modified `{raw_modified}` is outside a batch summary interval for `{}`",
                            summary.primary_id
                        ),
                    ));
                }
                advisories.push(normalize_advisory(
                    record,
                    &state.query,
                    &summary.modified,
                    raw_modified,
                )?);
            }
            advisories.sort_by(|left, right| left.primary_id.cmp(&right.primary_id));
            queries.push(QuerySnapshot {
                query: state.query,
                summaries: state.summaries,
                advisories,
            });
        }
        Ok(CompleteSnapshot {
            queries,
            request_count: 0,
            total_decoded_bytes: 0,
        })
    }

    fn hydrate_details<'b>(
        &self,
        ids: impl Iterator<Item = &'b String>,
        coordinator: &OsvCoordinator<'_>,
        started: Instant,
        budget: &mut OperationBudget,
    ) -> Result<BTreeMap<String, (argus_osv_schema::OsvRecord, String)>, OsvError> {
        let ids = ids.cloned().collect::<Vec<_>>();
        let mut details = BTreeMap::new();
        for chunk in ids.chunks(coordinator.window_size()) {
            self.ensure_operation_time(started)?;
            let maximum_attempts = chunk.len().checked_mul(GET_MAX_ATTEMPTS).ok_or_else(|| {
                OsvError::new(
                    OsvErrorKind::ResourceLimit,
                    "advisory detail request reservation overflowed",
                )
            })?;
            budget.reserve_requests(maximum_attempts)?;
            let outcomes = coordinator.execute_window(chunk, |_, requested_id| {
                let operation_remaining = self.operation_remaining(started)?;
                let encoded = percent_encode_id(requested_id);
                let attempted = self.transport.get_advisory_attempted(
                    &encoded,
                    response_limits(MAX_DETAIL_RESPONSE_BYTES, operation_remaining),
                );
                let result = attempted.result.and_then(|response| {
                    let body =
                        validate_response(response, MAX_DETAIL_RESPONSE_BYTES, "advisory detail")?;
                    let decoded_bytes = body.len();
                    let raw_modified = detail_modified(&body)?;
                    let record = parse_osv_record(&body).map_err(|error| {
                        OsvError::new(
                            OsvErrorKind::MalformedResponse,
                            format!("parse advisory detail `{requested_id}`: {error}"),
                        )
                    })?;
                    if record.id != *requested_id {
                        return Err(OsvError::new(
                            OsvErrorKind::MalformedResponse,
                            format!(
                                "detail ID `{}` does not match requested `{requested_id}`",
                                record.id
                            ),
                        ));
                    }
                    Ok(ParsedDetail {
                        decoded_bytes,
                        raw_modified,
                        record,
                    })
                });
                Ok(DetailOutcome {
                    attempts: attempted.attempts,
                    result,
                })
            })?;
            self.ensure_operation_time(started)?;
            let actual_attempts = outcomes.iter().try_fold(0usize, |total, outcome| {
                total.checked_add(outcome.attempts).ok_or_else(|| {
                    OsvError::new(
                        OsvErrorKind::ResourceLimit,
                        "advisory detail attempt count overflowed",
                    )
                })
            })?;
            budget.settle_request_reservation(maximum_attempts, actual_attempts)?;
            for (requested_id, outcome) in chunk.iter().cloned().zip(outcomes) {
                let parsed = outcome.result?;
                budget.observe_bytes(parsed.decoded_bytes)?;
                details.insert(requested_id, (parsed.record, parsed.raw_modified));
            }
        }
        Ok(details)
    }

    fn operation_remaining(&self, started: Instant) -> Result<Duration, OsvError> {
        let remaining = OPERATION_TIMEOUT.saturating_sub(self.clock.elapsed(started));
        if remaining.is_zero() {
            return Err(operation_timeout());
        }
        Ok(remaining)
    }

    fn ensure_operation_time(&self, started: Instant) -> Result<(), OsvError> {
        self.operation_remaining(started).map(|_| ())
    }
}

#[derive(Default)]
struct OperationBudget {
    requests: usize,
    decoded_bytes: usize,
}

impl OperationBudget {
    fn ensure_request_capacity(&self, count: usize) -> Result<(), OsvError> {
        let requests = self.requests.checked_add(count).ok_or_else(|| {
            OsvError::new(OsvErrorKind::ResourceLimit, "HTTP request count overflowed")
        })?;
        if requests > MAX_HTTP_REQUESTS {
            return Err(OsvError::new(
                OsvErrorKind::ResourceLimit,
                format!("HTTP request count exceeds maximum {MAX_HTTP_REQUESTS}"),
            ));
        }
        Ok(())
    }

    fn reserve_requests(&mut self, count: usize) -> Result<(), OsvError> {
        self.ensure_request_capacity(count)?;
        self.requests += count;
        Ok(())
    }

    fn settle_request_reservation(
        &mut self,
        reserved: usize,
        actual: usize,
    ) -> Result<(), OsvError> {
        if actual > reserved {
            return Err(OsvError::new(
                OsvErrorKind::Internal,
                "OSV transport exceeded its reserved attempt count",
            ));
        }
        let unused = reserved - actual;
        self.requests = self.requests.checked_sub(unused).ok_or_else(|| {
            OsvError::new(
                OsvErrorKind::Internal,
                "OSV request reservation accounting underflowed",
            )
        })?;
        Ok(())
    }

    fn observe_bytes(&mut self, count: usize) -> Result<(), OsvError> {
        self.decoded_bytes = self.decoded_bytes.checked_add(count).ok_or_else(|| {
            OsvError::new(OsvErrorKind::ResourceLimit, "decoded byte count overflowed")
        })?;
        if self.decoded_bytes > MAX_TOTAL_DECODED_BYTES {
            return Err(OsvError::new(
                OsvErrorKind::ResourceLimit,
                format!("total decoded bytes exceed maximum {MAX_TOTAL_DECODED_BYTES}"),
            ));
        }
        Ok(())
    }
}

struct QueryState {
    query: CoordinateQuery,
    summaries: Vec<QuerySummary>,
    seen_ids: BTreeSet<String>,
    seen_tokens: BTreeSet<String>,
    next_page_token: Option<String>,
    pages: usize,
}

impl QueryState {
    fn new(query: CoordinateQuery) -> Self {
        Self {
            query,
            summaries: Vec::new(),
            seen_ids: BTreeSet::new(),
            seen_tokens: BTreeSet::new(),
            next_page_token: None,
            pages: 0,
        }
    }
}

struct BatchWork {
    indices: Vec<usize>,
    body: Vec<u8>,
}

struct BatchOutcome {
    decoded_bytes: usize,
    response: BatchResponse,
}

struct ParsedDetail {
    decoded_bytes: usize,
    raw_modified: String,
    record: argus_osv_schema::OsvRecord,
}

struct DetailOutcome {
    attempts: usize,
    result: Result<ParsedDetail, OsvError>,
}

#[derive(Serialize)]
struct BatchRequest<'a> {
    queries: Vec<BatchQuery<'a>>,
}

#[derive(Serialize)]
struct BatchQuery<'a> {
    package: BatchPackage<'a>,
    version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<&'a str>,
}

#[derive(Serialize)]
struct BatchPackage<'a> {
    ecosystem: &'a str,
    name: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchResponse {
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchResult {
    #[serde(default, deserialize_with = "deserialize_optional_vec")]
    vulns: Vec<BatchSummary>,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchSummary {
    id: String,
    modified: String,
}

fn deserialize_optional_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Vec::<T>::deserialize(deserializer)
}

fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

fn encode_batch_request(indices: &[usize], states: &[QueryState]) -> Result<Vec<u8>, OsvError> {
    let request = BatchRequest {
        queries: indices
            .iter()
            .map(|&index| {
                let state = &states[index];
                BatchQuery {
                    package: BatchPackage {
                        ecosystem: state.query.coordinate.ecosystem.osv_name(),
                        name: &state.query.coordinate.canonical_name,
                    },
                    version: &state.query.coordinate.version,
                    page_token: state.next_page_token.as_deref(),
                }
            })
            .collect(),
    };
    let body = serde_json::to_vec(&request).map_err(|error| {
        OsvError::new(
            OsvErrorKind::Internal,
            format!("serialize querybatch request: {error}"),
        )
    })?;
    if body.len() > MAX_ENCODED_REQUEST_BYTES {
        return Err(OsvError::new(
            OsvErrorKind::ResourceLimit,
            format!(
                "encoded querybatch request is {} bytes; maximum is {MAX_ENCODED_REQUEST_BYTES}",
                body.len()
            ),
        ));
    }
    Ok(body)
}

fn process_batch_result(
    index: usize,
    result: BatchResult,
    states: &mut [QueryState],
    intervals: &mut BTreeMap<String, Vec<ModifiedInterval>>,
    association_count: &mut usize,
    next_pending: &mut Vec<usize>,
) -> Result<(), OsvError> {
    let state = &mut states[index];
    state.pages = state
        .pages
        .checked_add(1)
        .ok_or_else(|| OsvError::new(OsvErrorKind::ResourceLimit, "page count overflowed"))?;
    for summary in result.vulns {
        crate::model::validate_scalar("batch advisory id", &summary.id, MAX_ID_BYTES)?;
        if !state.seen_ids.insert(summary.id.clone()) {
            return Err(OsvError::new(
                OsvErrorKind::MalformedResponse,
                format!(
                    "duplicate coordinate/advisory association for `{}`",
                    summary.id
                ),
            ));
        }
        *association_count = association_count.checked_add(1).ok_or_else(|| {
            OsvError::new(
                OsvErrorKind::ResourceLimit,
                "summary association count overflowed",
            )
        })?;
        if *association_count > MAX_ASSOCIATIONS {
            return Err(OsvError::new(
                OsvErrorKind::ResourceLimit,
                format!("summary associations exceed maximum {MAX_ASSOCIATIONS}"),
            ));
        }
        let interval = parse_modified(&summary.modified)?;
        let id_intervals = intervals.entry(summary.id.clone()).or_default();
        id_intervals.push(interval);
        if !modified_intervals_overlap(id_intervals) {
            return Err(OsvError::new(
                OsvErrorKind::MalformedResponse,
                format!(
                    "batch modified intervals conflict for advisory `{}`",
                    summary.id
                ),
            ));
        }
        state.summaries.push(QuerySummary {
            primary_id: summary.id,
            modified: summary.modified,
        });
    }
    state
        .summaries
        .sort_by(|left, right| left.primary_id.cmp(&right.primary_id));

    state.next_page_token = match result.next_page_token {
        None => None,
        Some(token) => {
            if token.is_empty() {
                return Err(OsvError::new(
                    OsvErrorKind::MalformedResponse,
                    "querybatch returned an empty page token",
                ));
            }
            if token.len() > MAX_PAGE_TOKEN_BYTES {
                return Err(OsvError::new(
                    OsvErrorKind::ResourceLimit,
                    format!(
                        "page token is {} bytes; maximum is {MAX_PAGE_TOKEN_BYTES}",
                        token.len()
                    ),
                ));
            }
            if !state.seen_tokens.insert(token.clone()) {
                return Err(OsvError::new(
                    OsvErrorKind::MalformedResponse,
                    "querybatch page token did not converge",
                ));
            }
            if state.pages == MAX_PAGES_PER_COORDINATE {
                return Err(OsvError::new(
                    OsvErrorKind::ResourceLimit,
                    format!(
                        "coordinate pagination exceeds maximum {MAX_PAGES_PER_COORDINATE} pages"
                    ),
                ));
            }
            next_pending.push(index);
            Some(token)
        }
    };
    Ok(())
}

fn validate_response(
    response: TransportResponse,
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>, OsvError> {
    if response.status != 200 {
        return Err(OsvError::new(
            OsvErrorKind::Transport,
            format!("{label} returned HTTP status {}", response.status),
        ));
    }
    let content_type = response.content_type.ok_or_else(|| {
        OsvError::new(
            OsvErrorKind::Transport,
            format!("{label} response is missing Content-Type"),
        )
    })?;
    let media_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(OsvError::new(
            OsvErrorKind::Transport,
            format!("{label} response Content-Type is not application/json"),
        ));
    }
    if response.body.len() > maximum {
        return Err(OsvError::new(
            OsvErrorKind::ResourceLimit,
            format!(
                "{label} decoded body is {} bytes; maximum is {maximum}",
                response.body.len()
            ),
        ));
    }
    Ok(response.body)
}

fn response_limits(decoded_response_bytes: usize, operation_remaining: Duration) -> ResponseLimits {
    ResponseLimits {
        encoded_request_bytes: MAX_ENCODED_REQUEST_BYTES,
        decoded_response_bytes,
        connect_timeout: CONNECT_TIMEOUT,
        request_timeout: operation_remaining.min(REQUEST_TIMEOUT),
        redirect_limit: 0,
        send_credentials: false,
    }
}

fn detail_modified(body: &[u8]) -> Result<String, OsvError> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
        OsvError::new(
            OsvErrorKind::MalformedResponse,
            format!("parse advisory detail JSON: {error}"),
        )
    })?;
    let raw = value
        .as_object()
        .and_then(|object| object.get("modified"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            OsvError::new(
                OsvErrorKind::MalformedResponse,
                "advisory detail modified must be a string",
            )
        })?;
    parse_modified(raw)?;
    Ok(raw.to_string())
}

fn percent_encode_id(id: &str) -> String {
    let mut encoded = String::with_capacity(id.len());
    for byte in id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

fn operation_timeout() -> OsvError {
    OsvError::new(
        OsvErrorKind::Transport,
        "OSV operation exceeded 300 second timeout",
    )
}

fn ensure_unique_advisory_count(count: usize) -> Result<(), OsvError> {
    if count > MAX_UNIQUE_ADVISORY_IDS {
        return Err(OsvError::new(
            OsvErrorKind::ResourceLimit,
            format!("unique advisory ID count {count} exceeds maximum {MAX_UNIQUE_ADVISORY_IDS}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod resource_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_budgets_accept_equality_and_reject_plus_one() {
        let mut budget = OperationBudget::default();
        budget.observe_bytes(MAX_TOTAL_DECODED_BYTES).unwrap();
        assert!(budget.observe_bytes(1).is_err());
        budget.requests = MAX_HTTP_REQUESTS - 1;
        budget.reserve_requests(1).unwrap();
        assert!(budget.reserve_requests(1).is_err());
    }
}
