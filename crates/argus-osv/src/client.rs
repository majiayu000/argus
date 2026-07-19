use crate::model::{
    modified_intervals_overlap, parse_modified, CoordinateQuery, CoordinateSet, ModifiedInterval,
    NormalizedAdvisory, OsvError, OsvErrorKind, MAX_ID_BYTES,
};
use crate::normalize::normalize_advisory;
use argus_intel::parse_osv_record;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::time::{Duration, Instant};

pub const MAX_BATCH_QUERIES: usize = 1_000;
pub const MAX_PAGE_TOKEN_BYTES: usize = 4 * 1024;
pub const MAX_PAGES_PER_COORDINATE: usize = 16;
pub const MAX_ASSOCIATIONS: usize = 100_000;
pub const MAX_UNIQUE_ADVISORY_IDS: usize = 20_000;
pub const MAX_HTTP_REQUESTS: usize = 25_000;
pub const MAX_DETAIL_CONCURRENCY: usize = 8;
pub const MAX_ENCODED_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_QUERY_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DETAIL_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TOTAL_DECODED_BYTES: usize = 512 * 1024 * 1024;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseLimits {
    pub encoded_request_bytes: usize,
    pub decoded_response_bytes: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub redirect_limit: usize,
    pub send_credentials: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

pub trait OsvTransport: Send + Sync {
    fn post_query_batch(
        &self,
        body: &[u8],
        limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError>;

    fn get_advisory(
        &self,
        percent_encoded_id: &str,
        limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError>;
}

pub struct HttpsOsvTransport(ureq::Agent);

impl HttpsOsvTransport {
    pub fn new() -> Self {
        Self(
            ureq::AgentBuilder::new()
                .timeout_connect(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .redirects(0)
                .build(),
        )
    }
}

impl Default for HttpsOsvTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl OsvTransport for HttpsOsvTransport {
    fn post_query_batch(
        &self,
        body: &[u8],
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        if body.len() > MAX_ENCODED_REQUEST_BYTES {
            return Err(OsvError::new(
                OsvErrorKind::ResourceLimit,
                "encoded querybatch request exceeds 4 MiB",
            ));
        }
        read_http_response(
            self.0
                .post("https://api.osv.dev/v1/querybatch")
                .set("Accept", "application/json")
                .set("Content-Type", "application/json")
                .send_bytes(body),
            MAX_QUERY_RESPONSE_BYTES,
            "querybatch",
        )
    }

    fn get_advisory(
        &self,
        percent_encoded_id: &str,
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        if percent_encoded_id.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'%'))
        }) {
            return Err(OsvError::malformed(
                "advisory path ID is not percent encoded",
            ));
        }
        read_http_response(
            self.0
                .get(&format!(
                    "https://api.osv.dev/v1/vulns/{percent_encoded_id}"
                ))
                .set("Accept", "application/json")
                .call(),
            MAX_DETAIL_RESPONSE_BYTES,
            "advisory detail",
        )
    }
}

fn read_http_response(
    response: Result<ureq::Response, ureq::Error>,
    maximum: usize,
    label: &str,
) -> Result<TransportResponse, OsvError> {
    let response = match response {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(error) => {
            return Err(OsvError::new(
                OsvErrorKind::Transport,
                format!("{label} transport failed: {error}"),
            ))
        }
    };
    let status = response.status();
    let content_type = response.header("Content-Type").map(str::to_string);
    let mut body = Vec::new();
    response
        .into_reader()
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|error| {
            OsvError::new(
                OsvErrorKind::Transport,
                format!("read {label} response body: {error}"),
            )
        })?;
    if body.len() > maximum {
        return Err(OsvError::new(
            OsvErrorKind::ResourceLimit,
            format!("{label} decoded body exceeds maximum {maximum}"),
        ));
    }
    Ok(TransportResponse {
        status,
        content_type,
        body,
    })
}

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

pub struct OsvClient<'a> {
    transport: &'a dyn OsvTransport,
}

impl<'a> OsvClient<'a> {
    pub fn new(transport: &'a dyn OsvTransport) -> Self {
        Self { transport }
    }

    pub fn query(&self, coordinates: &CoordinateSet) -> Result<CompleteSnapshot, OsvError> {
        coordinates.validate()?;
        let started = Instant::now();
        let mut budget = OperationBudget::default();
        let first = self.query_round(coordinates, started, &mut budget);
        let mut snapshot = match first {
            Err(error) if error.kind == OsvErrorKind::SnapshotRace => {
                self.query_round(coordinates, started, &mut budget)?
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
        started: Instant,
        budget: &mut OperationBudget,
    ) -> Result<CompleteSnapshot, OsvError> {
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
            for chunk in pending.chunks(MAX_BATCH_QUERIES) {
                ensure_time(started)?;
                let body = encode_batch_request(chunk, &states)?;
                budget.observe_request()?;
                let response = self
                    .transport
                    .post_query_batch(&body, response_limits(MAX_QUERY_RESPONSE_BYTES))?;
                ensure_time(started)?;
                let body =
                    validate_response(response, MAX_QUERY_RESPONSE_BYTES, "querybatch", budget)?;
                let response: BatchResponse = serde_json::from_slice(&body).map_err(|error| {
                    OsvError::new(
                        OsvErrorKind::MalformedResponse,
                        format!("parse querybatch JSON: {error}"),
                    )
                })?;
                if response.results.len() != chunk.len() {
                    return Err(OsvError::new(
                        OsvErrorKind::MalformedResponse,
                        format!(
                            "querybatch returned {} results for {} positional queries",
                            response.results.len(),
                            chunk.len()
                        ),
                    ));
                }
                for (&index, result) in chunk.iter().zip(response.results) {
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
            pending = next_pending;
        }

        if intervals.len() > MAX_UNIQUE_ADVISORY_IDS {
            return Err(OsvError::new(
                OsvErrorKind::ResourceLimit,
                format!(
                    "unique advisory ID count {} exceeds maximum {MAX_UNIQUE_ADVISORY_IDS}",
                    intervals.len()
                ),
            ));
        }
        let details = self.hydrate_details(intervals.keys(), started, budget)?;
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
        started: Instant,
        budget: &mut OperationBudget,
    ) -> Result<BTreeMap<String, (argus_intel::OsvRecord, String)>, OsvError> {
        let ids = ids.cloned().collect::<Vec<_>>();
        let mut details = BTreeMap::new();
        for chunk in ids.chunks(MAX_DETAIL_CONCURRENCY) {
            ensure_time(started)?;
            for _ in chunk {
                budget.observe_request()?;
            }
            let responses = std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(chunk.len());
                for id in chunk {
                    let encoded = percent_encode_id(id);
                    handles.push((
                        id.clone(),
                        scope.spawn(move || {
                            self.transport
                                .get_advisory(&encoded, response_limits(MAX_DETAIL_RESPONSE_BYTES))
                        }),
                    ));
                }
                handles
                    .into_iter()
                    .map(|(id, handle)| {
                        handle.join().map(|response| (id, response)).map_err(|_| {
                            OsvError::new(
                                OsvErrorKind::Internal,
                                "OSV detail transport worker panicked",
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })?;
            ensure_time(started)?;
            for (requested_id, response) in responses {
                let response = response?;
                let body = validate_response(
                    response,
                    MAX_DETAIL_RESPONSE_BYTES,
                    "advisory detail",
                    budget,
                )?;
                let raw_modified = detail_modified(&body)?;
                let record = parse_osv_record(&body).map_err(|error| {
                    OsvError::new(
                        OsvErrorKind::MalformedResponse,
                        format!("parse advisory detail `{requested_id}`: {error}"),
                    )
                })?;
                if record.id != requested_id {
                    return Err(OsvError::new(
                        OsvErrorKind::MalformedResponse,
                        format!(
                            "detail ID `{}` does not match requested `{requested_id}`",
                            record.id
                        ),
                    ));
                }
                details.insert(requested_id, (record, raw_modified));
            }
        }
        Ok(details)
    }
}

#[derive(Default)]
struct OperationBudget {
    requests: usize,
    decoded_bytes: usize,
}

impl OperationBudget {
    fn observe_request(&mut self) -> Result<(), OsvError> {
        self.requests = self.requests.checked_add(1).ok_or_else(|| {
            OsvError::new(OsvErrorKind::ResourceLimit, "HTTP request count overflowed")
        })?;
        if self.requests > MAX_HTTP_REQUESTS {
            return Err(OsvError::new(
                OsvErrorKind::ResourceLimit,
                format!("HTTP request count exceeds maximum {MAX_HTTP_REQUESTS}"),
            ));
        }
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
    budget: &mut OperationBudget,
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
    budget.observe_bytes(response.body.len())?;
    Ok(response.body)
}

fn response_limits(decoded_response_bytes: usize) -> ResponseLimits {
    ResponseLimits {
        encoded_request_bytes: MAX_ENCODED_REQUEST_BYTES,
        decoded_response_bytes,
        connect_timeout: CONNECT_TIMEOUT,
        request_timeout: REQUEST_TIMEOUT,
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

fn ensure_time(started: Instant) -> Result<(), OsvError> {
    if started.elapsed() > OPERATION_TIMEOUT {
        return Err(OsvError::new(
            OsvErrorKind::Transport,
            "OSV operation exceeded 300 second timeout",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_budgets_accept_equality_and_reject_plus_one() {
        let mut budget = OperationBudget::default();
        budget.observe_bytes(MAX_TOTAL_DECODED_BYTES).unwrap();
        assert!(budget.observe_bytes(1).is_err());
        budget.requests = MAX_HTTP_REQUESTS - 1;
        budget.observe_request().unwrap();
        assert!(budget.observe_request().is_err());
    }
}
