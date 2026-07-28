use crate::client::{
    MAX_DETAIL_RESPONSE_BYTES, MAX_ENCODED_REQUEST_BYTES, MAX_QUERY_RESPONSE_BYTES,
};
use crate::model::{OsvError, OsvErrorKind};
use argus_transport::{
    checked_retry_byte_budget, classify_io_error, classify_ureq_transport, is_retryable_status,
    AttemptContext, GetRetryPolicy, RetryDisposition, RetryFailure, RetryRuntime,
    SystemRetryRuntime, GET_ATTEMPT_TIMEOUT, GET_TOTAL_TIMEOUT,
};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const QUERY_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const DETAIL_URL_PREFIX: &str = "https://api.osv.dev/v1/vulns/";

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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

pub struct TransportAttempt {
    pub attempts: usize,
    pub result: Result<TransportResponse, OsvError>,
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

    fn get_advisory_attempted(
        &self,
        percent_encoded_id: &str,
        limits: ResponseLimits,
    ) -> TransportAttempt {
        TransportAttempt {
            attempts: 1,
            result: self.get_advisory(percent_encoded_id, limits),
        }
    }
}

pub struct HttpsOsvTransport {
    agent: ureq::Agent,
    retry_runtime: Arc<dyn RetryRuntime>,
}

impl HttpsOsvTransport {
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(CONNECT_TIMEOUT)
                .timeout(GET_ATTEMPT_TIMEOUT)
                .redirects(0)
                .build(),
            retry_runtime: Arc::new(SystemRetryRuntime::default()),
        }
    }

    fn get_advisory_attempt(
        &self,
        percent_encoded_id: &str,
        attempt: AttemptContext,
        runtime: &dyn RetryRuntime,
    ) -> Result<TransportResponse, RetryFailure<OsvError>> {
        let url = format!("{DETAIL_URL_PREFIX}{percent_encoded_id}");
        let response = self
            .agent
            .get(&url)
            .set("Accept", "application/json")
            .timeout(attempt.request_timeout(runtime))
            .call();
        read_retryable_response(response, MAX_DETAIL_RESPONSE_BYTES, "advisory detail")
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
        limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        if body.len() > MAX_ENCODED_REQUEST_BYTES {
            return Err(OsvError::new(
                OsvErrorKind::ResourceLimit,
                "encoded querybatch request exceeds 4 MiB",
            ));
        }
        if limits.request_timeout.is_zero() {
            return Err(operation_timeout());
        }
        read_one_shot_response(
            self.agent
                .post(QUERY_BATCH_URL)
                .set("Accept", "application/json")
                .set("Content-Type", "application/json")
                .timeout(limits.request_timeout.min(REQUEST_TIMEOUT))
                .send_bytes(body),
            MAX_QUERY_RESPONSE_BYTES,
            "querybatch",
        )
    }

    fn get_advisory(
        &self,
        percent_encoded_id: &str,
        limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        self.get_advisory_attempted(percent_encoded_id, limits)
            .result
    }

    fn get_advisory_attempted(
        &self,
        percent_encoded_id: &str,
        limits: ResponseLimits,
    ) -> TransportAttempt {
        if let Err(error) = validate_percent_encoded_id(percent_encoded_id) {
            return TransportAttempt {
                attempts: 0,
                result: Err(error),
            };
        }
        if checked_retry_byte_budget(MAX_DETAIL_RESPONSE_BYTES as u64).is_none() {
            return TransportAttempt {
                attempts: 0,
                result: Err(OsvError::new(
                    OsvErrorKind::ResourceLimit,
                    "advisory retry byte amplification overflowed",
                )),
            };
        }
        if limits.request_timeout.is_zero() {
            return TransportAttempt {
                attempts: 0,
                result: Err(operation_timeout()),
            };
        }
        execute_retrying_detail(
            self.retry_runtime.as_ref(),
            limits.request_timeout,
            |attempt, runtime| self.get_advisory_attempt(percent_encoded_id, attempt, runtime),
        )
    }
}

fn execute_retrying_detail(
    runtime: &dyn RetryRuntime,
    maximum_duration: Duration,
    attempt: impl FnMut(
        AttemptContext,
        &dyn RetryRuntime,
    ) -> Result<TransportResponse, RetryFailure<OsvError>>,
) -> TransportAttempt {
    let runtime = CappedRetryRuntime::new(runtime, maximum_duration);
    let mut attempt = attempt;
    let mut successful_attempts = 0usize;
    let result = GetRetryPolicy.execute(&runtime, |context| {
        successful_attempts += 1;
        attempt(context, &runtime)
    });
    match result {
        Ok(response) => TransportAttempt {
            attempts: successful_attempts,
            result: Ok(response),
        },
        Err(error) => TransportAttempt {
            attempts: error.attempts(),
            result: Err(error.into_last_cause()),
        },
    }
}

struct CappedRetryRuntime<'a> {
    inner: &'a dyn RetryRuntime,
    bias: Duration,
    first_monotonic_read: AtomicBool,
}

impl<'a> CappedRetryRuntime<'a> {
    fn new(inner: &'a dyn RetryRuntime, maximum_duration: Duration) -> Self {
        Self {
            inner,
            bias: GET_TOTAL_TIMEOUT.saturating_sub(maximum_duration.min(GET_TOTAL_TIMEOUT)),
            first_monotonic_read: AtomicBool::new(true),
        }
    }
}

impl RetryRuntime for CappedRetryRuntime<'_> {
    fn monotonic_now(&self) -> Duration {
        let now = self.inner.monotonic_now();
        if self.first_monotonic_read.swap(false, Ordering::Relaxed) {
            now
        } else {
            now.saturating_add(self.bias)
        }
    }

    fn wall_now(&self) -> std::time::SystemTime {
        self.inner.wall_now()
    }

    fn sleep(&self, duration: Duration) {
        self.inner.sleep(duration);
    }

    fn jitter(&self, base: Duration) -> Duration {
        self.inner.jitter(base)
    }
}

fn operation_timeout() -> OsvError {
    OsvError::new(
        OsvErrorKind::Transport,
        "OSV operation exceeded 300 second timeout",
    )
}

fn validate_percent_encoded_id(id: &str) -> Result<(), OsvError> {
    if id.bytes().any(|byte| {
        !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'%'))
    }) {
        return Err(OsvError::malformed(
            "advisory path ID is not percent encoded",
        ));
    }
    Ok(())
}

fn read_one_shot_response(
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
            ));
        }
    };
    read_bounded_response(response, maximum, label).map_err(RetryFailure::into_error)
}

fn read_retryable_response(
    response: Result<ureq::Response, ureq::Error>,
    maximum: usize,
    label: &str,
) -> Result<TransportResponse, RetryFailure<OsvError>> {
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            if is_retryable_status(status) {
                let retry_after = response.header("Retry-After");
                return Err(RetryFailure::retryable(
                    OsvError::new(
                        OsvErrorKind::Transport,
                        format!("{label} returned HTTP status {status}"),
                    ),
                    retry_after,
                ));
            }
            response
        }
        Err(ureq::Error::Transport(error)) => {
            let disposition = classify_ureq_transport(&error);
            let error = OsvError::new(
                OsvErrorKind::Transport,
                format!("{label} transport failed: {error}"),
            );
            return Err(match disposition {
                RetryDisposition::Retryable => RetryFailure::retryable(error, None),
                RetryDisposition::Fatal => RetryFailure::fatal(error),
            });
        }
    };
    read_bounded_response(response, maximum, label)
}

fn read_bounded_response(
    response: ureq::Response,
    maximum: usize,
    label: &str,
) -> Result<TransportResponse, RetryFailure<OsvError>> {
    let status = response.status();
    let content_type = response.header("Content-Type").map(str::to_string);
    if let Some(raw) = response.header("Content-Length") {
        let length = raw.parse::<usize>().map_err(|_| {
            RetryFailure::fatal(OsvError::new(
                OsvErrorKind::Transport,
                format!("{label} response has malformed Content-Length"),
            ))
        })?;
        if length > maximum {
            return Err(RetryFailure::fatal(OsvError::new(
                OsvErrorKind::ResourceLimit,
                format!("{label} decoded body exceeds maximum {maximum}"),
            )));
        }
    }
    let mut body = Vec::new();
    if let Err(error) = response
        .into_reader()
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut body)
    {
        let disposition = classify_io_error(&error);
        let error = OsvError::new(
            OsvErrorKind::Transport,
            format!("read {label} response body: {error}"),
        );
        return Err(match disposition {
            RetryDisposition::Retryable => RetryFailure::retryable(error, None),
            RetryDisposition::Fatal => RetryFailure::fatal(error),
        });
    }
    if body.len() > maximum {
        return Err(RetryFailure::fatal(OsvError::new(
            OsvErrorKind::ResourceLimit,
            format!("{label} decoded body exceeds maximum {maximum}"),
        )));
    }
    Ok(TransportResponse {
        status,
        content_type,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Default)]
    struct FakeRuntime {
        now: Mutex<Duration>,
        sleeps: Mutex<Vec<Duration>>,
    }

    impl RetryRuntime for FakeRuntime {
        fn monotonic_now(&self) -> Duration {
            *self.now.lock().unwrap()
        }

        fn wall_now(&self) -> SystemTime {
            UNIX_EPOCH
        }

        fn sleep(&self, duration: Duration) {
            *self.now.lock().unwrap() += duration;
            self.sleeps.lock().unwrap().push(duration);
        }

        fn jitter(&self, base: Duration) -> Duration {
            base
        }
    }

    fn retryable() -> RetryFailure<OsvError> {
        RetryFailure::retryable(
            OsvError::new(OsvErrorKind::Transport, "transient detail GET"),
            None,
        )
    }

    #[test]
    fn production_detail_path_uses_shared_three_attempt_get_policy() {
        let runtime = FakeRuntime::default();
        let mut calls = 0usize;
        let attempted = execute_retrying_detail(&runtime, GET_TOTAL_TIMEOUT, |_, _| {
            calls += 1;
            if calls < 3 {
                Err(retryable())
            } else {
                Ok(TransportResponse {
                    status: 200,
                    content_type: Some("application/json".to_string()),
                    body: b"{}".to_vec(),
                })
            }
        });
        assert!(attempted.result.is_ok());
        assert_eq!(attempted.attempts, 3);
        assert_eq!(
            *runtime.sleeps.lock().unwrap(),
            [Duration::from_millis(100), Duration::from_millis(200)]
        );
    }

    #[test]
    fn production_detail_path_does_not_retry_fatal_get_failure() {
        let runtime = FakeRuntime::default();
        let attempted = execute_retrying_detail(&runtime, GET_TOTAL_TIMEOUT, |_, _| {
            Err(RetryFailure::fatal(OsvError::new(
                OsvErrorKind::Transport,
                "fatal detail GET",
            )))
        });
        assert!(attempted.result.is_err());
        assert_eq!(attempted.attempts, 1);
        assert!(runtime.sleeps.lock().unwrap().is_empty());
    }

    #[test]
    fn detail_retry_timeout_and_sleeps_stop_at_operation_remaining() {
        let runtime = FakeRuntime::default();
        let mut timeouts = Vec::new();
        let attempted = execute_retrying_detail(
            &runtime,
            Duration::from_millis(250),
            |context, capped_runtime| {
                timeouts.push(context.request_timeout(capped_runtime));
                Err(retryable())
            },
        );
        assert_eq!(attempted.attempts, 2);
        assert_eq!(
            timeouts,
            [Duration::from_millis(250), Duration::from_millis(150)]
        );
        assert_eq!(
            *runtime.sleeps.lock().unwrap(),
            [Duration::from_millis(100), Duration::from_millis(150)]
        );
        assert_eq!(runtime.monotonic_now(), Duration::from_millis(250));
    }
}
