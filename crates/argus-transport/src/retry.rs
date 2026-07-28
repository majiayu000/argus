use std::error::Error as _;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const GET_MAX_ATTEMPTS: usize = 3;
pub const GET_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
pub const GET_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
pub const GET_MAX_RETRY_AFTER: Duration = Duration::from_secs(10);

const FIRST_BACKOFF: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDisposition {
    Retryable,
    Fatal,
}

pub struct RetryFailure<E> {
    error: E,
    disposition: RetryDisposition,
    retry_after: Option<String>,
}

#[derive(Debug)]
pub struct GetRetryError<E> {
    attempts: usize,
    last_cause: E,
}

impl<E> GetRetryError<E> {
    fn new(attempts: usize, last_cause: E) -> Self {
        Self {
            attempts,
            last_cause,
        }
    }

    pub fn attempts(&self) -> usize {
        self.attempts
    }

    pub fn last_cause(&self) -> &E {
        &self.last_cause
    }

    pub fn into_last_cause(self) -> E {
        self.last_cause
    }
}

impl<E: fmt::Display> fmt::Display for GetRetryError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GET failed after {} attempt{}: {}",
            self.attempts,
            if self.attempts == 1 { "" } else { "s" },
            self.last_cause
        )
    }
}

impl std::error::Error for GetRetryError<anyhow::Error> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.last_cause.root_cause())
    }
}

impl<E> RetryFailure<E> {
    pub fn retryable(error: E, retry_after: Option<&str>) -> Self {
        Self {
            error,
            disposition: RetryDisposition::Retryable,
            retry_after: retry_after.map(str::to_owned),
        }
    }

    pub fn fatal(error: E) -> Self {
        Self {
            error,
            disposition: RetryDisposition::Fatal,
            retry_after: None,
        }
    }

    pub fn into_error(self) -> E {
        self.error
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AttemptContext {
    started_at: Duration,
    deadline: Duration,
}

impl AttemptContext {
    pub fn remaining(self, runtime: &dyn RetryRuntime) -> Duration {
        self.deadline.saturating_sub(runtime.monotonic_now())
    }

    pub fn request_timeout(self, runtime: &dyn RetryRuntime) -> Duration {
        self.remaining(runtime).min(GET_ATTEMPT_TIMEOUT)
    }

    pub fn elapsed(self, runtime: &dyn RetryRuntime) -> Duration {
        runtime.monotonic_now().saturating_sub(self.started_at)
    }
}

pub trait RetryRuntime: Send + Sync {
    fn monotonic_now(&self) -> Duration;
    fn wall_now(&self) -> SystemTime;
    fn sleep(&self, duration: Duration);
    fn jitter(&self, base: Duration) -> Duration;
}

pub struct SystemRetryRuntime {
    start: Instant,
    jitter_state: AtomicU64,
}

impl Default for SystemRetryRuntime {
    fn default() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            start: Instant::now(),
            jitter_state: AtomicU64::new(seed),
        }
    }
}

impl RetryRuntime for SystemRetryRuntime {
    fn monotonic_now(&self) -> Duration {
        self.start.elapsed()
    }

    fn wall_now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn jitter(&self, base: Duration) -> Duration {
        let mut state = self.jitter_state.load(Ordering::Relaxed);
        loop {
            let next = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            match self.jitter_state.compare_exchange_weak(
                state,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let half_nanos = base.as_nanos() / 2;
                    let span = base.as_nanos().saturating_sub(half_nanos);
                    let offset = if span == 0 {
                        0
                    } else {
                        u128::from(next) % (span + 1)
                    };
                    return duration_from_nanos(half_nanos + offset);
                }
                Err(observed) => state = observed,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GetRetryPolicy;

impl GetRetryPolicy {
    pub fn execute<T, E>(
        self,
        runtime: &dyn RetryRuntime,
        mut attempt: impl FnMut(AttemptContext) -> Result<T, RetryFailure<E>>,
    ) -> Result<T, GetRetryError<E>> {
        let logical_start = runtime.monotonic_now();
        let logical_deadline = logical_start.saturating_add(GET_TOTAL_TIMEOUT);

        for attempt_index in 0..GET_MAX_ATTEMPTS {
            let now = runtime.monotonic_now();
            let attempt_deadline = now
                .saturating_add(GET_ATTEMPT_TIMEOUT)
                .min(logical_deadline);
            let context = AttemptContext {
                started_at: now,
                deadline: attempt_deadline,
            };
            match attempt(context) {
                Ok(value) => return Ok(value),
                Err(failure) => {
                    if failure.disposition == RetryDisposition::Fatal
                        || attempt_index + 1 == GET_MAX_ATTEMPTS
                    {
                        return Err(GetRetryError::new(attempt_index + 1, failure.error));
                    }

                    let remaining = logical_deadline.saturating_sub(runtime.monotonic_now());
                    if remaining.is_zero() {
                        return Err(GetRetryError::new(attempt_index + 1, failure.error));
                    }
                    let computed = FIRST_BACKOFF
                        .checked_mul(1_u32 << attempt_index)
                        .unwrap_or(GET_MAX_RETRY_AFTER);
                    let delay = failure
                        .retry_after
                        .as_deref()
                        .and_then(|value| parse_retry_after(value, runtime.wall_now()))
                        .unwrap_or_else(|| clamp_jitter(runtime.jitter(computed), computed));
                    if delay >= remaining {
                        runtime.sleep(remaining);
                        return Err(GetRetryError::new(attempt_index + 1, failure.error));
                    }
                    runtime.sleep(delay);
                }
            }
        }
        unreachable!("GET retry loop has a positive fixed attempt count")
    }
}

pub fn checked_retry_byte_budget(max_bytes: u64) -> Option<u64> {
    max_bytes.checked_mul(GET_MAX_ATTEMPTS as u64)
}

pub fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504)
}

pub fn classify_io_error(error: &io::Error) -> RetryDisposition {
    match error.kind() {
        io::ErrorKind::TimedOut
        | io::ErrorKind::Interrupted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof => RetryDisposition::Retryable,
        _ => RetryDisposition::Fatal,
    }
}

pub fn classify_ureq_transport(error: &ureq::Transport) -> RetryDisposition {
    classify_ureq_error_kind_from_source(error.kind(), error.source())
}

fn classify_ureq_error_kind_from_source(
    kind: ureq::ErrorKind,
    mut source: Option<&(dyn std::error::Error + 'static)>,
) -> RetryDisposition {
    let source_present = source.is_some();
    let mut io_kind = None;
    let mut tls_failure = false;
    let mut invalid_server_name = false;
    while let Some(current) = source {
        if io_kind.is_none() {
            io_kind = current.downcast_ref::<io::Error>().map(io::Error::kind);
        }
        tls_failure |= current.downcast_ref::<rustls::Error>().is_some();
        invalid_server_name |= current
            .downcast_ref::<rustls::pki_types::InvalidDnsNameError>()
            .is_some();
        source = current.source();
    }
    if tls_failure || invalid_server_name {
        return RetryDisposition::Fatal;
    }
    match kind {
        ureq::ErrorKind::Dns if !source_present || io_kind.is_some() => RetryDisposition::Retryable,
        ureq::ErrorKind::ProxyConnect => RetryDisposition::Retryable,
        ureq::ErrorKind::ConnectionFailed => match io_kind {
            Some(kind) => classify_io_error(&io::Error::from(kind)),
            None => RetryDisposition::Fatal,
        },
        ureq::ErrorKind::Io => match io_kind {
            Some(kind) => classify_io_error(&io::Error::from(kind)),
            None => RetryDisposition::Fatal,
        },
        _ => RetryDisposition::Fatal,
    }
}

pub fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
            .filter(|delay| *delay <= GET_MAX_RETRY_AFTER);
    }

    let target = parse_imf_fixdate(value)?;
    let delay = target.duration_since(now).ok()?;
    (delay <= GET_MAX_RETRY_AFTER).then_some(delay)
}

fn clamp_jitter(value: Duration, base: Duration) -> Duration {
    value.clamp(base / 2, base)
}

fn duration_from_nanos(nanos: u128) -> Duration {
    let secs = (nanos / 1_000_000_000).min(u128::from(u64::MAX)) as u64;
    let subsec = (nanos % 1_000_000_000) as u32;
    Duration::new(secs, subsec)
}

fn parse_imf_fixdate(value: &str) -> Option<SystemTime> {
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 6 || fields[0].len() != 4 || !fields[0].ends_with(',') || fields[5] != "GMT"
    {
        return None;
    }
    let weekday = &fields[0][..3];
    if !matches!(
        weekday,
        "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
    ) {
        return None;
    }
    let day = parse_fixed_decimal(fields[1], 2)?;
    let month = match fields[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year = parse_fixed_decimal(fields[3], 4)? as i64;
    let clock = fields[4].split(':').collect::<Vec<_>>();
    if clock.len() != 3 {
        return None;
    }
    let hour = parse_fixed_decimal(clock[0], 2)?;
    let minute = parse_fixed_decimal(clock[1], 2)?;
    let second = parse_fixed_decimal(clock[2], 2)?;
    if year < 1970
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let expected_weekday =
        ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][(days + 4).rem_euclid(7) as usize];
    if weekday != expected_weekday {
        return None;
    }
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;
    let seconds = u64::try_from(seconds).ok()?;
    UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
}

fn parse_fixed_decimal(value: &str, width: usize) -> Option<u32> {
    (value.len() == width && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<u32>().ok())
        .flatten()
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(mut year: i64, month: u32, day: u32) -> i64 {
    year -= i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{is_not_found, HttpStatusError, HttpTransport, Transport};
    use anyhow::{bail, Result};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    struct FakeRuntime {
        elapsed: Mutex<Duration>,
        wall: SystemTime,
        jitter: Mutex<Vec<Duration>>,
        sleeps: Mutex<Vec<Duration>>,
    }

    impl FakeRuntime {
        fn new(jitter: Vec<Duration>) -> Self {
            Self {
                elapsed: Mutex::new(Duration::ZERO),
                wall: UNIX_EPOCH + Duration::from_secs(784_111_777),
                jitter: Mutex::new(jitter),
                sleeps: Mutex::new(Vec::new()),
            }
        }

        fn sleeps(&self) -> Vec<Duration> {
            self.sleeps.lock().unwrap().clone()
        }
    }

    impl RetryRuntime for FakeRuntime {
        fn monotonic_now(&self) -> Duration {
            *self.elapsed.lock().unwrap()
        }

        fn wall_now(&self) -> SystemTime {
            self.wall
        }

        fn sleep(&self, duration: Duration) {
            self.sleeps.lock().unwrap().push(duration);
            *self.elapsed.lock().unwrap() += duration;
        }

        fn jitter(&self, _base: Duration) -> Duration {
            self.jitter.lock().unwrap().remove(0)
        }
    }

    #[test]
    fn retry_policy_uses_exact_attempt_count_and_scripted_backoff() {
        let runtime = FakeRuntime::new(vec![Duration::from_millis(50), Duration::from_millis(200)]);
        let mut attempts = 0;
        let result = GetRetryPolicy.execute(&runtime, |_| {
            attempts += 1;
            Err::<(), _>(RetryFailure::retryable(attempts, None))
        });
        let error = result.expect_err("three retryable attempts must be exhausted");
        assert_eq!(error.attempts(), 3);
        assert_eq!(error.into_last_cause(), 3);
        assert_eq!(attempts, GET_MAX_ATTEMPTS);
        assert_eq!(
            runtime.sleeps(),
            [Duration::from_millis(50), Duration::from_millis(200)]
        );
    }

    #[test]
    fn fatal_failure_is_not_retried() {
        let runtime = FakeRuntime::new(Vec::new());
        let mut attempts = 0;
        let result = GetRetryPolicy.execute(&runtime, |_| {
            attempts += 1;
            Err::<(), _>(RetryFailure::fatal("fatal"))
        });
        let error = result.expect_err("fatal failure must be returned");
        assert_eq!(error.attempts(), 1);
        assert_eq!(error.into_last_cause(), "fatal");
        assert_eq!(attempts, 1);
        assert!(runtime.sleeps().is_empty());
    }

    #[test]
    fn total_elapsed_cap_truncates_sleep_and_prevents_next_attempt() {
        let runtime = FakeRuntime::new(vec![Duration::from_millis(100)]);
        let result = GetRetryPolicy.execute(&runtime, |_| {
            *runtime.elapsed.lock().unwrap() = GET_TOTAL_TIMEOUT - Duration::from_millis(25);
            Err::<(), _>(RetryFailure::retryable("timeout", None))
        });
        let error = result.expect_err("elapsed cap must preserve the last failure");
        assert_eq!(error.attempts(), 1);
        assert_eq!(error.into_last_cause(), "timeout");
        assert_eq!(runtime.sleeps(), [Duration::from_millis(25)]);
        assert_eq!(runtime.monotonic_now(), GET_TOTAL_TIMEOUT);
    }

    #[test]
    fn retry_after_supports_delta_and_imf_fixdate_with_bounds() {
        let now = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(parse_retry_after("10", now), Some(Duration::from_secs(10)));
        assert_eq!(parse_retry_after("11", now), None);
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:47 GMT", now),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:48 GMT", now),
            None
        );
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:36 GMT", now),
            None
        );
        assert_eq!(
            parse_retry_after("Mon, 06 Nov 1994 08:49:47 GMT", now),
            None
        );
        assert_eq!(parse_retry_after("not-a-date", now), None);
    }

    #[test]
    fn retry_after_replaces_jittered_backoff() {
        let runtime = FakeRuntime::new(Vec::new());
        let mut attempts = 0;
        let result = GetRetryPolicy.execute(&runtime, |_| {
            attempts += 1;
            if attempts == 1 {
                Err(RetryFailure::retryable("retry", Some("2")))
            } else {
                Ok("ok")
            }
        });
        assert_eq!(result.expect("second attempt must succeed"), "ok");
        assert_eq!(runtime.sleeps(), [Duration::from_secs(2)]);
    }

    #[test]
    fn status_and_io_classification_is_exact() {
        for status in [408, 425, 429, 500, 502, 503, 504] {
            assert!(is_retryable_status(status));
        }
        for status in [400, 404, 410, 422, 501, 505] {
            assert!(!is_retryable_status(status));
        }
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert_eq!(
                classify_io_error(&io::Error::from(kind)),
                RetryDisposition::Retryable
            );
        }
        assert_eq!(
            classify_io_error(&io::Error::from(io::ErrorKind::InvalidData)),
            RetryDisposition::Fatal
        );
        assert_eq!(
            classify_ureq_error_kind_from_source(ureq::ErrorKind::Dns, None),
            RetryDisposition::Retryable
        );
        assert_eq!(
            classify_ureq_error_kind_from_source(ureq::ErrorKind::ProxyConnect, None),
            RetryDisposition::Retryable
        );
        for kind in [
            ureq::ErrorKind::InvalidUrl,
            ureq::ErrorKind::UnknownScheme,
            ureq::ErrorKind::InsecureRequestHttpsOnly,
            ureq::ErrorKind::TooManyRedirects,
            ureq::ErrorKind::BadStatus,
            ureq::ErrorKind::BadHeader,
            ureq::ErrorKind::InvalidProxyUrl,
            ureq::ErrorKind::ProxyUnauthorized,
            ureq::ErrorKind::HTTP,
        ] {
            assert_eq!(
                classify_ureq_error_kind_from_source(kind, None),
                RetryDisposition::Fatal
            );
        }
        assert_eq!(
            classify_ureq_error_kind_from_source(ureq::ErrorKind::Io, None),
            RetryDisposition::Fatal
        );
        assert_eq!(
            classify_ureq_error_kind_from_source(ureq::ErrorKind::ConnectionFailed, None),
            RetryDisposition::Fatal,
            "connection failures without a typed source are unknown and fatal"
        );
        let tls = rustls::Error::General("certificate validation failed".to_string());
        assert_eq!(
            classify_ureq_error_kind_from_source(ureq::ErrorKind::ConnectionFailed, Some(&tls),),
            RetryDisposition::Fatal,
            "typed rustls failures must override generic connection retry"
        );
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(
            classify_ureq_error_kind_from_source(ureq::ErrorKind::ConnectionFailed, Some(&refused),),
            RetryDisposition::Retryable,
            "typed TCP connection failures remain retryable"
        );
        let dns_lookup = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(
            classify_ureq_error_kind_from_source(ureq::ErrorKind::Dns, Some(&dns_lookup)),
            RetryDisposition::Retryable
        );
        let invalid_sni = rustls::pki_types::InvalidDnsNameError;
        assert_eq!(
            classify_ureq_error_kind_from_source(ureq::ErrorKind::Dns, Some(&invalid_sni)),
            RetryDisposition::Fatal,
            "typed invalid SNI names must not be treated as DNS lookup failures"
        );
    }

    #[test]
    fn byte_amplification_is_checked() {
        assert_eq!(checked_retry_byte_budget(7), Some(21));
        assert_eq!(
            checked_retry_byte_budget(u64::MAX / GET_MAX_ATTEMPTS as u64 + 1),
            None
        );
    }

    #[test]
    fn http_retry_restarts_at_origin_and_revalidates_redirect() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let origin = format!("http://{address}/origin");
        let target = format!("http://{address}/target");
        let server_target = target.clone();
        let handle = thread::spawn(move || -> Result<()> {
            for (expected_path, response) in [
                (
                    "/origin",
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {server_target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    ),
                ),
                (
                    "/target",
                    "HTTP/1.1 503 Busy\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string(),
                ),
                (
                    "/origin",
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {server_target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    ),
                ),
                (
                    "/target",
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                        .to_string(),
                ),
            ] {
                let (mut stream, _) = listener.accept()?;
                let mut request = [0_u8; 1024];
                let read = stream.read(&mut request)?;
                let request = std::str::from_utf8(&request[..read])?;
                if !request.starts_with(&format!("GET {expected_path} ")) {
                    bail!("unexpected request: {request}");
                }
                stream.write_all(response.as_bytes())?;
            }
            Ok(())
        });
        let validations = Mutex::new(Vec::new());
        let body = HttpTransport::with_retry_runtime(Arc::new(FakeRuntime::new(Vec::new())))
            .get_redirect_checked(&origin, 2, &|url| {
                validations.lock().unwrap().push(url.to_string());
                Ok(())
            })?;
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("retry test server panicked"))??;
        assert_eq!(body, b"ok");
        assert_eq!(
            *validations.lock().unwrap(),
            [origin.clone(), target.clone(), origin, target]
        );
        Ok(())
    }

    #[test]
    fn http_retry_stops_after_three_and_absence_is_immediate() -> Result<()> {
        let status_response =
            "HTTP/1.1 500 Error\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}/resource", listener.local_addr()?);
        let handle = thread::spawn(move || -> Result<()> {
            for _ in 0..GET_MAX_ATTEMPTS {
                let (mut stream, _) = listener.accept()?;
                let mut request = [0_u8; 1024];
                let _read = stream.read(&mut request)?;
                stream.write_all(status_response.as_bytes())?;
            }
            Ok(())
        });
        let error = HttpTransport::with_retry_runtime(Arc::new(FakeRuntime::new(Vec::new())))
            .get(&url, 1)
            .expect_err("three retryable statuses must fail");
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("status test server panicked"))??;
        assert_eq!(
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<HttpStatusError>()),
            Some(&HttpStatusError { status: 500 })
        );
        let retry = error
            .downcast_ref::<GetRetryError<anyhow::Error>>()
            .expect("exhausted GET must preserve typed retry metadata");
        assert_eq!(retry.attempts(), 3);

        for status in [404, 410] {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let url = format!("http://{}/missing", listener.local_addr()?);
            let hits = Arc::new(AtomicUsize::new(0));
            let server_hits = Arc::clone(&hits);
            let handle = thread::spawn(move || -> Result<()> {
                let (mut stream, _) = listener.accept()?;
                server_hits.fetch_add(1, Ordering::SeqCst);
                let mut request = [0_u8; 1024];
                let _read = stream.read(&mut request)?;
                let response = format!(
                    "HTTP/1.1 {status} Missing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(response.as_bytes())?;
                Ok(())
            });
            let error = HttpTransport::with_retry_runtime(Arc::new(FakeRuntime::new(Vec::new())))
                .get(&url, 1)
                .expect_err("confirmed absence must fail immediately");
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("absence test server panicked"))??;
            assert!(is_not_found(&error));
            let retry = error
                .downcast_ref::<GetRetryError<anyhow::Error>>()
                .expect("fatal GET must preserve typed retry metadata");
            assert_eq!(retry.attempts(), 1);
            assert_eq!(hits.load(Ordering::SeqCst), 1);
        }
        Ok(())
    }
}
