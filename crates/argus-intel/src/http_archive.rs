use crate::import::{ArchiveTransport, DownloadMetadata};
use anyhow::{anyhow, bail, Context, Result};
use argus_transport::{
    checked_retry_byte_budget, classify_io_error, classify_ureq_transport, is_retryable_status,
    AttemptContext, GetRetryPolicy, HttpStatusError, RetryDisposition, RetryFailure, RetryRuntime,
    SystemRetryRuntime, GET_ATTEMPT_TIMEOUT, GET_MAX_ATTEMPTS,
};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use url::Url;

pub struct HttpArchiveTransport {
    agent: ureq::Agent,
    user_agent: String,
    retry_runtime: Arc<dyn RetryRuntime>,
}

impl HttpArchiveTransport {
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(GET_ATTEMPT_TIMEOUT)
                .redirects(0)
                .build(),
            user_agent: format!("argus/{}", env!("CARGO_PKG_VERSION")),
            retry_runtime: Arc::new(SystemRetryRuntime::default()),
        }
    }

    fn download_attempt(
        &self,
        initial_url: &str,
        expected_redirect: &str,
        max_bytes: u64,
        attempt: AttemptContext,
    ) -> std::result::Result<StagedDownload, RetryFailure<anyhow::Error>> {
        validate_http_url(initial_url).map_err(RetryFailure::fatal)?;
        validate_http_url(expected_redirect).map_err(RetryFailure::fatal)?;
        let mut stage = tempfile::Builder::new()
            .prefix("argus-intel-http-attempt-")
            .tempfile()
            .context("create bounded archive retry staging file")
            .map_err(RetryFailure::fatal)?;
        let result = self.download_attempt_to_stage(
            initial_url,
            expected_redirect,
            max_bytes,
            attempt,
            &mut stage,
        );
        match result {
            Ok(metadata) => Ok(StagedDownload { stage, metadata }),
            Err(failure) => match stage
                .close()
                .context("remove failed archive retry staging file")
            {
                Ok(()) => Err(failure),
                Err(cleanup) => Err(RetryFailure::fatal(failure.into_error().context(format!(
                    "additionally failed to clean archive retry stage: {cleanup:#}"
                )))),
            },
        }
    }

    fn download_attempt_to_stage(
        &self,
        initial_url: &str,
        expected_redirect: &str,
        max_bytes: u64,
        attempt: AttemptContext,
        stage: &mut tempfile::NamedTempFile,
    ) -> std::result::Result<DownloadMetadata, RetryFailure<anyhow::Error>> {
        let mut current = initial_url.to_string();
        let mut redirects = 0;
        loop {
            validate_http_url(&current).map_err(RetryFailure::fatal)?;
            if attempt.remaining(self.retry_runtime.as_ref()).is_zero() {
                return Err(attempt_timeout_failure(&current));
            }
            let response = self.get_once(&current, attempt)?;
            if is_redirect(response.status()) {
                if redirects == 1 {
                    return Err(RetryFailure::fatal(anyhow!(
                        "archive download attempted more than one redirect"
                    )));
                }
                let location = response.header("Location").ok_or_else(|| {
                    RetryFailure::fatal(anyhow!("archive redirect is missing Location"))
                })?;
                let resolved = Url::parse(&current)
                    .context("parse archive redirect base")
                    .and_then(|base| {
                        base.join(location)
                            .context("resolve archive redirect Location")
                    })
                    .map_err(RetryFailure::fatal)?;
                check_no_scheme_downgrade(&current, resolved.as_str())
                    .map_err(RetryFailure::fatal)?;
                if resolved.as_str() != expected_redirect {
                    return Err(RetryFailure::fatal(anyhow!(
                        "archive redirect target `{}` is not exact expected target `{expected_redirect}`",
                        resolved.as_str()
                    )));
                }
                validate_http_url(resolved.as_str()).map_err(RetryFailure::fatal)?;
                current = expected_redirect.to_string();
                redirects += 1;
                continue;
            }
            if !(200..300).contains(&response.status()) {
                return Err(RetryFailure::fatal(anyhow!(
                    "archive download returned unexpected status {}",
                    response.status()
                )));
            }
            if current != initial_url && current != expected_redirect {
                return Err(RetryFailure::fatal(anyhow!(
                    "archive final URL escaped the fixed source contract"
                )));
            }
            if let Some(length) = response.header("Content-Length") {
                let length = length.parse::<u64>().map_err(|_| {
                    RetryFailure::fatal(anyhow!(
                        "archive response has malformed Content-Length {length:?}"
                    ))
                })?;
                if length > max_bytes {
                    return Err(RetryFailure::fatal(anyhow!(
                        "archive Content-Length {length} exceeds cap {max_bytes}"
                    )));
                }
            }
            let bytes_written =
                copy_response_capped(response.into_reader(), stage.as_file_mut(), max_bytes)?;
            stage
                .as_file_mut()
                .flush()
                .context("flush successful archive retry stage")
                .map_err(RetryFailure::fatal)?;
            if attempt.remaining(self.retry_runtime.as_ref()).is_zero() {
                return Err(attempt_timeout_failure(&current));
            }
            return Ok(DownloadMetadata {
                final_url: current,
                redirect_count: redirects,
                bytes_written,
            });
        }
    }

    fn get_once(
        &self,
        url: &str,
        attempt: AttemptContext,
    ) -> std::result::Result<ureq::Response, RetryFailure<anyhow::Error>> {
        match self
            .agent
            .get(url)
            .set("User-Agent", &self.user_agent)
            .timeout(attempt.request_timeout(self.retry_runtime.as_ref()))
            .call()
        {
            Ok(response) => Ok(response),
            Err(ureq::Error::Status(status, response)) if is_redirect(status) => Ok(response),
            Err(ureq::Error::Status(status, response)) => {
                let retry_after = response.header("Retry-After");
                let error = anyhow::Error::new(HttpStatusError { status })
                    .context(format!("HTTP GET {url} returned status {status}"));
                if is_retryable_status(status) {
                    Err(RetryFailure::retryable(error, retry_after))
                } else {
                    Err(RetryFailure::fatal(error))
                }
            }
            Err(ureq::Error::Transport(transport)) => {
                let disposition = classify_ureq_transport(&transport);
                let error = anyhow::Error::new(transport).context(format!("HTTP GET {url}"));
                match disposition {
                    RetryDisposition::Retryable => Err(RetryFailure::retryable(error, None)),
                    RetryDisposition::Fatal => Err(RetryFailure::fatal(error)),
                }
            }
        }
    }
}

impl Default for HttpArchiveTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveTransport for HttpArchiveTransport {
    fn download_to(
        &self,
        initial_url: &str,
        expected_redirect: &str,
        max_bytes: u64,
        output: &mut dyn Write,
    ) -> Result<DownloadMetadata> {
        checked_retry_byte_budget(max_bytes).ok_or_else(|| {
            anyhow!(
                "archive cap {max_bytes} overflows the {}-attempt amplification bound",
                GET_MAX_ATTEMPTS
            )
        })?;
        validate_http_url(initial_url)?;
        validate_http_url(expected_redirect)?;
        let mut download = GetRetryPolicy
            .execute(self.retry_runtime.as_ref(), |attempt| {
                self.download_attempt(initial_url, expected_redirect, max_bytes, attempt)
            })
            .map_err(anyhow::Error::new)?;
        let copy_result = (|| {
            download
                .stage
                .as_file_mut()
                .seek(SeekFrom::Start(0))
                .context("rewind successful archive retry stage")?;
            copy_success_to_caller(
                download.stage.as_file_mut(),
                output,
                download.metadata.bytes_written,
            )
        })();
        let cleanup_result = download
            .stage
            .close()
            .context("remove successful archive retry staging file");
        match (copy_result, cleanup_result) {
            (Ok(()), Ok(())) => Ok(download.metadata),
            (Err(copy), Ok(())) => Err(copy),
            (Ok(()), Err(cleanup)) => Err(cleanup),
            (Err(copy), Err(cleanup)) => Err(anyhow!(
                "{copy:#}; additionally failed to remove archive retry staging file: {cleanup:#}"
            )),
        }
    }
}

struct StagedDownload {
    stage: tempfile::NamedTempFile,
    metadata: DownloadMetadata,
}

fn copy_response_capped(
    mut input: impl Read,
    output: &mut dyn Write,
    max_bytes: u64,
) -> std::result::Result<u64, RetryFailure<anyhow::Error>> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = match input.read(&mut buffer) {
            Ok(read) => read,
            Err(error) => {
                let disposition = classify_io_error(&error);
                let error = anyhow::Error::new(error).context("read archive HTTP response");
                return Err(match disposition {
                    RetryDisposition::Retryable => RetryFailure::retryable(error, None),
                    RetryDisposition::Fatal => RetryFailure::fatal(error),
                });
            }
        };
        if read == 0 {
            return Ok(total);
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| RetryFailure::fatal(anyhow!("archive byte counter overflow")))?;
        if total > max_bytes {
            return Err(RetryFailure::fatal(anyhow!(
                "archive response exceeds compressed cap {max_bytes}"
            )));
        }
        output
            .write_all(&buffer[..read])
            .context("write bounded archive retry stage")
            .map_err(RetryFailure::fatal)?;
    }
}

fn copy_success_to_caller(
    input: &mut impl Read,
    output: &mut dyn Write,
    expected_bytes: u64,
) -> Result<()> {
    let copied = std::io::copy(&mut input.take(expected_bytes + 1), output)
        .context("copy fully validated archive to caller")?;
    if copied != expected_bytes {
        bail!(
            "validated archive stage copy wrote {copied} bytes, expected exactly {expected_bytes}"
        );
    }
    output
        .flush()
        .context("flush fully validated archive to caller")
}

fn validate_http_url(value: &str) -> Result<()> {
    let parsed = Url::parse(value).with_context(|| format!("parse archive URL {value}"))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        scheme => bail!("unsupported archive URL scheme `{scheme}`"),
    }
}

fn check_no_scheme_downgrade(current: &str, next: &str) -> Result<()> {
    let current = Url::parse(current).context("parse archive redirect source URL")?;
    let next = Url::parse(next).context("parse archive redirect target URL")?;
    if current.scheme() == "https" && next.scheme() != "https" {
        bail!("HTTPS downgrade detected in archive redirect");
    }
    Ok(())
}

fn attempt_timeout_failure(url: &str) -> RetryFailure<anyhow::Error> {
    RetryFailure::retryable(
        anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "logical archive GET attempt deadline reached",
        ))
        .context(format!("HTTP GET {url}")),
        None,
    )
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Read};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct NoSleepRuntime {
        elapsed: Mutex<Duration>,
    }

    impl NoSleepRuntime {
        fn new() -> Self {
            Self {
                elapsed: Mutex::new(Duration::ZERO),
            }
        }
    }

    impl RetryRuntime for NoSleepRuntime {
        fn monotonic_now(&self) -> Duration {
            *self.elapsed.lock().unwrap()
        }

        fn wall_now(&self) -> SystemTime {
            UNIX_EPOCH
        }

        fn sleep(&self, duration: Duration) {
            *self.elapsed.lock().unwrap() += duration;
        }

        fn jitter(&self, base: Duration) -> Duration {
            base / 2
        }
    }

    fn test_transport() -> HttpArchiveTransport {
        HttpArchiveTransport {
            agent: ureq::AgentBuilder::new()
                .timeout(GET_ATTEMPT_TIMEOUT)
                .redirects(0)
                .build(),
            user_agent: "argus-test".to_string(),
            retry_runtime: Arc::new(NoSleepRuntime::new()),
        }
    }

    struct PassThroughTls;

    impl ureq::TlsConnector for PassThroughTls {
        fn connect(
            &self,
            _dns_name: &str,
            io: Box<dyn ureq::ReadWrite>,
        ) -> std::result::Result<Box<dyn ureq::ReadWrite>, ureq::Error> {
            Ok(Box::new(PassThroughStream(io)))
        }
    }

    #[derive(Debug)]
    struct PassThroughStream(Box<dyn ureq::ReadWrite>);

    impl Read for PassThroughStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.0.read(buffer)
        }
    }

    impl Write for PassThroughStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl ureq::ReadWrite for PassThroughStream {
        fn socket(&self) -> Option<&TcpStream> {
            self.0.socket()
        }
    }

    #[test]
    fn https_downgrade_is_rejected_before_target_is_opened() -> Result<()> {
        let target_listener = TcpListener::bind("127.0.0.1:0")?;
        let target = format!("http://{}/archive", target_listener.local_addr()?);
        let origin_listener = TcpListener::bind("127.0.0.1:0")?;
        let origin = format!("https://{}/start", origin_listener.local_addr()?);
        let server_target = target.clone();
        let origin_server = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = origin_listener.accept()?;
            let mut request = [0_u8; 1024];
            let _read = stream.read(&mut request)?;
            stream.write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {server_target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )?;
            Ok(())
        });
        let transport = HttpArchiveTransport {
            agent: ureq::AgentBuilder::new()
                .timeout(GET_ATTEMPT_TIMEOUT)
                .redirects(0)
                .tls_connector(Arc::new(PassThroughTls))
                .build(),
            user_agent: "argus-test".to_string(),
            retry_runtime: Arc::new(NoSleepRuntime::new()),
        };
        let error = transport
            .download_to(&origin, &target, 7, &mut Vec::new())
            .expect_err("HTTPS redirect downgrade must fail");
        origin_server
            .join()
            .map_err(|_| anyhow!("downgrade origin server panicked"))??;
        target_listener.set_nonblocking(true)?;
        assert!(
            matches!(
                target_listener.accept(),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock
            ),
            "downgrade target was opened before rejection"
        );
        assert!(error.to_string().contains("HTTPS downgrade"));
        Ok(())
    }

    #[test]
    fn failed_attempt_body_bytes_never_reach_caller() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let initial = format!("http://{address}/start");
        let expected = format!("http://{address}/final");
        let server_expected = expected.clone();
        let server = thread::spawn(move || -> Result<()> {
            for (expected_path, response) in [
                (
                    "/start",
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {server_expected}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    ),
                ),
                (
                    "/final",
                    "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nbad"
                        .to_string(),
                ),
                (
                    "/start",
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {server_expected}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    ),
                ),
                (
                    "/final",
                    "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nworse"
                        .to_string(),
                ),
                (
                    "/start",
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {server_expected}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    ),
                ),
                (
                    "/final",
                    "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\narchive"
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
        let mut output = Vec::new();
        let metadata = test_transport().download_to(&initial, &expected, 7, &mut output)?;
        server
            .join()
            .map_err(|_| anyhow!("partial-body test server panicked"))??;
        assert_eq!(metadata.bytes_written, 7);
        assert_eq!(metadata.redirect_count, 1);
        assert_eq!(output, b"archive");
        Ok(())
    }

    struct FailingWriter {
        bytes: Vec<u8>,
        remaining: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("injected caller copy failure"));
            }
            let written = buffer.len().min(self.remaining);
            self.bytes.extend_from_slice(&buffer[..written]);
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn successful_stage_copy_errors_are_explicit() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let initial = format!("http://{address}/start");
        let expected = format!("http://{address}/final");
        let server = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 1024];
            let _read = stream.read(&mut request)?;
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\narchive",
            )?;
            Ok(())
        });
        let mut output = FailingWriter {
            bytes: Vec::new(),
            remaining: 2,
        };
        let error = test_transport()
            .download_to(&initial, &expected, 7, &mut output)
            .expect_err("caller copy failure must be reported");
        server
            .join()
            .map_err(|_| anyhow!("copy-error test server panicked"))??;
        assert!(format!("{error:#}").contains("copy fully validated archive to caller"));
        assert_eq!(output.bytes, b"ar");
        Ok(())
    }
}
