//! HTTP transport for the npm registry. Abstracted as a trait so tests can
//! inject in-memory bytes without binding to a real socket.

use anyhow::{anyhow, bail, Context, Result};
use std::io::Read;

const MAX_REDIRECTS: usize = 3;

/// Maximum size we will accept for a single response body, in bytes.
///
/// The caller passes a per-request cap because packuments are tiny (~hundreds
/// of KB) but tarballs can legitimately be tens of MB. Returning before the
/// body is fully read prevents the "attacker streams 4 GiB into our RAM"
/// failure mode the security review called out.
pub trait Transport {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>>;

    /// Like [`get`](Transport::get), but every HTTP redirect hop's target URL
    /// must satisfy `allow` (return `Ok`) before it is followed; otherwise the
    /// fetch aborts before the redirect target is requested. Use this for
    /// artifact downloads so a 3xx from an allowed registry host cannot
    /// silently redirect the download to an unallowlisted host (an
    /// SSRF-adjacent allowlist bypass).
    ///
    /// The default implementation ignores `allow` and delegates to `get`,
    /// because in-memory transports (tests) do not follow redirects.
    fn get_redirect_checked(
        &self,
        url: &str,
        max_bytes: u64,
        allow: &dyn Fn(&str) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let _ = allow;
        self.get(url, max_bytes)
    }
}

/// A non-success HTTP status surfaced through the otherwise-opaque
/// `anyhow::Error` that [`Transport::get`] returns. Callers downcast to it
/// (via [`is_not_found`]) so they can distinguish a *confirmed* 404 — where a
/// downgrade may be legitimate (e.g. a Maven artifact that genuinely ships no
/// `.sha256`) — from a transient failure (timeout / 5xx / TLS), which must
/// fail closed (U-29) rather than silently weaken integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpStatusError {
    pub status: u16,
}

impl std::fmt::Display for HttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP status {}", self.status)
    }
}

impl std::error::Error for HttpStatusError {}

/// True iff `err` carries a [`HttpStatusError`] with status 404 — i.e. the
/// resource was confirmed absent, not merely unreachable. Any other error
/// (transient network, 5xx, parse, cap) returns false and must be treated as
/// a hard failure by integrity-sensitive callers.
pub fn is_not_found(err: &anyhow::Error) -> bool {
    err.downcast_ref::<HttpStatusError>()
        .is_some_and(|e| e.status == 404)
}

/// Default ureq-backed transport used by the CLI.
pub struct HttpTransport {
    agent: ureq::Agent,
    user_agent: String,
}

impl HttpTransport {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(30))
            .redirects(0)
            .build();
        Self {
            agent,
            user_agent: format!("argus/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for HttpTransport {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        // Plain get: no per-hop host policy (scheme-downgrade is still
        // enforced). Artifact downloads should use `get_redirect_checked`.
        self.get_redirect_checked(url, max_bytes, &|_| Ok(()))
    }

    fn get_redirect_checked(
        &self,
        url: &str,
        max_bytes: u64,
        allow: &dyn Fn(&str) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let mut current_url = url.to_string();

        for redirect_count in 0..=MAX_REDIRECTS {
            let resp = self.get_once(&current_url)?;
            if is_redirect_status(resp.status()) {
                if redirect_count == MAX_REDIRECTS {
                    bail!("too many HTTP redirects while fetching {url}");
                }
                let location = resp.header("Location").ok_or_else(|| {
                    anyhow!("redirect response from {current_url} missing Location header")
                })?;
                let next_url = resolve_redirect_url(&current_url, location)?;
                check_no_scheme_downgrade(&current_url, &next_url)?;
                // Re-validate the redirect target against the caller's host
                // policy BEFORE requesting it, so an allowed host cannot bounce
                // the download to an unallowlisted one.
                allow(&next_url).with_context(|| {
                    format!("redirect target {next_url} rejected by host allowlist (from {current_url})")
                })?;
                current_url = next_url;
                continue;
            }

            return read_capped_body(resp, max_bytes, &current_url);
        }

        bail!("too many HTTP redirects while fetching {url}")
    }
}

impl HttpTransport {
    fn get_once(&self, url: &str) -> Result<ureq::Response> {
        // Redirects are disabled on the agent so the caller can inspect
        // each `Location` before opening the next URL. ureq still surfaces
        // non-redirect non-2xx responses as errors.
        // Deliberately do NOT send an explicit Accept header. crates.io's
        // download endpoint (`/api/v1/crates/<n>/<v>/download`) does
        // content negotiation: with `Accept: application/json` it returns
        // a 200 JSON body `{"url": "...static.crates.io/..."}` *instead
        // of* a 302 redirect, which means ureq can't follow it
        // automatically and we end up with a 67-byte JSON body where we
        // expected an 83 KB `.crate` archive. Sending no Accept (ureq
        // default `*/*` semantics) makes crates.io serve the redirect
        // that points at the actual artifact. The npm and PyPI metadata
        // endpoints both return JSON regardless of Accept, so this is
        // pure upside.
        match self
            .agent
            .get(url)
            .set("User-Agent", &self.user_agent)
            .call()
        {
            Ok(resp) => Ok(resp),
            // A 4xx/5xx (ureq surfaces these as `Status`, while 3xx are returned
            // as `Ok` because the agent is built with `redirects(0)`). Attach a
            // typed `HttpStatusError` so integrity-sensitive callers can tell a
            // confirmed 404 from a transient failure.
            Err(ureq::Error::Status(code, _resp)) => {
                Err(anyhow::Error::new(HttpStatusError { status: code })
                    .context(format!("HTTP GET {url} returned status {code}")))
            }
            Err(e) => Err(anyhow::Error::new(e).context(format!("HTTP GET {url}"))),
        }
    }
}

fn read_capped_body(resp: ureq::Response, max_bytes: u64, url: &str) -> Result<Vec<u8>> {
    // ureq 2.x returns Err for non-2xx, so a response that reaches here is
    // either 2xx or a manually handled redirect. Anything else is unexpected.
    if !(200..300).contains(&resp.status()) {
        bail!(
            "HTTP GET {url} returned unexpected status {}",
            resp.status()
        );
    }

    // If the server announces Content-Length, refuse early rather than
    // reading the body. Some registries omit this header on chunked
    // responses, so this is a fast-path, not the only guard.
    if let Some(len_str) = resp.header("Content-Length") {
        if let Ok(len) = len_str.parse::<u64>() {
            if len > max_bytes {
                bail!("Content-Length {len} exceeds cap {max_bytes} for {url}");
            }
        }
    }

    // Authoritative cap: bound the reader at `max_bytes + 1` and bail if
    // we actually consume that one extra byte (meaning the server tried
    // to deliver more than max_bytes).
    let mut body = Vec::new();
    resp.into_reader()
        .take(max_bytes + 1)
        .read_to_end(&mut body)
        .with_context(|| format!("read body of {url}"))?;
    if body.len() as u64 > max_bytes {
        return Err(anyhow!("response body for {url} exceeded cap {max_bytes}"));
    }
    Ok(body)
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn resolve_redirect_url(current_url: &str, location: &str) -> Result<String> {
    let base = url::Url::parse(current_url)
        .with_context(|| format!("parse redirect base URL {current_url}"))?;
    let next = base
        .join(location)
        .with_context(|| format!("resolve redirect Location {location:?} against {current_url}"))?;
    match next.scheme() {
        "http" | "https" => Ok(next.to_string()),
        other => bail!("unsupported redirect scheme `{other}` in Location {location:?}"),
    }
}

/// Refuse a request where the final response URL is on a weaker scheme than
/// the request URL. Pure function so we can unit-test it without a real
/// HTTP server. URLs that were never https to begin with pass through.
fn check_no_scheme_downgrade(requested: &str, final_url: &str) -> Result<()> {
    if !requested.starts_with("https://") {
        // Caller explicitly asked for http — nothing to downgrade from.
        return Ok(());
    }
    if !final_url.starts_with("https://") {
        bail!("HTTPS downgrade detected during redirect: requested {requested}, final URL {final_url}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn spawn_response_server(
        scheme: &'static str,
        response: String,
    ) -> Result<(String, Arc<AtomicUsize>, thread::JoinHandle<Result<()>>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let handle = thread::spawn(move || -> Result<()> {
            let deadline = Instant::now() + Duration::from_millis(500);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        server_hits.fetch_add(1, Ordering::SeqCst);
                        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                        let mut buf = [0_u8; 1024];
                        let _read = std::io::Read::read(&mut stream, &mut buf)
                            .context("read test request")?;
                        std::io::Write::write_all(&mut stream, response.as_bytes())?;
                        return Ok(());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Ok(());
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        });

        Ok((format!("{scheme}://{addr}/resource"), hits, handle))
    }

    fn join_server(handle: thread::JoinHandle<Result<()>>) -> Result<()> {
        match handle.join() {
            Ok(result) => result,
            Err(_) => bail!("test server thread panicked"),
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

    impl std::io::Read for PassThroughStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.0, buf)
        }
    }

    impl std::io::Write for PassThroughStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::io::Write::write(&mut self.0, buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            std::io::Write::flush(&mut self.0)
        }
    }

    impl ureq::ReadWrite for PassThroughStream {
        fn socket(&self) -> Option<&TcpStream> {
            self.0.socket()
        }
    }

    #[test]
    fn http_redirect_is_followed_manually() -> Result<()> {
        let (target_url, target_hits, target_handle) = spawn_response_server(
            "http",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string(),
        )?;
        let (redirect_url, redirect_hits, redirect_handle) = spawn_response_server(
            "http",
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        )?;

        let body = HttpTransport::new().get(&redirect_url, 16)?;

        join_server(redirect_handle)?;
        join_server(target_handle)?;
        assert_eq!(body, b"ok");
        assert_eq!(redirect_hits.load(Ordering::SeqCst), 1);
        assert_eq!(target_hits.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn redirect_to_disallowed_host_is_rejected_before_target_request() -> Result<()> {
        let (target_url, target_hits, target_handle) = spawn_response_server(
            "http",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string(),
        )?;
        let (redirect_url, redirect_hits, redirect_handle) = spawn_response_server(
            "http",
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        )?;

        // Allow policy that rejects everything except the original redirect
        // host — i.e. the redirect target is NOT allowlisted.
        let err = match HttpTransport::new().get_redirect_checked(&redirect_url, 16, &|u: &str| {
            if u.starts_with(&redirect_url) {
                Ok(())
            } else {
                bail!("host not in allowlist: {u}")
            }
        }) {
            Ok(b) => bail!("expected allowlist rejection, got body {:?}", b),
            Err(e) => format!("{e:#}"),
        };

        join_server(redirect_handle)?;
        join_server(target_handle)?;
        assert!(err.contains("allowlist"), "got: {err}");
        assert_eq!(redirect_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            target_hits.load(Ordering::SeqCst),
            0,
            "disallowed redirect target must NOT be requested"
        );
        Ok(())
    }

    #[test]
    fn https_to_http_redirect_is_rejected_before_target_request() -> Result<()> {
        let (target_url, target_hits, target_handle) = spawn_response_server(
            "http",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string(),
        )?;
        let (redirect_url, redirect_hits, redirect_handle) = spawn_response_server(
            "https",
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        )?;
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .redirects(0)
            .tls_connector(Arc::new(PassThroughTls))
            .build();
        let transport = HttpTransport {
            agent,
            user_agent: "argus-test".to_string(),
        };

        let err = match transport.get(&redirect_url, 16) {
            Ok(body) => bail!(
                "expected HTTPS downgrade rejection, got body {:?}",
                String::from_utf8_lossy(&body)
            ),
            Err(err) => err.to_string(),
        };

        join_server(redirect_handle)?;
        join_server(target_handle)?;
        assert!(err.contains("HTTPS downgrade"), "got: {err}");
        assert_eq!(redirect_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            target_hits.load(Ordering::SeqCst),
            0,
            "downgrade target was requested before rejection"
        );
        Ok(())
    }

    #[test]
    fn relative_redirect_location_resolves_against_current_url() -> Result<()> {
        let next = resolve_redirect_url("https://registry.example/a/b/package", "../tarball.tgz")?;
        assert_eq!(next, "https://registry.example/a/tarball.tgz");
        Ok(())
    }

    #[test]
    fn https_to_https_is_allowed() {
        check_no_scheme_downgrade(
            "https://registry.npmjs.org/chalk",
            "https://registry.npmjs.org/chalk",
        )
        .unwrap();
        check_no_scheme_downgrade(
            "https://registry.npmjs.org/chalk",
            "https://other.example.invalid/chalk",
        )
        .unwrap();
    }

    #[test]
    fn https_to_http_is_rejected() {
        let err = check_no_scheme_downgrade(
            "https://registry.npmjs.org/chalk",
            "http://evil.example.invalid/chalk",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("HTTPS downgrade"), "got: {err}");
    }

    #[test]
    fn http_to_http_is_allowed_at_this_layer() {
        // If the caller already accepted http (e.g. a private local mirror),
        // we do not introduce a new requirement here. The tarball-URL check
        // in `lib.rs` already refuses non-HTTPS tarball URLs separately.
        check_no_scheme_downgrade("http://localhost:4873/chalk", "http://localhost:4873/chalk")
            .unwrap();
    }
}
