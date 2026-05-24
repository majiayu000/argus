//! HTTP transport for the npm registry. Abstracted as a trait so tests can
//! inject in-memory bytes without binding to a real socket.

use anyhow::{anyhow, bail, Context, Result};
use std::io::Read;

/// Maximum size we will accept for a single response body, in bytes.
///
/// The caller passes a per-request cap because packuments are tiny (~hundreds
/// of KB) but tarballs can legitimately be tens of MB. Returning before the
/// body is fully read prevents the "attacker streams 4 GiB into our RAM"
/// failure mode the security review called out.
pub trait Transport {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>>;
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
            .redirects(3)
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
        // ureq 2.x returns Err for non-2xx, so a successful `call()` is
        // already a 2xx response — no extra status branch needed.
        let resp = self
            .agent
            .get(url)
            .set("User-Agent", &self.user_agent)
            .set("Accept", "application/json, application/octet-stream")
            .call()
            .with_context(|| format!("HTTP GET {url}"))?;

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
}
