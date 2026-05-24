//! HTTP transport for the npm registry. Abstracted as a trait so tests can
//! inject in-memory bytes without binding to a real socket.

use anyhow::{anyhow, Context, Result};

/// Minimal byte-oriented GET transport. Implementations must follow redirects
/// up to a reasonable limit and surface the final response body.
pub trait Transport {
    fn get(&self, url: &str) -> Result<Vec<u8>>;
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
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self
            .agent
            .get(url)
            .set("User-Agent", &self.user_agent)
            .set("Accept", "application/json, application/octet-stream")
            .call()
            .with_context(|| format!("HTTP GET {url}"))?;

        if !(200..300).contains(&resp.status()) {
            return Err(anyhow!("HTTP GET {url} returned status {}", resp.status()));
        }

        let mut body = Vec::new();
        resp.into_reader()
            .read_to_end(&mut body)
            .with_context(|| format!("read body of {url}"))?;
        Ok(body)
    }
}
