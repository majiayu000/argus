//! Shared test helpers for argus ecosystem crates.
//!
//! Hoisted from three identical `MockTransport` copies in
//! `argus-fetch/tests/integration.rs`, `argus-pypi/tests/integration.rs`,
//! and `argus-crates/tests/integration.rs`. The crate is `publish = false`
//! and only intended as a dev-dependency.

use anyhow::{anyhow, Result};
use argus_fetch::Transport;
use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory [`Transport`] that returns pre-registered bodies per URL.
///
/// Mirrors `HttpTransport`'s contract:
/// - Returns an error if no route is registered for the URL.
/// - Refuses bodies larger than the per-request `max_bytes` cap so tests
///   exercise the same streaming-cap path as production.
pub struct MockTransport {
    routes: Mutex<HashMap<String, Vec<u8>>>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            routes: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, url: &str, body: Vec<u8>) {
        self.routes.lock().unwrap().insert(url.to_string(), body);
    }
}

impl Transport for MockTransport {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let body = self
            .routes
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| anyhow!("MockTransport: no route for {url}"))?;
        if body.len() as u64 > max_bytes {
            return Err(anyhow!(
                "MockTransport: body for {url} ({} bytes) exceeds cap {max_bytes}",
                body.len()
            ));
        }
        Ok(body)
    }
}
