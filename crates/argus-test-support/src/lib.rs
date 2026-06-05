//! Shared test helpers for argus ecosystem crates.
//!
//! Hoisted from three identical `MockTransport` copies in
//! `argus-fetch/tests/integration.rs`, `argus-pypi/tests/integration.rs`,
//! and `argus-crates/tests/integration.rs`. The crate is `publish = false`
//! and only intended as a dev-dependency.

use anyhow::{anyhow, Result};
use argus_fetch::{HttpStatusError, Transport};
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
    /// URLs that return a non-success HTTP status instead of a body, so tests
    /// can simulate a *transient* failure (e.g. 500) distinct from a confirmed
    /// 404. Checked before `routes`.
    status_routes: Mutex<HashMap<String, u16>>,
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
            status_routes: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, url: &str, body: Vec<u8>) {
        self.routes.lock().unwrap().insert(url.to_string(), body);
    }

    /// Make `url` fail with the given HTTP status (carried as a downcastable
    /// `HttpStatusError`). Use a non-404 status (e.g. 500) to exercise the
    /// transient-failure path that must NOT trigger an integrity downgrade.
    pub fn insert_status(&self, url: &str, status: u16) {
        self.status_routes
            .lock()
            .unwrap()
            .insert(url.to_string(), status);
    }
}

impl Transport for MockTransport {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        if let Some(&status) = self.status_routes.lock().unwrap().get(url) {
            return Err(anyhow::Error::new(HttpStatusError { status })
                .context(format!("MockTransport: status {status} for {url}")));
        }
        let body = self
            .routes
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            // Mirror HttpTransport: a missing route is a confirmed 404, carried
            // as a downcastable `HttpStatusError` so `is_not_found` works in
            // tests exercising the 404-vs-transient downgrade paths.
            .ok_or_else(|| {
                anyhow::Error::new(HttpStatusError { status: 404 })
                    .context(format!("MockTransport: no route for {url}"))
            })?;
        if body.len() as u64 > max_bytes {
            return Err(anyhow!(
                "MockTransport: body for {url} ({} bytes) exceeds cap {max_bytes}",
                body.len()
            ));
        }
        Ok(body)
    }
}
