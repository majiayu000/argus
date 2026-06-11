//! Shared test helpers for argus ecosystem crates.
//!
//! Hoisted from three identical `MockTransport` copies in
//! `argus-fetch/tests/integration.rs`, `argus-pypi/tests/integration.rs`,
//! and `argus-crates/tests/integration.rs`. The crate is `publish = false`
//! and only intended as a dev-dependency.

use anyhow::{anyhow, Result};
use argus_fetch::{HttpStatusError, Transport};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

const MAX_MOCK_REDIRECTS: usize = 3;

fn lock<'a, T>(mutex: &'a Mutex<T>, label: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => panic!("MockTransport {label} mutex poisoned: {poisoned}"),
    }
}

/// In-memory [`Transport`] that returns pre-registered bodies per URL.
///
/// Mirrors `HttpTransport`'s contract:
/// - Returns an error if no route is registered for the URL.
/// - Refuses bodies larger than the per-request `max_bytes` cap so tests
///   exercise the same streaming-cap path as production.
pub struct MockTransport {
    routes: Mutex<HashMap<String, Vec<u8>>>,
    redirect_routes: Mutex<HashMap<String, String>>,
    /// URLs that return a non-success HTTP status instead of a body, so tests
    /// can simulate a *transient* failure (e.g. 500) distinct from a confirmed
    /// 404. Checked before `routes`.
    status_routes: Mutex<HashMap<String, u16>>,
    request_counts: Mutex<HashMap<String, usize>>,
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
            redirect_routes: Mutex::new(HashMap::new()),
            status_routes: Mutex::new(HashMap::new()),
            request_counts: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, url: &str, body: Vec<u8>) {
        lock(&self.routes, "routes").insert(url.to_string(), body);
    }

    pub fn insert_redirect(&self, url: &str, location: &str) {
        lock(&self.redirect_routes, "redirect_routes")
            .insert(url.to_string(), location.to_string());
    }

    /// Make `url` fail with the given HTTP status (carried as a downcastable
    /// `HttpStatusError`). Use a non-404 status (e.g. 500) to exercise the
    /// transient-failure path that must NOT trigger an integrity downgrade.
    pub fn insert_status(&self, url: &str, status: u16) {
        lock(&self.status_routes, "status_routes").insert(url.to_string(), status);
    }

    pub fn request_count(&self, url: &str) -> usize {
        lock(&self.request_counts, "request_counts")
            .get(url)
            .copied()
            .unwrap_or(0)
    }

    fn get_with_redirect_policy(
        &self,
        url: &str,
        max_bytes: u64,
        allow: &dyn Fn(&str) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let mut current_url = url.to_string();

        for redirect_count in 0..=MAX_MOCK_REDIRECTS {
            *lock(&self.request_counts, "request_counts")
                .entry(current_url.clone())
                .or_insert(0) += 1;

            if let Some(next_url) = lock(&self.redirect_routes, "redirect_routes")
                .get(&current_url)
                .cloned()
            {
                if redirect_count == MAX_MOCK_REDIRECTS {
                    return Err(anyhow!("MockTransport: too many redirects for {url}"));
                }
                allow(&next_url).map_err(|e| {
                    anyhow!(
                        "MockTransport: redirect target {next_url} rejected by host allowlist \
                         (from {current_url}): {e:#}"
                    )
                })?;
                current_url = next_url;
                continue;
            }

            if let Some(&status) = lock(&self.status_routes, "status_routes").get(&current_url) {
                return Err(anyhow::Error::new(HttpStatusError { status })
                    .context(format!("MockTransport: status {status} for {current_url}")));
            }
            let body = lock(&self.routes, "routes")
                .get(&current_url)
                .cloned()
                // Mirror HttpTransport: a missing route is a confirmed 404, carried
                // as a downcastable `HttpStatusError` so `is_not_found` works in
                // tests exercising the 404-vs-transient downgrade paths.
                .ok_or_else(|| {
                    anyhow::Error::new(HttpStatusError { status: 404 })
                        .context(format!("MockTransport: no route for {current_url}"))
                })?;
            if body.len() as u64 > max_bytes {
                return Err(anyhow!(
                    "MockTransport: body for {current_url} ({} bytes) exceeds cap {max_bytes}",
                    body.len()
                ));
            }
            return Ok(body);
        }

        Err(anyhow!("MockTransport: too many redirects for {url}"))
    }
}

impl Transport for MockTransport {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        self.get_with_redirect_policy(url, max_bytes, &|_| Ok(()))
    }

    fn get_redirect_checked(
        &self,
        url: &str,
        max_bytes: u64,
        allow: &dyn Fn(&str) -> Result<()>,
    ) -> Result<Vec<u8>> {
        self.get_with_redirect_policy(url, max_bytes, allow)
    }
}
