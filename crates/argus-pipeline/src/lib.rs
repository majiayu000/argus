//! The shared entry point every argus ecosystem scanner implements.
//!
//! Before this trait existed the CLI carried seven verbatim-identical
//! `cmd_*_fetch` handlers because the ecosystem crates exported parallel
//! but unrelated types (`XRef::parse` / `XFetchOptions` /
//! `fetch_and_scan_x`) with no common interface (#132). Implementations
//! wrap their existing pipeline; the trait deliberately stays thin — it
//! standardizes the *entry point*, not the per-ecosystem internals.
//!
//! Mirrors the pattern proven by `argus-lockfile`'s `LockfileParser`.

use anyhow::Result;
use argus_core::{Ecosystem, ScanReport};
use argus_transport::Transport;
use std::path::PathBuf;

/// Options shared by every ecosystem fetch. Ecosystem-specific knobs (npm
/// Sigstore verification, PyPI artifact preference, ...) stay on the
/// concrete crate's own options and are reachable through its native API.
#[derive(Debug, Clone)]
pub struct CommonFetchOptions {
    /// Registry base URL. Use [`EcosystemFetcher::default_registry`] when
    /// the caller did not override it.
    pub registry: String,
    /// Parent directory for the extraction scratch dir; `None` uses a
    /// private temp dir.
    pub cache_dir: Option<PathBuf>,
}

/// One package ecosystem's fetch-verify-extract-scan pipeline.
///
/// Contract (identical across implementations): resolve `spec` against the
/// registry, download the artifact, verify its integrity digest (hard error
/// on mismatch; explicit finding when no digest exists), safe-extract, run
/// static rules, and return a report whose `path` is the registry
/// coordinate. Nothing inside the artifact is ever executed.
pub trait EcosystemFetcher {
    fn ecosystem(&self) -> Ecosystem;
    /// Default registry base URL (e.g. `https://pypi.org`).
    fn default_registry(&self) -> &'static str;
    /// Parse `spec` (`name`, `name@version`, or the ecosystem's native
    /// coordinate syntax) and run the full pipeline.
    fn fetch_and_scan(
        &self,
        spec: &str,
        opts: &CommonFetchOptions,
        transport: &dyn Transport,
    ) -> Result<ScanReport>;
}
