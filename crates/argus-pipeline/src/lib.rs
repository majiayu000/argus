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
use argus_core::{Ecosystem, ExecutionContext, ScanReport};
use argus_rules::RuleSession;
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
        rules: &RuleSession,
    ) -> Result<ScanReport>;

    /// Run through one invocation-local worker pool supplied by the caller.
    fn fetch_and_scan_with_context(
        &self,
        spec: &str,
        opts: &CommonFetchOptions,
        transport: &dyn Transport,
        rules: &RuleSession,
        _execution: &ExecutionContext,
    ) -> Result<ScanReport> {
        self.fetch_and_scan(spec, opts, transport, rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::{ArtifactKind, Decision, ScanConcurrency};
    use std::sync::Mutex;

    struct NoNetwork;

    impl Transport for NoNetwork {
        fn get(&self, _url: &str, _max_bytes: u64) -> Result<Vec<u8>> {
            unreachable!("routing test performs no network work")
        }
    }

    struct Probe(Mutex<Vec<usize>>);

    impl EcosystemFetcher for Probe {
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::Npm
        }

        fn default_registry(&self) -> &'static str {
            "https://example.test"
        }

        fn fetch_and_scan(
            &self,
            spec: &str,
            opts: &CommonFetchOptions,
            transport: &dyn Transport,
            rules: &RuleSession,
        ) -> Result<ScanReport> {
            let execution = ExecutionContext::serial()?;
            self.fetch_and_scan_with_context(spec, opts, transport, rules, &execution)
        }

        fn fetch_and_scan_with_context(
            &self,
            _spec: &str,
            _opts: &CommonFetchOptions,
            _transport: &dyn Transport,
            _rules: &RuleSession,
            execution: &ExecutionContext,
        ) -> Result<ScanReport> {
            self.0.lock().unwrap().push(execution.concurrency().get());
            Ok(ScanReport {
                artifact: ArtifactKind::PackageDir,
                path: "probe".into(),
                package_name: None,
                package_version: None,
                decision: Decision::Allow,
                findings: Vec::new(),
                coordinate: None,
                intelligence: None,
                rules: None,
                vulnerability: None,
                risk: None,
            })
        }
    }

    #[test]
    fn trait_routes_explicit_context_and_legacy_serial_wrapper() {
        let probe = Probe(Mutex::new(Vec::new()));
        let options = CommonFetchOptions {
            registry: probe.default_registry().to_string(),
            cache_dir: None,
        };
        let rules = RuleSession::builtin().unwrap();
        let execution = ExecutionContext::new(ScanConcurrency::new(64).unwrap()).unwrap();
        probe
            .fetch_and_scan_with_context("demo", &options, &NoNetwork, &rules, &execution)
            .unwrap();
        probe
            .fetch_and_scan("demo", &options, &NoNetwork, &rules)
            .unwrap();
        assert_eq!(*probe.0.lock().unwrap(), [64, 1]);
    }
}
