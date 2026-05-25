//! PyPI JSON-API parsing.
//!
//! The shape we care about is documented at
//! <https://warehouse.pypa.io/api-reference/json.html>.
//!
//! We only deserialize the fields argus needs: `info.version` for the
//! `latest` shortcut, and `releases[version][]` for the per-version
//! artifact list. Unknown fields are dropped silently — the full
//! packument carries large prose fields we never touch.

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct PypiPackument {
    pub info: PypiInfo,
    #[serde(default)]
    pub releases: BTreeMap<String, Vec<PypiUrl>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PypiInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PypiUrl {
    pub filename: String,
    pub url: String,
    /// `"sdist"`, `"bdist_wheel"`, occasionally `"bdist_egg"`.
    pub packagetype: String,
    pub digests: PypiDigests,
    /// PyPI marks a release as yanked when the maintainer has retracted it.
    #[serde(default)]
    pub yanked: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PypiDigests {
    /// Hex-encoded SHA-256 of the artifact bytes. The only digest we
    /// actually verify; PyPI also publishes MD5 but that hash is broken
    /// and we explicitly refuse to depend on it.
    pub sha256: String,
}

/// Resolve a user-supplied version string against a PyPI packument.
///
/// Lookup order:
/// 1. `None` → `info.version` (PyPI's notion of "latest non-pre-release").
/// 2. Exact match in `releases`.
pub fn resolve_version(packument: &PypiPackument, requested: Option<&str>) -> Result<String> {
    match requested {
        None => {
            let v = packument.info.version.trim();
            if v.is_empty() {
                bail!(
                    "PyPI packument has no `info.version` for {}",
                    packument.info.name
                );
            }
            Ok(v.to_string())
        }
        Some(v) => {
            if packument.releases.contains_key(v) {
                Ok(v.to_string())
            } else {
                Err(anyhow!(
                    "version `{v}` not present in PyPI packument for {}",
                    packument.info.name
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(json: &str) -> PypiPackument {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn resolve_default_returns_info_version() {
        let p = pkg(r#"{
              "info": {"name": "demo", "version": "1.2.3"},
              "releases": {
                "1.2.3": [{"filename": "demo-1.2.3.tar.gz", "url": "https://x", "packagetype": "sdist", "digests": {"sha256": "deadbeef"}}]
              }
            }"#);
        assert_eq!(resolve_version(&p, None).unwrap(), "1.2.3");
    }

    #[test]
    fn resolve_exact() {
        let p = pkg(r#"{
              "info": {"name": "demo", "version": "2.0.0"},
              "releases": {
                "1.0.0": [{"filename": "demo-1.0.0.tar.gz", "url": "https://x", "packagetype": "sdist", "digests": {"sha256": "a"}}],
                "2.0.0": [{"filename": "demo-2.0.0.tar.gz", "url": "https://y", "packagetype": "sdist", "digests": {"sha256": "b"}}]
              }
            }"#);
        assert_eq!(resolve_version(&p, Some("1.0.0")).unwrap(), "1.0.0");
    }

    #[test]
    fn resolve_unknown_errors() {
        let p = pkg(r#"{
              "info": {"name": "demo", "version": "1.0.0"},
              "releases": {"1.0.0": []}
            }"#);
        let e = resolve_version(&p, Some("9.9.9")).unwrap_err().to_string();
        assert!(e.contains("9.9.9"));
    }

    #[test]
    fn yanked_release_still_parses() {
        let p = pkg(r#"{
              "info": {"name": "demo", "version": "1.0.0"},
              "releases": {
                "1.0.0": [{"filename": "demo-1.0.0.tar.gz", "url": "https://x", "packagetype": "sdist", "digests": {"sha256": "a"}, "yanked": true}]
              }
            }"#);
        let r = &p.releases["1.0.0"][0];
        assert!(r.yanked);
    }
}
