//! npm packument parsing + version resolution.
//!
//! We deserialize only the fields argus actually needs: `dist-tags` for tag
//! lookup, `versions[<v>].dist` for the tarball URL and SSRI string. The
//! full packument has many more fields (maintainers, time, etc.) — we let
//! serde drop them with `#[serde(deny_unknown_fields)]` deliberately off.

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Packument {
    pub name: String,
    #[serde(default, rename = "dist-tags")]
    pub dist_tags: BTreeMap<String, String>,
    #[serde(default)]
    pub versions: BTreeMap<String, PackumentVersion>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackumentVersion {
    pub dist: Dist,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Dist {
    /// HTTPS URL to the `.tgz` blob on the registry.
    pub tarball: String,
    /// SSRI string, e.g. `sha512-base64hash` (may carry multiple
    /// space-separated entries — we accept any one that matches).
    pub integrity: String,
}

/// Resolve a user-supplied version reference against a packument.
///
/// Lookup order:
/// 1. `None` → `dist-tags.latest`.
/// 2. Exact match in `versions`.
/// 3. Lookup as a dist-tag.
pub fn resolve_version(packument: &Packument, requested: Option<&str>) -> Result<String> {
    match requested {
        None => packument
            .dist_tags
            .get("latest")
            .cloned()
            .ok_or_else(|| anyhow!("packument has no `latest` dist-tag")),
        Some(v) => {
            if packument.versions.contains_key(v) {
                return Ok(v.to_string());
            }
            if let Some(resolved) = packument.dist_tags.get(v) {
                return Ok(resolved.clone());
            }
            bail!(
                "requested version `{v}` is neither a published version nor a dist-tag of {}",
                packument.name
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(json: &str) -> Packument {
        serde_json::from_str(json).expect("parse packument")
    }

    #[test]
    fn latest_dist_tag_is_default() {
        let pkg = sample(
            r#"{
              "name": "demo",
              "dist-tags": {"latest": "1.2.3"},
              "versions": {
                "1.2.3": {"dist": {"tarball": "https://x/y.tgz", "integrity": "sha512-AAA"}}
              }
            }"#,
        );
        assert_eq!(resolve_version(&pkg, None).unwrap(), "1.2.3");
    }

    #[test]
    fn exact_version_resolves() {
        let pkg = sample(
            r#"{
              "name": "demo",
              "dist-tags": {"latest": "2.0.0"},
              "versions": {
                "1.0.0": {"dist": {"tarball": "https://x/a.tgz", "integrity": "sha512-AAA"}},
                "2.0.0": {"dist": {"tarball": "https://x/b.tgz", "integrity": "sha512-BBB"}}
              }
            }"#,
        );
        assert_eq!(resolve_version(&pkg, Some("1.0.0")).unwrap(), "1.0.0");
    }

    #[test]
    fn unknown_version_errors() {
        let pkg = sample(
            r#"{
              "name": "demo",
              "dist-tags": {"latest": "1.0.0"},
              "versions": {
                "1.0.0": {"dist": {"tarball": "https://x/a.tgz", "integrity": "sha512-A"}}
              }
            }"#,
        );
        let e = resolve_version(&pkg, Some("9.9.9"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("9.9.9"), "actual: {e}");
    }

    #[test]
    fn dist_tag_resolves() {
        let pkg = sample(
            r#"{
              "name": "demo",
              "dist-tags": {"latest": "1.0.0", "beta": "1.1.0-beta.1"},
              "versions": {
                "1.0.0": {"dist": {"tarball": "https://x/a.tgz", "integrity": "sha512-A"}},
                "1.1.0-beta.1": {"dist": {"tarball": "https://x/b.tgz", "integrity": "sha512-B"}}
              }
            }"#,
        );
        assert_eq!(resolve_version(&pkg, Some("beta")).unwrap(), "1.1.0-beta.1");
    }
}
