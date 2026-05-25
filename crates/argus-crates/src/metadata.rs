//! crates.io JSON API parsing.
//!
//! The shape we care about: `crate` + `versions[]`. Each version carries
//! `num` (semver string), `dl_path` (relative download path), `checksum`
//! (hex SHA-256), and `yanked`. Everything else is dropped silently.

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct CratesPackument {
    #[serde(rename = "crate")]
    pub crate_meta: CrateMeta,
    pub versions: Vec<CrateVersion>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CrateMeta {
    pub name: String,
    #[serde(default)]
    pub max_stable_version: Option<String>,
    #[serde(default)]
    pub max_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CrateVersion {
    pub num: String,
    pub dl_path: String,
    pub checksum: String,
    #[serde(default)]
    pub yanked: bool,
}

/// Resolve a user-supplied version against the packument.
///
/// Lookup order:
/// 1. `None` → `crate.max_stable_version` if present, else `max_version`,
///    else the first non-yanked version in the list.
/// 2. Exact match in `versions[].num`.
pub fn resolve_version(packument: &CratesPackument, requested: Option<&str>) -> Result<String> {
    match requested {
        None => {
            if let Some(v) = packument
                .crate_meta
                .max_stable_version
                .as_deref()
                .or(packument.crate_meta.max_version.as_deref())
            {
                if !v.is_empty() {
                    return Ok(v.to_string());
                }
            }
            let v = packument
                .versions
                .iter()
                .find(|v| !v.yanked)
                .ok_or_else(|| {
                    anyhow!(
                        "crates.io packument for `{}` has no non-yanked versions",
                        packument.crate_meta.name
                    )
                })?;
            Ok(v.num.clone())
        }
        Some(v) => {
            if packument.versions.iter().any(|x| x.num == v) {
                Ok(v.to_string())
            } else {
                bail!(
                    "version `{v}` not present in crates.io packument for `{}`",
                    packument.crate_meta.name
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(json: &str) -> CratesPackument {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn resolve_default_prefers_max_stable() {
        let p = pkg(r#"{
              "crate": {"name": "demo", "max_stable_version": "1.2.3", "max_version": "2.0.0-beta"},
              "versions": [
                {"num": "1.2.3", "dl_path": "/dl/demo/1.2.3", "checksum": "aaaa"},
                {"num": "2.0.0-beta", "dl_path": "/dl/demo/2.0.0-beta", "checksum": "bbbb"}
              ]
            }"#);
        assert_eq!(resolve_version(&p, None).unwrap(), "1.2.3");
    }

    #[test]
    fn resolve_default_falls_back_to_max_version() {
        let p = pkg(r#"{
              "crate": {"name": "demo", "max_version": "0.9.0"},
              "versions": [
                {"num": "0.9.0", "dl_path": "/dl/demo/0.9.0", "checksum": "aaaa"}
              ]
            }"#);
        assert_eq!(resolve_version(&p, None).unwrap(), "0.9.0");
    }

    #[test]
    fn resolve_exact() {
        let p = pkg(r#"{
              "crate": {"name": "demo", "max_stable_version": "2.0.0"},
              "versions": [
                {"num": "1.0.0", "dl_path": "/dl/demo/1.0.0", "checksum": "aaaa"},
                {"num": "2.0.0", "dl_path": "/dl/demo/2.0.0", "checksum": "bbbb"}
              ]
            }"#);
        assert_eq!(resolve_version(&p, Some("1.0.0")).unwrap(), "1.0.0");
    }

    #[test]
    fn resolve_unknown_errors() {
        let p = pkg(r#"{
              "crate": {"name": "demo", "max_stable_version": "1.0.0"},
              "versions": [
                {"num": "1.0.0", "dl_path": "/dl/demo/1.0.0", "checksum": "aaaa"}
              ]
            }"#);
        assert!(resolve_version(&p, Some("9.9.9")).is_err());
    }
}
