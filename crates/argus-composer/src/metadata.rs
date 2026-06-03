//! Packagist p2 metadata structures and version resolution.

use anyhow::{bail, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

/// A parsed `vendor/package[@version]` specifier from the CLI.
#[derive(Debug, Clone)]
pub struct ComposerRef {
    pub vendor: String,
    pub package: String,
    pub version: Option<String>,
}

impl ComposerRef {
    /// Parse `vendor/package` or `vendor/package@version`.
    ///
    /// Splits on the LAST `@` so `vendor/pkg@dev-main` works correctly.
    /// Requires exactly one `/` separating vendor from package name.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty Composer package spec");
        }

        // Split version off the LAST `@`.
        let (name_part, version) = match spec.rsplit_once('@') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (spec, None),
        };

        // Validate that version is non-empty when present.
        if let Some(ref v) = version {
            if v.is_empty() {
                bail!("empty version after `@` in Composer spec: {spec}");
            }
        }

        // Split vendor/package.
        let (vendor, package) = match name_part.split_once('/') {
            Some((v, p)) => (v, p),
            None => bail!("Composer package spec must be `vendor/package[@version]`, got: {spec}"),
        };

        if vendor.is_empty() {
            bail!("empty vendor in Composer spec: {spec}");
        }
        if package.is_empty() {
            bail!("empty package name in Composer spec: {spec}");
        }

        Ok(ComposerRef {
            vendor: vendor.to_string(),
            package: package.to_string(),
            version,
        })
    }
}

/// A single dist block inside a p2 version object.
#[derive(Debug, Clone, Deserialize)]
pub struct ComposerDist {
    #[serde(rename = "type")]
    pub dist_type: Option<String>,
    pub url: Option<String>,
    pub reference: Option<String>,
    pub shasum: Option<String>,
}

/// A single version entry in the p2 metadata array.
#[derive(Debug, Clone, Deserialize)]
pub struct ComposerVersionObj {
    pub version: String,
    pub version_normalized: Option<String>,
    pub dist: Option<ComposerDist>,
    /// Inline scripts from registry metadata (may duplicate composer.json).
    #[serde(default)]
    pub scripts: Option<BTreeMap<String, ScriptValue>>,
}

/// A script value can be a single string or an array of strings.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ScriptValue {
    One(String),
    Many(Vec<String>),
}

impl ScriptValue {
    /// Flatten to an iterator of command strings.
    pub fn commands(&self) -> Vec<&str> {
        match self {
            ScriptValue::One(s) => vec![s.as_str()],
            ScriptValue::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

/// Autoload section (we only care about `files`).
#[derive(Debug, Clone, Deserialize)]
pub struct ComposerAutoload {
    #[serde(default)]
    pub files: Vec<String>,
}

/// The top-level p2 metadata response.
///
/// Shape: `{"packages": {"vendor/name": [ <version-object>, ... ]}}`
/// Unknown fields are dropped silently.
#[derive(Debug, Deserialize)]
pub struct ComposerPackument {
    pub packages: BTreeMap<String, Vec<ComposerVersionObj>>,
}

/// Resolve the version to use from the packument.
///
/// - `requested=None` → first entry whose `version` does NOT start with `dev-`
///   (p2 lists newest-first per Composer docs).
/// - `requested=Some(v)` → exact match on `version` field.
pub fn resolve_version<'a>(
    packument: &'a ComposerPackument,
    full_name: &str,
    requested: Option<&str>,
) -> Result<&'a ComposerVersionObj> {
    let versions = packument.packages.get(full_name).ok_or_else(|| {
        anyhow::anyhow!(
            "package `{full_name}` not found in p2 metadata (got keys: {:?})",
            packument.packages.keys().collect::<Vec<_>>()
        )
    })?;

    if versions.is_empty() {
        bail!("no versions available for {full_name}");
    }

    match requested {
        None => {
            // Pick first stable (non-dev) version.
            versions
                .iter()
                .find(|v| !v.version.starts_with("dev-"))
                .ok_or_else(|| {
                    anyhow::anyhow!("no stable version found for {full_name} (all are dev-*)")
                })
        }
        Some(req) => versions.iter().find(|v| v.version == req).ok_or_else(|| {
            anyhow::anyhow!("version `{req}` not found for {full_name} in p2 metadata")
        }),
    }
}

/// The `composer.json` manifest struct (parsed from within the extracted ZIP).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ComposerManifest {
    pub name: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub scripts: Option<BTreeMap<String, ScriptValue>>,
    pub autoload: Option<ComposerAutoload>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain() {
        let r = ComposerRef::parse("guzzlehttp/guzzle").unwrap();
        assert_eq!(r.vendor, "guzzlehttp");
        assert_eq!(r.package, "guzzle");
        assert_eq!(r.version, None);
    }

    #[test]
    fn parse_with_semver() {
        let r = ComposerRef::parse("guzzlehttp/guzzle@7.8.1").unwrap();
        assert_eq!(r.version.as_deref(), Some("7.8.1"));
    }

    #[test]
    fn parse_dev_version() {
        let r = ComposerRef::parse("vendor/pkg@dev-main").unwrap();
        assert_eq!(r.version.as_deref(), Some("dev-main"));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(ComposerRef::parse("").is_err());
    }

    #[test]
    fn parse_rejects_no_slash() {
        assert!(ComposerRef::parse("nodash").is_err());
    }

    #[test]
    fn parse_rejects_empty_vendor() {
        assert!(ComposerRef::parse("/package").is_err());
    }

    #[test]
    fn parse_rejects_empty_package() {
        assert!(ComposerRef::parse("vendor/").is_err());
    }

    #[test]
    fn resolve_latest_skips_dev() {
        let packument = serde_json::from_str::<ComposerPackument>(
            r#"{
            "packages": {
                "foo/bar": [
                    {"version": "2.0.0", "version_normalized": "2.0.0.0"},
                    {"version": "dev-main", "version_normalized": "dev-main"}
                ]
            }
        }"#,
        )
        .unwrap();
        let v = resolve_version(&packument, "foo/bar", None).unwrap();
        assert_eq!(v.version, "2.0.0");
    }

    #[test]
    fn resolve_exact_version() {
        let packument = serde_json::from_str::<ComposerPackument>(
            r#"{
            "packages": {
                "foo/bar": [
                    {"version": "2.0.0"},
                    {"version": "1.5.0"}
                ]
            }
        }"#,
        )
        .unwrap();
        let v = resolve_version(&packument, "foo/bar", Some("1.5.0")).unwrap();
        assert_eq!(v.version, "1.5.0");
    }

    #[test]
    fn resolve_unknown_version_errors() {
        let packument = serde_json::from_str::<ComposerPackument>(
            r#"{
            "packages": {
                "foo/bar": [{"version": "1.0.0"}]
            }
        }"#,
        )
        .unwrap();
        assert!(resolve_version(&packument, "foo/bar", Some("9.9.9")).is_err());
    }

    #[test]
    fn resolve_missing_package_errors() {
        let packument = serde_json::from_str::<ComposerPackument>(
            r#"{
            "packages": {}
        }"#,
        )
        .unwrap();
        assert!(resolve_version(&packument, "foo/bar", None).is_err());
    }

    #[test]
    fn script_value_one() {
        let sv = ScriptValue::One("composer install".to_string());
        assert_eq!(sv.commands(), vec!["composer install"]);
    }

    #[test]
    fn script_value_many() {
        let sv = ScriptValue::Many(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(sv.commands(), vec!["a", "b"]);
    }
}
