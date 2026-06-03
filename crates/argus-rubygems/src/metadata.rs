//! RubyGems v1 JSON-API parsing.
//!
//! The shapes we care about are documented at
//! <https://guides.rubygems.org/rubygems-org-api/>.
//!
//! ASSUMPTION (flagged in the design's risk section — NOT re-verified live
//! this session): the per-version `sha` field on
//! `/api/v1/versions/<name>.json` entries carries the hex SHA-256 of that
//! version's `.gem` file, each entry has `number` (the version string) and
//! `prerelease` (bool), and the array is newest-first. If the field name or
//! ordering differs, the integrity gate hard-fails (verify_sha256_hex bails
//! on empty hex) rather than silently passing -- the correct failure mode per
//! U-29.
//!
//! We only deserialize the fields argus needs; unknown fields are dropped.

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;

/// One entry in the `/api/v1/versions/<name>.json` array.
#[derive(Debug, Clone, Deserialize)]
pub struct GemVersion {
    /// The version string, e.g. `"1.2.3"`.
    pub number: String,
    /// Hex-encoded SHA-256 of that version's `.gem` artifact bytes. The only
    /// digest argus verifies. An absent/empty value is a hard error at
    /// verification time (U-29), never a silent skip.
    #[serde(default)]
    pub sha: String,
    /// RubyGems marks pre-release versions (`1.0.0.rc1`, etc.) with this flag.
    #[serde(default)]
    pub prerelease: bool,
}

/// Resolve a requested version against a RubyGems version array.
///
/// Lookup order:
/// 1. `None` -> first non-prerelease entry (the array is documented
///    newest-first; we do not re-sort, matching the design assumption, but
///    we do skip prereleases so `latest` means latest stable).
/// 2. Exact `number` match.
///
/// Returns the resolved `(version, sha)` pair. The `sha` is carried through
/// so the caller verifies the exact per-version digest, not the latest one.
pub fn resolve_version(
    versions: &[GemVersion],
    name: &str,
    requested: Option<&str>,
) -> Result<(String, String)> {
    if versions.is_empty() {
        bail!("RubyGems version list for `{name}` is empty");
    }
    match requested {
        None => {
            let chosen = versions
                .iter()
                .find(|v| !v.prerelease)
                .or_else(|| versions.first())
                .ok_or_else(|| anyhow!("no resolvable version for `{name}`"))?;
            Ok((chosen.number.clone(), chosen.sha.clone()))
        }
        Some(req) => {
            let chosen = versions.iter().find(|v| v.number == req).ok_or_else(|| {
                anyhow!("version `{req}` not present in RubyGems version list for `{name}`")
            })?;
            Ok((chosen.number.clone(), chosen.sha.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions(json: &str) -> Vec<GemVersion> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn resolve_default_picks_first_non_prerelease() {
        let v = versions(
            r#"[
              {"number": "2.0.0.rc1", "sha": "aa", "prerelease": true},
              {"number": "1.5.0", "sha": "bb", "prerelease": false},
              {"number": "1.0.0", "sha": "cc", "prerelease": false}
            ]"#,
        );
        let (ver, sha) = resolve_version(&v, "demo", None).unwrap();
        assert_eq!(ver, "1.5.0");
        assert_eq!(sha, "bb");
    }

    #[test]
    fn resolve_exact_match_returns_its_sha() {
        let v = versions(
            r#"[
              {"number": "1.5.0", "sha": "bb"},
              {"number": "1.0.0", "sha": "cc"}
            ]"#,
        );
        let (ver, sha) = resolve_version(&v, "demo", Some("1.0.0")).unwrap();
        assert_eq!(ver, "1.0.0");
        assert_eq!(sha, "cc");
    }

    #[test]
    fn resolve_unknown_errors_with_version() {
        let v = versions(r#"[{"number": "1.0.0", "sha": "cc"}]"#);
        let e = resolve_version(&v, "demo", Some("9.9.9"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("9.9.9"), "got: {e}");
    }

    #[test]
    fn resolve_empty_errors() {
        let v: Vec<GemVersion> = Vec::new();
        assert!(resolve_version(&v, "demo", None).is_err());
    }

    #[test]
    fn missing_sha_defaults_to_empty() {
        let v = versions(r#"[{"number": "1.0.0"}]"#);
        let (_, sha) = resolve_version(&v, "demo", None).unwrap();
        assert_eq!(sha, "");
    }
}
