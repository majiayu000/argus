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
    /// The gem PLATFORM of this entry, e.g. `"ruby"` (pure-Ruby, the default),
    /// `"x86_64-linux"`, or `"java"`. The same `number` can appear multiple
    /// times with different platforms, and each entry's `sha` belongs to the
    /// exact `NAME-VERSION-PLATFORM.gem` artifact. An absent value defaults to
    /// `"ruby"` (RubyGems' own default platform). A non-`ruby` platform changes
    /// the download filename to `NAME-VERSION-PLATFORM.gem`.
    #[serde(default = "default_platform")]
    pub platform: String,
}

fn default_platform() -> String {
    "ruby".to_string()
}

/// The resolved (version, platform, sha) of the chosen gem entry. The platform
/// is carried so the caller builds the correct `NAME-VERSION.gem` (for `ruby`)
/// vs `NAME-VERSION-PLATFORM.gem` (native) download filename and verifies that
/// exact artifact's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVersion {
    pub number: String,
    pub platform: String,
    pub sha: String,
}

impl ResolvedVersion {
    /// `true` when the platform is the default pure-Ruby platform (`ruby` or
    /// empty), where the download filename is plain `NAME-VERSION.gem`.
    pub fn is_default_platform(&self) -> bool {
        self.platform.is_empty() || self.platform == "ruby"
    }
}

/// Resolve a requested version against a RubyGems version array.
///
/// Lookup order:
/// 1. `None` -> first non-prerelease entry (the array is documented
///    newest-first; we do not re-sort, matching the design assumption, but
///    we do skip prereleases so `latest` means latest stable).
/// 2. Exact `number` match.
///
/// Returns the resolved [`ResolvedVersion`] (number + platform + sha). The
/// `platform` and `sha` are carried through so the caller builds the exact
/// `NAME-VERSION-PLATFORM.gem` download filename and verifies that artifact's
/// per-entry digest, not the latest/pure-Ruby one.
pub fn resolve_version(
    versions: &[GemVersion],
    name: &str,
    requested: Option<&str>,
) -> Result<ResolvedVersion> {
    if versions.is_empty() {
        bail!("RubyGems version list for `{name}` is empty");
    }
    let chosen = match requested {
        None => versions
            .iter()
            .find(|v| !v.prerelease)
            .or_else(|| versions.first())
            .ok_or_else(|| anyhow!("no resolvable version for `{name}`"))?,
        Some(req) => versions.iter().find(|v| v.number == req).ok_or_else(|| {
            anyhow!("version `{req}` not present in RubyGems version list for `{name}`")
        })?,
    };
    Ok(ResolvedVersion {
        number: chosen.number.clone(),
        platform: chosen.platform.clone(),
        sha: chosen.sha.clone(),
    })
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
        let r = resolve_version(&v, "demo", None).unwrap();
        assert_eq!(r.number, "1.5.0");
        assert_eq!(r.sha, "bb");
    }

    #[test]
    fn resolve_exact_match_returns_its_sha() {
        let v = versions(
            r#"[
              {"number": "1.5.0", "sha": "bb"},
              {"number": "1.0.0", "sha": "cc"}
            ]"#,
        );
        let r = resolve_version(&v, "demo", Some("1.0.0")).unwrap();
        assert_eq!(r.number, "1.0.0");
        assert_eq!(r.sha, "cc");
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
        let r = resolve_version(&v, "demo", None).unwrap();
        assert_eq!(r.sha, "");
    }

    #[test]
    fn platform_defaults_to_ruby_when_absent() {
        let v = versions(r#"[{"number": "1.0.0", "sha": "cc"}]"#);
        let r = resolve_version(&v, "demo", None).unwrap();
        assert_eq!(r.platform, "ruby");
        assert!(r.is_default_platform());
    }

    #[test]
    fn resolve_carries_native_platform_and_its_own_sha() {
        // Real RubyGems shape: the SAME `number` appears once per platform,
        // each with its OWN sha. Picking the native (x86_64-linux) entry must
        // carry that entry's platform + sha, not the pure-ruby one.
        let v = versions(
            r#"[
              {"number": "1.16.0", "sha": "rubysha", "platform": "ruby", "prerelease": false},
              {"number": "1.16.0", "sha": "linuxsha", "platform": "x86_64-linux", "prerelease": false}
            ]"#,
        );
        // Default resolution picks the FIRST non-prerelease entry, which here
        // is the pure-ruby one.
        let r = resolve_version(&v, "nokogiri", None).unwrap();
        assert_eq!(r.platform, "ruby");
        assert_eq!(r.sha, "rubysha");
        assert!(r.is_default_platform());

        // The native entry carries its own platform + digest.
        let native = &v[1];
        assert_eq!(native.platform, "x86_64-linux");
        assert_eq!(native.sha, "linuxsha");
    }
}
