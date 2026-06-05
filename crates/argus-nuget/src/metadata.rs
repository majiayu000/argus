//! NuGet v3 registry parsing + version resolution + SHA-512 integrity.
//!
//! The standard NuGet v3 install path uses two JSON shapes:
//!
//! - **flat container** `index.json`: `{"versions": ["1.0.0", ...]}` — the
//!   list of available versions. There is NO hash or size here.
//! - **registration leaf**: a `catalogEntry` object whose `@id` URL points
//!   at the **catalog leaf**, which is the ONLY document that carries
//!   `packageHash` + `packageHashAlgorithm`. That document is not on the
//!   normal download path, so content-digest verification is best-effort
//!   and may be unavailable — see [`crate`] docs and the `nuget-integrity-*`
//!   rules for the U-29 disclosure.
//!
//! No registry value is ever trusted to mutate the filesystem; the download
//! URL argus uses is constructed locally and validated before transport.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

/// Flat-container `index.json`: just the versions array.
#[derive(Debug, Clone, Deserialize)]
pub struct FlatContainerIndex {
    #[serde(default)]
    pub versions: Vec<String>,
}

/// Registration leaf document. We only care about the embedded
/// `catalogEntry`, which carries the catalog leaf URL.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationLeaf {
    #[serde(rename = "catalogEntry")]
    pub catalog_entry: CatalogEntryRef,
}

/// The `catalogEntry` field inside a registration leaf, which resolves to the
/// catalog leaf document (a separate fetch).
///
/// On real nuget.org registration leaves this field appears in BOTH shapes:
/// - a bare string URL: `"catalogEntry": "https://.../leaf.json"`, and
/// - an expanded object: `"catalogEntry": { "@id": "https://.../leaf.json" }`.
///
/// We accept either (untagged) and resolve both to the catalog URL via
/// [`CatalogEntryRef::catalog_url`]. Requiring only the object shape would
/// fail deserialization on common real data, silently disabling integrity
/// verification (U-29).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum CatalogEntryRef {
    /// `"catalogEntry": "https://.../leaf.json"`
    Url(String),
    /// `"catalogEntry": { "@id": "https://.../leaf.json" }`
    Object {
        #[serde(rename = "@id")]
        id: String,
    },
}

impl CatalogEntryRef {
    /// The catalog leaf URL, regardless of which shape was deserialized.
    pub fn catalog_url(&self) -> &str {
        match self {
            CatalogEntryRef::Url(u) => u,
            CatalogEntryRef::Object { id } => id,
        }
    }
}

/// Catalog leaf document. This is the ONLY place `packageHash` lives.
#[derive(Debug, Clone, Deserialize)]
pub struct CatalogLeaf {
    #[serde(rename = "packageHash", default)]
    pub package_hash: Option<String>,
    #[serde(rename = "packageHashAlgorithm", default)]
    pub package_hash_algorithm: Option<String>,
}

/// Resolve a requested version against the flat-container version list.
///
/// - `requested == None` → the highest non-prerelease version. A version is
///   considered prerelease when its string contains a `-` suffix (SemVer
///   prerelease marker). If every version is prerelease, the last entry in
///   the array is taken (the flat container lists oldest-first).
/// - `requested == Some(v)` → case-insensitive, normalized exact match
///   against the published list.
///
/// HONEST GAP: this is a heuristic, not a full SemVer 2.0.0 comparator;
/// for purely-numeric versions it is correct, but exotic prerelease
/// ordering may mis-rank. See crate docs.
pub fn resolve_version(index: &FlatContainerIndex, requested: Option<&str>) -> Result<String> {
    if index.versions.is_empty() {
        bail!("NuGet flat-container index has no versions");
    }
    match requested {
        None => {
            let stable: Vec<&String> = index
                .versions
                .iter()
                .filter(|v| !is_prerelease(v))
                .collect();
            if let Some(best) = stable.iter().max_by(|a, b| compare_versions(a, b)) {
                Ok((**best).clone())
            } else {
                // All prerelease — take the last published entry.
                Ok(index
                    .versions
                    .last()
                    .expect("non-empty checked above")
                    .clone())
            }
        }
        Some(v) => {
            let want = normalize_version(v);
            index
                .versions
                .iter()
                .find(|published| normalize_version(published) == want)
                .cloned()
                .ok_or_else(|| anyhow!("version `{v}` not present in NuGet flat-container index"))
        }
    }
}

/// A NuGet version is prerelease when it carries a `-<label>` suffix.
fn is_prerelease(version: &str) -> bool {
    // Drop build metadata first so `1.0.0+build` is not seen as prerelease.
    let core = version.split('+').next().unwrap_or(version);
    core.contains('-')
}

/// Minimal NuGet version normalization for v1: lowercase + strip `+build`
/// metadata. Full NuGet equivalence (1.0 == 1.0.0.0, leading-zero
/// stripping) is NOT implemented — documented gap.
pub fn normalize_version(version: &str) -> String {
    let no_build = version.split('+').next().unwrap_or(version);
    no_build.trim().to_ascii_lowercase()
}

/// Compare two version strings numerically segment-by-segment on the
/// release core (digits split by `.`), falling back to lexical ordering
/// for non-numeric segments.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let core = |v: &str| -> String {
        v.split('+')
            .next()
            .unwrap_or(v)
            .split('-')
            .next()
            .unwrap_or(v)
            .to_string()
    };
    let (ca, cb) = (core(a), core(b));
    let mut sa = ca.split('.');
    let mut sb = cb.split('.');
    loop {
        match (sa.next(), sb.next()) {
            (None, None) => return Ordering::Equal,
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(nx), Ok(ny)) => nx.cmp(&ny),
                    _ => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// Verify the SHA-512 digest of `bytes` against a base64-encoded
/// `expected_b64` (the NuGet catalog `packageHash` encoding) in constant
/// time. An empty hash is a hard error — callers must never pass a
/// fabricated/absent digest (U-29).
pub fn verify_sha512_b64(bytes: &[u8], expected_b64: &str) -> Result<()> {
    if expected_b64.trim().is_empty() {
        bail!("expected SHA-512 is empty — catalog did not advertise packageHash");
    }
    let expected = STANDARD
        .decode(expected_b64.trim())
        .with_context(|| format!("decode expected SHA-512 base64 `{expected_b64}`"))?;
    let actual = Sha512::digest(bytes);
    if bool::from(actual.as_slice().ct_eq(&expected)) {
        Ok(())
    } else {
        Err(anyhow!(
            "SHA-512 mismatch for {} downloaded bytes (expected `{expected_b64}`)",
            bytes.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(versions: &[&str]) -> FlatContainerIndex {
        FlatContainerIndex {
            versions: versions.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn resolve_none_picks_highest_non_prerelease() {
        let index = idx(&["1.0.0", "2.0.0-beta", "1.5.0"]);
        assert_eq!(resolve_version(&index, None).unwrap(), "1.5.0");
    }

    #[test]
    fn resolve_some_exact_case_insensitive() {
        let index = idx(&["1.0.0", "2.0.0-Beta", "1.5.0"]);
        assert_eq!(
            resolve_version(&index, Some("2.0.0-beta")).unwrap(),
            "2.0.0-Beta"
        );
    }

    #[test]
    fn resolve_unknown_errors() {
        let index = idx(&["1.0.0"]);
        assert!(resolve_version(&index, Some("9.9.9")).is_err());
    }

    #[test]
    fn resolve_all_prerelease_takes_last() {
        let index = idx(&["1.0.0-a", "1.0.0-b"]);
        assert_eq!(resolve_version(&index, None).unwrap(), "1.0.0-b");
    }

    #[test]
    fn empty_index_errors() {
        assert!(resolve_version(&idx(&[]), None).is_err());
    }

    #[test]
    fn normalize_lowercases_and_strips_build() {
        assert_eq!(normalize_version("1.0.0+BUILD.7"), "1.0.0");
        assert_eq!(normalize_version("2.0.0-Beta"), "2.0.0-beta");
    }

    #[test]
    fn registration_leaf_accepts_object_catalog_entry() {
        let json = r#"{"catalogEntry": {"@id": "https://api.nuget.org/v3/catalog0/x.json"}}"#;
        let leaf: RegistrationLeaf = serde_json::from_str(json).unwrap();
        assert_eq!(
            leaf.catalog_entry.catalog_url(),
            "https://api.nuget.org/v3/catalog0/x.json"
        );
    }

    #[test]
    fn registration_leaf_accepts_bare_string_catalog_entry() {
        // Real nuget.org leaves frequently inline catalogEntry as a URL string.
        let json = r#"{"catalogEntry": "https://api.nuget.org/v3/catalog0/x.json"}"#;
        let leaf: RegistrationLeaf = serde_json::from_str(json).unwrap();
        assert_eq!(
            leaf.catalog_entry.catalog_url(),
            "https://api.nuget.org/v3/catalog0/x.json"
        );
    }

    #[test]
    fn sha512_b64_matches() {
        let b = b"hello";
        let h = STANDARD.encode(Sha512::digest(b));
        verify_sha512_b64(b, &h).unwrap();
    }

    #[test]
    fn sha512_b64_rejects_mismatch() {
        let b = b"hello";
        let h = STANDARD.encode(Sha512::digest(b));
        let mut tampered = b.to_vec();
        tampered.push(b'!');
        assert!(verify_sha512_b64(&tampered, &h).is_err());
    }

    #[test]
    fn sha512_b64_rejects_empty() {
        assert!(verify_sha512_b64(b"x", "").is_err());
    }

    #[test]
    fn compare_versions_numeric() {
        assert_eq!(
            compare_versions("1.5.0", "1.10.0"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_versions("2.0.0", "1.99.0"),
            std::cmp::Ordering::Greater
        );
    }
}
