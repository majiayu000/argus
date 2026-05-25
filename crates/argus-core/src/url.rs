//! Shared URL + integrity helpers used by every ecosystem crate.
//!
//! Hoisted from per-ecosystem copies in `argus-fetch`, `argus-pypi`, and
//! `argus-crates` once duplication crossed the "three copies → extract"
//! threshold. Each ecosystem still owns its own CDN allowlist; the
//! mechanism is shared.

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Extract the lowercased host from an `http(s)` URL.
///
/// Returns the host between the scheme and the first `/`, or the entire
/// authority section if there is no path. Errors if the URL has no
/// `http(s)` scheme or has an empty host.
pub fn host_of(url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| anyhow!("URL has no http(s) scheme: {url}"))?;
    let end = rest.find('/').unwrap_or(rest.len());
    let host = rest[..end].to_ascii_lowercase();
    if host.is_empty() {
        bail!("URL has empty host: {url}");
    }
    Ok(host)
}

/// Validate an artifact download URL against a registry host and an
/// allowlist of additional acceptable hosts (typically CDN hosts).
///
/// Rules:
/// - URL must be `https://`.
/// - Host must equal `registry_host`, OR
/// - Host must equal an `allowed` entry (exact match, case-insensitive), OR
/// - An `allowed` entry beginning with `.` is a strict subdomain-suffix
///   match: `.pythonhosted.org` matches `files.pythonhosted.org` and
///   `pypi.pythonhosted.org` but NOT the bare `pythonhosted.org` and NOT
///   `evilpythonhosted.org`.
pub fn validate_artifact_url<S: AsRef<str>>(
    url: &str,
    registry_host: &str,
    allowed: &[S],
) -> Result<()> {
    if !url.starts_with("https://") {
        bail!("refusing non-HTTPS artifact URL `{url}`");
    }
    let host = host_of(url)?;
    if host == registry_host {
        return Ok(());
    }
    for entry in allowed {
        let entry = entry.as_ref().to_ascii_lowercase();
        if entry.starts_with('.') {
            if host.ends_with(&entry) {
                return Ok(());
            }
        } else if host == entry {
            return Ok(());
        }
    }
    bail!(
        "artifact host `{host}` is neither the registry host `{registry_host}` nor in the allowlist (URL {url})"
    );
}

/// Verify the SHA-256 digest of `bytes` matches `expected_hex` in
/// constant time. An empty `expected_hex` is treated as a hard error so
/// callers cannot silently accept "no digest advertised".
pub fn verify_sha256_hex(bytes: &[u8], expected_hex: &str) -> Result<()> {
    if expected_hex.is_empty() {
        bail!("expected SHA-256 is empty — registry did not advertise an integrity digest");
    }
    let expected = hex::decode(expected_hex)
        .with_context(|| format!("decode expected SHA-256 hex `{expected_hex}`"))?;
    let actual = Sha256::digest(bytes);
    if bool::from(actual.as_slice().ct_eq(&expected)) {
        Ok(())
    } else {
        Err(anyhow!(
            "SHA-256 mismatch for {} downloaded bytes (expected `{expected_hex}`)",
            bytes.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_strips_scheme_and_lowercases() {
        assert_eq!(
            host_of("https://Registry.NpmJS.Org/x").unwrap(),
            "registry.npmjs.org"
        );
        assert_eq!(
            host_of("http://localhost:4873/x").unwrap(),
            "localhost:4873"
        );
    }

    #[test]
    fn host_of_handles_no_path() {
        assert_eq!(host_of("https://crates.io").unwrap(), "crates.io");
    }

    #[test]
    fn host_of_rejects_missing_scheme() {
        assert!(host_of("ftp://x.example/").is_err());
        assert!(host_of("x.example/").is_err());
    }

    #[test]
    fn host_of_rejects_empty_host() {
        assert!(host_of("https:///path").is_err());
    }

    #[test]
    fn validate_accepts_registry_host() {
        validate_artifact_url::<&str>(
            "https://registry.npmjs.org/chalk/-/chalk-1.0.0.tgz",
            "registry.npmjs.org",
            &[],
        )
        .unwrap();
    }

    #[test]
    fn validate_rejects_http() {
        assert!(validate_artifact_url::<&str>(
            "http://registry.npmjs.org/x.tgz",
            "registry.npmjs.org",
            &[],
        )
        .is_err());
    }

    #[test]
    fn validate_accepts_exact_allowlist_entry() {
        validate_artifact_url(
            "https://static.crates.io/crates/serde/serde-1.0.crate",
            "crates.io",
            &["static.crates.io"],
        )
        .unwrap();
    }

    #[test]
    fn validate_accepts_exact_entry_case_insensitive() {
        validate_artifact_url(
            "https://CDN.Example.Org/x.tgz",
            "registry.example.invalid",
            &["cdn.example.org"],
        )
        .unwrap();
    }

    #[test]
    fn validate_accepts_suffix_allowlist_entry() {
        validate_artifact_url(
            "https://files.pythonhosted.org/p/r/requests-2.0.tar.gz",
            "pypi.org",
            &[".pythonhosted.org"],
        )
        .unwrap();
    }

    #[test]
    fn validate_suffix_does_not_match_bare_domain() {
        assert!(validate_artifact_url(
            "https://pythonhosted.org/x.tar.gz",
            "pypi.org",
            &[".pythonhosted.org"],
        )
        .is_err());
    }

    #[test]
    fn validate_suffix_does_not_match_lookalike() {
        assert!(validate_artifact_url(
            "https://evilpythonhosted.org/x.tar.gz",
            "pypi.org",
            &[".pythonhosted.org"],
        )
        .is_err());
    }

    #[test]
    fn validate_rejects_cross_host_without_allowlist() {
        assert!(validate_artifact_url::<&str>(
            "https://evil.example.invalid/x.tgz",
            "registry.npmjs.org",
            &[],
        )
        .is_err());
    }

    #[test]
    fn validate_allowlist_does_not_bypass_https() {
        assert!(validate_artifact_url(
            "http://cdn.example.org/x.tgz",
            "registry.npmjs.org",
            &["cdn.example.org"],
        )
        .is_err());
    }

    #[test]
    fn verify_sha256_matches() {
        let b = b"hello";
        let h = hex::encode(Sha256::digest(b));
        verify_sha256_hex(b, &h).unwrap();
    }

    #[test]
    fn verify_sha256_rejects_mismatch() {
        let b = b"hello";
        let h = hex::encode(Sha256::digest(b));
        let mut tampered = b.to_vec();
        tampered.push(b'!');
        assert!(verify_sha256_hex(&tampered, &h).is_err());
    }

    #[test]
    fn verify_sha256_rejects_empty_digest() {
        assert!(verify_sha256_hex(b"x", "").is_err());
    }

    #[test]
    fn verify_sha256_rejects_malformed_hex() {
        assert!(verify_sha256_hex(b"x", "not-hex").is_err());
    }
}
