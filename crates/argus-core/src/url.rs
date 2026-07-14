//! Shared URL + integrity helpers used by every ecosystem crate.
//!
//! Hoisted from per-ecosystem copies in `argus-fetch`, `argus-pypi`, and
//! `argus-crates` once duplication crossed the "three copies → extract"
//! threshold. Each ecosystem still owns its own CDN allowlist; the
//! mechanism is shared.

use anyhow::{anyhow, bail, Context, Result};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::{Position, Url};

/// Extract the lowercased host from an `http(s)` URL.
///
/// Preserves an explicit port (for example, `localhost:4873`) so existing
/// private-registry comparisons remain origin-specific. Userinfo, query, and
/// fragment text are never treated as part of the host.
pub fn host_of(url: &str) -> Result<String> {
    let parsed = parse_http_url(url)?;
    canonical_authority(&parsed, url)
}

fn parse_http_url(raw: &str) -> Result<Url> {
    let parsed = Url::parse(raw).with_context(|| format!("parse URL `{raw}`"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("URL has no http(s) scheme: {raw}");
    }
    if raw_authority(raw, parsed.scheme().len())?.is_empty() || parsed.host_str().is_none() {
        bail!("URL has empty host: {raw}");
    }
    Ok(parsed)
}

fn raw_authority(raw: &str, scheme_len: usize) -> Result<&str> {
    let rest = raw
        .get(scheme_len..)
        .and_then(|rest| rest.strip_prefix("://"))
        .ok_or_else(|| anyhow!("URL has no http(s) authority: {raw}"))?;
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    Ok(&rest[..end])
}

fn canonical_authority(parsed: &Url, raw: &str) -> Result<String> {
    let raw_authority = raw_authority(raw, parsed.scheme().len())?;
    let mut host = parsed[Position::BeforeHost..Position::AfterHost].to_ascii_lowercase();
    if let Some(port) = explicit_port(raw_authority) {
        host.push(':');
        host.push_str(port);
    }
    Ok(host)
}

fn explicit_port(authority: &str) -> Option<&str> {
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    if let Some(ipv6) = host_port.strip_prefix('[') {
        let (_, suffix) = ipv6.split_once(']')?;
        return suffix.strip_prefix(':').filter(|port| !port.is_empty());
    }
    host_port
        .rsplit_once(':')
        .map(|(_, port)| port)
        .filter(|port| !port.is_empty())
}

fn normalize_host_pattern(raw: &str) -> Result<String> {
    if raw.is_empty() {
        bail!("host pattern is empty");
    }
    if raw.chars().any(char::is_whitespace) {
        bail!("host pattern contains whitespace: `{raw}`");
    }

    let is_suffix = raw.starts_with('.');
    if is_suffix && raw.len() == 1 {
        bail!("host suffix pattern cannot be `.`");
    }

    let authority = if is_suffix {
        format!("allowlist-probe{raw}")
    } else {
        raw.to_owned()
    };
    if authority.contains('@') || authority.ends_with(':') {
        bail!("host pattern must contain only a host and optional port: `{raw}`");
    }

    let probe = format!("https://{authority}/");
    let parsed = parse_http_url(&probe)?;
    if raw_authority(&probe, parsed.scheme().len())? != authority {
        bail!("host pattern must not contain a path, query, or fragment: `{raw}`");
    }

    let normalized = canonical_authority(&parsed, &probe)?;
    if is_suffix {
        normalized
            .strip_prefix("allowlist-probe")
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("invalid host suffix pattern: `{raw}`"))
    } else {
        Ok(normalized)
    }
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
    let parsed = parse_http_url(url)?;
    if parsed.scheme() != "https" {
        bail!("refusing non-HTTPS artifact URL `{url}`");
    }
    let host = canonical_authority(&parsed, url)?;
    let registry_host = normalize_host_pattern(registry_host)
        .with_context(|| format!("invalid registry host `{registry_host}`"))?;
    let allowed = allowed
        .iter()
        .map(|entry| {
            let raw_entry = entry.as_ref();
            normalize_host_pattern(raw_entry)
                .with_context(|| format!("invalid artifact host allowlist entry `{raw_entry}`"))
        })
        .collect::<Result<Vec<_>>>()?;
    if host == registry_host {
        return Ok(());
    }
    for entry in &allowed {
        let entry = entry.as_str();
        if entry.starts_with('.') {
            if host.ends_with(entry) {
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

/// Verify the SHA-1 digest of `bytes` matches `expected_hex` in constant time.
///
/// An empty `expected_hex` is treated as a hard error (U-29): callers cannot
/// silently accept "no digest advertised". SHA-1 is collision-weak but
/// provides second-preimage resistance adequate for corruption detection
/// against a non-adversarial registry. This is documented in the Composer
/// scanner crate docs.
///
/// The error message contains "SHA-1 mismatch" (integration tests assert this).
pub fn verify_sha1_hex(bytes: &[u8], expected_hex: &str) -> Result<()> {
    if expected_hex.is_empty() {
        bail!("expected SHA-1 is empty — registry did not advertise an integrity digest");
    }
    let expected = hex::decode(expected_hex)
        .with_context(|| format!("decode expected SHA-1 hex `{expected_hex}`"))?;
    let actual = <Sha1 as Digest>::digest(bytes);
    if bool::from(actual.as_slice().ct_eq(&expected)) {
        Ok(())
    } else {
        Err(anyhow!(
            "SHA-1 mismatch for {} downloaded bytes (expected `{expected_hex}`)",
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
    fn host_of_preserves_explicit_ports() -> Result<()> {
        assert_eq!(host_of("https://example.com:443/x")?, "example.com:443");
        assert_eq!(host_of("http://example.com:80/x")?, "example.com:80");
        assert_eq!(host_of("https://[::1]:8443/x")?, "[::1]:8443");
        Ok(())
    }

    #[test]
    fn host_of_rejects_missing_scheme() {
        assert!(host_of("ftp://x.example/").is_err());
        assert!(host_of("x.example/").is_err());
        assert!(host_of("https:/x.example/").is_err());
        assert!(host_of("https:x.example/").is_err());
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
    fn validate_normalizes_idna_allowlist_entries() -> Result<()> {
        validate_artifact_url(
            "https://files.bücher.example/pkg.tar.gz",
            "registry.example.invalid",
            &[".bücher.example"],
        )?;
        Ok(())
    }

    #[test]
    fn validate_rejects_malformed_host_patterns() {
        for entry in [
            "cdn.example/path",
            "cdn.example?tenant=x",
            "cdn.example#fragment",
            r"cdn.example\ignored",
            "user@cdn.example",
            "cdn.example:",
        ] {
            let result = validate_artifact_url(
                "https://cdn.example/package.tar.gz",
                "registry.example.invalid",
                &[entry],
            );
            assert!(
                matches!(&result, Err(error) if format!("{error:#}").contains("invalid artifact host allowlist entry")),
                "malformed allowlist entry was not rejected as configuration: {entry}"
            );
        }

        let result = validate_artifact_url::<&str>(
            "https://registry.example/package.tar.gz",
            "registry.example/path",
            &[],
        );
        assert!(
            matches!(&result, Err(error) if format!("{error:#}").contains("invalid registry host")),
            "malformed registry host was not rejected as configuration"
        );

        for (url, registry_host, allowed) in [
            (
                "https://registry.example/package.tar.gz",
                "registry.example",
                &["bad/path"][..],
            ),
            (
                "https://cdn.example/package.tar.gz",
                "registry.example",
                &["cdn.example", "bad/path"][..],
            ),
        ] {
            let result = validate_artifact_url(url, registry_host, allowed);
            assert!(
                matches!(&result, Err(error) if format!("{error:#}").contains("invalid artifact host allowlist entry")),
                "successful host match skipped malformed allowlist configuration"
            );
        }
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
    fn validate_suffix_uses_only_the_parsed_host() {
        for url in [
            "https://evil.example?.pythonhosted.org/payload",
            "https://evil.example#.pythonhosted.org",
            r"https://evil.example\.pythonhosted.org/payload",
            "https://files.pythonhosted.org@evil.example/.pythonhosted.org",
        ] {
            assert!(
                validate_artifact_url(url, "pypi.org", &[".pythonhosted.org"]).is_err(),
                "allowlist suffix outside the parsed host was accepted: {url}"
            );
        }
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

    #[test]
    fn verify_sha1_matches() {
        let b = b"hello";
        let h = hex::encode(<Sha1 as Digest>::digest(b));
        verify_sha1_hex(b, &h).unwrap();
    }

    #[test]
    fn verify_sha1_rejects_mismatch() {
        let b = b"hello";
        let h = hex::encode(<Sha1 as Digest>::digest(b));
        let mut tampered = b.to_vec();
        tampered.push(b'!');
        let err = verify_sha1_hex(&tampered, &h).unwrap_err();
        assert!(
            err.to_string().contains("SHA-1 mismatch"),
            "expected 'SHA-1 mismatch', got: {err}"
        );
    }

    #[test]
    fn verify_sha1_rejects_empty_digest() {
        assert!(verify_sha1_hex(b"x", "").is_err());
    }

    #[test]
    fn verify_sha1_rejects_malformed_hex() {
        assert!(verify_sha1_hex(b"x", "not-hex").is_err());
    }
}
