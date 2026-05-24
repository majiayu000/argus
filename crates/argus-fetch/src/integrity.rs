//! Subresource Integrity (SRI / SSRI) verification.
//!
//! npm publishes tarball checksums in the `dist.integrity` field as one or
//! more space-separated entries shaped `<alg>-<base64 hash>`. A tarball
//! passes verification if *any* declared entry matches.
//!
//! Supported algorithms: sha512, sha384, sha256. Anything else is rejected
//! explicitly so we never silently accept an attacker-chosen weak hash.

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "sha256" => Some(HashAlg::Sha256),
            "sha384" => Some(HashAlg::Sha384),
            "sha512" => Some(HashAlg::Sha512),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SsriEntry {
    pub alg: HashAlg,
    /// Raw bytes of the hash (already base64-decoded).
    pub digest: Vec<u8>,
}

/// Parse `sha512-<b64>[ sha256-<b64>]` into one or more entries. Returns at
/// least one entry; otherwise errors so callers never silently skip
/// verification on a malformed string.
pub fn parse_ssri(ssri: &str) -> Result<Vec<SsriEntry>> {
    let mut out = Vec::new();
    for token in ssri.split_whitespace() {
        let (alg_s, digest_b64) = token
            .split_once('-')
            .ok_or_else(|| anyhow!("SSRI entry missing `-`: {token}"))?;
        let alg =
            HashAlg::parse(alg_s).ok_or_else(|| anyhow!("unsupported SSRI algorithm: {alg_s}"))?;
        // Trim any URL-safe options after `?`, which SSRI v2 allows.
        let digest_b64 = digest_b64.split('?').next().unwrap_or(digest_b64);
        let digest = STANDARD
            .decode(digest_b64.as_bytes())
            .map_err(|e| anyhow!("SSRI base64 decode failed for {alg_s}: {e}"))?;
        out.push(SsriEntry { alg, digest });
    }
    if out.is_empty() {
        bail!("empty SSRI string");
    }
    Ok(out)
}

/// Hash `bytes` with `alg` and return the digest.
pub fn hash(alg: HashAlg, bytes: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha256 => Sha256::digest(bytes).to_vec(),
        HashAlg::Sha384 => Sha384::digest(bytes).to_vec(),
        HashAlg::Sha512 => Sha512::digest(bytes).to_vec(),
    }
}

/// Verify `bytes` against the SSRI string.
///
/// Only the **strongest declared algorithm** is checked. A registry response
/// that contains both `sha256-<correct>` and `sha512-<forged>` would pass
/// any-entry-matches semantics by virtue of the sha256 entry, defeating the
/// stronger sha512 guarantee that the publisher intended. We refuse that
/// downgrade by verifying only the strongest entry per SRI spec
/// recommendations.
pub fn verify_ssri(bytes: &[u8], ssri: &str) -> Result<()> {
    let entries = parse_ssri(ssri)?;
    let strongest = entries
        .iter()
        .max_by_key(|e| match e.alg {
            HashAlg::Sha512 => 3,
            HashAlg::Sha384 => 2,
            HashAlg::Sha256 => 1,
        })
        .expect("parse_ssri guarantees a non-empty entry list");
    let actual = hash(strongest.alg, bytes);
    if bool::from(actual.ct_eq(&strongest.digest)) {
        return Ok(());
    }
    Err(anyhow!(
        "integrity mismatch: strongest entry ({:?}) did not match the {} downloaded bytes",
        strongest.alg,
        bytes.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sha512() {
        let bytes = b"argus";
        let digest = hash(HashAlg::Sha512, bytes);
        let ssri = format!("sha512-{}", STANDARD.encode(&digest));
        verify_ssri(bytes, &ssri).unwrap();
    }

    #[test]
    fn truncated_bytes_fail() {
        let bytes = b"argus";
        let digest = hash(HashAlg::Sha512, bytes);
        let ssri = format!("sha512-{}", STANDARD.encode(&digest));
        let tampered = &bytes[..bytes.len() - 1];
        assert!(verify_ssri(tampered, &ssri).is_err());
    }

    #[test]
    fn unsupported_alg_rejected() {
        assert!(parse_ssri("md5-deadbeef").is_err());
        assert!(parse_ssri("sha1-deadbeef").is_err());
    }

    #[test]
    fn strongest_entry_must_match_even_if_weaker_does() {
        let bytes = b"argus";
        let sha256 = hash(HashAlg::Sha256, bytes);
        let mut forged_sha512 = hash(HashAlg::Sha512, bytes);
        forged_sha512[0] ^= 0xff; // tamper the sha512 digest

        // Attacker scenario: tampered packument supplies a correct sha256
        // alongside a forged sha512. We must NOT accept by virtue of the
        // sha256 match — sha512 is the strongest declared entry and is
        // the one verified.
        let ssri = format!(
            "sha256-{} sha512-{}",
            STANDARD.encode(&sha256),
            STANDARD.encode(&forged_sha512),
        );
        assert!(verify_ssri(bytes, &ssri).is_err());
    }

    #[test]
    fn correct_strongest_entry_passes_even_with_weaker_present() {
        let bytes = b"argus";
        let sha256 = hash(HashAlg::Sha256, bytes);
        let sha512 = hash(HashAlg::Sha512, bytes);
        let ssri = format!(
            "sha256-{} sha512-{}",
            STANDARD.encode(&sha256),
            STANDARD.encode(&sha512),
        );
        verify_ssri(bytes, &ssri).unwrap();
    }
}
