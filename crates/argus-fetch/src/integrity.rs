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

/// Verify `bytes` against the SSRI string. Returns `Ok(())` if at least one
/// entry matches; otherwise an error naming the strongest expected
/// algorithm.
pub fn verify_ssri(bytes: &[u8], ssri: &str) -> Result<()> {
    let entries = parse_ssri(ssri)?;
    let mut strongest = HashAlg::Sha256;
    for entry in &entries {
        if matches!(
            (strongest, entry.alg),
            (HashAlg::Sha256, HashAlg::Sha384 | HashAlg::Sha512)
                | (HashAlg::Sha384, HashAlg::Sha512)
        ) {
            strongest = entry.alg;
        }
    }
    for entry in &entries {
        let actual = hash(entry.alg, bytes);
        if subtle_eq(&actual, &entry.digest) {
            return Ok(());
        }
    }
    Err(anyhow!(
        "integrity mismatch: no SSRI entry matched (expected {:?})",
        strongest
    ))
}

/// Constant-time byte comparison. We only verify integrity (not secrets),
/// but using constant-time eq here costs nothing and keeps the intent
/// explicit.
fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
    fn multiple_entries_any_match_passes() {
        let bytes = b"argus";
        let sha256 = hash(HashAlg::Sha256, bytes);
        let sha512 = hash(HashAlg::Sha512, bytes);
        // First entry is wrong-by-truncation; second is correct.
        let mut wrong = sha256.clone();
        wrong[0] ^= 0xff;
        let ssri = format!(
            "sha256-{} sha512-{}",
            STANDARD.encode(&wrong),
            STANDARD.encode(&sha512),
        );
        verify_ssri(bytes, &ssri).unwrap();
    }
}
