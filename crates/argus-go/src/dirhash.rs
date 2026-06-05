//! Go module checksum (`h1:`) recomputation and verification.
//!
//! THIS IS THE INTEGRITY HONESTY POINT for the Go ecosystem and it must
//! never be faked (U-29).
//!
//! The checksum the GOPROXY advertises at `.../@v/<version>.ziphash` and
//! that `go.sum` records is **not** a plain SHA-256 over the `.zip` bytes.
//! It is `golang.org/x/mod/sumdb/dirhash.Hash1`:
//!
//! ```text
//! h1:base64std( SHA-256( manifest ) )
//! ```
//!
//! where `manifest` is a deterministic text blob, one line per file:
//!
//! ```text
//! <lowercase-hex(SHA-256(file-bytes))>  <module>@<version>/<path>\n
//! ```
//!
//! where the FILE NAMES are sorted first and the lines are emitted in that
//! filename order (sorting the formatted lines instead would order them by
//! the leading hash and diverge from Go). Therefore
//! `argus_core::url::verify_sha256_hex(zip_bytes, ...)` CANNOT be applied
//! to the downloaded zip and MUST NOT be used as if it could — doing so
//! would fabricate an integrity result.
//!
//! We recompute `h1` independently from the extracted file tree and
//! compare it against the proxy's advertised value in constant time
//! (`subtle::ConstantTimeEq`), mirroring `verify_sha256_hex`'s discipline.
//!
//! ## Known gap (deferred, documented per design risk 1)
//!
//! This proves the downloaded bytes match what the proxy advertises; it
//! does NOT prove the proxy itself is honest. A fully compromised/MITM'd
//! GOPROXY could serve matching malicious bytes + matching h1. The real
//! defense — cross-checking against sum.golang.org's signed checksum
//! transparency log — is DEFERRED to a later milestone and is explicitly
//! NOT implemented in v1.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Recompute the Go module `h1:` dirhash from an extracted file set.
///
/// `files` is a list of `(name, bytes)` pairs, where `name` is the full
/// in-zip entry name including the `<module>@<version>/` prefix (Go's
/// module zip layout). The returned string carries the `h1:` prefix so it
/// compares directly against the proxy `.ziphash` body.
pub fn compute_h1(files: &[(String, Vec<u8>)]) -> String {
    // dirhash.Hash1 sorts the FILE NAMES, then writes one
    // `<lower-hex(sha256(content))>  <name>\n` line per file in that order.
    // Sorting the *formatted lines* instead would order them by the leading
    // hash digest, which differs from filename order for any multi-file
    // module and yields a different h1 than Go (rejecting valid zips).
    let mut entries: Vec<(&str, String)> = files
        .iter()
        .map(|(name, bytes)| (name.as_str(), lower_hex(&Sha256::digest(bytes))))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut h = Sha256::new();
    for (name, hex) in &entries {
        // Go's dirhash uses exactly two spaces between the hex digest and
        // the file name, terminated by a newline.
        h.update(format!("{hex}  {name}\n").as_bytes());
    }
    format!("h1:{}", BASE64_STANDARD.encode(h.finalize()))
}

/// Verify a recomputed `h1:` against the proxy-advertised `h1:` value in
/// constant time.
///
/// `expected` is the raw `.ziphash` response body; it MUST start with the
/// `h1:` prefix. An empty or non-`h1:` value is a hard error (U-29) — the
/// caller must never treat "no checksum advertised" as a pass.
pub fn verify_h1(recomputed: &str, expected: &str) -> Result<()> {
    let expected = expected.trim();
    if expected.is_empty() {
        bail!("GOPROXY did not advertise a module checksum (empty .ziphash body)");
    }
    if !expected.starts_with("h1:") {
        bail!(
            "GOPROXY .ziphash value is not an h1: checksum (got `{expected}`); refusing to proceed"
        );
    }
    if bool::from(recomputed.as_bytes().ct_eq(expected.as_bytes())) {
        Ok(())
    } else {
        Err(anyhow!(
            "module checksum mismatch: recomputed h1 `{recomputed}` does not match proxy-advertised `{expected}`"
        ))
    }
}

/// Parse + validate a `.ziphash` response body, returning the trimmed
/// `h1:`-prefixed checksum. Fails closed on empty or malformed bodies.
pub fn parse_ziphash(body: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(body).context("GOPROXY .ziphash body is not valid UTF-8")?;
    let s = s.trim();
    if s.is_empty() {
        bail!("GOPROXY .ziphash body is empty");
    }
    if !s.starts_with("h1:") {
        bail!("GOPROXY .ziphash body is not an h1: checksum (got `{s}`)");
    }
    Ok(s.to_string())
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden value computed by an INDEPENDENT oracle (a Python reimpl of
    /// golang.org/x/mod/sumdb/dirhash.Hash1: sort filenames -> write
    /// `<hex(sha256(content))>  <name>\n` per file -> sha256 -> base64-std),
    /// not by this code, so it catches drift in the manifest layout
    /// (two-space separator, trailing newline, filename sort order, base64
    /// alphabet). In this case foo.go sorts before go.mod by filename.
    #[test]
    fn compute_h1_matches_golden() {
        let files = vec![
            (
                "example.com/m@v1.0.0/go.mod".to_string(),
                b"module example.com/m\n\ngo 1.21\n".to_vec(),
            ),
            (
                "example.com/m@v1.0.0/foo.go".to_string(),
                b"package m\n\nfunc Foo() {}\n".to_vec(),
            ),
        ];
        assert_eq!(
            compute_h1(&files),
            "h1:WsmPR4cuJiO0+eRnapJH6cu2pud2bSBidcFmZj0K2rU="
        );
    }

    /// Regression guard for the filename-vs-hash sort order: this 3-file set
    /// is constructed so that sorting by content hash produces a DIFFERENT
    /// manifest order (hence a different digest) than sorting by filename.
    /// Only the correct (filename-sorted) implementation yields this golden,
    /// which was computed by the same independent oracle.
    #[test]
    fn compute_h1_sorts_by_filename_not_hash() {
        let files = vec![
            (
                "m@v1.0.0/z.go".to_string(),
                b"package m\nvar Z = 1\n".to_vec(),
            ),
            (
                "m@v1.0.0/a.go".to_string(),
                b"package m\nvar A = 2\n".to_vec(),
            ),
            ("m@v1.0.0/go.mod".to_string(), b"module m\n".to_vec()),
        ];
        assert_eq!(
            compute_h1(&files),
            "h1:spAGgsMxpsia/RBx7YiCLAkw9kVn5d1/oRBhyZIOo6A="
        );
    }

    #[test]
    fn compute_h1_is_order_independent() {
        let a = vec![
            ("m@v1/a.go".to_string(), b"aaa".to_vec()),
            ("m@v1/b.go".to_string(), b"bbb".to_vec()),
        ];
        let b = vec![
            ("m@v1/b.go".to_string(), b"bbb".to_vec()),
            ("m@v1/a.go".to_string(), b"aaa".to_vec()),
        ];
        assert_eq!(compute_h1(&a), compute_h1(&b));
    }

    #[test]
    fn verify_h1_accepts_match() {
        let files = vec![("m@v1/a.go".to_string(), b"x".to_vec())];
        let h = compute_h1(&files);
        verify_h1(&h, &h).unwrap();
    }

    #[test]
    fn verify_h1_rejects_mismatch() {
        let files = vec![("m@v1/a.go".to_string(), b"x".to_vec())];
        let h = compute_h1(&files);
        let err = verify_h1(&h, "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .unwrap_err()
            .to_string();
        assert!(err.contains("checksum mismatch"), "got: {err}");
        assert!(err.contains("h1"), "got: {err}");
    }

    #[test]
    fn verify_h1_rejects_empty() {
        assert!(verify_h1("h1:whatever", "").is_err());
    }

    #[test]
    fn verify_h1_rejects_non_h1() {
        let err = verify_h1("h1:whatever", "deadbeef")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not an h1"), "got: {err}");
    }

    #[test]
    fn parse_ziphash_strips_whitespace() {
        assert_eq!(parse_ziphash(b"h1:abc123==\n").unwrap(), "h1:abc123==");
    }

    #[test]
    fn parse_ziphash_rejects_empty_and_malformed() {
        assert!(parse_ziphash(b"").is_err());
        assert!(parse_ziphash(b"   \n").is_err());
        assert!(parse_ziphash(b"not-a-checksum").is_err());
    }
}
