//! Full Sigstore bundle verification — Fulcio chain + Rekor inclusion +
//! OIDC identity allowlist.
//!
//! Builds on [`crate::dsse`]: where the DSSE module verifies *only* that the
//! envelope signature matches the embedded leaf cert's public key, this
//! module additionally:
//!
//! - Validates the leaf certificate chains to a trusted Sigstore Fulcio CA.
//! - Validates the Rekor transparency-log entry's inclusion proof + Signed
//!   Entry Timestamp (SET).
//! - Cross-checks the in-toto subject digest against the supplied artifact
//!   bytes (DSSE-internal: PAE + subject-digest match).
//! - Enforces an operator-supplied OIDC identity policy: a literal issuer
//!   match plus a regex-allowlist over the leaf cert's SAN URI. The regex
//!   layer is argus-side because `sigstore_verify::VerificationPolicy`
//!   only supports literal identity equality (verified by reading the
//!   crate source at `verify.rs:293`).
//!
//! The Sigstore [`TrustedRoot`] is vendored in
//! `src/trust/trusted_root.json` — a captured-from-production snapshot of
//! the Sigstore public-good TUF target. argus-verify runs fully offline at
//! runtime; root rotation is a manual checklist item (design doc §10).

use anyhow::{bail, Context, Result};
use regex::Regex;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::Bundle;
use sigstore_verify::{verify as sigstore_verify_fn, VerificationPolicy};

/// Sigstore public-good trust root, snapshotted from
/// `https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json`
/// (canonical TUF target: `https://tuf-repo-cdn.sigstore.dev/`).
///
/// Rotated by hand when Sigstore publishes a new root. The snapshot is
/// pinned by [`TRUSTED_ROOT_SHA256`]; a unit test verifies the constant
/// still matches the bytes that ship in the crate, so accidental drift
/// (e.g. an LF/CRLF rewrite by a tool) trips a CI failure rather than
/// silently broadening trust.
const TRUSTED_ROOT_JSON: &str = include_str!("trust/trusted_root.json");

/// SHA-256 of the captured `trusted_root.json`, pinned at the time of
/// vendoring (2026-05-28). Verified by `vendored_trusted_root_matches_pinned_sha256`.
#[cfg(test)]
const TRUSTED_ROOT_SHA256: &str =
    "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66";

/// Operator-supplied OIDC identity policy.
///
/// Both fields must be set; a `verify_bundle_full` caller declaring "no
/// policy at all" is an anti-pattern and is rejected by construction.
pub struct IdentityAllowlist<'a> {
    /// Literal OIDC issuer URL the leaf cert must carry. For GitHub Actions
    /// this is `"https://token.actions.githubusercontent.com"`.
    pub issuer: &'a str,
    /// Regex patterns matched against the leaf cert's SAN URI. Match against
    /// **any** pattern is sufficient. Use anchored patterns (`^…$`).
    pub san_uri_patterns: &'a [Regex],
}

/// Verdict produced by [`verify_bundle_full`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigstoreVerdict {
    /// Every Sigstore layer (DSSE signature, Fulcio chain, Rekor inclusion,
    /// SCT, subject digest) verified AND the SAN URI matched the allowlist.
    Verified { identity: String, issuer: String },
    /// One of the Sigstore cryptographic layers failed (signature, chain,
    /// transparency-log entry, subject-digest mismatch, …).
    SignatureInvalid { reason: String },
    /// Cryptographic layers passed but the leaf cert's SAN URI is not in
    /// the operator's allowlist. The attestation is *real* but it was not
    /// issued by an allowlisted builder.
    UntrustedIssuer {
        actual_identity: String,
        actual_issuer: String,
    },
    /// The bundle uses a verification material this layer cannot handle —
    /// most importantly the npm-keyring `publicKey` hint path, which needs
    /// the npm public keyring instead of a Fulcio cert chain.
    Unsupported { reason: String },
}

/// Verify a Sigstore bundle end-to-end against an operator-supplied
/// identity policy.
///
/// `artifact` is the bytes the in-toto subject digest must match (for npm
/// this is the tarball). `sigstore-verify` handles PAE + subject-digest
/// matching internally.
pub fn verify_bundle_full(
    bundle_json: &str,
    artifact: &[u8],
    allowlist: &IdentityAllowlist<'_>,
) -> Result<SigstoreVerdict> {
    // An empty SAN allowlist would silently block every bundle as
    // UntrustedIssuer with no error — almost certainly a caller mistake
    // (forgot to populate the patterns vec). Fail fast so the
    // misconfiguration is visible.
    if allowlist.san_uri_patterns.is_empty() {
        bail!(
            "IdentityAllowlist.san_uri_patterns must contain at least one \
             regex; an empty list silently rejects every signed bundle"
        );
    }

    let bundle =
        Bundle::from_json(bundle_json).context("parse Sigstore bundle JSON for full verify")?;

    // The npm-keyring path carries no x509 chain to evaluate against the
    // Sigstore trust root. Surface as Unsupported rather than running the
    // full verifier (which would error out with a less informative message).
    if !has_x509_chain(&bundle) {
        return Ok(SigstoreVerdict::Unsupported {
            reason: "bundle has no x509CertificateChain (likely an npm-keyring \
                     publicKey-hint attestation); Sigstore full verification \
                     requires a Fulcio-issued cert chain"
                .to_string(),
        });
    }

    let trusted_root = TrustedRoot::from_json(TRUSTED_ROOT_JSON)
        .context("load vendored Sigstore trusted_root.json")?;

    // Pass the literal issuer to sigstore-verify; the SAN identity regex
    // is applied by us after a successful crypto verdict (the crate only
    // does literal identity equality, verified at verify.rs:293).
    let policy = VerificationPolicy::default().require_issuer(allowlist.issuer);

    match sigstore_verify_fn(artifact, &bundle, &policy, &trusted_root) {
        Ok(result) => match (result.identity, result.issuer) {
            (Some(identity), Some(issuer)) => {
                if san_matches(&identity, allowlist.san_uri_patterns) {
                    Ok(SigstoreVerdict::Verified { identity, issuer })
                } else {
                    Ok(SigstoreVerdict::UntrustedIssuer {
                        actual_identity: identity,
                        actual_issuer: issuer,
                    })
                }
            }
            // Crypto path returned Ok but the cert info is incomplete. A
            // bundle that reaches here without an identity/issuer cannot be
            // distinguished from forged material at this layer; treat it as
            // SignatureInvalid rather than letting an Err leak through the
            // structured verdict.
            (id, iss) => Ok(SigstoreVerdict::SignatureInvalid {
                reason: format!(
                    "Sigstore verify returned Ok with incomplete cert info \
                     (identity: {}, issuer: {})",
                    if id.is_some() { "present" } else { "missing" },
                    if iss.is_some() { "present" } else { "missing" }
                ),
            }),
        },
        Err(e) => Ok(SigstoreVerdict::SignatureInvalid {
            reason: e.to_string(),
        }),
    }
}

fn has_x509_chain(bundle: &Bundle) -> bool {
    // We round-trip the bundle through JSON to keep this independent of
    // the sigstore-types enum layout (which has churned across the 0.x
    // series). Cheap: bundles are <50KB.
    let Ok(v) = serde_json::to_value(bundle) else {
        return false;
    };
    v.get("verificationMaterial")
        .and_then(|vm| vm.get("x509CertificateChain"))
        .and_then(|c| c.get("certificates"))
        .and_then(|arr| arr.as_array())
        .map(|arr| !arr.is_empty())
        .unwrap_or(false)
}

fn san_matches(identity: &str, patterns: &[Regex]) -> bool {
    patterns.iter().any(|p| p.is_match(identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn vendored_trusted_root_matches_pinned_sha256() {
        // Drift-detector: if the bytes of `src/trust/trusted_root.json`
        // change without bumping `TRUSTED_ROOT_SHA256`, this test fails.
        // Catches LF/CRLF rewrites by tooling, accidental partial
        // overwrites, and unannounced upstream root rotations.
        let actual = hex_lower(&Sha256::digest(TRUSTED_ROOT_JSON.as_bytes()));
        assert_eq!(
            actual, TRUSTED_ROOT_SHA256,
            "vendored trusted_root.json drift: update TRUSTED_ROOT_SHA256 \
             if the change is intentional"
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}
