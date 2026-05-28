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

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::Bundle;
use sigstore_verify::{verify as sigstore_verify_fn, VerificationPolicy};

/// Sigstore public-good trust root, snapshotted from
/// `https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json`.
/// Rotated by hand when Sigstore publishes a new root.
const TRUSTED_ROOT_JSON: &str = include_str!("trust/trusted_root.json");

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

    // Pass the literal issuer to sigstore-verify; the SAN identity regex is
    // applied by us after a successful crypto verdict (the crate only does
    // literal identity equality).
    //
    // `skip_timestamp()`: npm-published v0.2 bundles use `kindVersion 0.0.2`
    // (which sigstore-verify 0.8.0 treats as Rekor V2) BUT carry a
    // non-zero `integratedTime` and zero `rfc3161Timestamps` — there is no
    // standalone TSA timestamp to verify in the first place. Rekor's
    // Signed Entry Timestamp (SET) still attests to `integratedTime`, and
    // SET verification (plus the cert validity window check) remains on.
    // See docs/design/sigstore-verification.md §10 for the honest gap.
    let policy = VerificationPolicy::default()
        .require_issuer(allowlist.issuer)
        .skip_timestamp();

    match sigstore_verify_fn(artifact, &bundle, &policy, &trusted_root) {
        Ok(result) => {
            let identity = result
                .identity
                .ok_or_else(|| anyhow!("Sigstore verify returned no identity"))?;
            let issuer = result
                .issuer
                .ok_or_else(|| anyhow!("Sigstore verify returned no issuer"))?;
            if san_matches(&identity, allowlist.san_uri_patterns) {
                Ok(SigstoreVerdict::Verified { identity, issuer })
            } else {
                Ok(SigstoreVerdict::UntrustedIssuer {
                    actual_identity: identity,
                    actual_issuer: issuer,
                })
            }
        }
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
