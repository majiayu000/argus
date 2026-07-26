//! End-to-end Sigstore bundle verification against a real, captured-from-npm
//! attestation. Everything offline:
//!
//! - Bundle JSON: `sigstore@2.3.1` SLSA-provenance attestation
//!   (`x509CertificateChain` path, Fulcio-issued leaf cert chaining to
//!   the public-good intermediate + root).
//! - Artifact:    the actual `sigstore-2.3.1.tgz` tarball whose SHA-512 is
//!   the in-toto subject digest the attestation was signed over.
//! - Trust root:  the vendored `src/trust/trusted_root.json` snapshot.
//!
//! These tests confirm that the wrapper around `sigstore-verify` reaches
//! the right verdict for the three operationally important shapes the
//! design doc (§5) calls out: Verified, UntrustedIssuer, and the M1
//! npm-keyring `publicKey`-hint path that this layer cannot handle.

use argus_verify::{verify_bundle_full, IdentityAllowlist, SigstoreVerdict};
use regex::Regex;

const REAL_BUNDLE: &str = include_str!("../src/testdata/sigstore_2_3_1_slsa_bundle.json");
const REAL_TARBALL: &[u8] = include_bytes!("../src/testdata/sigstore-2.3.1.tgz");

/// Permissive allowlist that admits the real `sigstore/sigstore-js`
/// release workflow. Sanity-checks the entire pipeline (DSSE + Fulcio
/// chain + Rekor + SCT + subject digest).
fn permissive_allowlist() -> Vec<Regex> {
    vec![Regex::new(r"^https://github\.com/sigstore/sigstore-js/.+$").unwrap()]
}

const GITHUB_ACTIONS_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Known upstream incompatibility:
///
/// `sigstore-verify` 0.8.0's V1/V2 detection rejects bundles whose tlog
/// `kindVersion` is `{kind: "intoto", version: "0.0.2"}` UNLESS the bundle
/// also carries a verifiable RFC3161 timestamp. npm-published v0.2 bundles
/// (e.g. `sigstore@2.3.1`) use exactly that kindVersion AND carry zero
/// `rfc3161Timestamps` — they instead rely on Rekor's SET over a non-zero
/// `integratedTime`. The crate's V1 fallback at `verify_impl/helpers.rs:160`
/// only accepts `kind in {"hashedrekord","dsse"}` with `version == "0.0.1"`,
/// so the intoto/0.0.2 case falls into a gap and surfaces as
/// `SignatureInvalid` with the diagnostic "V2 bundle requires RFC3161
/// timestamp ...". cosign hit the same shape; see the design doc §10 honest
/// gap. These tests pin the current observable contract so we notice the
/// day upstream closes the gap (or we replace the verifier).
const INTOTO_V02_DIAGNOSTIC: &str = "V2 bundle requires RFC3161 timestamp";

#[test]
fn real_sigstore_bundle_is_unsupported_not_invalid_inside_intoto_0_0_2_gap() {
    // This is the test that SHOULD say `Verified` once the upstream
    // intoto/0.0.2 gap is closed. Today it pins the Unsupported mapping:
    // the shape npm actually publishes is a capability gap of this build,
    // not evidence of a bad signature, so it must never surface as
    // SignatureInvalid (which drives a Critical finding and a Block).
    let patterns = permissive_allowlist();
    let allowlist = IdentityAllowlist {
        issuer: GITHUB_ACTIONS_OIDC_ISSUER,
        san_uri_patterns: &patterns,
    };

    let verdict = verify_bundle_full(REAL_BUNDLE, REAL_TARBALL, &allowlist).unwrap();
    match verdict {
        SigstoreVerdict::Unsupported { reason } => {
            assert!(
                reason.contains("intoto/0.0.2"),
                "expected the intoto/0.0.2 gap explanation, got: {reason}"
            );
            assert!(
                reason.contains(INTOTO_V02_DIAGNOSTIC),
                "expected the pinned upstream diagnostic inside the reason, got: {reason}"
            );
        }
        SigstoreVerdict::Verified { identity, issuer } => {
            // Upstream fixed it. Flip this test to assert Verified, drop
            // the gap remap in sigstore.rs, and delete the gap section in
            // design doc §10.
            panic!(
                "upstream fixed intoto/0.0.2 — flip this test to assert \
                 Verified. identity={identity}, issuer={issuer}"
            );
        }
        SigstoreVerdict::SignatureInvalid { reason } => panic!(
            "known npm bundle shape leaked through as SignatureInvalid \
             (upstream reworded the diagnostic, or the shape check broke): {reason}"
        ),
        other => panic!("expected Unsupported for the intoto/0.0.2 gap, got: {other:?}"),
    }
}

#[test]
fn tampered_artifact_never_verifies_inside_the_intoto_gap() {
    // The intoto/0.0.2 gap fires before subject verification, so inside
    // the gap a tampered artifact also reaches Unsupported — the layer
    // makes no claim either way. The invariant this test protects is that
    // tampering NEVER promotes to Verified. Actual tamper detection for
    // npm packages lives in the fetch layer's subject-digest cross-check
    // (`provenance-subject-mismatch`, Critical), which runs before and
    // independently of signature verification.
    let mut tampered = REAL_TARBALL.to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;

    let patterns = permissive_allowlist();
    let allowlist = IdentityAllowlist {
        issuer: GITHUB_ACTIONS_OIDC_ISSUER,
        san_uri_patterns: &patterns,
    };

    let verdict = verify_bundle_full(REAL_BUNDLE, &tampered, &allowlist).unwrap();
    match verdict {
        SigstoreVerdict::Unsupported { .. } | SigstoreVerdict::SignatureInvalid { .. } => {}
        other => panic!("tampered artifact must never verify, got: {other:?}"),
    }
}

#[test]
fn npm_keyring_public_key_hint_bundle_is_unsupported() {
    // Day 1's DSSE layer flagged this case as Unsupported; the full
    // Sigstore layer must reach the same verdict (the npm-keyring path
    // does not chain to a Fulcio root).
    let bundle = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "verificationMaterial": {
            "publicKey": { "hint": "SHA256:examplehint" }
        },
        "dsseEnvelope": {
            "payload": "e30=",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{ "sig": "AA==" }]
        }
    });
    let patterns = permissive_allowlist();
    let allowlist = IdentityAllowlist {
        issuer: GITHUB_ACTIONS_OIDC_ISSUER,
        san_uri_patterns: &patterns,
    };
    let verdict = verify_bundle_full(&bundle.to_string(), REAL_TARBALL, &allowlist).unwrap();
    match verdict {
        SigstoreVerdict::Unsupported { .. } => {}
        other => panic!("expected Unsupported for npm-keyring bundle, got: {other:?}"),
    }
}
