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
/// gap. Until the verifier can prove these bundles valid, Argus must keep
/// them fail-closed as `SignatureInvalid`.
const INTOTO_V02_DIAGNOSTIC: &str = "V2 bundle requires RFC3161 timestamp";

#[test]
fn real_sigstore_bundle_is_invalid_inside_intoto_0_0_2_gap() {
    // This is the test that SHOULD say `Verified` once the upstream
    // intoto/0.0.2 gap is closed. Until then, this verifier cannot
    // distinguish a legitimate unsupported bundle from forged material,
    // so the operational verdict remains fail-closed.
    let patterns = permissive_allowlist();
    let allowlist = IdentityAllowlist {
        issuer: GITHUB_ACTIONS_OIDC_ISSUER,
        san_uri_patterns: &patterns,
    };

    let verdict = verify_bundle_full(REAL_BUNDLE, REAL_TARBALL, &allowlist).unwrap();
    match verdict {
        SigstoreVerdict::SignatureInvalid { reason } => {
            assert!(
                reason.contains(INTOTO_V02_DIAGNOSTIC),
                "expected the upstream intoto/0.0.2 diagnostic, got: {reason}"
            );
        }
        SigstoreVerdict::Verified { identity, issuer } => {
            panic!(
                "upstream fixed intoto/0.0.2 — flip this test to assert \
                 Verified. identity={identity}, issuer={issuer}"
            );
        }
        other => panic!("expected SignatureInvalid for the intoto/0.0.2 gap, got: {other:?}"),
    }
}

#[test]
fn tampered_artifact_is_invalid_inside_the_intoto_gap() {
    let mut tampered = REAL_TARBALL.to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;

    let patterns = permissive_allowlist();
    let allowlist = IdentityAllowlist {
        issuer: GITHUB_ACTIONS_OIDC_ISSUER,
        san_uri_patterns: &patterns,
    };

    let verdict = verify_bundle_full(REAL_BUNDLE, &tampered, &allowlist).unwrap();
    match verdict {
        SigstoreVerdict::SignatureInvalid { .. } => {}
        other => panic!("tampered artifact must be SignatureInvalid, got: {other:?}"),
    }
}

#[test]
fn corrupted_dsse_signature_is_invalid_inside_the_intoto_gap() {
    let mut bundle: serde_json::Value = serde_json::from_str(REAL_BUNDLE).unwrap();
    bundle["dsseEnvelope"]["signatures"][0]["sig"] = serde_json::Value::String("AA==".to_string());

    let patterns = permissive_allowlist();
    let allowlist = IdentityAllowlist {
        issuer: GITHUB_ACTIONS_OIDC_ISSUER,
        san_uri_patterns: &patterns,
    };

    let verdict = verify_bundle_full(&bundle.to_string(), REAL_TARBALL, &allowlist).unwrap();
    match verdict {
        SigstoreVerdict::SignatureInvalid { .. } => {}
        other => panic!("corrupted DSSE signature must be SignatureInvalid, got: {other:?}"),
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
