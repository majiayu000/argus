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
//! These tests confirm the positive path and fail-closed behavior for each
//! cryptographic or policy boundary used by the wrapper.

use argus_verify::{verify_bundle_full, IdentityAllowlist, SigstoreVerdict};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use regex::Regex;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::Bundle;
use sigstore_verify::VerificationPolicy;

const REAL_BUNDLE: &str = include_str!("../src/testdata/sigstore_2_3_1_slsa_bundle.json");
const REAL_TARBALL: &[u8] = include_bytes!("../src/testdata/sigstore-2.3.1.tgz");
const TRUSTED_ROOT: &str = include_str!("../src/trust/trusted_root.json");

/// Permissive allowlist that admits the real `sigstore/sigstore-js`
/// release workflow. Sanity-checks the entire pipeline (DSSE + Fulcio
/// chain + Rekor + SCT + subject digest).
fn permissive_allowlist() -> Vec<Regex> {
    vec![Regex::new(r"^https://github\.com/sigstore/sigstore-js/.+$").unwrap()]
}

const GITHUB_ACTIONS_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

fn verdict(bundle: &serde_json::Value, artifact: &[u8]) -> SigstoreVerdict {
    let patterns = permissive_allowlist();
    let allowlist = IdentityAllowlist {
        issuer: GITHUB_ACTIONS_OIDC_ISSUER,
        san_uri_patterns: &patterns,
    };
    verify_bundle_full(&bundle.to_string(), artifact, &allowlist).unwrap()
}

fn assert_bundle_invalid(mutator: impl FnOnce(&mut serde_json::Value)) {
    let mut bundle: serde_json::Value = serde_json::from_str(REAL_BUNDLE).unwrap();
    mutator(&mut bundle);
    assert!(
        matches!(
            verdict(&bundle, REAL_TARBALL),
            SigstoreVerdict::SignatureInvalid { .. }
        ),
        "mutated bundle must fail closed"
    );
}

#[test]
fn real_sigstore_bundle_is_fully_verified() {
    let bundle = serde_json::from_str(REAL_BUNDLE).unwrap();
    match verdict(&bundle, REAL_TARBALL) {
        SigstoreVerdict::Verified { identity, issuer } => {
            assert_eq!(issuer, GITHUB_ACTIONS_OIDC_ISSUER);
            assert_eq!(
                identity,
                "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main"
            );
        }
        other => panic!("expected full cryptographic verification, got: {other:?}"),
    }
}

#[test]
fn tampered_artifact_subject_is_invalid() {
    let mut tampered = REAL_TARBALL.to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;

    let bundle = serde_json::from_str(REAL_BUNDLE).unwrap();
    assert!(matches!(
        verdict(&bundle, &tampered),
        SigstoreVerdict::SignatureInvalid { .. }
    ));
}

#[test]
fn corrupted_dsse_signature_is_invalid() {
    assert_bundle_invalid(|bundle| {
        bundle["dsseEnvelope"]["signatures"][0]["sig"] = "AA==".into();
    });
}

#[test]
fn missing_or_forged_set_is_invalid() {
    assert_bundle_invalid(|bundle| {
        bundle["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionPromise");
    });
    assert_bundle_invalid(|bundle| {
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"]
            ["signedEntryTimestamp"] = "AA==".into();
    });
}

#[test]
fn invalid_integrated_times_are_rejected() {
    for invalid_time in [0_i64, 1, 4_102_444_800] {
        assert_bundle_invalid(|bundle| {
            bundle["verificationMaterial"]["tlogEntries"][0]["integratedTime"] =
                invalid_time.to_string().into();
        });
    }
}

#[test]
fn rekor_body_or_inclusion_proof_mismatch_is_invalid() {
    assert_bundle_invalid(|bundle| {
        let encoded = bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
            ["rootHash"]
            .as_str()
            .unwrap();
        let mut root_hash = STANDARD.decode(encoded).unwrap();
        root_hash[0] ^= 1;
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["rootHash"] =
            STANDARD.encode(root_hash).into();
    });
    assert_bundle_invalid(|bundle| {
        let encoded = bundle["verificationMaterial"]["tlogEntries"][0]["canonicalizedBody"]
            .as_str()
            .unwrap();
        let mut body: serde_json::Value =
            serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
        body["spec"]["content"]["payloadHash"]["value"] = "00".repeat(32).into();
        bundle["verificationMaterial"]["tlogEntries"][0]["canonicalizedBody"] =
            STANDARD.encode(serde_json::to_vec(&body).unwrap()).into();
    });
}

#[test]
fn downgraded_bundle_without_inclusion_material_is_invalid() {
    assert_bundle_invalid(|bundle| {
        bundle["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.1".into();
        bundle["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionProof");
    });
    assert_bundle_invalid(|bundle| {
        bundle["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.1".into();
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
            .as_object_mut()
            .unwrap()
            .remove("checkpoint");
    });
}

#[test]
fn every_tlog_entry_requires_inclusion_material() {
    assert_bundle_invalid(|bundle| {
        bundle["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.1".into();
        let mut unproven_entry = bundle["verificationMaterial"]["tlogEntries"][0].clone();
        unproven_entry
            .as_object_mut()
            .unwrap()
            .remove("inclusionProof");
        bundle["verificationMaterial"]["tlogEntries"]
            .as_array_mut()
            .unwrap()
            .push(unproven_entry);
    });
}

#[test]
fn unproven_tlog_entry_cannot_supply_validation_time() {
    assert_bundle_invalid(|bundle| {
        bundle["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.1".into();
        let proven_entry = bundle["verificationMaterial"]["tlogEntries"][0].clone();
        bundle["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionProof");
        bundle["verificationMaterial"]["tlogEntries"]
            .as_array_mut()
            .unwrap()
            .push(proven_entry);
    });
}

#[test]
fn broken_fulcio_chain_is_invalid() {
    assert_bundle_invalid(|bundle| {
        let encoded = bundle["verificationMaterial"]["x509CertificateChain"]["certificates"][0]
            ["rawBytes"]
            .as_str()
            .unwrap();
        let mut cert = STANDARD.decode(encoded).unwrap();
        *cert.last_mut().unwrap() ^= 1;
        bundle["verificationMaterial"]["x509CertificateChain"]["certificates"][0]["rawBytes"] =
            STANDARD.encode(cert).into();
    });
}

#[test]
fn wrong_ct_log_key_rejects_the_embedded_sct() {
    let mut root: serde_json::Value = serde_json::from_str(TRUSTED_ROOT).unwrap();
    for ctlog in root["ctlogs"].as_array_mut().unwrap() {
        let encoded = ctlog["publicKey"]["rawBytes"].as_str().unwrap();
        let mut key = STANDARD.decode(encoded).unwrap();
        *key.last_mut().unwrap() ^= 1;
        ctlog["publicKey"]["rawBytes"] = STANDARD.encode(key).into();
    }

    let trusted_root = TrustedRoot::from_json(&root.to_string()).unwrap();
    let bundle = Bundle::from_json(REAL_BUNDLE).unwrap();
    let policy =
        VerificationPolicy::default().require_issuer(GITHUB_ACTIONS_OIDC_ISSUER.to_string());
    let err = sigstore_verify::verify(REAL_TARBALL, &bundle, &policy, &trusted_root).unwrap_err();
    assert!(
        err.to_string().contains("SCT"),
        "wrong CT key must fail SCT verification, got: {err}"
    );
}

#[test]
fn issuer_and_identity_policy_mismatches_are_invalid() {
    let bundle: serde_json::Value = serde_json::from_str(REAL_BUNDLE).unwrap();
    let patterns = permissive_allowlist();
    let wrong_issuer = IdentityAllowlist {
        issuer: "https://issuer.invalid",
        san_uri_patterns: &patterns,
    };
    assert!(matches!(
        verify_bundle_full(&bundle.to_string(), REAL_TARBALL, &wrong_issuer).unwrap(),
        SigstoreVerdict::SignatureInvalid { .. }
    ));

    let wrong_patterns = vec![Regex::new(r"^https://example\.invalid/.+$").unwrap()];
    let wrong_identity = IdentityAllowlist {
        issuer: GITHUB_ACTIONS_OIDC_ISSUER,
        san_uri_patterns: &wrong_patterns,
    };
    assert!(matches!(
        verify_bundle_full(&bundle.to_string(), REAL_TARBALL, &wrong_identity).unwrap(),
        SigstoreVerdict::SignatureInvalid { .. }
    ));
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
