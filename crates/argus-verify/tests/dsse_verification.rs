//! Offline synthetic-fixture tests for DSSE signature verification.
//!
//! These do not touch the network or any real Sigstore trust root. Each test
//! generates a P-256 key, embeds its public key in a self-signed X.509 cert
//! (via rcgen), signs a DSSE Pre-Authentication Encoding with that key, and
//! checks that argus-verify reaches the expected verdict.

use argus_verify::{verify_bundle_dsse, verify_dsse_signature, DsseVerdict};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use rand_core::OsRng;

/// Independent reimplementation of the DSSE PAE so a bug in the library's
/// own PAE construction cannot be masked by sharing the same code.
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(format!("{}", payload_type.len()).as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(format!("{}", payload.len()).as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Generate a P-256 signing key and a self-signed DER certificate whose
/// embedded public key matches that key.
fn keypair_and_cert() -> (SigningKey, Vec<u8>) {
    let signing_key = SigningKey::random(&mut OsRng);
    let pkcs8 = signing_key
        .to_pkcs8_der()
        .expect("export P-256 key to PKCS#8");
    let rc_key = rcgen::KeyPair::try_from(pkcs8.as_bytes()).expect("rcgen KeyPair from PKCS#8");
    let params =
        rcgen::CertificateParams::new(vec!["argus-test".to_string()]).expect("cert params");
    let cert = params.self_signed(&rc_key).expect("self-sign cert");
    (signing_key, cert.der().to_vec())
}

const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const PAYLOAD: &[u8] = br#"{"_type":"https://in-toto.io/Statement/v1","subject":[]}"#;

#[test]
fn valid_signature_verifies() {
    let (key, cert_der) = keypair_and_cert();
    let sig: Signature = key.sign(&pae(PAYLOAD_TYPE, PAYLOAD));
    let sig_der = sig.to_der();

    let verdict =
        verify_dsse_signature(PAYLOAD_TYPE, PAYLOAD, sig_der.as_bytes(), &cert_der).unwrap();
    assert_eq!(verdict, DsseVerdict::Verified);
}

#[test]
fn signature_from_wrong_key_is_invalid() {
    // Cert embeds key A; signature is produced by key B. This is the
    // forged-attestation case: a valid subject digest but a bogus signing key.
    let (_key_a, cert_der) = keypair_and_cert();
    let key_b = SigningKey::random(&mut OsRng);
    let sig: Signature = key_b.sign(&pae(PAYLOAD_TYPE, PAYLOAD));
    let sig_der = sig.to_der();

    let verdict =
        verify_dsse_signature(PAYLOAD_TYPE, PAYLOAD, sig_der.as_bytes(), &cert_der).unwrap();
    match verdict {
        DsseVerdict::SignatureInvalid { .. } => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn tampered_payload_is_invalid() {
    // Signature is over the original payload; verification is attempted over a
    // mutated payload. The PAE differs, so the signature must fail.
    let (key, cert_der) = keypair_and_cert();
    let sig: Signature = key.sign(&pae(PAYLOAD_TYPE, PAYLOAD));
    let sig_der = sig.to_der();

    let mut tampered = PAYLOAD.to_vec();
    tampered.extend_from_slice(b" ");
    let verdict =
        verify_dsse_signature(PAYLOAD_TYPE, &tampered, sig_der.as_bytes(), &cert_der).unwrap();
    match verdict {
        DsseVerdict::SignatureInvalid { .. } => {}
        other => panic!("expected SignatureInvalid for tampered payload, got {other:?}"),
    }
}

#[test]
fn bundle_json_with_cert_chain_verifies() {
    let (key, cert_der) = keypair_and_cert();
    let sig: Signature = key.sign(&pae(PAYLOAD_TYPE, PAYLOAD));
    let sig_der = sig.to_der();

    let bundle = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [
                    { "rawBytes": STANDARD.encode(&cert_der) }
                ]
            }
        },
        "dsseEnvelope": {
            "payload": STANDARD.encode(PAYLOAD),
            "payloadType": PAYLOAD_TYPE,
            "signatures": [
                { "sig": STANDARD.encode(sig_der.as_bytes()) }
            ]
        }
    });
    let verdict = verify_bundle_dsse(bundle.to_string().as_bytes()).unwrap();
    assert_eq!(verdict, DsseVerdict::Verified);
}

#[test]
fn bundle_json_tampered_payload_is_invalid() {
    let (key, cert_der) = keypair_and_cert();
    let sig: Signature = key.sign(&pae(PAYLOAD_TYPE, PAYLOAD));
    let sig_der = sig.to_der();

    // Envelope advertises a different payload than the one that was signed.
    let other_payload = br#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x"}]}"#;
    let bundle = serde_json::json!({
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [ { "rawBytes": STANDARD.encode(&cert_der) } ]
            }
        },
        "dsseEnvelope": {
            "payload": STANDARD.encode(other_payload),
            "payloadType": PAYLOAD_TYPE,
            "signatures": [ { "sig": STANDARD.encode(sig_der.as_bytes()) } ]
        }
    });
    let verdict = verify_bundle_dsse(bundle.to_string().as_bytes()).unwrap();
    match verdict {
        DsseVerdict::SignatureInvalid { .. } => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn bundle_with_only_public_key_hint_is_unsupported() {
    // npm-keyring path: no x509 chain, just a publicKey hint. DSSE signature
    // verification against a cert is not possible; expect Unsupported (not a
    // hard failure).
    let bundle = serde_json::json!({
        "verificationMaterial": {
            "publicKey": { "hint": "SHA256:examplehint" }
        },
        "dsseEnvelope": {
            "payload": STANDARD.encode(PAYLOAD),
            "payloadType": PAYLOAD_TYPE,
            "signatures": [ { "sig": STANDARD.encode(b"whatever") } ]
        }
    });
    let verdict = verify_bundle_dsse(bundle.to_string().as_bytes()).unwrap();
    match verdict {
        DsseVerdict::Unsupported { .. } => {}
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn malformed_bundle_json_errors() {
    let err = verify_bundle_dsse(b"not json").unwrap_err();
    assert!(err.to_string().contains("parse Sigstore bundle JSON"));
}
