//! DSSE (Dead Simple Signing Envelope) signature verification.
//!
//! A Sigstore bundle wraps a DSSE envelope. The envelope's `payload` is a
//! base64-encoded in-toto Statement; the signature is computed over the
//! envelope's **Pre-Authentication Encoding** (PAE), not over the raw payload.
//!
//! This module verifies that the envelope signature was produced by the
//! private key matching the public key embedded in the leaf certificate of
//! `verificationMaterial.x509CertificateChain`. It does NOT (yet) verify the
//! Fulcio certificate chain or the Rekor transparency-log inclusion proof —
//! those are later milestones (see docs/design/sigstore-verification.md).
//!
//! No certificate-trust decision is made here: a signature that verifies
//! against an embedded leaf cert only proves "whoever holds this cert's key
//! signed this payload", not that the cert is trustworthy. Trust-root and
//! OIDC-identity checks live in a separate layer.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use spki::DecodePublicKey;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

/// secp256r1 / prime256v1 (NIST P-256).
const OID_P256: &str = "1.2.840.10045.3.1.7";
/// secp384r1 (NIST P-384).
const OID_P384: &str = "1.3.132.0.34";

/// Outcome of verifying one DSSE envelope's signature against its embedded
/// leaf certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsseVerdict {
    /// The signature verified against the leaf certificate's public key.
    ///
    /// This is a cryptographic fact about the envelope, NOT a trust decision.
    /// The caller must still verify the certificate chain and OIDC identity
    /// before treating the attestation as trustworthy.
    Verified,
    /// The envelope is well-formed and uses a supported key algorithm, but the
    /// signature did not verify against the leaf certificate's public key.
    SignatureInvalid { reason: String },
    /// The bundle does not carry an x509 certificate chain we can verify a
    /// DSSE signature against — e.g. it uses a bare `publicKey` hint
    /// (npm-keyring path) or an unsupported key algorithm. Not a failure;
    /// the caller decides how to treat it.
    Unsupported { reason: String },
}

#[derive(Debug, Clone, Deserialize)]
struct Bundle {
    #[serde(rename = "verificationMaterial")]
    verification_material: VerificationMaterial,
    #[serde(rename = "dsseEnvelope")]
    dsse_envelope: Envelope,
}

#[derive(Debug, Clone, Deserialize)]
struct VerificationMaterial {
    #[serde(rename = "x509CertificateChain")]
    x509_certificate_chain: Option<X509Chain>,
    #[serde(rename = "certificate")]
    certificate: Option<Cert>,
    #[serde(rename = "publicKey")]
    public_key: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct X509Chain {
    certificates: Vec<Cert>,
}

#[derive(Debug, Clone, Deserialize)]
struct Cert {
    /// base64-encoded DER certificate.
    #[serde(rename = "rawBytes")]
    raw_bytes: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Envelope {
    payload: String,
    #[serde(rename = "payloadType")]
    payload_type: String,
    signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, Clone, Deserialize)]
struct EnvelopeSignature {
    sig: String,
}

/// Verify the DSSE signature of a single Sigstore bundle (parsed from JSON)
/// against the leaf certificate embedded in its verification material.
pub fn verify_bundle_dsse(bundle_json: &[u8]) -> Result<DsseVerdict> {
    let bundle: Bundle =
        serde_json::from_slice(bundle_json).context("parse Sigstore bundle JSON")?;

    let leaf_b64 = match leaf_cert_b64(&bundle.verification_material) {
        Some(b64) => b64,
        None => {
            return Ok(DsseVerdict::Unsupported {
                reason: "bundle has no x509CertificateChain/certificate (bare publicKey hint or \
                         missing material); DSSE signature cannot be checked against a cert"
                    .to_string(),
            })
        }
    };

    let leaf_der = STANDARD
        .decode(leaf_b64.as_bytes())
        .context("base64-decode leaf certificate rawBytes")?;

    let env = &bundle.dsse_envelope;
    let signature = env
        .signatures
        .first()
        .ok_or_else(|| anyhow!("DSSE envelope carries no signatures"))?;
    let sig_der = STANDARD
        .decode(signature.sig.as_bytes())
        .context("base64-decode DSSE signature")?;
    let payload = STANDARD
        .decode(env.payload.as_bytes())
        .context("base64-decode DSSE payload")?;

    verify_dsse_signature(&env.payload_type, &payload, &sig_der, &leaf_der)
}

/// The lowest-level primitive: verify that `sig_der` (ASN.1 DER ECDSA) is a
/// valid signature over `PAE(payload_type, payload)` for the public key in
/// `leaf_cert_der` (DER X.509).
pub fn verify_dsse_signature(
    payload_type: &str,
    payload: &[u8],
    sig_der: &[u8],
    leaf_cert_der: &[u8],
) -> Result<DsseVerdict> {
    let cert = Certificate::from_der(leaf_cert_der).context("parse leaf certificate DER")?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let spki_der = spki.to_der().context("re-encode certificate SPKI to DER")?;

    let curve_oid = ec_curve_oid(spki)?;
    let pae = pae(payload_type, payload);

    let verified = match curve_oid.as_deref() {
        Some(OID_P256) => verify_p256(&spki_der, &pae, sig_der),
        Some(OID_P384) => verify_p384(&spki_der, &pae, sig_der),
        other => {
            return Ok(DsseVerdict::Unsupported {
                reason: format!(
                    "leaf certificate public key is not P-256 or P-384 (curve OID {other:?}); \
                     only NIST P-256/P-384 ECDSA is supported"
                ),
            })
        }
    };

    Ok(match verified {
        Ok(()) => DsseVerdict::Verified,
        Err(e) => DsseVerdict::SignatureInvalid {
            reason: e.to_string(),
        },
    })
}

fn leaf_cert_b64(vm: &VerificationMaterial) -> Option<&str> {
    if let Some(chain) = &vm.x509_certificate_chain {
        if let Some(first) = chain.certificates.first() {
            return Some(&first.raw_bytes);
        }
    }
    if let Some(cert) = &vm.certificate {
        return Some(&cert.raw_bytes);
    }
    // `public_key` (hint) path is intentionally ignored here — it is the
    // npm-keyring case handled elsewhere.
    let _ = &vm.public_key;
    None
}

/// Extract the named-curve OID from an EC SubjectPublicKeyInfo.
fn ec_curve_oid(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<Option<String>> {
    use x509_cert::der::asn1::ObjectIdentifier;
    match &spki.algorithm.parameters {
        Some(any) => {
            let oid: ObjectIdentifier = any
                .decode_as()
                .context("decode EC named-curve parameters as OID")?;
            Ok(Some(oid.to_string()))
        }
        None => Ok(None),
    }
}

/// DSSE Pre-Authentication Encoding (PAE), per the DSSE spec:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, where SP is a single
/// 0x20 space and LEN is the ASCII-decimal byte length.
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

fn verify_p256(spki_der: &[u8], msg: &[u8], sig_der: &[u8]) -> Result<()> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let vk = VerifyingKey::from_public_key_der(spki_der)
        .map_err(|e| anyhow!("decode P-256 public key: {e}"))?;
    let sig = Signature::from_der(sig_der).map_err(|e| anyhow!("decode P-256 signature: {e}"))?;
    vk.verify(msg, &sig)
        .map_err(|e| anyhow!("P-256 signature did not verify: {e}"))
}

fn verify_p384(spki_der: &[u8], msg: &[u8], sig_der: &[u8]) -> Result<()> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let vk = VerifyingKey::from_public_key_der(spki_der)
        .map_err(|e| anyhow!("decode P-384 public key: {e}"))?;
    let sig = Signature::from_der(sig_der).map_err(|e| anyhow!("decode P-384 signature: {e}"))?;
    vk.verify(msg, &sig)
        .map_err(|e| anyhow!("P-384 signature did not verify: {e}"))
}
