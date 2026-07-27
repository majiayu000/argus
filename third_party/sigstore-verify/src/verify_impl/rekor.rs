//! Rekor transparency log entry validation
//!
//! This module handles validation of different Rekor entry types against
//! bundle content to ensure consistency.

use crate::error::{Error, Result};
use base64::Engine;
use sigstore_rekor::body::RekorEntryBody;
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Bundle, SignatureContent, TransparencyLogEntry};

/// Verify that all log entries are consistent with the bundle's content and artifact
pub fn verify_tlog_consistency(
    bundle: &Bundle,
    artifact: &sigstore_types::Artifact<'_>,
) -> Result<()> {
    for entry in &bundle.verification_material.tlog_entries {
        match &bundle.content {
            // DSSE envelope handling depends on Rekor version:
            // * Rekor 1 gives us a "dsse 0.0.1" entry (or "intoto 0.0.2")
            // * Rekor 2 gives us a "hashedrekord 0.0.2" entry
            SignatureContent::DsseEnvelope(envelope) => match entry.kind_version.kind.as_str() {
                "hashedrekord" => match entry.kind_version.version.as_str() {
                    "0.0.2" => {
                        super::hashedrekord::verify_hashedrekord_entry(entry, bundle, artifact)?;
                    }
                    version => {
                        return Err(Error::Verification(format!(
                            "unsupported hashedrekord entry version for DSSE envelope: {}",
                            version
                        )))
                    }
                },
                "dsse" => match entry.kind_version.version.as_str() {
                    "0.0.1" => verify_dsse_v001(entry, envelope, bundle)?,
                    version => {
                        return Err(Error::Verification(format!(
                            "unsupported dsse entry version: {}",
                            version
                        )))
                    }
                },
                "intoto" => match entry.kind_version.version.as_str() {
                    "0.0.2" => verify_intoto_v002(entry, envelope, bundle)?,
                    version => {
                        return Err(Error::Verification(format!(
                            "unsupported intoto entry version: {}",
                            version
                        )))
                    }
                },
                kind => {
                    return Err(Error::Verification(format!(
                        "unsupported log entry kind for DSSE envelope: {}",
                        kind
                    )))
                }
            },
            SignatureContent::MessageSignature(_) => match entry.kind_version.kind.as_str() {
                "hashedrekord" => match entry.kind_version.version.as_str() {
                    "0.0.1" | "0.0.2" => {
                        super::hashedrekord::verify_hashedrekord_entry(entry, bundle, artifact)?;
                    }
                    version => {
                        return Err(Error::Verification(format!(
                            "unsupported hashedrekord entry version: {}",
                            version
                        )))
                    }
                },
                kind => {
                    return Err(Error::Verification(format!(
                        "unsupported log entry kind for MessageSignature: {}",
                        kind
                    )))
                }
            },
        }
    }

    Ok(())
}

/// Verify DSSE v0.0.1 entry
///
/// NOTE: This does NOT verify the envelope hash.
/// The envelope hash in DSSE v0.0.1 entries cannot be reliably verified because:
/// 1. The hash is computed over uncanonicalized JSON during submission to Rekor
/// 2. JSON serialization can vary (field ordering, whitespace) between implementations
/// 3. We cannot reproduce the exact JSON representation that was originally submitted
///
/// Instead, we verify:
/// - Payload hash (hash of envelope.payload bytes)
/// - Signatures list matches between entry and envelope (both signature and verifier)
fn verify_dsse_v001(
    entry: &TransparencyLogEntry,
    envelope: &sigstore_types::DsseEnvelope,
    bundle: &Bundle,
) -> Result<()> {
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body.to_base64(),
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (expected_hash, rekor_signatures) = match &body {
        RekorEntryBody::DsseV001(dsse_body) => (
            &dsse_body.spec.payload_hash.value,
            &dsse_body.spec.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected DSSE v0.0.1 body, got different type".to_string(),
            ))
        }
    };

    // Verify payload hash (v0.0.1 uses hex encoding)
    let payload_bytes = envelope.payload.as_bytes();
    let payload_hash = sigstore_crypto::sha256(payload_bytes);
    let payload_hash_hex = hex::encode(payload_hash);

    if &payload_hash_hex != expected_hash {
        return Err(Error::Verification(format!(
            "DSSE payload hash mismatch: computed {}, expected {}",
            payload_hash_hex, expected_hash
        )));
    }

    // Extract the signing certificate from the bundle. Key-based bundles
    // carry no certificate (the Rekor verifier is a public key), so only the
    // signature bytes can be compared for them.
    let bundle_cert = match &bundle.verification_material.content {
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            certificates.first().map(|c| c.raw_bytes.clone())
        }
        VerificationMaterialContent::Certificate(cert) => Some(cert.raw_bytes.clone()),
        VerificationMaterialContent::PublicKey { .. } => None,
    };

    // Verify that the signatures in the bundle match what's in Rekor
    // This prevents signature substitution attacks
    // IMPORTANT: We must verify BOTH the signature bytes AND the verifier (certificate)
    if envelope.signatures.len() != rekor_signatures.len() {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has {}, Rekor entry has {}",
            envelope.signatures.len(),
            rekor_signatures.len()
        )));
    }

    // Check that each signature in the bundle exists in the Rekor entry
    // We must match both the signature AND the verifier to prevent signature substitution
    for bundle_sig in &envelope.signatures {
        let mut found = false;
        for rekor_sig in rekor_signatures {
            if bundle_sig.sig.as_bytes() != rekor_sig.signature.as_bytes() {
                continue;
            }
            match &bundle_cert {
                Some(cert) => {
                    // Convert Rekor's PEM verifier to DER for canonical comparison
                    let rekor_cert_der = rekor_sig
                        .to_certificate()
                        .map_err(|e| Error::Verification(format!("{}", e)))?;
                    if cert.as_bytes() == rekor_cert_der.as_bytes() {
                        found = true;
                        break;
                    }
                }
                None => {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(Error::Verification(
                "DSSE signature in bundle does not match any signature in Rekor entry (signature or verifier mismatch)".to_string(),
            ));
        }
    }

    Ok(())
}

/// Verify intoto v0.0.2 entry
fn verify_intoto_v002(
    entry: &TransparencyLogEntry,
    envelope: &sigstore_types::DsseEnvelope,
    bundle: &Bundle,
) -> Result<()> {
    let body: CommittedIntotoV002 = serde_json::from_slice(entry.canonicalized_body.as_bytes())
        .map_err(|e| {
            Error::Verification(format!(
                "failed to parse committed intoto v0.0.2 body: {}",
                e
            ))
        })?;
    let content = body.spec.content;

    if content.envelope.payload_type != envelope.payload_type {
        return Err(Error::Verification(
            "DSSE payload type does not match intoto Rekor entry".to_string(),
        ));
    }
    if content.payload_hash.algorithm != "sha256" {
        return Err(Error::Verification(format!(
            "unsupported intoto payload hash algorithm: {}",
            content.payload_hash.algorithm
        )));
    }
    let payload_hash = hex::encode(sigstore_crypto::sha256(envelope.payload.as_bytes()));
    if payload_hash != content.payload_hash.value {
        return Err(Error::Verification(format!(
            "DSSE payload hash mismatch: computed {}, expected {}",
            payload_hash, content.payload_hash.value
        )));
    }

    let bundle_cert =
        crate::verify_impl::helpers::extract_certificate(&bundle.verification_material.content)?;
    if envelope.signatures.len() != content.envelope.signatures.len() {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has {}, Rekor entry has {}",
            envelope.signatures.len(),
            content.envelope.signatures.len()
        )));
    }

    for bundle_sig in &envelope.signatures {
        let mut found_match = false;
        for rekor_sig in &content.envelope.signatures {
            let sig_b64 = base64::engine::general_purpose::STANDARD
                .decode(rekor_sig.sig.as_bytes())
                .map_err(|e| {
                    Error::Verification(format!("failed to decode Rekor signature: {}", e))
                })?;
            let sig_bytes = base64::engine::general_purpose::STANDARD
                .decode(&sig_b64)
                .map_err(|e| {
                    Error::Verification(format!("failed to decode nested Rekor signature: {}", e))
                })?;
            if bundle_sig.sig.as_bytes() != sig_bytes {
                continue;
            }

            let pem_bytes = base64::engine::general_purpose::STANDARD
                .decode(rekor_sig.public_key.as_bytes())
                .map_err(|e| {
                    Error::Verification(format!("failed to decode Rekor public key: {}", e))
                })?;
            let pem = std::str::from_utf8(&pem_bytes).map_err(|e| {
                Error::Verification(format!("Rekor public key is not UTF-8 PEM: {}", e))
            })?;
            let rekor_cert = sigstore_types::DerCertificate::from_pem(pem).map_err(|e| {
                Error::Verification(format!("failed to parse Rekor certificate: {}", e))
            })?;
            if bundle_cert.as_bytes() == rekor_cert.as_bytes() {
                found_match = true;
                break;
            }
        }
        if !found_match {
            return Err(Error::Verification(
                "DSSE signature in bundle does not match any signature and certificate in intoto Rekor entry".to_string(),
            ));
        }
    }

    // Rekor computes this over the original, non-canonical DSSE JSON bytes.
    // Those serialization bytes are not retained in a Sigstore bundle, so the
    // value cannot be reproduced. Require the declared algorithm and shape;
    // the verified SET and inclusion proof still bind the value to the log.
    if content.hash.algorithm != "sha256"
        || content.hash.value.len() != 64
        || hex::decode(&content.hash.value).is_err()
    {
        return Err(Error::Verification(
            "invalid committed intoto envelope hash".to_string(),
        ));
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct CommittedIntotoV002 {
    spec: CommittedIntotoSpec,
}

#[derive(serde::Deserialize)]
struct CommittedIntotoSpec {
    content: CommittedIntotoContent,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommittedIntotoContent {
    envelope: CommittedIntotoEnvelope,
    hash: CommittedHash,
    payload_hash: CommittedHash,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommittedIntotoEnvelope {
    payload_type: String,
    signatures: Vec<CommittedIntotoSignature>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommittedIntotoSignature {
    sig: String,
    public_key: String,
}

#[derive(serde::Deserialize)]
struct CommittedHash {
    algorithm: String,
    value: String,
}
