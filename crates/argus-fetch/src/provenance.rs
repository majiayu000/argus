//! npm OIDC provenance — attestations subject-digest cross-check.
//!
//! Packages published with `npm publish --provenance` carry a
//! `dist.attestations.url` pointing to a JSON document containing one or more
//! Sigstore bundles. Each bundle wraps a DSSE envelope, whose decoded payload
//! is an in-toto Statement with a `subject` array. Every subject names the
//! published package and a `digest` map.
//!
//! For npm specifically, the subject's `sha512` field is the same digest the
//! packument advertises in `dist.integrity` — it is the SHA-512 of the
//! tarball bytes (verified, after our PR #6, before extraction).
//!
//! What this module does:
//!
//! - Parse the attestations JSON.
//! - Decode each DSSE payload.
//! - Pull out subject digests + SLSA builder id (when present).
//! - Return a summary the caller can cross-check against the actual tarball
//!   bytes it just downloaded.
//!
//! What this module **does not** do (yet):
//!
//! - Verify Sigstore signatures, Fulcio certificate chains, or Rekor
//!   inclusion proofs. Catching forged attestations needs the `sigstore`
//!   crate; that work is tracked in the M2 follow-up issue.

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
struct AttestationsFile {
    attestations: Vec<RawAttestation>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawAttestation {
    #[serde(rename = "predicateType")]
    predicate_type: String,
    bundle: RawBundle,
}

#[derive(Debug, Clone, Deserialize)]
struct RawBundle {
    #[serde(rename = "dsseEnvelope")]
    dsse_envelope: DsseEnvelope,
}

#[derive(Debug, Clone, Deserialize)]
struct DsseEnvelope {
    /// Base64-encoded in-toto Statement.
    payload: String,
}

/// In-toto Statement v0.1 / v1 (we accept either; the fields we need are the
/// same).
#[derive(Debug, Clone, Deserialize)]
struct InTotoStatement {
    subject: Vec<Subject>,
    /// SLSA `predicate` object. We only care about the builder id; everything
    /// else is decoded opaquely.
    #[serde(default)]
    predicate: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct Subject {
    name: String,
    digest: BTreeMap<String, String>,
}

/// One attestation summary fit for cross-checking.
#[derive(Debug, Clone)]
pub struct AttestationSummary {
    pub predicate_type: String,
    pub subject_name: String,
    pub sha512_hex: Option<String>,
    pub builder_id: Option<String>,
}

/// Parse the JSON document at `dist.attestations.url`. Returns one
/// `AttestationSummary` per attestation entry whose subject carries a
/// SHA-512 digest. Malformed attestation payloads are errors: provenance
/// data that exists but cannot be decoded must remain visible to policy,
/// not collapse into "no subject digest present".
pub fn parse_attestations(raw: &[u8]) -> Result<Vec<AttestationSummary>> {
    let file: AttestationsFile =
        serde_json::from_slice(raw).context("parse npm attestations JSON")?;
    let mut out = Vec::new();
    for att in file.attestations {
        let payload_bytes = STANDARD
            .decode(att.bundle.dsse_envelope.payload.as_bytes())
            .with_context(|| format!("decode DSSE payload for {}", att.predicate_type))?;
        let stmt: InTotoStatement = serde_json::from_slice(&payload_bytes)
            .with_context(|| format!("parse in-toto Statement in {}", att.predicate_type))?;
        for subj in stmt.subject {
            let sha512_hex = subj.digest.get("sha512").cloned();
            let builder_id = stmt
                .predicate
                .as_ref()
                .and_then(|p| p.get("buildDefinition"))
                .and_then(|bd| bd.get("buildType"))
                .or_else(|| {
                    stmt.predicate
                        .as_ref()
                        .and_then(|p| p.get("builder"))
                        .and_then(|b| b.get("id"))
                })
                .and_then(|v| v.as_str())
                .map(str::to_string);
            out.push(AttestationSummary {
                predicate_type: att.predicate_type.clone(),
                subject_name: subj.name,
                sha512_hex,
                builder_id,
            });
        }
    }
    Ok(out)
}

/// Cross-check verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectCheck {
    /// At least one attestation subject's sha512 matches the bytes.
    Matched {
        subject_name: String,
        predicate_type: String,
        builder_id: Option<String>,
    },
    /// Attestations were present but none agreed on the bytes we have.
    Mismatch {
        expected: Vec<String>,
        actual_hex: String,
    },
    /// No attestation carried a sha512 subject digest. We cannot conclude
    /// anything; treat as informational only.
    NoSha512Subject,
}

/// Compare the SHA-512 digest of the tarball against every attestation
/// subject. Returns the strongest verdict we can derive.
pub fn check_subject_digest(
    summaries: &[AttestationSummary],
    tarball_sha512_hex: &str,
) -> SubjectCheck {
    let mut expected: Vec<String> = Vec::new();
    for s in summaries {
        if let Some(hex) = &s.sha512_hex {
            if hex.eq_ignore_ascii_case(tarball_sha512_hex) {
                return SubjectCheck::Matched {
                    subject_name: s.subject_name.clone(),
                    predicate_type: s.predicate_type.clone(),
                    builder_id: s.builder_id.clone(),
                };
            }
            expected.push(hex.clone());
        }
    }
    if expected.is_empty() {
        SubjectCheck::NoSha512Subject
    } else {
        SubjectCheck::Mismatch {
            expected,
            actual_hex: tarball_sha512_hex.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_NPM_ATTESTATION: &str = include_str!("testdata/sigstore_2_3_1_attestations.json");

    #[test]
    fn parses_real_npm_attestations_file() {
        let summaries = parse_attestations(REAL_NPM_ATTESTATION.as_bytes()).unwrap();
        assert_eq!(summaries.len(), 2, "two attestations expected");
        // Both subjects should carry the same sha512 for sigstore@2.3.1.
        let s = &summaries[0];
        assert!(s.subject_name.contains("sigstore@2.3.1"));
        assert_eq!(
            s.sha512_hex.as_deref(),
            Some(
                "f06fbf5c353cc0db093904b9cac0d53b412d83dff6b80e6047d9786708a38e5c\
                 3105cad4e913dfc22dbe8c999b3fe029d47969fe75406843b8163db6fd22f681"
            )
        );
    }

    #[test]
    fn check_subject_digest_matches() {
        let summaries = parse_attestations(REAL_NPM_ATTESTATION.as_bytes()).unwrap();
        let real_hex = "f06fbf5c353cc0db093904b9cac0d53b412d83dff6b80e6047d9786708a38e5c\
                        3105cad4e913dfc22dbe8c999b3fe029d47969fe75406843b8163db6fd22f681";
        match check_subject_digest(&summaries, real_hex) {
            SubjectCheck::Matched { .. } => {}
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn check_subject_digest_case_insensitive() {
        let summaries = parse_attestations(REAL_NPM_ATTESTATION.as_bytes()).unwrap();
        let upper_hex = "F06FBF5C353CC0DB093904B9CAC0D53B412D83DFF6B80E6047D9786708A38E5C\
                         3105CAD4E913DFC22DBE8C999B3FE029D47969FE75406843B8163DB6FD22F681";
        match check_subject_digest(&summaries, upper_hex) {
            SubjectCheck::Matched { .. } => {}
            other => panic!("expected Matched (case-insensitive), got {other:?}"),
        }
    }

    #[test]
    fn check_subject_digest_mismatch_returns_expected_list() {
        let summaries = parse_attestations(REAL_NPM_ATTESTATION.as_bytes()).unwrap();
        let wrong_hex = "0".repeat(128);
        match check_subject_digest(&summaries, &wrong_hex) {
            SubjectCheck::Mismatch {
                expected,
                actual_hex,
            } => {
                assert!(!expected.is_empty());
                assert_eq!(actual_hex, wrong_hex);
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn check_subject_digest_no_sha512_returns_no_subject() {
        let summaries = vec![AttestationSummary {
            predicate_type: "x".to_string(),
            subject_name: "y".to_string(),
            sha512_hex: None,
            builder_id: None,
        }];
        assert_eq!(
            check_subject_digest(&summaries, "deadbeef"),
            SubjectCheck::NoSha512Subject
        );
    }

    #[test]
    fn rejects_malformed_attestations_json() {
        let err = parse_attestations(b"not json").unwrap_err();
        assert!(err.to_string().contains("parse npm attestations JSON"));
    }

    #[test]
    fn rejects_malformed_intoto_statement_payload() -> Result<()> {
        let payload_b64 = STANDARD.encode(br#"{"not":"a statement"}"#);
        let attestations = serde_json::json!({
            "attestations": [{
                "predicateType": "https://slsa.dev/provenance/v1",
                "bundle": {
                    "dsseEnvelope": { "payload": payload_b64 }
                }
            }]
        })
        .to_string();

        let err = match parse_attestations(attestations.as_bytes()) {
            Ok(summaries) => {
                anyhow::bail!("malformed in-toto payload was accepted as {summaries:?}")
            }
            Err(err) => err.to_string(),
        };
        assert!(err.contains("parse in-toto Statement"), "got: {err}");
        Ok(())
    }
}
