use crate::{IntegrityEvidence, IntegrityState};
use base64::Engine as _;

#[derive(Clone, Copy)]
pub(crate) enum DigestEncoding {
    Hex,
    Base64,
    HexOrBase64,
}

pub(crate) fn valid_digest(value: &str, expected_bytes: usize, encoding: DigestEncoding) -> bool {
    let valid_hex = || {
        expected_bytes.checked_mul(2).is_some_and(|expected_len| {
            value.len() == expected_len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    };
    let valid_base64 = || {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .is_ok_and(|decoded| decoded.len() == expected_bytes)
    };

    match encoding {
        DigestEncoding::Hex => valid_hex(),
        DigestEncoding::Base64 => valid_base64(),
        DigestEncoding::HexOrBase64 => valid_hex() || valid_base64(),
    }
}

pub(crate) fn parse_sri(value: &str, locator: &str) -> (IntegrityState, Vec<IntegrityEvidence>) {
    let mut evidence = Vec::new();
    let mut invalid = value.is_empty();

    for token in value.split_ascii_whitespace() {
        let Some((algorithm, digest)) = token.split_once('-') else {
            invalid = true;
            evidence.push(invalid_evidence(token, locator));
            continue;
        };
        let normalized_algorithm = algorithm.to_ascii_lowercase();
        let expected_bytes = match normalized_algorithm.as_str() {
            "sha1" => Some(20),
            "sha256" => Some(32),
            "sha384" => Some(48),
            "sha512" => Some(64),
            _ => None,
        };
        if expected_bytes.is_none_or(|expected_bytes| {
            !valid_digest(digest, expected_bytes, DigestEncoding::Base64)
        }) {
            invalid = true;
        }
        evidence.push(IntegrityEvidence {
            algorithm: Some(normalized_algorithm),
            value: Some(digest.to_string()),
            locator: locator.to_string(),
        });
    }

    if evidence.is_empty() {
        evidence.push(invalid_evidence(value, locator));
        invalid = true;
    }

    (
        if invalid {
            IntegrityState::Invalid
        } else {
            IntegrityState::RequiredPresent
        },
        evidence,
    )
}

fn invalid_evidence(value: &str, locator: &str) -> IntegrityEvidence {
    IntegrityEvidence {
        algorithm: None,
        value: Some(value.to_string()),
        locator: locator.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_sri, valid_digest, DigestEncoding};
    use crate::IntegrityState;
    use base64::Engine as _;

    fn encoded(bytes: usize) -> String {
        base64::engine::general_purpose::STANDARD.encode(vec![0; bytes])
    }

    #[test]
    fn digest_encodings_enforce_alphabet_and_decoded_length() {
        assert!(valid_digest(&"a".repeat(40), 20, DigestEncoding::Hex));
        assert!(valid_digest(&"A".repeat(40), 20, DigestEncoding::Hex));
        assert!(!valid_digest(&"a".repeat(39), 20, DigestEncoding::Hex));
        assert!(!valid_digest(&"g".repeat(40), 20, DigestEncoding::Hex));
        assert!(!valid_digest("", usize::MAX, DigestEncoding::Hex));

        assert!(valid_digest(&encoded(32), 32, DigestEncoding::Base64));
        assert!(!valid_digest(&encoded(31), 32, DigestEncoding::Base64));
        assert!(!valid_digest(&"a".repeat(64), 32, DigestEncoding::Base64));

        assert!(valid_digest(
            &"a".repeat(64),
            32,
            DigestEncoding::HexOrBase64
        ));
        assert!(valid_digest(&encoded(32), 32, DigestEncoding::HexOrBase64));
        assert!(!valid_digest(
            "not-a-digest",
            32,
            DigestEncoding::HexOrBase64
        ));
    }

    #[test]
    fn sri_accepts_supported_algorithms_case_insensitively() {
        let value = format!(
            "SHA1-{} sha256-{} Sha384-{} sHa512-{}",
            encoded(20),
            encoded(32),
            encoded(48),
            encoded(64)
        );
        let (state, evidence) = parse_sri(&value, "record.integrity");

        assert_eq!(state, IntegrityState::RequiredPresent);
        assert_eq!(evidence.len(), 4);
        assert_eq!(
            evidence
                .iter()
                .map(|item| item.algorithm.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("sha1"), Some("sha256"), Some("sha384"), Some("sha512")]
        );
        assert!(evidence
            .iter()
            .all(|item| item.locator == "record.integrity"));
    }

    #[test]
    fn sri_preserves_duplicate_tokens_and_their_evidence() {
        let token = format!("sha256-{}", encoded(32));
        let (state, evidence) = parse_sri(&format!("{token} {token}"), "same.locator");

        assert_eq!(state, IntegrityState::RequiredPresent);
        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[0], evidence[1]);
    }

    #[test]
    fn one_invalid_sri_token_invalidates_the_whole_value() {
        let valid = format!("sha512-{}", encoded(64));
        for invalid in [
            "sha999-AAAA",
            "sha256-AAAA",
            "sha256-not+standard/base64?",
            "missing-separator-extra",
            "bare-token",
        ] {
            let (state, evidence) = parse_sri(&format!("{valid} {invalid}"), "artifact.integrity");
            assert_eq!(state, IntegrityState::Invalid, "{invalid}");
            assert_eq!(evidence.len(), 2, "{invalid}");
            assert_eq!(evidence[1].locator, "artifact.integrity");
        }
    }

    #[test]
    fn empty_sri_is_invalid_and_retains_raw_evidence() {
        for value in ["", "   "] {
            let (state, evidence) = parse_sri(value, "empty.integrity");
            assert_eq!(state, IntegrityState::Invalid);
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[0].algorithm, None);
            assert_eq!(evidence[0].value.as_deref(), Some(value));
            assert_eq!(evidence[0].locator, "empty.integrity");
        }
    }
}
