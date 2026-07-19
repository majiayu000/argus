use crate::model::{validate_scalar, OsvError, MAX_ID_BYTES};
use argus_intel::{OsvAffectedMatch, OsvSeverity};
use polycvss::{Score, Vector, Version};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityLevel {
    Unknown,
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SeveritySource {
    #[serde(rename = "NVD")]
    Nvd,
    #[serde(rename = "CNA")]
    Cna,
    #[serde(rename = "SELF")]
    SelfReported,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SeverityEvidence {
    pub severity_type: String,
    pub score: String,
    pub source: Option<SeveritySource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedSeverity {
    pub level: SeverityLevel,
    pub base_score: Option<String>,
    pub evidence: Vec<SeverityEvidence>,
}

pub fn normalize_severities(
    top_level: &[OsvSeverity],
    affected_matches: &[OsvAffectedMatch],
) -> Result<NormalizedSeverity, OsvError> {
    let affected = affected_matches
        .iter()
        .flat_map(|affected_match| affected_match.severity.iter())
        .collect::<Vec<_>>();
    if !top_level.is_empty() && !affected.is_empty() {
        return Err(OsvError::malformed(
            "top-level and matching affected-level severity cannot both be present",
        ));
    }
    let selected = if affected.is_empty() {
        top_level.iter().collect::<Vec<_>>()
    } else {
        affected
    };

    let mut evidence = Vec::with_capacity(selected.len());
    let mut maximum_score: Option<Score> = None;
    for severity in selected {
        validate_scalar("severity type", &severity.severity_type, MAX_ID_BYTES)?;
        validate_scalar("severity score", &severity.score, MAX_ID_BYTES)?;
        let source = normalize_source(severity.source.as_deref())?;
        let score = match severity.severity_type.as_str() {
            "CVSS_V2" => Some(parse_cvss(
                &severity.score,
                |version| version == Version::V20,
                "CVSS v2",
            )?),
            "CVSS_V3" => Some(parse_cvss(
                &severity.score,
                |version| matches!(version, Version::V30 | Version::V31),
                "CVSS v3",
            )?),
            "CVSS_V4" => Some(parse_cvss(
                &severity.score,
                |version| version == Version::V40,
                "CVSS v4",
            )?),
            "Ubuntu" => None,
            unsupported => {
                return Err(OsvError::malformed(format!(
                    "unsupported OSV severity type `{unsupported}`"
                )))
            }
        };
        if let Some(score) = score {
            maximum_score = Some(maximum_score.map_or(score, |current| current.max(score)));
        }
        evidence.push(SeverityEvidence {
            severity_type: severity.severity_type.clone(),
            score: severity.score.clone(),
            source,
        });
    }
    evidence.sort();
    evidence.dedup();

    let base_score = maximum_score.map(|score| score.to_string());
    let level = maximum_score.map_or(SeverityLevel::Unknown, score_level);
    Ok(NormalizedSeverity {
        level,
        base_score,
        evidence,
    })
}

fn normalize_source(source: Option<&str>) -> Result<Option<SeveritySource>, OsvError> {
    source
        .map(|source| match source {
            "NVD" => Ok(SeveritySource::Nvd),
            "CNA" => Ok(SeveritySource::Cna),
            "SELF" => Ok(SeveritySource::SelfReported),
            _ => Err(OsvError::malformed(format!(
                "unsupported OSV severity source `{source}`"
            ))),
        })
        .transpose()
}

fn parse_cvss(
    raw: &str,
    expected_version: impl FnOnce(Version) -> bool,
    label: &str,
) -> Result<Score, OsvError> {
    let vector = raw
        .parse::<Vector>()
        .map_err(|error| OsvError::malformed(format!("invalid {label} vector `{raw}`: {error}")))?;
    if !expected_version(Version::from(vector)) {
        return Err(OsvError::malformed(format!(
            "{label} severity carries a different CVSS version"
        )));
    }
    Ok(vector.base_score())
}

fn score_level(score: Score) -> SeverityLevel {
    let numeric = f64::from(score);
    match numeric {
        0.0 => SeverityLevel::None,
        value if value < 4.0 => SeverityLevel::Low,
        value if value < 7.0 => SeverityLevel::Medium,
        value if value < 9.0 => SeverityLevel::High,
        _ => SeverityLevel::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn severity(severity_type: &str, score: &str, source: Option<&str>) -> OsvSeverity {
        OsvSeverity {
            severity_type: severity_type.to_string(),
            score: score.to_string(),
            source: source.map(str::to_string),
        }
    }

    #[test]
    fn severity_matrix_scores_cvss_v2_v3_v4() {
        let cases = [
            (
                "CVSS_V2",
                "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "10.0",
                SeverityLevel::Critical,
            ),
            (
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "9.8",
                SeverityLevel::Critical,
            ),
            (
                "CVSS_V4",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                "10.0",
                SeverityLevel::Critical,
            ),
        ];
        for (severity_type, raw, score, level) in cases {
            let normalized =
                normalize_severities(&[severity(severity_type, raw, None)], &[]).unwrap();
            assert_eq!(normalized.base_score.as_deref(), Some(score));
            assert_eq!(normalized.level, level);
        }
    }

    #[test]
    fn severity_matrix_preserves_unknown_and_sources() {
        let missing = normalize_severities(&[], &[]).unwrap();
        assert_eq!(missing.level, SeverityLevel::Unknown);
        assert_eq!(missing.base_score, None);

        let ubuntu = normalize_severities(&[severity("Ubuntu", "high", Some("CNA"))], &[]).unwrap();
        assert_eq!(ubuntu.level, SeverityLevel::Unknown);
        assert_eq!(ubuntu.evidence[0].source, Some(SeveritySource::Cna));
        assert_eq!(
            serde_json::to_string(&SeveritySource::SelfReported).unwrap(),
            "\"SELF\""
        );

        assert!(normalize_severities(
            &[severity("CVSS_V3", "CVSS:4.0/not-valid", Some("NVD"))],
            &[]
        )
        .is_err());
        assert!(normalize_severities(
            &[severity(
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                Some("UNKNOWN")
            )],
            &[]
        )
        .is_err());
    }
}
