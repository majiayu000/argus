use argus_core::PackageCoordinate;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

use crate::severity::NormalizedSeverity;

pub const MAX_COORDINATES: usize = 10_000;
pub const MAX_LOCATORS_PER_COORDINATE: usize = 10_000;
pub const MAX_PACKAGE_NAME_BYTES: usize = 4 * 1024;
pub const MAX_PACKAGE_VERSION_BYTES: usize = 1024;
pub const MAX_ID_BYTES: usize = 512;
pub const MAX_REFERENCE_URL_BYTES: usize = 8 * 1024;
pub const MAX_LOCATOR_BYTES: usize = 8 * 1024;
pub const MAX_KNOWN_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsvErrorKind {
    InvalidInput,
    UnsupportedSchema,
    MalformedResponse,
    IncompleteAnalysis,
    ResourceLimit,
    SnapshotRace,
    Transport,
    Cache,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsvError {
    pub kind: OsvErrorKind,
    pub detail: String,
}

impl OsvError {
    pub fn new(kind: OsvErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) fn invalid(detail: impl Into<String>) -> Self {
        Self::new(OsvErrorKind::InvalidInput, detail)
    }

    pub(crate) fn malformed(detail: impl Into<String>) -> Self {
        Self::new(OsvErrorKind::MalformedResponse, detail)
    }

    pub(crate) fn incomplete(detail: impl Into<String>) -> Self {
        Self::new(OsvErrorKind::IncompleteAnalysis, detail)
    }

    pub(crate) fn limit(detail: impl Into<String>) -> Self {
        Self::new(OsvErrorKind::ResourceLimit, detail)
    }
}

impl fmt::Display for OsvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}

impl Error for OsvError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinateQuery {
    pub coordinate: PackageCoordinate,
    pub locators: Vec<String>,
}

impl CoordinateQuery {
    pub fn new(
        coordinate: PackageCoordinate,
        locators: impl IntoIterator<Item = String>,
    ) -> Result<Self, OsvError> {
        validate_coordinate(&coordinate)?;
        let mut locators = locators.into_iter().collect::<Vec<_>>();
        normalize_locators(&mut locators)?;
        Ok(Self {
            coordinate,
            locators,
        })
    }

    pub fn validate(&self) -> Result<(), OsvError> {
        validate_coordinate(&self.coordinate)?;
        validate_locators(&self.locators)?;
        if self.locators.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(OsvError::invalid(
                "coordinate locators are not sorted and unique",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinateSet {
    pub queries: Vec<CoordinateQuery>,
    pub excluded_local_records: usize,
}

impl CoordinateSet {
    pub fn new(
        mut queries: Vec<CoordinateQuery>,
        excluded_local_records: usize,
    ) -> Result<Self, OsvError> {
        for query in &queries {
            query.validate()?;
        }
        queries.sort_by(|left, right| {
            query_identity(&left.coordinate)
                .cmp(&query_identity(&right.coordinate))
                .then_with(|| left.coordinate.cmp(&right.coordinate))
        });
        let mut merged: Vec<CoordinateQuery> = Vec::with_capacity(queries.len());
        for query in queries {
            if let Some(previous) = merged.last_mut().filter(|previous| {
                query_identity(&previous.coordinate) == query_identity(&query.coordinate)
            }) {
                previous.locators.extend(query.locators);
                normalize_locators(&mut previous.locators)?;
            } else {
                merged.push(query);
            }
        }
        if merged.len() > MAX_COORDINATES {
            return Err(OsvError::limit(format!(
                "coordinate count {} exceeds maximum {MAX_COORDINATES}",
                merged.len()
            )));
        }
        let set = Self {
            queries: merged,
            excluded_local_records,
        };
        ensure_known_evidence_size(&set, MAX_KNOWN_EVIDENCE_BYTES)?;
        Ok(set)
    }

    pub fn validate(&self) -> Result<(), OsvError> {
        for query in &self.queries {
            query.validate()?;
        }
        if self.queries.len() > MAX_COORDINATES {
            return Err(OsvError::limit(format!(
                "coordinate count {} exceeds maximum {MAX_COORDINATES}",
                self.queries.len()
            )));
        }
        if self
            .queries
            .windows(2)
            .any(|pair| query_identity(&pair[0].coordinate) >= query_identity(&pair[1].coordinate))
        {
            return Err(OsvError::invalid(
                "coordinate set is not in canonical order",
            ));
        }
        ensure_known_evidence_size(self, MAX_KNOWN_EVIDENCE_BYTES)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct QueryIdentity<'a> {
    pub ecosystem: argus_core::Ecosystem,
    pub name: &'a str,
    pub version: &'a str,
}

pub(crate) fn query_identity(coordinate: &PackageCoordinate) -> QueryIdentity<'_> {
    QueryIdentity {
        ecosystem: coordinate.ecosystem,
        name: &coordinate.canonical_name,
        version: &coordinate.version,
    }
}

pub(crate) fn canonical_query_coordinate(
    coordinate: &PackageCoordinate,
) -> Result<PackageCoordinate, OsvError> {
    PackageCoordinate::new(
        coordinate.ecosystem,
        coordinate.canonical_name.clone(),
        coordinate.version.clone(),
    )
    .map_err(|error| OsvError::invalid(format!("canonicalize query coordinate: {error}")))
}

fn ensure_known_evidence_size(coordinates: &CoordinateSet, maximum: usize) -> Result<(), OsvError> {
    let size = serde_json_canonicalizer::to_vec(&coordinates.queries)
        .map_err(|error| {
            OsvError::new(
                OsvErrorKind::Internal,
                format!("canonicalize known query evidence: {error}"),
            )
        })?
        .len();
    if size > maximum {
        return Err(OsvError::limit(format!(
            "known locator and coordinate evidence bytes {size} exceed maximum {maximum}"
        )));
    }
    Ok(())
}

fn validate_coordinate(coordinate: &PackageCoordinate) -> Result<(), OsvError> {
    coordinate
        .validate()
        .map_err(|error| OsvError::invalid(format!("invalid package coordinate: {error}")))?;
    if coordinate.original_name.len() > MAX_PACKAGE_NAME_BYTES {
        return Err(OsvError::limit(format!(
            "package name is {} bytes; maximum is {MAX_PACKAGE_NAME_BYTES}",
            coordinate.original_name.len()
        )));
    }
    if coordinate.original_version.len() > MAX_PACKAGE_VERSION_BYTES {
        return Err(OsvError::limit(format!(
            "package version is {} bytes; maximum is {MAX_PACKAGE_VERSION_BYTES}",
            coordinate.original_version.len()
        )));
    }
    argus_intel::validate_osv_coordinate(coordinate)
        .map_err(|error| OsvError::invalid(format!("invalid exact package version: {error}")))
}

fn normalize_locators(locators: &mut Vec<String>) -> Result<(), OsvError> {
    validate_locators(locators)?;
    locators.sort();
    locators.dedup();
    Ok(())
}

fn validate_locators(locators: &[String]) -> Result<(), OsvError> {
    for locator in locators {
        validate_scalar("locator", locator, MAX_LOCATOR_BYTES)?;
    }
    if locators.len() > MAX_LOCATORS_PER_COORDINATE {
        return Err(OsvError::limit(format!(
            "locator count {} exceeds per-coordinate maximum {MAX_LOCATORS_PER_COORDINATE}",
            locators.len()
        )));
    }
    Ok(())
}

pub(crate) fn validate_scalar(label: &str, value: &str, maximum: usize) -> Result<(), OsvError> {
    if value.is_empty() {
        return Err(OsvError::malformed(format!("{label} is empty")));
    }
    if value.len() > maximum {
        return Err(OsvError::limit(format!(
            "{label} is {} bytes; maximum is {maximum}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(OsvError::malformed(format!(
            "{label} contains a control character"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ModifiedInterval {
    pub start: DateTime<Utc>,
    end: DateTime<Utc>,
}

impl ModifiedInterval {
    pub(crate) fn contains(self, instant: DateTime<Utc>) -> bool {
        self.start <= instant && instant < self.end
    }
}

pub(crate) fn parse_modified(raw: &str) -> Result<ModifiedInterval, OsvError> {
    if !raw.is_ascii() || !raw.ends_with('Z') {
        return Err(OsvError::malformed(format!(
            "modified timestamp `{raw}` is not RFC 3339 UTC"
        )));
    }
    let fraction = if raw.len() == 20 {
        ""
    } else if raw.len() >= 22 && raw.as_bytes().get(19) == Some(&b'.') {
        &raw[20..raw.len() - 1]
    } else {
        return Err(OsvError::malformed(format!(
            "modified timestamp `{raw}` has an invalid fractional form"
        )));
    };
    if fraction.len() > 9 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OsvError::malformed(format!(
            "modified timestamp `{raw}` precision is outside 0..=9"
        )));
    }
    let start = DateTime::parse_from_rfc3339(raw)
        .map_err(|error| {
            OsvError::malformed(format!("modified timestamp `{raw}` is invalid: {error}"))
        })?
        .with_timezone(&Utc);
    let quantum = 10_i64.pow((9 - fraction.len()) as u32);
    let end = start
        .checked_add_signed(TimeDelta::nanoseconds(quantum))
        .ok_or_else(|| OsvError::malformed(format!("modified timestamp `{raw}` overflows")))?;
    Ok(ModifiedInterval { start, end })
}

pub(crate) fn modified_intervals_overlap(intervals: &[ModifiedInterval]) -> bool {
    let latest_start = intervals.iter().map(|interval| interval.start).max();
    let earliest_end = intervals.iter().map(|interval| interval.end).min();
    matches!((latest_start, earliest_end), (Some(start), Some(end)) if start < end)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RangeEvidence {
    pub affected_index: usize,
    pub range_type: String,
    pub introduced: String,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
    pub limit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AffectedEvidence {
    pub affected_index: usize,
    pub exact_versions: Vec<String>,
    pub ranges: Vec<RangeEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AdvisoryReference {
    pub reference_type: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryEvidence {
    pub locators: Vec<String>,
    pub affected: Vec<AffectedEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedAdvisory {
    pub coordinate: PackageCoordinate,
    pub primary_id: String,
    pub aliases: Vec<String>,
    pub evidence: AdvisoryEvidence,
    pub severity: NormalizedSeverity,
    pub references: Vec<AdvisoryReference>,
    pub batch_summary_modified: String,
    pub detail_modified: String,
    pub database_modified: DateTime<Utc>,
    pub published: Option<DateTime<Utc>>,
    pub source_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::Ecosystem;

    #[test]
    fn model_contract_merges_duplicate_coordinates_and_locators() {
        let display = PackageCoordinate::new(Ecosystem::Npm, "Demo", "1.2.3").unwrap();
        let canonical = PackageCoordinate::new(Ecosystem::Npm, "demo", "1.2.3").unwrap();
        let set = CoordinateSet::new(
            vec![
                CoordinateQuery::new(display, ["b".to_string()]).unwrap(),
                CoordinateQuery::new(canonical, ["a".to_string(), "b".to_string()]).unwrap(),
            ],
            2,
        )
        .unwrap();
        assert_eq!(set.queries.len(), 1);
        assert_eq!(set.queries[0].locators, ["a", "b"]);
        assert_eq!(set.excluded_local_records, 2);
        set.validate().unwrap();
    }

    #[test]
    fn model_contract_enforces_exact_version_and_scalar_bounds() {
        let range = PackageCoordinate::new(Ecosystem::Npm, "demo", "^1.2.3").unwrap();
        assert_eq!(
            CoordinateQuery::new(range, Vec::new()).unwrap_err().kind,
            OsvErrorKind::InvalidInput
        );
        let coordinate = PackageCoordinate::new(Ecosystem::Npm, "demo", "1.2.3").unwrap();
        let oversized = "x".repeat(MAX_LOCATOR_BYTES + 1);
        assert_eq!(
            CoordinateQuery::new(coordinate, [oversized])
                .unwrap_err()
                .kind,
            OsvErrorKind::ResourceLimit
        );

        let versions = [
            (Ecosystem::Npm, "demo", "1.2.3-beta.1+build", "^1.2.3"),
            (Ecosystem::PyPi, "demo", "1.2rc1", ">=1.2"),
            (Ecosystem::CratesIo, "demo", "1.2.3-alpha.1", "*"),
            (
                Ecosystem::Go,
                "example.com/demo",
                "v0.0.0-20240719120000-abcdefabcdef",
                "v1.2",
            ),
            (Ecosystem::NuGet, "demo", "1.2.3-beta.1+build", "[1.0,2.0)"),
            (
                Ecosystem::Maven,
                "org.example:demo",
                "1.2.3-SNAPSHOT",
                "[1.0,2.0)",
            ),
            (Ecosystem::RubyGems, "demo", "1.2.3.pre.1", "~>1.2"),
            (Ecosystem::Packagist, "vendor/demo", "v1.2.3-RC1", "^1.2"),
        ];
        for (ecosystem, name, valid, non_exact) in versions {
            let valid_coordinate = PackageCoordinate::new(ecosystem, name, valid).unwrap();
            CoordinateQuery::new(valid_coordinate, Vec::new()).unwrap();
            for invalid in [non_exact.to_string(), format!(" {valid}")] {
                let coordinate = PackageCoordinate::new(ecosystem, name, invalid).unwrap();
                assert!(
                    CoordinateQuery::new(coordinate, Vec::new()).is_err(),
                    "{ecosystem:?} accepted a non-exact version"
                );
            }
        }
        for dynamic in ["1.*", "LATEST", "RELEASE", "(,1.0]"] {
            let coordinate =
                PackageCoordinate::new(Ecosystem::Maven, "org.example:demo", dynamic).unwrap();
            assert!(CoordinateQuery::new(coordinate, Vec::new()).is_err());
        }
    }

    #[test]
    fn model_contract_measures_aggregate_known_evidence_as_canonical_json() {
        let set = CoordinateSet::new(
            vec![CoordinateQuery::new(
                PackageCoordinate::new(Ecosystem::Npm, "demo", "1.2.3").unwrap(),
                ["lock:2".to_string(), "lock:1".to_string()],
            )
            .unwrap()],
            0,
        )
        .unwrap();
        let exact = serde_json_canonicalizer::to_vec(&set.queries)
            .unwrap()
            .len();
        ensure_known_evidence_size(&set, exact).unwrap();
        assert_eq!(
            ensure_known_evidence_size(&set, exact - 1)
                .unwrap_err()
                .kind,
            OsvErrorKind::ResourceLimit
        );
    }
}
