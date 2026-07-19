use argus_core::{Ecosystem, PackageCoordinate};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockfileFormat {
    PackageLock,
    YarnClassic,
    YarnBerry,
    Pnpm,
    Poetry,
    Uv,
    Cargo,
    GoSum,
    Bundler,
    Composer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FormatVersion {
    PackageLock2,
    PackageLock3,
    YarnClassic1,
    YarnBerry4,
    YarnBerry6,
    YarnBerry8,
    Pnpm5_4,
    Pnpm6_0,
    Pnpm9_0,
    Poetry1_1,
    Poetry2_0,
    Poetry2_1,
    Uv1,
    Cargo3,
    Cargo4,
    GoSumGrammar1,
    Bundler2,
    Bundler3,
    Bundler4,
    ComposerSchema1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedLockfile {
    pub format: LockfileFormat,
    pub version: FormatVersion,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Registry,
    Url,
    Git,
    Path,
    Workspace,
    UnavailableByFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NormalizedSource {
    pub kind: SourceKind,
    pub location: Option<String>,
    pub immutable_revision: Option<String>,
    pub locator: String,
}

impl NormalizedSource {
    pub fn validate(&self) -> Result<(), LockfileError> {
        if self.locator.is_empty() {
            return Err(LockfileError::InvalidModel {
                detail: "source locator must not be empty".to_string(),
            });
        }
        if self.kind == SourceKind::UnavailableByFormat {
            if self.location.is_some() || self.immutable_revision.is_some() {
                return Err(LockfileError::InvalidModel {
                    detail: format!(
                        "unavailable-by-format source at `{}` cannot carry location or revision",
                        self.locator
                    ),
                });
            }
        } else if !self
            .location
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(LockfileError::InvalidModel {
                detail: format!(
                    "source location is required for {:?} source at `{}`",
                    self.kind, self.locator
                ),
            });
        }
        if self.immutable_revision.is_some() && self.kind != SourceKind::Git {
            return Err(LockfileError::InvalidModel {
                detail: format!(
                    "immutable revision is only valid for git source at `{}`",
                    self.locator
                ),
            });
        }
        if let Some(revision) = &self.immutable_revision {
            let immutable = matches!(revision.len(), 40 | 64)
                && revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
            if !immutable {
                return Err(LockfileError::InvalidModel {
                    detail: format!(
                        "git source at `{}` has a non-immutable revision",
                        self.locator
                    ),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityState {
    RequiredPresent,
    RequiredMissing,
    OptionalPresent,
    OptionalAbsent,
    UnavailableByFormat,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IntegrityEvidence {
    pub algorithm: Option<String>,
    pub value: Option<String>,
    pub locator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedDependency {
    pub coordinate: Option<PackageCoordinate>,
    pub format: LockfileFormat,
    pub sources: Vec<NormalizedSource>,
    pub integrity_state: IntegrityState,
    pub integrity: Vec<IntegrityEvidence>,
    pub raw_name: Option<String>,
    pub raw_version: Option<String>,
    pub locator: String,
    pub condition: Option<String>,
    pub platform: Option<String>,
    pub occurrence_index: u64,
}

impl NormalizedDependency {
    fn ecosystem(&self) -> Option<Ecosystem> {
        self.coordinate.as_ref().map(|value| value.ecosystem)
    }

    fn canonical_name(&self) -> Option<&str> {
        self.coordinate
            .as_ref()
            .map(|value| value.canonical_name.as_str())
    }

    fn canonical_version(&self) -> Option<&str> {
        self.coordinate.as_ref().map(|value| value.version.as_str())
    }
}

impl Ord for NormalizedDependency {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.ecosystem(),
            self.canonical_name(),
            self.canonical_version(),
            self.sources.as_slice(),
            self.locator.as_str(),
            self.occurrence_index,
        )
            .cmp(&(
                other.ecosystem(),
                other.canonical_name(),
                other.canonical_version(),
                other.sources.as_slice(),
                other.locator.as_str(),
                other.occurrence_index,
            ))
    }
}

impl PartialOrd for NormalizedDependency {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub total_units: usize,
    pub recognized_units: usize,
    pub unsupported_units: usize,
    pub record_units: usize,
    pub traversed_non_record_units: usize,
}

impl Coverage {
    pub fn validate(self) -> Result<(), LockfileError> {
        let accounted = self
            .record_units
            .checked_add(self.traversed_non_record_units)
            .ok_or_else(|| LockfileError::CoverageMismatch {
                detail: "coverage unit total overflowed".to_string(),
            })?;
        if accounted != self.total_units {
            return Err(LockfileError::CoverageMismatch {
                detail: format!(
                    "total_units {} does not equal record_units {} plus traversed_non_record_units {}",
                    self.total_units, self.record_units, self.traversed_non_record_units
                ),
            });
        }
        if self.recognized_units != self.total_units || self.unsupported_units != 0 {
            return Err(LockfileError::PartialAnalysis {
                total_units: self.total_units,
                recognized_units: self.recognized_units,
                unsupported_units: self.unsupported_units,
            });
        }
        crate::ensure_record_count(self.record_units)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseOutput {
    pub detected: DetectedLockfile,
    pub records: Vec<NormalizedDependency>,
    pub coverage: Coverage,
    pub metadata_integrity: Vec<IntegrityEvidence>,
}

impl ParseOutput {
    pub fn validate_and_sort(&mut self) -> Result<(), LockfileError> {
        self.coverage.validate()?;
        if self.records.len() != self.coverage.record_units {
            return Err(LockfileError::CoverageMismatch {
                detail: format!(
                    "records length {} does not equal record_units {}",
                    self.records.len(),
                    self.coverage.record_units
                ),
            });
        }
        for record in &mut self.records {
            if record.sources.is_empty() {
                return Err(LockfileError::InvalidModel {
                    detail: format!("record at `{}` has no source evidence", record.locator),
                });
            }
            for source in &record.sources {
                source.validate()?;
            }
            record.sources.sort();
            if let Some(coordinate) = &record.coordinate {
                coordinate
                    .validate()
                    .map_err(|error| LockfileError::InvalidModel {
                        detail: error.to_string(),
                    })?;
                if record.raw_name.as_deref() != Some(coordinate.original_name.as_str())
                    || record.raw_version.as_deref() != Some(coordinate.original_version.as_str())
                {
                    return Err(LockfileError::InvalidModel {
                        detail: format!(
                            "raw identity does not match coordinate at `{}`",
                            record.locator
                        ),
                    });
                }
            } else {
                let all_local = record
                    .sources
                    .iter()
                    .all(|source| matches!(source.kind, SourceKind::Path | SourceKind::Workspace));
                let unavailable_root = record
                    .sources
                    .iter()
                    .all(|source| source.kind == SourceKind::UnavailableByFormat)
                    && (record.raw_name.is_none() || record.raw_version.is_none());
                let identity_incomplete = record.raw_name.is_none() || record.raw_version.is_none();
                let coordinate_optional = identity_incomplete && (all_local || unavailable_root);
                if !coordinate_optional {
                    return Err(LockfileError::InvalidModel {
                        detail: format!(
                            "coordinate is required for non-local source set at `{}`",
                            record.locator
                        ),
                    });
                }
            }
            if record.locator.is_empty() {
                return Err(LockfileError::InvalidModel {
                    detail: "record locator must not be empty".to_string(),
                });
            }
            if matches!(
                record.integrity_state,
                IntegrityState::RequiredPresent
                    | IntegrityState::OptionalPresent
                    | IntegrityState::Invalid
            ) && record.integrity.is_empty()
            {
                return Err(LockfileError::InvalidModel {
                    detail: format!(
                        "{:?} integrity requires evidence at `{}`",
                        record.integrity_state, record.locator
                    ),
                });
            }
            if record
                .integrity
                .iter()
                .any(|evidence| evidence.locator.is_empty())
            {
                return Err(LockfileError::InvalidModel {
                    detail: format!(
                        "integrity evidence locator is empty at `{}`",
                        record.locator
                    ),
                });
            }
        }
        self.records.sort();
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockfileError {
    InputTooLarge {
        actual: usize,
        maximum: usize,
    },
    InvalidUtf8 {
        detail: String,
    },
    NestingLimit {
        actual: usize,
        maximum: usize,
    },
    ScalarTooLarge {
        actual: usize,
        maximum: usize,
    },
    ScalarCountLimit {
        actual: usize,
        maximum: usize,
    },
    RecordLimit {
        actual: usize,
        maximum: usize,
    },
    CanonicalOutputLimit {
        actual: usize,
        maximum: usize,
    },
    DuplicateKey {
        syntax: &'static str,
        key: String,
    },
    UnsupportedYamlFeature {
        feature: &'static str,
    },
    Parse {
        syntax: &'static str,
        detail: String,
    },
    MissingBasename,
    UnknownBasename {
        basename: String,
    },
    BasenameConflict {
        basename: String,
        expected: String,
    },
    SignatureMismatch {
        format: String,
        detail: String,
    },
    AmbiguousFormat {
        evidence: Vec<String>,
    },
    UnsupportedVersion {
        format: String,
        version: String,
    },
    ParserUnavailable {
        format: LockfileFormat,
    },
    PartialAnalysis {
        total_units: usize,
        recognized_units: usize,
        unsupported_units: usize,
    },
    CoverageMismatch {
        detail: String,
    },
    InvalidModel {
        detail: String,
    },
}

impl fmt::Display for LockfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, maximum } => {
                write!(formatter, "input is {actual} bytes; maximum is {maximum}")
            }
            Self::InvalidUtf8 { detail } => write!(formatter, "input is not UTF-8: {detail}"),
            Self::NestingLimit { actual, maximum } => {
                write!(formatter, "nesting depth {actual} exceeds maximum {maximum}")
            }
            Self::ScalarTooLarge { actual, maximum } => {
                write!(formatter, "scalar is {actual} bytes; maximum is {maximum}")
            }
            Self::ScalarCountLimit { actual, maximum } => {
                write!(formatter, "scalar count {actual} exceeds maximum {maximum}")
            }
            Self::RecordLimit { actual, maximum } => {
                write!(formatter, "record count {actual} exceeds maximum {maximum}")
            }
            Self::CanonicalOutputLimit { actual, maximum } => write!(
                formatter,
                "canonical finding/evidence JSON is {actual} bytes; maximum is {maximum}"
            ),
            Self::DuplicateKey { syntax, key } => {
                write!(formatter, "duplicate {syntax} map key `{key}`")
            }
            Self::UnsupportedYamlFeature { feature } => {
                write!(formatter, "unsupported YAML feature: {feature}")
            }
            Self::Parse { syntax, detail } => write!(formatter, "parse {syntax}: {detail}"),
            Self::MissingBasename => write!(
                formatter,
                "lockfile basename is required unless an explicit format is provided"
            ),
            Self::UnknownBasename { basename } => {
                write!(formatter, "unknown lockfile basename `{basename}`")
            }
            Self::BasenameConflict { basename, expected } => write!(
                formatter,
                "basename `{basename}` conflicts with explicit format; expected `{expected}`"
            ),
            Self::SignatureMismatch { format, detail } => {
                write!(formatter, "{format} signature mismatch: {detail}")
            }
            Self::AmbiguousFormat { evidence } => {
                write!(formatter, "ambiguous lockfile format: {}", evidence.join("; "))
            }
            Self::UnsupportedVersion { format, version } => {
                write!(formatter, "unsupported {format} version `{version}`")
            }
            Self::ParserUnavailable { format } => {
                write!(formatter, "{format:?} parser implementation is not installed")
            }
            Self::PartialAnalysis {
                total_units,
                recognized_units,
                unsupported_units,
            } => write!(
                formatter,
                "partial analysis: total={total_units}, recognized={recognized_units}, unsupported={unsupported_units}"
            ),
            Self::CoverageMismatch { detail } => {
                write!(formatter, "coverage accounting mismatch: {detail}")
            }
            Self::InvalidModel { detail } => write!(formatter, "invalid normalized record: {detail}"),
        }
    }
}

impl Error for LockfileError {}
