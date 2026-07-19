use super::LockfileParser;
use crate::{
    ensure_record_count, BoundedInput, Coverage, DetectedLockfile, FormatVersion,
    IntegrityEvidence, IntegrityState, LockfileError, LockfileFormat, NormalizedDependency,
    NormalizedSource, ParseOutput, ScalarBudget, SourceKind,
};
use argus_core::{Ecosystem, PackageCoordinate};
use base64::Engine as _;
use semver::Version;

pub struct GoSumParser;
pub static PARSER: GoSumParser = GoSumParser;

impl LockfileParser for GoSumParser {
    fn format(&self) -> LockfileFormat {
        LockfileFormat::GoSum
    }

    fn parse(
        &self,
        input: &BoundedInput<'_>,
        detected: &DetectedLockfile,
    ) -> Result<ParseOutput, LockfileError> {
        if detected.format != self.format() || detected.version != FormatVersion::GoSumGrammar1 {
            return Err(parse_error(
                "detected format/version does not match go.sum grammar-v1",
            ));
        }
        let lines = input.text().lines().collect::<Vec<_>>();
        let input_record_units = lines.len();
        ensure_record_count(input_record_units)?;
        let mut emitted_record_units = 0usize;
        let mut scalar_budget = ScalarBudget::new();
        let mut records = Vec::with_capacity(input_record_units);

        for (index, line) in lines.iter().enumerate() {
            let fields = line.split(' ').collect::<Vec<_>>();
            if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
                return Err(parse_error(format!(
                    "line {} must contain exactly three single-space fields",
                    index + 1
                )));
            }
            for field in &fields {
                scalar_budget.observe(field)?;
            }
            let module = fields[0];
            validate_module(module, index)?;
            let (raw_version, is_go_mod) = fields[1]
                .strip_suffix("/go.mod")
                .map_or((fields[1], false), |version| (version, true));
            let semver = raw_version.strip_prefix('v').ok_or_else(|| {
                parse_error(format!("line {} version must start with `v`", index + 1))
            })?;
            Version::parse(semver).map_err(|error| {
                parse_error(format!(
                    "line {} version is not Go semver: {error}",
                    index + 1
                ))
            })?;
            let hash = fields[2].strip_prefix("h1:").ok_or_else(|| {
                parse_error(format!(
                    "line {} integrity must start with `h1:`",
                    index + 1
                ))
            })?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(hash)
                .map_err(|error| parse_error(format!("line {} hash: {error}", index + 1)))?;
            if decoded.len() != 32 {
                return Err(parse_error(format!(
                    "line {} h1 digest decoded to {} bytes instead of 32",
                    index + 1,
                    decoded.len()
                )));
            }
            let coordinate =
                PackageCoordinate::new(Ecosystem::Go, module, raw_version).map_err(|error| {
                    LockfileError::InvalidModel {
                        detail: error.to_string(),
                    }
                })?;
            let locator = format!("line {}:{module} {}", index + 1, fields[1]);
            records.push(NormalizedDependency {
                coordinate: Some(coordinate),
                format: self.format(),
                sources: vec![NormalizedSource {
                    kind: SourceKind::UnavailableByFormat,
                    location: None,
                    immutable_revision: None,
                    locator: format!("line {}:source-unavailable", index + 1),
                }],
                integrity_state: IntegrityState::RequiredPresent,
                integrity: vec![IntegrityEvidence {
                    algorithm: Some("sha256".to_string()),
                    value: Some(hash.to_string()),
                    locator: locator.clone(),
                }],
                raw_name: Some(module.to_string()),
                raw_version: Some(raw_version.to_string()),
                locator,
                condition: is_go_mod.then(|| "go.mod".to_string()),
                platform: None,
                occurrence_index: index as u64,
            });
            emitted_record_units = emitted_record_units
                .checked_add(1)
                .ok_or_else(|| parse_error("emitted record count overflowed"))?;
        }

        if emitted_record_units != input_record_units {
            return Err(LockfileError::CoverageMismatch {
                detail: format!(
                    "input record units {input_record_units} do not equal emitted record units {emitted_record_units}"
                ),
            });
        }
        let mut output = ParseOutput {
            detected: detected.clone(),
            coverage: Coverage {
                total_units: input_record_units,
                recognized_units: input_record_units,
                unsupported_units: 0,
                record_units: input_record_units,
                traversed_non_record_units: 0,
            },
            records,
            metadata_integrity: Vec::new(),
        };
        output.validate_and_sort()?;
        Ok(output)
    }
}

fn validate_module(module: &str, index: usize) -> Result<(), LockfileError> {
    if module.is_empty()
        || module.starts_with('/')
        || module.ends_with('/')
        || module.split('/').any(|segment| segment.is_empty())
        || module.chars().any(char::is_whitespace)
    {
        return Err(parse_error(format!(
            "line {} has an invalid module path",
            index + 1
        )));
    }
    Ok(())
}

fn parse_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::Parse {
        syntax: "go.sum",
        detail: detail.into(),
    }
}
