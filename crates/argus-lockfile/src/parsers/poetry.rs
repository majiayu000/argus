use super::LockfileParser;
use crate::{
    ensure_record_count, parse_toml, BoundedInput, Coverage, DetectedLockfile, FormatVersion,
    IntegrityEvidence, IntegrityState, LockfileError, LockfileFormat, NormalizedDependency,
    NormalizedSource, ParseOutput, SourceKind,
};
use argus_core::{Ecosystem, PackageCoordinate};
use std::collections::{BTreeMap, BTreeSet};
use toml::value::Table;

pub struct PoetryParser;
pub static PARSER: PoetryParser = PoetryParser;

impl LockfileParser for PoetryParser {
    fn format(&self) -> LockfileFormat {
        LockfileFormat::Poetry
    }

    fn parse(
        &self,
        input: &BoundedInput<'_>,
        detected: &DetectedLockfile,
    ) -> Result<ParseOutput, LockfileError> {
        if detected.format != self.format()
            || !matches!(
                detected.version,
                FormatVersion::Poetry1_1 | FormatVersion::Poetry2_0 | FormatVersion::Poetry2_1
            )
        {
            return Err(parse_error(
                "detected format/version does not match Poetry 1.1/2.0/2.1",
            ));
        }
        let value = parse_toml(input)?;
        let root = table(&value, "root")?;
        deny_unknown(root, &["package", "metadata"], "root")?;
        let packages = array_field(root, "package", "root")?;
        let input_record_units = packages.len();
        ensure_record_count(input_record_units)?;
        let metadata = root
            .get("metadata")
            .ok_or_else(|| parse_error("root.metadata is required"))
            .and_then(|value| table(value, "metadata"))?;
        let legacy_files = validate_metadata(metadata, detected.version)?;
        validate_legacy_file_associations(packages, legacy_files)?;

        let mut traversed = 0usize;
        let mut emitted_record_units = 0usize;
        let mut records = Vec::with_capacity(input_record_units);
        for (index, value) in packages.iter().enumerate() {
            let context = format!("package[{index}]");
            let package = table(value, &context)?;
            deny_unknown(
                package,
                &[
                    "name",
                    "version",
                    "description",
                    "category",
                    "optional",
                    "python-versions",
                    "files",
                    "develop",
                    "dependencies",
                    "extras",
                    "source",
                    "marker",
                    "markers",
                    "groups",
                    "platform",
                ],
                &context,
            )?;
            validate_optional_scalars(package, &context)?;
            let name = string_field(package, "name", &context)?;
            let version = string_field(package, "version", &context)?;
            let coordinate =
                PackageCoordinate::new(Ecosystem::PyPi, name, version).map_err(|error| {
                    LockfileError::InvalidModel {
                        detail: error.to_string(),
                    }
                })?;
            let locator = format!("{context}/{name}@{version}");

            traversed = traverse_dependencies(package, &locator, traversed)?;
            let (source_kind, source_location, immutable_revision) =
                parse_source(package.get("source"), &locator)?;

            let files = if let Some(files) = package.get("files") {
                Some(
                    files
                        .as_array()
                        .ok_or_else(|| parse_error(format!("{locator}.files must be an array")))?,
                )
            } else {
                legacy_files
                    .and_then(|files| files.get(name))
                    .map(|value| {
                        value.as_array().ok_or_else(|| {
                            parse_error(format!("metadata.files.{name} must be an array"))
                        })
                    })
                    .transpose()?
            };
            let (integrity_state, integrity, artifact_units) =
                parse_artifacts(files, source_kind, &locator)?;
            traversed = traversed
                .checked_add(artifact_units)
                .ok_or_else(|| parse_error("coverage count overflowed"))?;

            records.push(NormalizedDependency {
                coordinate: Some(coordinate),
                format: self.format(),
                sources: vec![NormalizedSource {
                    kind: source_kind,
                    location: source_location,
                    immutable_revision,
                    locator: format!("{locator}.source"),
                }],
                integrity_state,
                integrity,
                raw_name: Some(name.to_string()),
                raw_version: Some(version.to_string()),
                locator,
                condition: package_condition(package)?,
                platform: optional_string(package, "platform", &context)?,
                occurrence_index: index as u64,
            });
            emitted_record_units = add_unit(emitted_record_units)?;
        }
        finish(
            detected,
            records,
            input_record_units,
            emitted_record_units,
            traversed,
        )
    }
}

fn validate_legacy_file_associations(
    packages: &[toml::Value],
    legacy_files: Option<&Table>,
) -> Result<(), LockfileError> {
    let Some(files) = legacy_files else {
        return Ok(());
    };
    let mut names = BTreeMap::<&str, usize>::new();
    for (index, package) in packages.iter().enumerate() {
        let package = table(package, &format!("package[{index}]"))?;
        let name = string_field(package, "name", &format!("package[{index}]"))?;
        let count = names.entry(name).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| parse_error("package name count overflowed"))?;
    }
    for name in files.keys() {
        match names.get(name.as_str()) {
            Some(1) => {}
            Some(_) => return Err(partial_error()),
            None => return Err(partial_error()),
        }
    }
    Ok(())
}

fn validate_metadata(
    metadata: &Table,
    version: FormatVersion,
) -> Result<Option<&Table>, LockfileError> {
    let allowed = match version {
        FormatVersion::Poetry1_1 => {
            &["lock-version", "python-versions", "content-hash", "files"][..]
        }
        FormatVersion::Poetry2_0 | FormatVersion::Poetry2_1 => {
            &["lock-version", "python-versions", "content-hash"][..]
        }
        _ => return Err(parse_error("unexpected Poetry version")),
    };
    deny_unknown(metadata, allowed, "metadata")?;
    for key in ["lock-version", "python-versions", "content-hash"] {
        if let Some(value) = metadata.get(key) {
            if !value.is_str() {
                return Err(parse_error(format!("metadata.{key} must be a string")));
            }
        }
    }
    let files = metadata
        .get("files")
        .map(|value| table(value, "metadata.files"))
        .transpose()?;
    if let Some(files) = files {
        for (name, value) in files {
            if name.is_empty() || !value.is_array() {
                return Err(parse_error(format!(
                    "metadata.files.{name} must be an artifact array"
                )));
            }
        }
    }
    Ok(files)
}

fn validate_optional_scalars(package: &Table, context: &str) -> Result<(), LockfileError> {
    for key in [
        "description",
        "category",
        "python-versions",
        "marker",
        "platform",
    ] {
        if let Some(value) = package.get(key) {
            if !value.is_str() {
                return Err(parse_error(format!("{context}.{key} must be a string")));
            }
        }
    }
    for key in ["optional", "develop"] {
        if let Some(value) = package.get(key) {
            if !value.is_bool() {
                return Err(parse_error(format!("{context}.{key} must be boolean")));
            }
        }
    }
    for key in ["groups", "markers"] {
        if let Some(value) = package.get(key) {
            validate_string_or_string_array(value, &format!("{context}.{key}"))?;
        }
    }
    Ok(())
}

fn traverse_dependencies(
    package: &Table,
    locator: &str,
    mut count: usize,
) -> Result<usize, LockfileError> {
    if let Some(value) = package.get("dependencies") {
        let dependencies = table(value, &format!("{locator}.dependencies"))?;
        for (name, requirement) in dependencies {
            if name.is_empty() {
                return Err(parse_error(format!(
                    "{locator}.dependencies contains an empty name"
                )));
            }
            validate_dependency(requirement, &format!("{locator}.dependencies.{name}"))?;
            count = add_unit(count)?;
        }
    }
    if let Some(value) = package.get("extras") {
        let extras = table(value, &format!("{locator}.extras"))?;
        for (name, values) in extras {
            let values = values
                .as_array()
                .ok_or_else(|| parse_error(format!("{locator}.extras.{name} must be an array")))?;
            for (index, value) in values.iter().enumerate() {
                if value.as_str().is_none_or(|value| value.is_empty()) {
                    return Err(parse_error(format!(
                        "{locator}.extras.{name}[{index}] must be a non-empty string"
                    )));
                }
                count = add_unit(count)?;
            }
        }
    }
    Ok(count)
}

fn validate_dependency(value: &toml::Value, context: &str) -> Result<(), LockfileError> {
    if let Some(requirement) = value.as_str() {
        if requirement.is_empty() {
            return Err(parse_error(format!(
                "{context} must not be an empty requirement"
            )));
        }
        return Ok(());
    }
    if let Some(values) = value.as_array() {
        if values.is_empty() {
            return Err(parse_error(format!("{context} must not be an empty array")));
        }
        for (index, value) in values.iter().enumerate() {
            validate_dependency_table(value, &format!("{context}[{index}]"))?;
        }
        return Ok(());
    }
    validate_dependency_table(value, context)
}

fn validate_dependency_table(value: &toml::Value, context: &str) -> Result<(), LockfileError> {
    let dependency = table(value, context)?;
    deny_unknown(
        dependency,
        &[
            "version",
            "markers",
            "python",
            "platform",
            "optional",
            "extras",
            "source",
            "allow-prereleases",
            "develop",
            "git",
            "branch",
            "tag",
            "rev",
            "path",
            "url",
        ],
        context,
    )?;
    if !["version", "git", "path", "url"]
        .iter()
        .any(|key| dependency.contains_key(*key))
    {
        return Err(parse_error(format!(
            "{context} has no version or immutable source requirement"
        )));
    }
    for (key, value) in dependency {
        match key.as_str() {
            "optional" | "allow-prereleases" | "develop" if value.is_bool() => {}
            "extras"
                if value.as_array().is_some_and(|values| {
                    values
                        .iter()
                        .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
                }) => {}
            _ if value.as_str().is_some_and(|value| !value.is_empty()) => {}
            _ => {
                return Err(parse_error(format!(
                    "{context}.{key} has an invalid dependency value"
                )))
            }
        }
    }
    Ok(())
}

fn parse_source(
    value: Option<&toml::Value>,
    locator: &str,
) -> Result<(SourceKind, Option<String>, Option<String>), LockfileError> {
    let Some(value) = value else {
        return Ok((
            SourceKind::Registry,
            Some("https://pypi.org/simple".to_string()),
            None,
        ));
    };
    let source = table(value, &format!("{locator}.source"))?;
    deny_unknown(
        source,
        &["type", "url", "reference", "resolved_reference"],
        &format!("{locator}.source"),
    )?;
    let source_type = string_field(source, "type", &format!("{locator}.source"))?;
    let url = string_field(source, "url", &format!("{locator}.source"))?;
    match source_type {
        "legacy" | "supplemental" | "primary" => {
            Ok((SourceKind::Registry, Some(url.to_string()), None))
        }
        "url" => Ok((SourceKind::Url, Some(url.to_string()), None)),
        "directory" | "file" | "path" => Ok((SourceKind::Path, Some(url.to_string()), None)),
        "git" => {
            let resolved = optional_string(source, "resolved_reference", locator)?;
            let reference = optional_string(source, "reference", locator)?;
            let immutable_revision = resolved
                .as_deref()
                .filter(|value| is_commit(value))
                .or_else(|| reference.as_deref().filter(|value| is_commit(value)))
                .map(ToOwned::to_owned);
            Ok((SourceKind::Git, Some(url.to_string()), immutable_revision))
        }
        _ => Err(partial_error()),
    }
}

fn parse_artifacts(
    files: Option<&Vec<toml::Value>>,
    source_kind: SourceKind,
    locator: &str,
) -> Result<(IntegrityState, Vec<IntegrityEvidence>, usize), LockfileError> {
    if matches!(source_kind, SourceKind::Git | SourceKind::Path) {
        if files.is_some_and(|files| !files.is_empty()) {
            return Err(parse_error(format!(
                "{locator} has artifacts for a source without content-hash semantics"
            )));
        }
        return Ok((IntegrityState::UnavailableByFormat, Vec::new(), 0));
    }
    let Some(files) = files else {
        return Ok((IntegrityState::RequiredMissing, Vec::new(), 0));
    };
    if files.is_empty() {
        return Ok((IntegrityState::RequiredMissing, Vec::new(), 0));
    }

    let mut evidence = Vec::with_capacity(files.len());
    let mut has_invalid = false;
    let mut has_missing = false;
    for (index, value) in files.iter().enumerate() {
        let artifact = table(value, &format!("{locator}.files[{index}]"))?;
        deny_unknown(
            artifact,
            &["file", "hash"],
            &format!("{locator}.files[{index}]"),
        )?;
        let file = string_field(artifact, "file", &format!("{locator}.files[{index}]"))?;
        let evidence_locator = format!("{locator}.files[{index}]/{file}");
        let (algorithm, digest, valid) = match artifact.get("hash") {
            None => (None, None, HashValidity::Missing),
            Some(value) => {
                let hash = value.as_str().ok_or_else(|| {
                    parse_error(format!("{locator}.files[{index}].hash must be a string"))
                })?;
                parse_hash(hash)
            }
        };
        has_missing |= valid == HashValidity::Missing;
        has_invalid |= valid == HashValidity::Invalid;
        evidence.push(IntegrityEvidence {
            algorithm,
            value: digest,
            locator: evidence_locator,
        });
    }
    let state = if has_invalid {
        IntegrityState::Invalid
    } else if has_missing {
        IntegrityState::RequiredMissing
    } else {
        IntegrityState::RequiredPresent
    };
    Ok((state, evidence, files.len()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HashValidity {
    Present,
    Missing,
    Invalid,
}

fn parse_hash(hash: &str) -> (Option<String>, Option<String>, HashValidity) {
    let Some((algorithm, value)) = hash.split_once(':') else {
        return (None, Some(hash.to_string()), HashValidity::Invalid);
    };
    let expected = match algorithm {
        "sha256" => Some(64),
        "sha384" => Some(96),
        "sha512" => Some(128),
        "sha1" => Some(40),
        "md5" => Some(32),
        _ => None,
    };
    let valid = expected.is_some_and(|length| is_hex(value, length));
    (
        Some(algorithm.to_string()),
        Some(value.to_ascii_lowercase()),
        if valid {
            HashValidity::Present
        } else {
            HashValidity::Invalid
        },
    )
}

fn package_condition(package: &Table) -> Result<Option<String>, LockfileError> {
    let mut conditions = Vec::new();
    for key in ["marker", "markers", "groups"] {
        let Some(value) = package.get(key) else {
            continue;
        };
        if let Some(value) = value.as_str() {
            conditions.push(format!("{key}={value}"));
        } else if let Some(values) = value.as_array() {
            let values = values
                .iter()
                .map(|value| value.as_str().unwrap_or_default())
                .collect::<Vec<_>>();
            conditions.push(format!("{key}={}", values.join(",")));
        }
    }
    Ok((!conditions.is_empty()).then(|| conditions.join(";")))
}

fn validate_string_or_string_array(
    value: &toml::Value,
    context: &str,
) -> Result<(), LockfileError> {
    if value.as_str().is_some_and(|value| !value.is_empty())
        || value.as_array().is_some_and(|values| {
            values
                .iter()
                .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
        })
    {
        return Ok(());
    }
    Err(parse_error(format!(
        "{context} must be a string or string array"
    )))
}

fn finish(
    detected: &DetectedLockfile,
    records: Vec<NormalizedDependency>,
    input_record_units: usize,
    emitted_record_units: usize,
    traversed: usize,
) -> Result<ParseOutput, LockfileError> {
    if emitted_record_units != input_record_units {
        return Err(LockfileError::CoverageMismatch {
            detail: format!(
                "input record units {input_record_units} do not equal emitted record units {emitted_record_units}"
            ),
        });
    }
    let total = input_record_units
        .checked_add(traversed)
        .ok_or_else(|| parse_error("coverage count overflowed"))?;
    let mut output = ParseOutput {
        detected: detected.clone(),
        coverage: Coverage {
            total_units: total,
            recognized_units: total,
            unsupported_units: 0,
            record_units: input_record_units,
            traversed_non_record_units: traversed,
        },
        records,
        metadata_integrity: Vec::new(),
    };
    output.validate_and_sort()?;
    Ok(output)
}

fn table<'a>(value: &'a toml::Value, context: &str) -> Result<&'a Table, LockfileError> {
    value
        .as_table()
        .ok_or_else(|| parse_error(format!("{context} must be a table")))
}

fn array_field<'a>(
    table: &'a Table,
    key: &str,
    context: &str,
) -> Result<&'a Vec<toml::Value>, LockfileError> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| parse_error(format!("{context}.{key} must be an array")))
}

fn string_field<'a>(table: &'a Table, key: &str, context: &str) -> Result<&'a str, LockfileError> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| parse_error(format!("{context}.{key} must be a non-empty string")))
}

fn optional_string(
    table: &Table,
    key: &str,
    context: &str,
) -> Result<Option<String>, LockfileError> {
    table
        .get(key)
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| parse_error(format!("{context}.{key} must be a non-empty string")))
        })
        .transpose()
}

fn deny_unknown(table: &Table, allowed: &[&str], _context: &str) -> Result<(), LockfileError> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if table.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err(partial_error());
    }
    Ok(())
}

fn is_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn add_unit(count: usize) -> Result<usize, LockfileError> {
    count
        .checked_add(1)
        .ok_or_else(|| parse_error("coverage count overflowed"))
}

fn parse_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::Parse {
        syntax: "Poetry TOML",
        detail: detail.into(),
    }
}

fn partial_error() -> LockfileError {
    LockfileError::PartialAnalysis {
        total_units: 1,
        recognized_units: 0,
        unsupported_units: 1,
    }
}
