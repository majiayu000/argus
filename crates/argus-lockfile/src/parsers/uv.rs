use super::LockfileParser;
use crate::{
    ensure_record_count, parse_toml, BoundedInput, Coverage, DetectedLockfile, FormatVersion,
    IntegrityEvidence, IntegrityState, LockfileError, LockfileFormat, NormalizedDependency,
    NormalizedSource, ParseOutput, SourceKind,
};
use argus_core::{Ecosystem, PackageCoordinate};
use std::collections::BTreeSet;
use toml::value::Table;

pub struct UvParser;
pub static PARSER: UvParser = UvParser;

impl LockfileParser for UvParser {
    fn format(&self) -> LockfileFormat {
        LockfileFormat::Uv
    }

    fn parse(
        &self,
        input: &BoundedInput<'_>,
        detected: &DetectedLockfile,
    ) -> Result<ParseOutput, LockfileError> {
        if detected.format != self.format() || detected.version != FormatVersion::Uv1 {
            return Err(parse_error("detected format/version does not match uv 1"));
        }
        let value = parse_toml(input)?;
        let root = table(&value, "root")?;
        deny_unknown(
            root,
            &[
                "version",
                "revision",
                "requires-python",
                "resolution-markers",
                "options",
                "manifest",
                "package",
            ],
            "root",
        )?;
        validate_root_metadata(root)?;
        let packages = array_field(root, "package", "root")?;
        let input_record_units = packages.len();
        ensure_record_count(input_record_units)?;
        let global_markers = string_array(root.get("resolution-markers"), "resolution-markers")?;

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
                    "source",
                    "dependencies",
                    "optional-dependencies",
                    "dev-dependencies",
                    "sdist",
                    "wheels",
                    "metadata",
                    "resolution-markers",
                ],
                &context,
            )?;
            let name = string_field(package, "name", &context)?;
            let version = string_field(package, "version", &context)?;
            let coordinate =
                PackageCoordinate::new(Ecosystem::PyPi, name, version).map_err(|error| {
                    LockfileError::InvalidModel {
                        detail: error.to_string(),
                    }
                })?;
            let locator = format!("{context}/{name}@{version}");
            let mut conditions = global_markers.clone();
            traversed = traverse_dependencies(package, &locator, traversed, &mut conditions)?;
            conditions.extend(string_array(
                package.get("resolution-markers"),
                &format!("{locator}.resolution-markers"),
            )?);
            if let Some(metadata) = package.get("metadata") {
                validate_package_metadata(metadata, &locator)?;
            }

            let package_source = parse_source(package.get("source"), &locator)?;
            let source_kind = package_source.kind;
            let (integrity_state, integrity, mut artifact_sources, platforms, artifact_units) =
                parse_artifacts(package, source_kind, &locator)?;
            traversed = traversed
                .checked_add(artifact_units)
                .ok_or_else(|| parse_error("coverage count overflowed"))?;
            let mut sources = vec![package_source];
            sources.append(&mut artifact_sources);
            conditions.sort();
            conditions.dedup();

            records.push(NormalizedDependency {
                coordinate: Some(coordinate),
                format: self.format(),
                sources,
                integrity_state,
                integrity,
                raw_name: Some(name.to_string()),
                raw_version: Some(version.to_string()),
                locator,
                condition: (!conditions.is_empty()).then(|| conditions.join(" || ")),
                platform: (!platforms.is_empty()).then(|| platforms.join(",")),
                occurrence_index: index as u64,
            });
            emitted_record_units = add_units(emitted_record_units, 1)?;
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

fn validate_root_metadata(root: &Table) -> Result<(), LockfileError> {
    if root
        .get("version")
        .and_then(toml::Value::as_integer)
        .is_none()
    {
        return Err(parse_error("root.version must be an integer"));
    }
    if let Some(revision) = root.get("revision") {
        if revision.as_integer().is_none() {
            return Err(parse_error("root.revision must be an integer"));
        }
    }
    if let Some(requires_python) = root.get("requires-python") {
        if !requires_python
            .as_str()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(parse_error(
                "root.requires-python must be a non-empty string",
            ));
        }
    }
    string_array(root.get("resolution-markers"), "root.resolution-markers")?;
    if let Some(options) = root.get("options") {
        let options = table(options, "root.options")?;
        deny_unknown(
            options,
            &[
                "exclude-newer",
                "exclude-newer-package",
                "resolution-mode",
                "prerelease",
                "fork-strategy",
                "index-strategy",
                "keyring-provider",
                "no-binary",
                "no-build",
                "no-build-isolation",
            ],
            "root.options",
        )?;
        for (key, value) in options {
            validate_metadata_value(value, &format!("root.options.{key}"))?;
        }
    }
    if let Some(manifest) = root.get("manifest") {
        let manifest = table(manifest, "root.manifest")?;
        deny_unknown(
            manifest,
            &[
                "members",
                "requirements",
                "constraints",
                "overrides",
                "dependency-groups",
            ],
            "root.manifest",
        )?;
        for (key, value) in manifest {
            match key.as_str() {
                "members" => {
                    string_array(Some(value), &format!("root.manifest.{key}"))?;
                }
                "requirements" | "constraints" | "overrides" => {
                    validate_dependency_array(value, &format!("root.manifest.{key}"), None)?;
                }
                "dependency-groups" => {
                    validate_dependency_groups(value, &format!("root.manifest.{key}"), None)?;
                }
                _ => return Err(partial_error()),
            }
        }
    }
    Ok(())
}

fn validate_package_metadata(value: &toml::Value, locator: &str) -> Result<(), LockfileError> {
    let metadata = table(value, &format!("{locator}.metadata"))?;
    deny_unknown(
        metadata,
        &["requires-dist", "requires-dev", "provides-extras"],
        &format!("{locator}.metadata"),
    )?;
    for (key, value) in metadata {
        match key.as_str() {
            "provides-extras" => {
                string_array(Some(value), &format!("{locator}.metadata.{key}"))?;
            }
            "requires-dist" | "requires-dev" => {
                validate_dependency_array(value, &format!("{locator}.metadata.{key}"), None)?;
            }
            _ => return Err(partial_error()),
        }
    }
    Ok(())
}

fn traverse_dependencies(
    package: &Table,
    locator: &str,
    mut count: usize,
    conditions: &mut Vec<String>,
) -> Result<usize, LockfileError> {
    if let Some(value) = package.get("dependencies") {
        let units =
            validate_dependency_array(value, &format!("{locator}.dependencies"), Some(conditions))?;
        count = add_units(count, units)?;
    }
    for key in ["optional-dependencies", "dev-dependencies"] {
        if let Some(value) = package.get(key) {
            let units =
                validate_dependency_groups(value, &format!("{locator}.{key}"), Some(conditions))?;
            count = add_units(count, units)?;
        }
    }
    Ok(count)
}

fn validate_dependency_groups(
    value: &toml::Value,
    context: &str,
    mut conditions: Option<&mut Vec<String>>,
) -> Result<usize, LockfileError> {
    let groups = table(value, context)?;
    let mut units = 0usize;
    for (group, value) in groups {
        if group.is_empty() {
            return Err(parse_error(format!("{context} contains an empty group")));
        }
        let nested_conditions = conditions.as_deref_mut();
        units = add_units(
            units,
            validate_dependency_array(value, &format!("{context}.{group}"), nested_conditions)?,
        )?;
    }
    Ok(units)
}

fn validate_dependency_array(
    value: &toml::Value,
    context: &str,
    mut conditions: Option<&mut Vec<String>>,
) -> Result<usize, LockfileError> {
    let dependencies = value
        .as_array()
        .ok_or_else(|| parse_error(format!("{context} must be an array")))?;
    for (index, value) in dependencies.iter().enumerate() {
        let dependency = table(value, &format!("{context}[{index}]"))?;
        deny_unknown(
            dependency,
            &[
                "name",
                "version",
                "specifier",
                "source",
                "marker",
                "extra",
                "extras",
                "groups",
            ],
            &format!("{context}[{index}]"),
        )?;
        string_field(dependency, "name", &format!("{context}[{index}]"))?;
        for key in ["version", "specifier", "marker", "extra"] {
            if let Some(value) = dependency.get(key) {
                if !value.as_str().is_some_and(|value| !value.is_empty()) {
                    return Err(parse_error(format!(
                        "{context}[{index}].{key} must be a non-empty string"
                    )));
                }
            }
        }
        for key in ["extras", "groups"] {
            string_array(dependency.get(key), &format!("{context}[{index}].{key}"))?;
        }
        if let Some(source) = dependency.get("source") {
            parse_source_value(source, &format!("{context}[{index}].source"))?;
        }
        if let (Some(conditions), Some(marker)) = (
            conditions.as_deref_mut(),
            dependency.get("marker").and_then(toml::Value::as_str),
        ) {
            conditions.push(marker.to_string());
        }
    }
    Ok(dependencies.len())
}

fn parse_source(
    value: Option<&toml::Value>,
    locator: &str,
) -> Result<NormalizedSource, LockfileError> {
    let Some(value) = value else {
        return Err(parse_error(format!(
            "{locator}.source is required for every uv package"
        )));
    };
    parse_source_value(value, &format!("{locator}.source"))
}

fn parse_source_value(
    value: &toml::Value,
    locator: &str,
) -> Result<NormalizedSource, LockfileError> {
    let source = table(value, locator)?;
    if source.len() != 1 {
        return Err(parse_error(format!(
            "{locator} must contain exactly one source kind"
        )));
    }
    let (key, value) = source
        .iter()
        .next()
        .ok_or_else(|| parse_error(format!("{locator} is empty")))?;
    let location = value
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| parse_error(format!("{locator}.{key} must be a non-empty string")))?;
    let (kind, immutable_revision) = match key.as_str() {
        "registry" => (SourceKind::Registry, None),
        "url" => (SourceKind::Url, None),
        "git" => (
            SourceKind::Git,
            location
                .rsplit_once('#')
                .map(|(_, revision)| revision)
                .filter(|revision| is_commit(revision))
                .map(ToOwned::to_owned),
        ),
        "editable" | "path" | "directory" => (SourceKind::Path, None),
        "virtual" | "workspace" => (SourceKind::Workspace, None),
        _ => return Err(partial_error()),
    };
    Ok(NormalizedSource {
        kind,
        location: Some(location.to_string()),
        immutable_revision,
        locator: locator.to_string(),
    })
}

type ArtifactResult = (
    IntegrityState,
    Vec<IntegrityEvidence>,
    Vec<NormalizedSource>,
    Vec<String>,
    usize,
);

fn parse_artifacts(
    package: &Table,
    source_kind: SourceKind,
    locator: &str,
) -> Result<ArtifactResult, LockfileError> {
    let mut artifacts = Vec::new();
    if let Some(sdist) = package.get("sdist") {
        artifacts.push(("sdist".to_string(), sdist));
    }
    if let Some(wheels) = package.get("wheels") {
        let wheels = wheels
            .as_array()
            .ok_or_else(|| parse_error(format!("{locator}.wheels must be an array")))?;
        for (index, wheel) in wheels.iter().enumerate() {
            artifacts.push((format!("wheels[{index}]"), wheel));
        }
    }
    if matches!(
        source_kind,
        SourceKind::Git | SourceKind::Path | SourceKind::Workspace
    ) {
        if !artifacts.is_empty() {
            return Err(parse_error(format!(
                "{locator} has distributions for a source without content-hash semantics"
            )));
        }
        return Ok((
            IntegrityState::UnavailableByFormat,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
        ));
    }
    if artifacts.is_empty() {
        return Ok((
            IntegrityState::RequiredMissing,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
        ));
    }

    let mut evidence = Vec::with_capacity(artifacts.len());
    let mut sources = Vec::with_capacity(artifacts.len());
    let mut platforms = BTreeSet::new();
    let mut has_missing = false;
    let mut has_invalid = false;
    for (artifact_name, value) in &artifacts {
        let artifact_locator = format!("{locator}.{artifact_name}");
        let artifact = table(value, &artifact_locator)?;
        deny_unknown(artifact, &["url", "hash", "size"], &artifact_locator)?;
        let url = string_field(artifact, "url", &artifact_locator)?;
        if let Some(size) = artifact.get("size") {
            if !size.as_integer().is_some_and(|size| size >= 0) {
                return Err(parse_error(format!(
                    "{artifact_locator}.size must be a non-negative integer"
                )));
            }
        }
        sources.push(NormalizedSource {
            kind: SourceKind::Url,
            location: Some(url.to_string()),
            immutable_revision: None,
            locator: format!("{artifact_locator}.url"),
        });
        if artifact_name.starts_with("wheels[") {
            if let Some(platform) = wheel_platform(url) {
                platforms.insert(platform);
            }
        }
        let (algorithm, digest, validity) = match artifact.get("hash") {
            None => (None, None, HashValidity::Missing),
            Some(value) => {
                let hash = value.as_str().ok_or_else(|| {
                    parse_error(format!("{artifact_locator}.hash must be a string"))
                })?;
                parse_hash(hash)
            }
        };
        has_missing |= validity == HashValidity::Missing;
        has_invalid |= validity == HashValidity::Invalid;
        evidence.push(IntegrityEvidence {
            algorithm,
            value: digest,
            locator: format!("{artifact_locator}.hash"),
        });
    }
    let state = if has_invalid {
        IntegrityState::Invalid
    } else if has_missing {
        IntegrityState::RequiredMissing
    } else {
        IntegrityState::RequiredPresent
    };
    Ok((
        state,
        evidence,
        sources,
        platforms.into_iter().collect(),
        artifacts.len(),
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HashValidity {
    Present,
    Missing,
    Invalid,
}

fn parse_hash(hash: &str) -> (Option<String>, Option<String>, HashValidity) {
    let Some((algorithm, digest)) = hash.split_once(':') else {
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
    let valid = expected.is_some_and(|length| is_hex(digest, length));
    (
        Some(algorithm.to_string()),
        Some(digest.to_ascii_lowercase()),
        if valid {
            HashValidity::Present
        } else {
            HashValidity::Invalid
        },
    )
}

fn wheel_platform(url: &str) -> Option<String> {
    let without_fragment = url.split(['?', '#']).next().unwrap_or(url);
    let filename = without_fragment.rsplit('/').next()?;
    let stem = filename.strip_suffix(".whl")?;
    let platform = stem.rsplit('-').next()?;
    (!platform.is_empty()).then(|| platform.to_string())
}

fn validate_metadata_value(value: &toml::Value, context: &str) -> Result<(), LockfileError> {
    if value.is_str() || value.is_bool() || value.is_integer() || value.is_float() {
        return Ok(());
    }
    if let Some(values) = value.as_array() {
        if values.iter().all(|value| {
            value.is_str() || value.is_bool() || value.is_integer() || value.is_float()
        }) {
            return Ok(());
        }
    }
    Err(parse_error(format!(
        "{context} has an unsupported metadata value"
    )))
}

fn string_array(value: Option<&toml::Value>, context: &str) -> Result<Vec<String>, LockfileError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| parse_error(format!("{context} must be an array")))?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    parse_error(format!("{context}[{index}] must be a non-empty string"))
                })
        })
        .collect()
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

fn add_units(count: usize, units: usize) -> Result<usize, LockfileError> {
    count
        .checked_add(units)
        .ok_or_else(|| parse_error("coverage count overflowed"))
}

fn parse_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::Parse {
        syntax: "uv TOML",
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
