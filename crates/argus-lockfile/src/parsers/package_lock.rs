use super::LockfileParser;
use argus_core::{Ecosystem, PackageCoordinate};
use base64::Engine as _;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

use crate::{
    parse_json, BoundedInput, Coverage, DetectedLockfile, FormatVersion, IntegrityEvidence,
    IntegrityState, LockfileError, LockfileFormat, NormalizedDependency, NormalizedSource,
    ParseOutput, SourceKind,
};

pub struct PackageLockParser;
pub static PARSER: PackageLockParser = PackageLockParser;

impl LockfileParser for PackageLockParser {
    fn format(&self) -> LockfileFormat {
        LockfileFormat::PackageLock
    }

    fn parse(
        &self,
        input: &BoundedInput<'_>,
        detected: &DetectedLockfile,
    ) -> Result<ParseOutput, LockfileError> {
        if detected.format != self.format()
            || !matches!(
                detected.version,
                FormatVersion::PackageLock2 | FormatVersion::PackageLock3
            )
        {
            return Err(parse_error("detected format/version does not match parser"));
        }
        let value = parse_json(input)?;
        let root = object(&value, "root")?;
        deny_unknown(
            root,
            &[
                "name",
                "version",
                "lockfileVersion",
                "requires",
                "packages",
                "dependencies",
            ],
            0,
        )?;
        let packages = object_field(root, "packages", "root")?;
        let mut units = PackageUnits {
            input_records: packages.len(),
            ..PackageUnits::default()
        };
        let mut records = Vec::with_capacity(packages.len());
        let mut coordinates = BTreeSet::new();
        for (occurrence_index, (path, raw)) in packages.iter().enumerate() {
            let entry = object(raw, &format!("packages[{path:?}]"))?;
            deny_unknown(
                entry,
                &[
                    "name",
                    "version",
                    "resolved",
                    "integrity",
                    "link",
                    "dev",
                    "optional",
                    "devOptional",
                    "peer",
                    "extraneous",
                    "inBundle",
                    "hasInstallScript",
                    "hasShrinkwrap",
                    "license",
                    "deprecated",
                    "engines",
                    "os",
                    "cpu",
                    "bin",
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                    "acceptDependencies",
                    "peerDependenciesMeta",
                    "bundleDependencies",
                    "funding",
                    "workspaces",
                ],
                occurrence_index,
            )?;
            validate_package_metadata(entry, occurrence_index)?;
            let record = package_record(path, entry, occurrence_index as u64)?;
            if let Some(coordinate) = &record.coordinate {
                coordinates.insert((
                    coordinate.original_name.clone(),
                    coordinate.original_version.clone(),
                ));
            }
            records.push(record);
            units.recognized_records += 1;
        }

        match detected.version {
            FormatVersion::PackageLock2 => {
                if let Some(dependencies) = root.get("dependencies") {
                    let dependencies = object(dependencies, "dependencies")?;
                    units.input_nodes = count_compatibility_nodes(dependencies)?;
                    units.recognized_nodes =
                        traverse_compatibility_tree(dependencies, &coordinates)?;
                }
            }
            FormatVersion::PackageLock3 if root.contains_key("dependencies") => {
                return Err(partial(units.input_records, 0, 1));
            }
            FormatVersion::PackageLock3 => {}
            _ => unreachable!("version was checked above"),
        }
        finish(detected, records, units)
    }
}

#[derive(Default)]
struct PackageUnits {
    input_records: usize,
    input_nodes: usize,
    recognized_records: usize,
    recognized_nodes: usize,
}

fn package_record(
    path: &str,
    entry: &Map<String, Value>,
    occurrence_index: u64,
) -> Result<NormalizedDependency, LockfileError> {
    let is_root = path.is_empty();
    let is_link = optional_bool(entry, "link")?.unwrap_or(false);
    let raw_name = optional_string(entry, "name")?
        .map(str::to_string)
        .or_else(|| package_name_from_path(path));
    let raw_version = optional_string(entry, "version")?.map(str::to_string);
    let coordinate = match (&raw_name, &raw_version) {
        (Some(name), Some(version)) => Some(
            PackageCoordinate::new(Ecosystem::Npm, name, version).map_err(|error| {
                parse_error(format!("invalid package coordinate at `{path}`: {error}"))
            })?,
        ),
        _ if is_root || is_link => None,
        _ => {
            return Err(parse_error(format!(
                "package entry `{path}` is missing name or version"
            )))
        }
    };

    let resolved = optional_string(entry, "resolved")?.map(str::to_string);
    let (source_kind, source_location) = if is_root {
        (SourceKind::Workspace, Some(".".to_string()))
    } else if is_link {
        let location = resolved
            .clone()
            .unwrap_or_else(|| format!("workspace:{path}"));
        (SourceKind::Workspace, Some(location))
    } else {
        classify_source(
            resolved.as_deref(),
            raw_name.as_deref().expect("coordinate checked"),
            raw_version.as_deref().expect("coordinate checked"),
        )
    };
    let integrity_locator = format!("packages[{path:?}].integrity");
    let (integrity_state, integrity) = match source_kind {
        SourceKind::Registry | SourceKind::Url => {
            parse_required_sri(optional_string(entry, "integrity")?, &integrity_locator)
        }
        _ => (
            IntegrityState::UnavailableByFormat,
            optional_string(entry, "integrity")?
                .map(|value| parse_sri(value, &integrity_locator).1)
                .unwrap_or_default(),
        ),
    };
    Ok(NormalizedDependency {
        coordinate,
        format: LockfileFormat::PackageLock,
        sources: vec![NormalizedSource {
            kind: source_kind,
            immutable_revision: (source_kind == SourceKind::Git)
                .then(|| source_location.as_deref().and_then(immutable_revision))
                .flatten(),
            location: source_location,
            locator: format!("packages[{path:?}].resolved"),
        }],
        integrity_state,
        integrity,
        raw_name,
        raw_version,
        locator: format!("packages[{path:?}]"),
        condition: package_condition(entry)?,
        platform: None,
        occurrence_index,
    })
}

fn classify_source(
    resolved: Option<&str>,
    name: &str,
    version: &str,
) -> (SourceKind, Option<String>) {
    let Some(resolved) = resolved else {
        return (SourceKind::Registry, Some(format!("npm:{name}@{version}")));
    };
    let lower = resolved.to_ascii_lowercase();
    if lower == "registry.npmjs.org" {
        return (
            SourceKind::Registry,
            Some("https://registry.npmjs.org/".to_string()),
        );
    }
    let kind =
        if lower.starts_with("git") || lower.starts_with("github:") || lower.starts_with("ssh:") {
            SourceKind::Git
        } else if lower.starts_with("workspace:") || lower.starts_with("link:") {
            SourceKind::Workspace
        } else if lower.starts_with("file:") {
            SourceKind::Path
        } else if npm_registry_url(&lower) {
            SourceKind::Registry
        } else {
            SourceKind::Url
        };
    (kind, Some(resolved.to_string()))
}

fn npm_registry_url(value: &str) -> bool {
    [
        "https://registry.npmjs.org/",
        "https://registry.yarnpkg.com/",
        "https://npm.pkg.github.com/",
        "http://registry.npmjs.org/",
        "http://registry.yarnpkg.com/",
        "http://npm.pkg.github.com/",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

fn parse_required_sri(
    value: Option<&str>,
    locator: &str,
) -> (IntegrityState, Vec<IntegrityEvidence>) {
    match value {
        None => (IntegrityState::RequiredMissing, Vec::new()),
        Some(value) => parse_sri(value, locator),
    }
}

pub(super) fn parse_sri(value: &str, locator: &str) -> (IntegrityState, Vec<IntegrityEvidence>) {
    if value.is_empty() {
        return (
            IntegrityState::Invalid,
            vec![evidence(None, Some(value), locator)],
        );
    }
    let mut evidence_items = Vec::new();
    let mut invalid = false;
    for token in value.split_ascii_whitespace() {
        let Some((algorithm, digest)) = token.split_once('-') else {
            evidence_items.push(evidence(None, Some(token), locator));
            invalid = true;
            continue;
        };
        let expected = match algorithm.to_ascii_lowercase().as_str() {
            "sha1" => Some(20),
            "sha256" => Some(32),
            "sha384" => Some(48),
            "sha512" => Some(64),
            _ => None,
        };
        let decoded = base64::engine::general_purpose::STANDARD.decode(digest);
        if expected.is_none() || decoded.as_ref().map(|bytes| bytes.len()).ok() != expected {
            invalid = true;
        }
        evidence_items.push(evidence(Some(algorithm), Some(digest), locator));
    }
    if evidence_items.is_empty() {
        evidence_items.push(evidence(None, Some(value), locator));
        invalid = true;
    }
    (
        if invalid {
            IntegrityState::Invalid
        } else {
            IntegrityState::RequiredPresent
        },
        evidence_items,
    )
}

fn evidence(algorithm: Option<&str>, value: Option<&str>, locator: &str) -> IntegrityEvidence {
    IntegrityEvidence {
        algorithm: algorithm.map(|value| value.to_ascii_lowercase()),
        value: value.map(str::to_string),
        locator: locator.to_string(),
    }
}

fn immutable_revision(source: &str) -> Option<String> {
    let candidate = source
        .rsplit_once('#')
        .map(|(_, value)| value)
        .or_else(|| source.rsplit_once("commit=").map(|(_, value)| value))?;
    is_commit(candidate).then(|| candidate.to_string())
}

fn is_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn package_name_from_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let marker = "node_modules/";
    let offset = path.rfind(marker).map_or(0, |index| index + marker.len());
    let name = &path[offset..];
    (!name.is_empty()).then(|| name.to_string())
}

fn package_condition(entry: &Map<String, Value>) -> Result<Option<String>, LockfileError> {
    let mut parts = Vec::new();
    for key in ["os", "cpu"] {
        if let Some(value) = entry.get(key) {
            let values = value
                .as_array()
                .ok_or_else(|| parse_error(format!("`{key}` must be an array")))?;
            let mut strings = Vec::with_capacity(values.len());
            for value in values {
                strings.push(
                    value
                        .as_str()
                        .ok_or_else(|| parse_error(format!("`{key}` values must be strings")))?,
                );
            }
            parts.push(format!("{key}={}", strings.join(",")));
        }
    }
    for key in ["dev", "optional", "devOptional"] {
        if optional_bool(entry, key)?.unwrap_or(false) {
            parts.push(key.to_string());
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join(";")))
}

fn validate_package_metadata(
    entry: &Map<String, Value>,
    recognized: usize,
) -> Result<(), LockfileError> {
    for key in [
        "name",
        "version",
        "resolved",
        "integrity",
        "license",
        "deprecated",
    ] {
        optional_string(entry, key)?;
    }
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "acceptDependencies",
    ] {
        validate_string_map(entry, key)?;
    }
    for key in ["os", "cpu", "workspaces"] {
        validate_string_array(entry, key)?;
    }
    validate_bundle_dependencies(entry)?;
    for key in [
        "link",
        "dev",
        "optional",
        "devOptional",
        "peer",
        "extraneous",
        "inBundle",
        "hasInstallScript",
        "hasShrinkwrap",
    ] {
        optional_bool(entry, key)?;
    }
    validate_bin(entry)?;
    validate_engines(entry)?;
    validate_peer_dependencies_meta(entry, recognized)?;
    validate_funding(entry, recognized)?;
    Ok(())
}

fn validate_string_map(entry: &Map<String, Value>, key: &str) -> Result<(), LockfileError> {
    let Some(value) = entry.get(key) else {
        return Ok(());
    };
    for dependency in object(value, key)?.values() {
        if !dependency.is_string() {
            return Err(parse_error(format!("`{key}` values must be strings")));
        }
    }
    Ok(())
}

fn validate_string_array(entry: &Map<String, Value>, key: &str) -> Result<(), LockfileError> {
    let Some(value) = entry.get(key) else {
        return Ok(());
    };
    let values = value
        .as_array()
        .ok_or_else(|| parse_error(format!("`{key}` must be an array")))?;
    if values.iter().any(|value| !value.is_string()) {
        return Err(parse_error(format!("`{key}` values must be strings")));
    }
    Ok(())
}

fn validate_bundle_dependencies(entry: &Map<String, Value>) -> Result<(), LockfileError> {
    let Some(value) = entry.get("bundleDependencies") else {
        return Ok(());
    };
    if value.is_boolean() {
        return Ok(());
    }
    let values = value
        .as_array()
        .ok_or_else(|| parse_error("`bundleDependencies` must be a boolean or array"))?;
    if values.iter().any(|value| !value.is_string()) {
        return Err(parse_error(
            "`bundleDependencies` array values must be strings",
        ));
    }
    Ok(())
}

fn validate_bin(entry: &Map<String, Value>) -> Result<(), LockfileError> {
    let Some(value) = entry.get("bin") else {
        return Ok(());
    };
    if value.is_string() {
        return Ok(());
    }
    for target in object(value, "bin")?.values() {
        if !target.is_string() {
            return Err(parse_error("`bin` values must be strings"));
        }
    }
    Ok(())
}

fn validate_engines(entry: &Map<String, Value>) -> Result<(), LockfileError> {
    let Some(value) = entry.get("engines") else {
        return Ok(());
    };
    if let Some(values) = value.as_array() {
        if values.iter().any(|value| !value.is_string()) {
            return Err(parse_error("`engines` values must be strings"));
        }
        return Ok(());
    }
    for requirement in object(value, "engines")?.values() {
        if !requirement.is_string() {
            return Err(parse_error("`engines` values must be strings"));
        }
    }
    Ok(())
}

fn validate_peer_dependencies_meta(
    entry: &Map<String, Value>,
    recognized: usize,
) -> Result<(), LockfileError> {
    let Some(value) = entry.get("peerDependenciesMeta") else {
        return Ok(());
    };
    for metadata in object(value, "peerDependenciesMeta")?.values() {
        let metadata = object(metadata, "peerDependenciesMeta entry")?;
        deny_unknown(metadata, &["optional"], recognized)?;
        optional_bool(metadata, "optional")?;
    }
    Ok(())
}

fn validate_funding(entry: &Map<String, Value>, recognized: usize) -> Result<(), LockfileError> {
    let Some(value) = entry.get("funding") else {
        return Ok(());
    };
    if let Some(values) = value.as_array() {
        for value in values {
            validate_funding_item(value, recognized)?;
        }
    } else {
        validate_funding_item(value, recognized)?;
    }
    Ok(())
}

fn validate_funding_item(value: &Value, recognized: usize) -> Result<(), LockfileError> {
    if value.is_string() {
        return Ok(());
    }
    let funding = object(value, "funding entry")?;
    deny_unknown(funding, &["type", "url"], recognized)?;
    optional_string(funding, "type")?;
    required_string(funding, "url")?;
    Ok(())
}

fn traverse_compatibility_tree(
    dependencies: &Map<String, Value>,
    coordinates: &BTreeSet<(String, String)>,
) -> Result<usize, LockfileError> {
    let mut recognized = 0usize;
    for (name, raw) in dependencies {
        let entry = object(raw, "v2 compatibility dependency")?;
        deny_unknown(
            entry,
            &[
                "version",
                "resolved",
                "integrity",
                "requires",
                "dependencies",
                "dev",
                "optional",
                "bundled",
            ],
            recognized,
        )?;
        let version = required_string(entry, "version")?;
        if !coordinates.contains(&(name.clone(), version.to_string())) {
            return Err(partial(0, recognized, 1));
        }
        for key in ["resolved", "integrity"] {
            optional_string(entry, key)?;
        }
        if let Some(value) = entry.get("requires") {
            for requirement in object(value, "requires")?.values() {
                if !requirement.is_string() {
                    return Err(parse_error("compatibility requires values must be strings"));
                }
            }
        }
        for key in ["dev", "optional", "bundled"] {
            optional_bool(entry, key)?;
        }
        recognized = recognized
            .checked_add(1)
            .ok_or_else(|| parse_error("coverage count overflowed"))?;
        if let Some(children) = entry.get("dependencies") {
            recognized = recognized
                .checked_add(traverse_compatibility_tree(
                    object(children, "dependencies")?,
                    coordinates,
                )?)
                .ok_or_else(|| parse_error("coverage count overflowed"))?;
        }
    }
    Ok(recognized)
}

fn count_compatibility_nodes(dependencies: &Map<String, Value>) -> Result<usize, LockfileError> {
    let mut total = dependencies.len();
    for raw in dependencies.values() {
        let entry = object(raw, "v2 compatibility dependency")?;
        if let Some(children) = entry.get("dependencies") {
            total = total
                .checked_add(count_compatibility_nodes(object(
                    children,
                    "dependencies",
                )?)?)
                .ok_or_else(|| parse_error("coverage count overflowed"))?;
        }
    }
    Ok(total)
}

fn finish(
    detected: &DetectedLockfile,
    records: Vec<NormalizedDependency>,
    units: PackageUnits,
) -> Result<ParseOutput, LockfileError> {
    if records.len() != units.recognized_records {
        return Err(LockfileError::CoverageMismatch {
            detail: "emitted package records differ from recognized input records".to_string(),
        });
    }
    let total_units = units
        .input_records
        .checked_add(units.input_nodes)
        .ok_or_else(|| parse_error("coverage count overflowed"))?;
    let recognized_units = units
        .recognized_records
        .checked_add(units.recognized_nodes)
        .ok_or_else(|| parse_error("coverage count overflowed"))?;
    let mut output = ParseOutput {
        detected: detected.clone(),
        coverage: Coverage {
            total_units,
            recognized_units,
            unsupported_units: total_units.saturating_sub(recognized_units),
            record_units: units.input_records,
            traversed_non_record_units: units.input_nodes,
        },
        records,
        metadata_integrity: Vec::new(),
    };
    output.validate_and_sort()?;
    Ok(output)
}

fn deny_unknown(
    map: &Map<String, Value>,
    allowed: &[&str],
    recognized: usize,
) -> Result<(), LockfileError> {
    if map.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(partial(0, recognized, 1));
    }
    Ok(())
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, LockfileError> {
    value
        .as_object()
        .ok_or_else(|| parse_error(format!("`{label}` must be an object")))
}

fn object_field<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, LockfileError> {
    object(
        map.get(key)
            .ok_or_else(|| parse_error(format!("`{label}.{key}` is required")))?,
        key,
    )
}

fn required_string<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, LockfileError> {
    optional_string(map, key)?.ok_or_else(|| parse_error(format!("`{key}` is required")))
}

fn optional_string<'a>(
    map: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, LockfileError> {
    match map.get(key) {
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| parse_error(format!("`{key}` must be a string"))),
        None => Ok(None),
    }
}

fn optional_bool(map: &Map<String, Value>, key: &str) -> Result<Option<bool>, LockfileError> {
    match map.get(key) {
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| parse_error(format!("`{key}` must be a boolean"))),
        None => Ok(None),
    }
}

fn partial(record_units: usize, recognized: usize, unsupported: usize) -> LockfileError {
    LockfileError::PartialAnalysis {
        total_units: record_units
            .saturating_add(recognized)
            .saturating_add(unsupported),
        recognized_units: record_units.saturating_add(recognized),
        unsupported_units: unsupported,
    }
}

fn parse_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::Parse {
        syntax: "package-lock JSON",
        detail: detail.into(),
    }
}
