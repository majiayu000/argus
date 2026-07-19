use super::LockfileParser;
use crate::{
    parse_json, BoundedInput, Coverage, DetectedLockfile, FormatVersion, IntegrityEvidence,
    IntegrityState, LockfileError, LockfileFormat, NormalizedDependency, NormalizedSource,
    ParseOutput, SourceKind,
};
use argus_core::{Ecosystem, PackageCoordinate};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub struct ComposerParser;
pub static PARSER: ComposerParser = ComposerParser;

const EDGE_FIELDS: [&str; 6] = [
    "require",
    "require-dev",
    "conflict",
    "provide",
    "replace",
    "suggest",
];

#[derive(Clone, Copy, Default)]
struct UnitCount {
    input: usize,
    recognized: usize,
}

#[derive(Default)]
struct InputCoverage {
    records: UnitCount,
    edges: [UnitCount; EDGE_FIELDS.len()],
}

impl InputCoverage {
    fn discover_record(&mut self) -> Result<(), LockfileError> {
        increment(&mut self.records.input, "Composer input record")
    }

    fn recognize_record(&mut self) -> Result<(), LockfileError> {
        increment(&mut self.records.recognized, "Composer recognized record")
    }

    fn discover_edge(&mut self, index: usize) -> Result<(), LockfileError> {
        increment(
            &mut self.edges[index].input,
            &format!("Composer {} input edge", EDGE_FIELDS[index]),
        )
    }

    fn recognize_edge(&mut self, index: usize) -> Result<(), LockfileError> {
        increment(
            &mut self.edges[index].recognized,
            &format!("Composer {} recognized edge", EDGE_FIELDS[index]),
        )
    }

    fn finish(&self, emitted_records: usize) -> Result<Coverage, LockfileError> {
        if self.records.input != self.records.recognized || self.records.input != emitted_records {
            return Err(coverage_error(format!(
                "input records {}, recognized records {}, emitted records {}",
                self.records.input, self.records.recognized, emitted_records
            )));
        }
        let mut input_non_records = 0usize;
        let mut recognized_non_records = 0usize;
        for (index, units) in self.edges.iter().enumerate() {
            if units.input != units.recognized {
                return Err(coverage_error(format!(
                    "{} input edges {} do not equal recognized edges {}",
                    EDGE_FIELDS[index], units.input, units.recognized
                )));
            }
            input_non_records = input_non_records
                .checked_add(units.input)
                .ok_or_else(|| model_error("Composer coverage overflowed"))?;
            recognized_non_records = recognized_non_records
                .checked_add(units.recognized)
                .ok_or_else(|| model_error("Composer coverage overflowed"))?;
        }
        let total_units = self
            .records
            .input
            .checked_add(input_non_records)
            .ok_or_else(|| model_error("Composer coverage overflowed"))?;
        let recognized_units = self
            .records
            .recognized
            .checked_add(recognized_non_records)
            .ok_or_else(|| model_error("Composer coverage overflowed"))?;
        Ok(Coverage {
            total_units,
            recognized_units,
            unsupported_units: 0,
            record_units: self.records.input,
            traversed_non_record_units: input_non_records,
        })
    }
}

impl LockfileParser for ComposerParser {
    fn format(&self) -> LockfileFormat {
        LockfileFormat::Composer
    }

    fn parse(
        &self,
        input: &BoundedInput<'_>,
        detected: &DetectedLockfile,
    ) -> Result<ParseOutput, LockfileError> {
        if detected.format != self.format() || detected.version != FormatVersion::ComposerSchema1 {
            return Err(model_error("Composer parser received mismatched detection"));
        }
        let value = parse_json(input)?;
        let root = value
            .as_object()
            .ok_or_else(|| parse_error("root must be an object"))?;
        validate_root(root)?;

        let mut records = Vec::new();
        let mut coverage = InputCoverage::default();
        for group in ["packages", "packages-dev"] {
            let packages = root
                .get(group)
                .and_then(Value::as_array)
                .ok_or_else(|| parse_error(format!("`{group}` must be an array")))?;
            for (index, package) in packages.iter().enumerate() {
                coverage.discover_record()?;
                let locator = format!("{group}[{index}]");
                let object = package
                    .as_object()
                    .ok_or_else(|| parse_error(format!("`{locator}` must be an object")))?;
                let occurrence_index = u64::try_from(coverage.records.input - 1)
                    .map_err(|_| model_error("Composer occurrence index overflowed"))?;
                let record = parse_package(object, group, index, occurrence_index, &mut coverage)?;
                coverage.recognize_record()?;
                records.push(record);
            }
        }

        let output_coverage = coverage.finish(records.len())?;
        let mut output = ParseOutput {
            detected: detected.clone(),
            records,
            coverage: output_coverage,
            metadata_integrity: Vec::new(),
        };
        output.validate_and_sort()?;
        Ok(output)
    }
}

fn validate_root(root: &Map<String, Value>) -> Result<(), LockfileError> {
    const ALLOWED: &[&str] = &[
        "_readme",
        "content-hash",
        "packages",
        "packages-dev",
        "aliases",
        "minimum-stability",
        "stability-flags",
        "prefer-stable",
        "prefer-lowest",
        "platform",
        "platform-dev",
        "plugin-api-version",
    ];
    reject_unknown(root, ALLOWED, "root")?;
    require_string(root, "content-hash", "root")?;
    require_array(root, "packages", "root")?;
    require_array(root, "packages-dev", "root")?;
    validate_optional_type(root, "_readme", Value::is_array, "array")?;
    validate_optional_type(root, "aliases", Value::is_array, "array")?;
    validate_optional_type(root, "minimum-stability", Value::is_string, "string")?;
    for field in ["stability-flags", "platform", "platform-dev"] {
        validate_optional_type(root, field, Value::is_object, "object")?;
    }
    for field in ["prefer-stable", "prefer-lowest"] {
        validate_optional_type(root, field, Value::is_boolean, "boolean")?;
    }
    validate_optional_type(root, "plugin-api-version", Value::is_string, "string")?;
    Ok(())
}

fn parse_package(
    package: &Map<String, Value>,
    group: &str,
    index: usize,
    occurrence_index: u64,
    coverage: &mut InputCoverage,
) -> Result<NormalizedDependency, LockfileError> {
    const ALLOWED: &[&str] = &[
        "name",
        "version",
        "version_normalized",
        "type",
        "target-dir",
        "time",
        "license",
        "authors",
        "description",
        "homepage",
        "keywords",
        "support",
        "funding",
        "notification-url",
        "include-path",
        "autoload",
        "autoload-dev",
        "bin",
        "extra",
        "transport-options",
        "archive",
        "abandoned",
        "dist",
        "source",
        "require",
        "require-dev",
        "conflict",
        "provide",
        "replace",
        "suggest",
    ];
    let locator = format!("{group}[{index}]");
    reject_unknown(package, ALLOWED, &locator)?;
    let name = require_string(package, "name", &locator)?.to_string();
    let version = require_string(package, "version", &locator)?.to_string();
    validate_package_metadata(package, &locator)?;

    for (section_index, field) in EDGE_FIELDS.iter().enumerate() {
        if let Some(edges) = package.get(*field) {
            let edges = edges
                .as_object()
                .ok_or_else(|| parse_error(format!("`{locator}.{field}` must be an object")))?;
            for (edge, constraint) in edges {
                coverage.discover_edge(section_index)?;
                let constraint = constraint.as_str().ok_or_else(|| {
                    parse_error(format!("`{locator}.{field}.{edge}` must be a string"))
                })?;
                if edge.trim().is_empty() || constraint.trim().is_empty() {
                    return Err(parse_error(format!(
                        "`{locator}.{field}` contains an empty edge or constraint"
                    )));
                }
                coverage.recognize_edge(section_index)?;
            }
        }
    }

    let dist = parse_transport(package.get("dist"), &locator, "dist", true)?;
    let source = parse_transport(package.get("source"), &locator, "source", false)?;
    let mut sources = Vec::with_capacity(2);
    if let Some(transport) = &dist {
        sources.push(normalize_transport_source(transport, &locator)?);
    }
    if let Some(transport) = &source {
        sources.push(normalize_transport_source(transport, &locator)?);
    }
    if sources.is_empty() {
        sources.push(NormalizedSource {
            kind: SourceKind::UnavailableByFormat,
            location: None,
            immutable_revision: None,
            locator: format!("{locator}.source-unavailable"),
        });
    }
    let (integrity_state, integrity) = dist.as_ref().map_or(
        (IntegrityState::UnavailableByFormat, Vec::new()),
        |transport| dist_integrity(transport, &locator),
    );

    let coordinate = PackageCoordinate::new(Ecosystem::Packagist, name.clone(), version.clone())
        .map_err(|error| model_error(error.to_string()))?;
    Ok(NormalizedDependency {
        coordinate: Some(coordinate),
        format: LockfileFormat::Composer,
        sources,
        integrity_state,
        integrity,
        raw_name: Some(name),
        raw_version: Some(version),
        locator,
        condition: Some(group.to_string()),
        platform: None,
        occurrence_index,
    })
}

struct Transport {
    section: &'static str,
    kind: String,
    url: String,
    reference: Option<String>,
    shasum: Option<String>,
}

fn normalize_transport_source(
    transport: &Transport,
    locator: &str,
) -> Result<NormalizedSource, LockfileError> {
    let kind = match (transport.section, transport.kind.as_str()) {
        (_, "path") => SourceKind::Path,
        ("source", "git") => SourceKind::Git,
        ("dist", "zip" | "tar" | "file" | "gzip" | "xz" | "phar" | "rar" | "7z") => SourceKind::Url,
        _ => {
            return Err(parse_error(format!(
                "unsupported Composer {} transport type `{}`",
                transport.section, transport.kind
            )))
        }
    };
    let immutable_revision = (kind == SourceKind::Git)
        .then_some(transport.reference.as_deref())
        .flatten()
        .and_then(immutable_revision);
    Ok(NormalizedSource {
        kind,
        location: Some(transport.url.clone()),
        immutable_revision,
        locator: format!("{locator}.{}.url", transport.section),
    })
}

fn parse_transport(
    value: Option<&Value>,
    locator: &str,
    section: &'static str,
    allow_shasum: bool,
) -> Result<Option<Transport>, LockfileError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| parse_error(format!("`{locator}.{section}` must be an object or null")))?;
    let allowed = if allow_shasum {
        &["type", "url", "reference", "shasum"][..]
    } else {
        &["type", "url", "reference"][..]
    };
    reject_unknown(object, allowed, &format!("{locator}.{section}"))?;
    let kind = require_string(object, "type", &format!("{locator}.{section}"))?.to_string();
    let url = require_string(object, "url", &format!("{locator}.{section}"))?.to_string();
    if kind.is_empty() || url.is_empty() {
        return Err(parse_error(format!(
            "`{locator}.{section}` type and url must not be empty"
        )));
    }
    let reference = optional_nullable_string(object, "reference", locator)?;
    let shasum = if allow_shasum {
        optional_nullable_string(object, "shasum", locator)?
    } else {
        None
    };
    Ok(Some(Transport {
        section,
        kind,
        url,
        reference,
        shasum,
    }))
}

fn dist_integrity(
    transport: &Transport,
    locator: &str,
) -> (IntegrityState, Vec<IntegrityEvidence>) {
    if transport.kind == "path"
        && transport
            .shasum
            .as_deref()
            .is_none_or(|value| value.is_empty())
    {
        return (IntegrityState::UnavailableByFormat, Vec::new());
    }
    let Some(raw) = transport
        .shasum
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return (IntegrityState::OptionalAbsent, Vec::new());
    };
    let normalized = raw.to_ascii_lowercase();
    let evidence = vec![IntegrityEvidence {
        algorithm: Some("sha1".to_string()),
        value: Some(normalized.clone()),
        locator: format!("{locator}.dist.shasum"),
    }];
    let valid = normalized.len() == 40
        && normalized
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if valid {
        (IntegrityState::OptionalPresent, evidence)
    } else {
        (IntegrityState::Invalid, evidence)
    }
}

fn validate_package_metadata(
    package: &Map<String, Value>,
    locator: &str,
) -> Result<(), LockfileError> {
    for field in [
        "version_normalized",
        "type",
        "target-dir",
        "time",
        "description",
        "homepage",
        "notification-url",
    ] {
        validate_optional_type(package, field, Value::is_string, "string")?;
    }
    for field in [
        "license",
        "authors",
        "keywords",
        "funding",
        "include-path",
        "bin",
    ] {
        validate_optional_type(package, field, Value::is_array, "array")?;
    }
    for field in [
        "support",
        "autoload",
        "autoload-dev",
        "extra",
        "transport-options",
        "archive",
    ] {
        validate_optional_type(package, field, Value::is_object, "object")?;
    }
    if let Some(abandoned) = package.get("abandoned") {
        if !(abandoned.is_boolean() || abandoned.is_string()) {
            return Err(parse_error(format!(
                "`{locator}.abandoned` must be a boolean or string"
            )));
        }
    }
    Ok(())
}

fn reject_unknown(
    object: &Map<String, Value>,
    allowed: &[&str],
    locator: &str,
) -> Result<(), LockfileError> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(field.as_str()))
    {
        return Err(parse_error(format!(
            "unsupported field `{locator}.{field}`"
        )));
    }
    Ok(())
}

fn require_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    locator: &str,
) -> Result<&'a str, LockfileError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| parse_error(format!("`{locator}.{field}` must be a string")))
}

fn require_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    locator: &str,
) -> Result<&'a Vec<Value>, LockfileError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| parse_error(format!("`{locator}.{field}` must be an array")))
}

fn validate_optional_type(
    object: &Map<String, Value>,
    field: &str,
    predicate: fn(&Value) -> bool,
    expected: &str,
) -> Result<(), LockfileError> {
    if object.get(field).is_some_and(|value| !predicate(value)) {
        return Err(parse_error(format!("`{field}` must be a {expected}")));
    }
    Ok(())
}

fn optional_nullable_string(
    object: &Map<String, Value>,
    field: &str,
    locator: &str,
) -> Result<Option<String>, LockfileError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(parse_error(format!(
            "`{locator}.{field}` must be a string or null"
        ))),
    }
}

fn immutable_revision(raw: &str) -> Option<String> {
    (matches!(raw.len(), 40 | 64)
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    .then(|| raw.to_string())
}

fn parse_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::Parse {
        syntax: "Composer JSON",
        detail: detail.into(),
    }
}

fn model_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::InvalidModel {
        detail: detail.into(),
    }
}

fn coverage_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::CoverageMismatch {
        detail: format!("Composer {}", detail.into()),
    }
}

fn increment(value: &mut usize, label: &str) -> Result<(), LockfileError> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| model_error(format!("{label} count overflowed")))?;
    Ok(())
}
