use super::LockfileParser;
use crate::{
    ensure_record_count, parse_toml, BoundedInput, Coverage, DetectedLockfile, FormatVersion,
    IntegrityEvidence, IntegrityState, LockfileError, LockfileFormat, NormalizedDependency,
    NormalizedSource, ParseOutput, SourceKind,
};
use argus_core::{Ecosystem, PackageCoordinate};
use semver::Version;
use std::collections::BTreeSet;
use toml::value::Table;

pub struct CargoParser;
pub static PARSER: CargoParser = CargoParser;

impl LockfileParser for CargoParser {
    fn format(&self) -> LockfileFormat {
        LockfileFormat::Cargo
    }

    fn parse(
        &self,
        input: &BoundedInput<'_>,
        detected: &DetectedLockfile,
    ) -> Result<ParseOutput, LockfileError> {
        if detected.format != self.format()
            || !matches!(
                detected.version,
                FormatVersion::Cargo3 | FormatVersion::Cargo4
            )
        {
            return Err(parse_error(
                "detected format/version does not match Cargo 3/4",
            ));
        }
        let value = parse_toml(input)?;
        let root = table(&value, "root")?;
        deny_unknown(root, &["version", "package", "metadata"], "root")?;
        let packages = array_field(root, "package", "root")?;
        let input_record_units = packages.len();
        ensure_record_count(input_record_units)?;
        let identities = collect_identities(packages)?;

        if let Some(metadata) = root.get("metadata") {
            table(metadata, "metadata")?;
        }

        let mut traversed = 0usize;
        let mut emitted_record_units = 0usize;
        let mut records = Vec::with_capacity(input_record_units);
        for (index, value) in packages.iter().enumerate() {
            let package = table(value, &format!("package[{index}]"))?;
            deny_unknown(
                package,
                &["name", "version", "source", "checksum", "dependencies"],
                &format!("package[{index}]"),
            )?;
            let name = string_field(package, "name", &format!("package[{index}]"))?;
            let version = string_field(package, "version", &format!("package[{index}]"))?;
            let coordinate = coordinate(Ecosystem::CratesIo, name, version)?;
            let locator = format!("package[{index}]/{name}@{version}");

            if let Some(dependencies) = package.get("dependencies") {
                let dependencies = dependencies.as_array().ok_or_else(|| {
                    parse_error(format!("{locator}.dependencies must be an array"))
                })?;
                for (dependency_index, dependency) in dependencies.iter().enumerate() {
                    let dependency = dependency.as_str().ok_or_else(|| {
                        parse_error(format!(
                            "{locator}.dependencies[{dependency_index}] must be a string"
                        ))
                    })?;
                    validate_dependency_locator(
                        dependency,
                        &locator,
                        dependency_index,
                        &identities,
                    )?;
                    traversed = add_unit(traversed)?;
                }
            }

            let (source_kind, source_location, immutable_revision) =
                parse_source(package.get("source"), &locator)?;
            let (integrity_state, integrity) =
                parse_checksum(package.get("checksum"), source_kind, &locator)?;
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
                condition: None,
                platform: None,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CargoIdentity {
    name: String,
    version: String,
    source: Option<String>,
}

fn collect_identities(packages: &[toml::Value]) -> Result<Vec<CargoIdentity>, LockfileError> {
    let mut identities = Vec::with_capacity(packages.len());
    for (index, value) in packages.iter().enumerate() {
        let context = format!("package[{index}]");
        let package = table(value, &context)?;
        let name = string_field(package, "name", &context)?;
        let version = string_field(package, "version", &context)?;
        let source = package
            .get("source")
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| parse_error(format!("{context}.source must be a string")))
            })
            .transpose()?;
        identities.push(CargoIdentity {
            name: name.to_string(),
            version: version.to_string(),
            source,
        });
    }
    Ok(identities)
}

fn parse_source(
    value: Option<&toml::Value>,
    locator: &str,
) -> Result<(SourceKind, Option<String>, Option<String>), LockfileError> {
    let Some(value) = value else {
        return Ok((SourceKind::Path, Some("workspace".to_string()), None));
    };
    let source = value
        .as_str()
        .ok_or_else(|| parse_error(format!("{locator}.source must be a string")))?;
    if source.starts_with("registry+") || source.starts_with("sparse+") {
        let location = source
            .split_once('+')
            .map(|(_, location)| location)
            .filter(|location| !location.is_empty())
            .ok_or_else(|| parse_error(format!("{locator}.source has an empty registry URL")))?;
        return Ok((SourceKind::Registry, Some(location.to_string()), None));
    }
    if let Some(location) = source.strip_prefix("git+") {
        if location.is_empty() {
            return Err(parse_error(format!(
                "{locator}.source has an empty git locator"
            )));
        }
        let revision = location.rsplit_once('#').map(|(_, revision)| revision);
        let immutable_revision = revision
            .filter(|revision| is_commit(revision))
            .map(ToOwned::to_owned);
        return Ok((
            SourceKind::Git,
            Some(location.to_string()),
            immutable_revision,
        ));
    }
    Err(partial_error())
}

fn parse_checksum(
    value: Option<&toml::Value>,
    source_kind: SourceKind,
    locator: &str,
) -> Result<(IntegrityState, Vec<IntegrityEvidence>), LockfileError> {
    if source_kind != SourceKind::Registry {
        if value.is_some() {
            return Err(parse_error(format!(
                "{locator}.checksum is only valid for registry packages"
            )));
        }
        return Ok((IntegrityState::UnavailableByFormat, Vec::new()));
    }
    let Some(value) = value else {
        return Ok((IntegrityState::RequiredMissing, Vec::new()));
    };
    let value = value
        .as_str()
        .ok_or_else(|| parse_error(format!("{locator}.checksum must be a string")))?;
    let evidence = IntegrityEvidence {
        algorithm: Some("sha256".to_string()),
        value: Some(value.to_ascii_lowercase()),
        locator: format!("{locator}.checksum"),
    };
    let state = if is_hex(value, 64) {
        IntegrityState::RequiredPresent
    } else {
        IntegrityState::Invalid
    };
    Ok((state, vec![evidence]))
}

fn validate_dependency_locator(
    dependency: &str,
    locator: &str,
    index: usize,
    identities: &[CargoIdentity],
) -> Result<(), LockfileError> {
    if dependency.is_empty() || dependency.trim() != dependency {
        return Err(parse_error(format!(
            "{locator}.dependencies[{index}] is empty or not canonical"
        )));
    }
    let (identity, source) = if let Some((identity, source)) = dependency.rsplit_once(" (") {
        let source = source.strip_suffix(')').ok_or_else(|| {
            parse_error(format!(
                "{locator}.dependencies[{index}] has an unterminated source locator"
            ))
        })?;
        if identity.is_empty()
            || source.is_empty()
            || identity.contains(" (")
            || source.contains(['(', ')'])
        {
            return Err(parse_error(format!(
                "{locator}.dependencies[{index}] has an invalid source locator"
            )));
        }
        (identity, Some(source))
    } else {
        if dependency.contains(['(', ')']) {
            return Err(parse_error(format!(
                "{locator}.dependencies[{index}] has an invalid source locator"
            )));
        }
        (dependency, None)
    };
    let fields = identity.split(' ').collect::<Vec<_>>();
    if fields.is_empty()
        || fields.len() > 2
        || fields.iter().any(|field| field.is_empty())
        || fields.join(" ") != identity
    {
        return Err(parse_error(format!(
            "{locator}.dependencies[{index}] has an invalid package identity"
        )));
    }
    let name = fields[0];
    let version = fields.get(1).copied();
    if let Some(version) = version {
        Version::parse(version).map_err(|error| {
            parse_error(format!(
                "{locator}.dependencies[{index}] has invalid Cargo SemVer: {error}"
            ))
        })?;
    }
    let matches = identities
        .iter()
        .filter(|candidate| {
            candidate.name == name
                && version.is_none_or(|version| candidate.version == version)
                && source.is_none_or(|source| candidate.source.as_deref() == Some(source))
        })
        .count();
    if matches != 1 {
        return Err(parse_error(format!(
            "{locator}.dependencies[{index}] resolves to {matches} package records"
        )));
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

fn coordinate(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<PackageCoordinate, LockfileError> {
    PackageCoordinate::new(ecosystem, name, version).map_err(|error| LockfileError::InvalidModel {
        detail: error.to_string(),
    })
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

fn add_unit(count: usize) -> Result<usize, LockfileError> {
    count
        .checked_add(1)
        .ok_or_else(|| parse_error("coverage count overflowed"))
}

fn parse_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::Parse {
        syntax: "Cargo TOML",
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
