use super::LockfileParser;
use argus_core::{Ecosystem, PackageCoordinate};
use base64::Engine as _;
use yaml_rust2::{yaml::Hash, Yaml};

use crate::{
    parse_yaml, BoundedInput, Coverage, DetectedLockfile, FormatVersion, IntegrityEvidence,
    IntegrityState, LockfileError, LockfileFormat, NormalizedDependency, NormalizedSource,
    ParseOutput, ScalarBudget, SourceKind,
};

pub struct YarnParser;
pub static PARSER: YarnParser = YarnParser;

impl LockfileParser for YarnParser {
    fn format(&self) -> LockfileFormat {
        LockfileFormat::YarnClassic
    }

    fn parse(
        &self,
        input: &BoundedInput<'_>,
        detected: &DetectedLockfile,
    ) -> Result<ParseOutput, LockfileError> {
        match (detected.format, detected.version) {
            (LockfileFormat::YarnClassic, FormatVersion::YarnClassic1) => {
                parse_classic(input, detected)
            }
            (
                LockfileFormat::YarnBerry,
                FormatVersion::YarnBerry4 | FormatVersion::YarnBerry6 | FormatVersion::YarnBerry8,
            ) => parse_berry(input, detected),
            _ => Err(yarn_error("detected format/version does not match parser")),
        }
    }
}

#[derive(Default)]
struct ClassicBlock {
    selectors: Vec<String>,
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
}

#[derive(Default)]
struct YarnUnits {
    input_records: usize,
    input_edges: usize,
    recognized_records: usize,
    recognized_edges: usize,
}

fn parse_classic(
    input: &BoundedInput<'_>,
    detected: &DetectedLockfile,
) -> Result<ParseOutput, LockfileError> {
    let lines = input.text().lines().collect::<Vec<_>>();
    let header = lines
        .iter()
        .position(|line| !line.trim().is_empty())
        .ok_or_else(|| yarn_error("classic lockfile is empty"))?;
    if lines[header].trim_end() != "# yarn lockfile v1" {
        return Err(yarn_error("classic header is missing"));
    }
    let mut blocks = Vec::new();
    let mut units = YarnUnits::default();
    let mut scalar_budget = ScalarBudget::new();
    let mut index = header + 1;
    while index < lines.len() {
        let line = lines[index];
        if line.trim().is_empty() || line.starts_with('#') {
            index += 1;
            continue;
        }
        if line.starts_with(' ') || !line.ends_with(':') {
            return Err(partial(0, blocks.len(), 1));
        }
        let selectors = split_descriptors(&line[..line.len() - 1])?;
        if selectors.is_empty() {
            return Err(yarn_error("descriptor block has no selectors"));
        }
        for selector in &selectors {
            scalar_budget.observe(selector)?;
            let (name, _) = split_descriptor(selector)?;
            scalar_budget.observe(name)?;
            units.input_records = add_units(units.input_records, 1)?;
        }
        let mut block = ClassicBlock {
            selectors,
            ..ClassicBlock::default()
        };
        index += 1;
        while index < lines.len() {
            let line = lines[index];
            if line.trim().is_empty() {
                index += 1;
                continue;
            }
            if !line.starts_with(' ') {
                break;
            }
            if !line.starts_with("  ") || line.starts_with("    ") {
                return Err(partial(0, units.recognized_edges, 1));
            }
            let field = &line[2..];
            if let Some(section) = field.strip_suffix(':') {
                if !matches!(section, "dependencies" | "optionalDependencies") {
                    return Err(partial(0, units.recognized_edges, 1));
                }
                index += 1;
                while index < lines.len() && lines[index].starts_with("    ") {
                    let edge = &lines[index][4..];
                    units.input_edges = add_units(units.input_edges, 1)?;
                    let (name, requirement) = parse_classic_edge(edge)?;
                    scalar_budget.observe(name)?;
                    scalar_budget.observe(&requirement)?;
                    units.recognized_edges = add_units(units.recognized_edges, 1)?;
                    index += 1;
                }
                continue;
            }
            let (key, value) = split_classic_field(field)?;
            if matches!(key, "version" | "resolved" | "integrity" | "uid") {
                scalar_budget.observe(&value)?;
            }
            match key {
                "version" => set_once(&mut block.version, value, "version")?,
                "resolved" => set_once(&mut block.resolved, value, "resolved")?,
                "integrity" => set_once(&mut block.integrity, value, "integrity")?,
                "uid" => {
                    if value.is_empty() {
                        return Err(yarn_error("uid must not be empty"));
                    }
                }
                _ => return Err(partial(0, units.recognized_edges, 1)),
            }
            index += 1;
        }
        blocks.push(block);
    }

    let mut records = Vec::new();
    for (block_index, block) in blocks.into_iter().enumerate() {
        let version = block
            .version
            .as_deref()
            .ok_or_else(|| yarn_error(format!("block {block_index} lacks version")))?;
        for selector in &block.selectors {
            let occurrence_index = records.len() as u64;
            records.push(classic_record(
                selector,
                version,
                block.resolved.as_deref(),
                block.integrity.as_deref(),
                block_index,
                occurrence_index,
            )?);
            units.recognized_records = add_units(units.recognized_records, 1)?;
        }
    }
    finish(detected, records, units)
}

fn classic_record(
    selector: &str,
    version: &str,
    resolved: Option<&str>,
    integrity: Option<&str>,
    block_index: usize,
    occurrence_index: u64,
) -> Result<NormalizedDependency, LockfileError> {
    let (name, range) = split_descriptor(selector)?;
    let coordinate = PackageCoordinate::new(Ecosystem::Npm, name, version)
        .map_err(|error| yarn_error(format!("invalid `{selector}` coordinate: {error}")))?;
    let (source_kind, source_location) = classify_yarn_source(resolved, range, name, version);
    let integrity_locator = format!("block[{block_index}].integrity");
    let (integrity_state, evidence) =
        if matches!(source_kind, SourceKind::Registry | SourceKind::Url) {
            match integrity {
                Some(value) => parse_sri(value, &integrity_locator),
                None => resolved_fragment(resolved, &integrity_locator),
            }
        } else {
            (IntegrityState::UnavailableByFormat, Vec::new())
        };
    Ok(NormalizedDependency {
        coordinate: Some(coordinate),
        format: LockfileFormat::YarnClassic,
        sources: vec![NormalizedSource {
            kind: source_kind,
            immutable_revision: (source_kind == SourceKind::Git)
                .then(|| source_location.as_deref().and_then(immutable_revision))
                .flatten(),
            location: source_location,
            locator: format!("block[{block_index}].resolved"),
        }],
        integrity_state,
        integrity: evidence,
        raw_name: Some(name.to_string()),
        raw_version: Some(version.to_string()),
        locator: format!("block[{block_index}].selector[{selector:?}]"),
        condition: None,
        platform: None,
        occurrence_index,
    })
}

fn parse_berry(
    input: &BoundedInput<'_>,
    detected: &DetectedLockfile,
) -> Result<ParseOutput, LockfileError> {
    let yaml = parse_yaml(input)?;
    let root = yaml_hash(&yaml, "root")?;
    let metadata = yaml_hash(
        yaml_get(root, "__metadata").ok_or_else(|| yarn_error("missing __metadata"))?,
        "__metadata",
    )?;
    deny_yaml_unknown(metadata, &["version", "cacheKey"], 0)?;
    let mut units = count_berry_units(root)?;
    let mut records = Vec::new();
    for (key, raw_entry) in root {
        let key = yaml_string(key, "root key")?;
        if key == "__metadata" {
            continue;
        }
        let entry = yaml_hash(raw_entry, key)?;
        deny_yaml_unknown(
            entry,
            &[
                "version",
                "resolution",
                "checksum",
                "languageName",
                "linkType",
                "conditions",
                "dependencies",
                "peerDependencies",
                "dependenciesMeta",
                "peerDependenciesMeta",
                "bin",
            ],
            add_units(units.recognized_records, units.recognized_edges)?,
        )?;
        let version = yaml_required_scalar(entry, "version")?;
        let resolution = yaml_required_scalar(entry, "resolution")?;
        let checksum = yaml_optional_scalar(entry, "checksum")?;
        validate_berry_metadata(entry)?;
        for section in [
            "dependencies",
            "peerDependencies",
            "dependenciesMeta",
            "peerDependenciesMeta",
        ] {
            if let Some(value) = yaml_get(entry, section) {
                let edges = yaml_hash(value, section)?;
                for (edge_name, edge_value) in edges {
                    yaml_string(edge_name, section)?;
                    validate_berry_edge(section, edge_value)?;
                    units.recognized_edges = add_units(units.recognized_edges, 1)?;
                }
            }
        }
        let descriptors = split_descriptors(key)?;
        for descriptor in descriptors {
            let (name, _) = split_descriptor(&descriptor)?;
            let occurrence_index = records.len() as u64;
            records.push(berry_record(
                detected.format,
                name,
                version,
                resolution,
                checksum,
                entry,
                key,
                occurrence_index,
            )?);
            units.recognized_records = add_units(units.recognized_records, 1)?;
        }
    }
    finish(detected, records, units)
}

fn count_berry_units(root: &Hash) -> Result<YarnUnits, LockfileError> {
    let mut units = YarnUnits::default();
    for (key, value) in root {
        let key = yaml_string(key, "root key")?;
        if key == "__metadata" {
            continue;
        }
        units.input_records = add_units(units.input_records, split_descriptors(key)?.len())?;
        let entry = yaml_hash(value, key)?;
        for section in [
            "dependencies",
            "peerDependencies",
            "dependenciesMeta",
            "peerDependenciesMeta",
        ] {
            if let Some(edges) = yaml_get(entry, section) {
                units.input_edges = add_units(units.input_edges, yaml_hash(edges, section)?.len())?;
            }
        }
    }
    Ok(units)
}

#[allow(clippy::too_many_arguments)]
fn berry_record(
    format: LockfileFormat,
    name: &str,
    version: &str,
    resolution: &str,
    checksum: Option<&str>,
    entry: &Hash,
    descriptor_key: &str,
    occurrence_index: u64,
) -> Result<NormalizedDependency, LockfileError> {
    let coordinate = PackageCoordinate::new(Ecosystem::Npm, name, version)
        .map_err(|error| yarn_error(format!("invalid Berry coordinate: {error}")))?;
    let (source_kind, source_location) = classify_yarn_source(
        Some(resolution),
        resolution_protocol(resolution),
        name,
        version,
    );
    let integrity_locator = format!("{descriptor_key:?}.checksum");
    let (integrity_state, integrity) =
        if matches!(source_kind, SourceKind::Registry | SourceKind::Url) {
            match checksum {
                Some(value) => parse_berry_checksum(value, &integrity_locator),
                None => (IntegrityState::RequiredMissing, Vec::new()),
            }
        } else {
            (IntegrityState::UnavailableByFormat, Vec::new())
        };
    Ok(NormalizedDependency {
        coordinate: Some(coordinate),
        format,
        sources: vec![NormalizedSource {
            kind: source_kind,
            immutable_revision: (source_kind == SourceKind::Git)
                .then(|| source_location.as_deref().and_then(immutable_revision))
                .flatten(),
            location: source_location,
            locator: format!("{descriptor_key:?}.resolution"),
        }],
        integrity_state,
        integrity,
        raw_name: Some(name.to_string()),
        raw_version: Some(version.to_string()),
        locator: format!("descriptor[{descriptor_key:?}]"),
        condition: yaml_condition(entry)?,
        platform: None,
        occurrence_index,
    })
}

fn validate_berry_metadata(entry: &Hash) -> Result<(), LockfileError> {
    for key in ["languageName", "linkType"] {
        yaml_optional_scalar(entry, key)?;
    }
    if let Some(bin) = yaml_get(entry, "bin") {
        for (key, value) in yaml_hash(bin, "bin")? {
            yaml_string(key, "bin key")?;
            yaml_string(value, "bin value")?;
        }
    }
    Ok(())
}

fn validate_berry_edge(section: &str, value: &Yaml) -> Result<(), LockfileError> {
    if matches!(section, "dependencies" | "peerDependencies") {
        yaml_string(value, section)?;
        return Ok(());
    }
    let metadata = yaml_hash(value, section)?;
    let allowed = if section == "dependenciesMeta" {
        &["built", "optional", "unplugged"][..]
    } else {
        &["optional"][..]
    };
    deny_yaml_unknown(metadata, allowed, 0)?;
    for (_, value) in metadata {
        if !matches!(value, Yaml::Boolean(_)) {
            return Err(yarn_error(format!(
                "{section} metadata values must be booleans"
            )));
        }
    }
    Ok(())
}

fn classify_yarn_source(
    source: Option<&str>,
    protocol_hint: &str,
    name: &str,
    version: &str,
) -> (SourceKind, Option<String>) {
    let value = source.unwrap_or(protocol_hint);
    let lower = yarn_protocol(value).to_ascii_lowercase();
    let kind = if lower.starts_with("workspace:") {
        SourceKind::Workspace
    } else if lower.starts_with("link:")
        || lower.starts_with("portal:")
        || lower.starts_with("patch:")
        || lower.starts_with("file:")
    {
        SourceKind::Path
    } else if lower.starts_with("git") || lower.starts_with("ssh:") || lower.starts_with("github:")
    {
        SourceKind::Git
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        if npm_registry_url(&lower) {
            SourceKind::Registry
        } else {
            SourceKind::Url
        }
    } else {
        SourceKind::Registry
    };
    let location = if source.is_none() && kind == SourceKind::Registry {
        format!("npm:{name}@{version}")
    } else {
        value.to_string()
    };
    (kind, Some(location))
}

fn yarn_protocol(value: &str) -> &str {
    let lower = value.to_ascii_lowercase();
    if [
        "http://",
        "https://",
        "git",
        "ssh:",
        "github:",
        "workspace:",
        "link:",
        "portal:",
        "patch:",
        "file:",
        "npm:",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
    {
        return value;
    }
    value
        .rfind('@')
        .map(|index| &value[index + 1..])
        .filter(|suffix| suffix.contains(':'))
        .unwrap_or(value)
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

fn resolution_protocol(resolution: &str) -> &str {
    resolution
        .split_once('@')
        .map(|(_, value)| value)
        .unwrap_or(resolution)
}

fn resolved_fragment(
    resolved: Option<&str>,
    locator: &str,
) -> (IntegrityState, Vec<IntegrityEvidence>) {
    let Some(fragment) = resolved.and_then(|value| value.rsplit_once('#').map(|(_, value)| value))
    else {
        return (IntegrityState::RequiredMissing, Vec::new());
    };
    let valid = fragment.len() == 40 && fragment.bytes().all(|byte| byte.is_ascii_hexdigit());
    (
        if valid {
            IntegrityState::RequiredPresent
        } else {
            IntegrityState::Invalid
        },
        vec![IntegrityEvidence {
            algorithm: Some("sha1".to_string()),
            value: Some(fragment.to_ascii_lowercase()),
            locator: locator.to_string(),
        }],
    )
}

fn parse_sri(value: &str, locator: &str) -> (IntegrityState, Vec<IntegrityEvidence>) {
    let mut evidence = Vec::new();
    let mut invalid = value.is_empty();
    for token in value.split_ascii_whitespace() {
        let Some((algorithm, digest)) = token.split_once('-') else {
            invalid = true;
            evidence.push(integrity_evidence(None, token, locator));
            continue;
        };
        let expected = match algorithm.to_ascii_lowercase().as_str() {
            "sha1" => Some(20),
            "sha256" => Some(32),
            "sha384" => Some(48),
            "sha512" => Some(64),
            _ => None,
        };
        if base64::engine::general_purpose::STANDARD
            .decode(digest)
            .ok()
            .map(|value| value.len())
            != expected
        {
            invalid = true;
        }
        evidence.push(IntegrityEvidence {
            algorithm: Some(algorithm.to_ascii_lowercase()),
            value: Some(digest.to_string()),
            locator: locator.to_string(),
        });
    }
    if evidence.is_empty() {
        evidence.push(integrity_evidence(None, value, locator));
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

fn parse_berry_checksum(value: &str, locator: &str) -> (IntegrityState, Vec<IntegrityEvidence>) {
    let digest = value.rsplit_once('/').map_or(value, |(_, digest)| digest);
    let algorithm = match digest.len() {
        64 => Some("sha256"),
        96 => Some("sha384"),
        128 => Some("sha512"),
        _ => None,
    };
    let valid = algorithm.is_some() && digest.bytes().all(|byte| byte.is_ascii_hexdigit());
    (
        if valid {
            IntegrityState::RequiredPresent
        } else {
            IntegrityState::Invalid
        },
        vec![IntegrityEvidence {
            algorithm: algorithm.map(str::to_string),
            value: Some(digest.to_ascii_lowercase()),
            locator: locator.to_string(),
        }],
    )
}

fn integrity_evidence(algorithm: Option<&str>, value: &str, locator: &str) -> IntegrityEvidence {
    IntegrityEvidence {
        algorithm: algorithm.map(str::to_string),
        value: Some(value.to_string()),
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

fn split_descriptors(value: &str) -> Result<Vec<String>, LockfileError> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut quote = None;
    for (index, character) in value.char_indices() {
        match character {
            '"' | '\'' if quote == Some(character) => quote = None,
            '"' | '\'' if quote.is_none() => quote = Some(character),
            ',' if quote.is_none() => {
                result.push(unquote(value[start..index].trim())?.to_string());
                start = index + 1;
            }
            _ => {}
        }
    }
    if quote.is_some() {
        return Err(yarn_error("unterminated descriptor quote"));
    }
    result.push(unquote(value[start..].trim())?.to_string());
    if result.iter().any(String::is_empty) {
        return Err(yarn_error("empty selector descriptor"));
    }
    Ok(result)
}

fn split_descriptor(descriptor: &str) -> Result<(&str, &str), LockfileError> {
    let separator = descriptor
        .char_indices()
        .rev()
        .find_map(|(index, character)| (character == '@' && index > 0).then_some(index))
        .ok_or_else(|| yarn_error(format!("invalid descriptor `{descriptor}`")))?;
    let (name, range) = descriptor.split_at(separator);
    if name.is_empty() || range.len() == 1 {
        return Err(yarn_error(format!("invalid descriptor `{descriptor}`")));
    }
    Ok((name, &range[1..]))
}

fn split_classic_field(value: &str) -> Result<(&str, String), LockfileError> {
    let index = value
        .find(char::is_whitespace)
        .ok_or_else(|| yarn_error(format!("invalid classic field `{value}`")))?;
    let key = &value[..index];
    let raw = value[index..].trim();
    Ok((key, unquote(raw)?.to_string()))
}

fn parse_classic_edge(value: &str) -> Result<(&str, String), LockfileError> {
    let (name, requirement) = split_classic_field(value)?;
    if name.is_empty() || requirement.is_empty() {
        return Err(yarn_error("invalid classic dependency edge"));
    }
    Ok((name, requirement))
}

fn unquote(value: &str) -> Result<&str, LockfileError> {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if matches!(first, b'"' | b'\'') {
            if last != first {
                return Err(yarn_error("mismatched quotes"));
            }
            return Ok(&value[1..value.len() - 1]);
        }
    }
    if value.contains(char::is_whitespace) {
        return Err(yarn_error("unquoted scalar contains whitespace"));
    }
    Ok(value)
}

fn set_once(slot: &mut Option<String>, value: String, field: &str) -> Result<(), LockfileError> {
    if slot.replace(value).is_some() {
        return Err(partial(0, 0, 1));
    }
    if slot.as_deref() == Some("") {
        return Err(yarn_error(format!("{field} must not be empty")));
    }
    Ok(())
}

fn yaml_condition(entry: &Hash) -> Result<Option<String>, LockfileError> {
    let Some(value) = yaml_get(entry, "conditions") else {
        return Ok(None);
    };
    match value {
        Yaml::String(value) => Ok(Some(value.clone())),
        Yaml::Array(values) => {
            let strings = values
                .iter()
                .map(|value| yaml_string(value, "condition"))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(strings.join(";")))
        }
        _ => Err(yarn_error("conditions must be a string or string array")),
    }
}

fn finish(
    detected: &DetectedLockfile,
    records: Vec<NormalizedDependency>,
    units: YarnUnits,
) -> Result<ParseOutput, LockfileError> {
    if records.len() != units.recognized_records {
        return Err(LockfileError::CoverageMismatch {
            detail: "emitted Yarn records differ from recognized input records".to_string(),
        });
    }
    let total_units = add_units(units.input_records, units.input_edges)?;
    let recognized_units = add_units(units.recognized_records, units.recognized_edges)?;
    let mut output = ParseOutput {
        detected: detected.clone(),
        coverage: Coverage {
            total_units,
            recognized_units,
            unsupported_units: total_units.saturating_sub(recognized_units),
            record_units: units.input_records,
            traversed_non_record_units: units.input_edges,
        },
        records,
        metadata_integrity: Vec::new(),
    };
    output.validate_and_sort()?;
    Ok(output)
}

fn add_units(left: usize, right: usize) -> Result<usize, LockfileError> {
    left.checked_add(right)
        .ok_or_else(|| yarn_error("coverage count overflowed"))
}

fn yaml_hash<'a>(value: &'a Yaml, label: &str) -> Result<&'a Hash, LockfileError> {
    value
        .as_hash()
        .ok_or_else(|| yarn_error(format!("`{label}` must be a mapping")))
}

fn yaml_get<'a>(map: &'a Hash, key: &str) -> Option<&'a Yaml> {
    map.get(&Yaml::String(key.to_string()))
}

fn yaml_string<'a>(value: &'a Yaml, label: &str) -> Result<&'a str, LockfileError> {
    value
        .as_str()
        .ok_or_else(|| yarn_error(format!("`{label}` must be a string")))
}

fn yaml_required_scalar<'a>(map: &'a Hash, key: &str) -> Result<&'a str, LockfileError> {
    yaml_optional_scalar(map, key)?.ok_or_else(|| yarn_error(format!("`{key}` is required")))
}

fn yaml_optional_scalar<'a>(map: &'a Hash, key: &str) -> Result<Option<&'a str>, LockfileError> {
    match yaml_get(map, key) {
        Some(value) => yaml_string(value, key).map(Some),
        None => Ok(None),
    }
}

fn deny_yaml_unknown(map: &Hash, allowed: &[&str], recognized: usize) -> Result<(), LockfileError> {
    for key in map.keys() {
        let key = yaml_string(key, "mapping key")?;
        if !allowed.contains(&key) {
            return Err(partial(0, recognized, 1));
        }
    }
    Ok(())
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

fn yarn_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::Parse {
        syntax: "Yarn lockfile",
        detail: detail.into(),
    }
}
