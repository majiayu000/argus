use super::LockfileParser;
use crate::{
    BoundedInput, Coverage, DetectedLockfile, FormatVersion, IntegrityEvidence, IntegrityState,
    LockfileError, LockfileFormat, NormalizedDependency, NormalizedSource, ParseOutput,
    ScalarBudget, SourceKind,
};
use argus_core::{Ecosystem, PackageCoordinate};
use semver::Version;
use std::collections::{BTreeMap, BTreeSet};

pub struct BundlerParser;
pub static PARSER: BundlerParser = BundlerParser;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Gem,
    Git,
    Path,
    Platforms,
    Dependencies,
    Checksums,
    RubyVersion,
    BundledWith,
}

struct Block<'a> {
    section: Section,
    lines: Vec<(usize, &'a str)>,
}

struct PendingSpec {
    name: String,
    version: String,
    lock_name: String,
    platform: Option<String>,
    source_kind: SourceKind,
    source_location: String,
    immutable_revision: Option<String>,
    locator: String,
    dependency_names: BTreeSet<String>,
    occurrence_index: u64,
}

struct ParsedChecksums {
    by_lock_name: BTreeMap<String, Vec<IntegrityEvidence>>,
    invalid_lock_names: BTreeSet<String>,
    metadata_integrity: Vec<IntegrityEvidence>,
}

#[derive(Default)]
struct InputCoverage {
    input_records: usize,
    input_non_records: usize,
    recognized_records: usize,
    recognized_non_records: usize,
}

impl InputCoverage {
    fn discover_record(&mut self) -> Result<(), LockfileError> {
        increment(&mut self.input_records, "Bundler input record")
    }

    fn recognize_record(&mut self) -> Result<(), LockfileError> {
        increment(&mut self.recognized_records, "Bundler recognized record")
    }

    fn discover_non_record(&mut self) -> Result<(), LockfileError> {
        increment(&mut self.input_non_records, "Bundler input non-record")
    }

    fn recognize_non_record(&mut self) -> Result<(), LockfileError> {
        increment(
            &mut self.recognized_non_records,
            "Bundler recognized non-record",
        )
    }

    fn finish(&self, emitted_records: usize) -> Result<Coverage, LockfileError> {
        if self.input_records != self.recognized_records
            || self.input_records != emitted_records
            || self.input_non_records != self.recognized_non_records
        {
            return Err(LockfileError::CoverageMismatch {
                detail: format!(
                    "Bundler input records {}, recognized records {}, emitted records {}, input non-records {}, recognized non-records {}",
                    self.input_records,
                    self.recognized_records,
                    emitted_records,
                    self.input_non_records,
                    self.recognized_non_records
                ),
            });
        }
        let total_units = self
            .input_records
            .checked_add(self.input_non_records)
            .ok_or_else(|| model_error("Bundler coverage overflowed"))?;
        let recognized_units = self
            .recognized_records
            .checked_add(self.recognized_non_records)
            .ok_or_else(|| model_error("Bundler coverage overflowed"))?;
        Ok(Coverage {
            total_units,
            recognized_units,
            unsupported_units: 0,
            record_units: self.input_records,
            traversed_non_record_units: self.input_non_records,
        })
    }
}

impl LockfileParser for BundlerParser {
    fn format(&self) -> LockfileFormat {
        LockfileFormat::Bundler
    }

    fn parse(
        &self,
        input: &BoundedInput<'_>,
        detected: &DetectedLockfile,
    ) -> Result<ParseOutput, LockfileError> {
        if detected.format != self.format()
            || !matches!(
                detected.version,
                FormatVersion::Bundler2 | FormatVersion::Bundler3 | FormatVersion::Bundler4
            )
        {
            return Err(model_error("Bundler parser received mismatched detection"));
        }

        let mut scalars = ScalarBudget::new();
        let blocks = split_blocks(input.text(), &mut scalars)?;
        let bundled_version = bundled_version(&blocks, &mut scalars)?;
        let parsed_version = Version::parse(&bundled_version)
            .map_err(|error| parse_error(format!("invalid BUNDLED WITH version: {error}")))?;
        ensure_detected_version(parsed_version.major, detected.version)?;

        let platforms = parse_platforms(&blocks, &mut scalars)?;
        observe_ruby_version(&blocks, &mut scalars)?;
        let mut specs = Vec::new();
        let mut coverage = InputCoverage::default();
        for block in &blocks {
            if matches!(block.section, Section::Gem | Section::Git | Section::Path) {
                parse_source_block(block, &platforms, &mut specs, &mut coverage, &mut scalars)?;
            }
        }
        if specs.is_empty() {
            return Err(parse_error("no GEM/GIT/PATH specs were recognized"));
        }

        let known_names = specs
            .iter()
            .map(|spec| spec.name.as_str())
            .collect::<BTreeSet<_>>();
        for spec in &specs {
            for dependency in &spec.dependency_names {
                if !known_names.contains(dependency.as_str()) {
                    return Err(parse_error(format!(
                        "unmatched spec dependency `{dependency}` at `{}`",
                        spec.locator
                    )));
                }
            }
        }
        parse_dependencies(&blocks, &known_names, &mut coverage, &mut scalars)?;

        let checksums = parse_checksums(
            &blocks,
            &specs,
            &bundled_version,
            parsed_version.major,
            parsed_version.minor,
            &mut coverage,
            &mut scalars,
        )?;
        let checksums_present = blocks
            .iter()
            .any(|block| block.section == Section::Checksums);

        let mut records = Vec::with_capacity(specs.len());
        for spec in specs {
            let checksum = checksums.by_lock_name.get(&spec.lock_name).cloned();
            let invalid = checksums.invalid_lock_names.contains(&spec.lock_name);
            let (integrity_state, integrity) =
                integrity_for_spec(spec.source_kind, checksums_present, checksum, invalid);
            let coordinate = PackageCoordinate::new(
                Ecosystem::RubyGems,
                spec.name.clone(),
                spec.version.clone(),
            )
            .map_err(|error| model_error(error.to_string()))?;
            records.push(NormalizedDependency {
                coordinate: Some(coordinate),
                format: LockfileFormat::Bundler,
                sources: vec![NormalizedSource {
                    kind: spec.source_kind,
                    location: Some(spec.source_location),
                    immutable_revision: spec.immutable_revision,
                    locator: format!("{}.source", spec.locator),
                }],
                integrity_state,
                integrity,
                raw_name: Some(spec.name),
                raw_version: Some(spec.version),
                locator: spec.locator,
                condition: None,
                platform: spec.platform,
                occurrence_index: spec.occurrence_index,
            });
        }

        let output_coverage = coverage.finish(records.len())?;
        let mut output = ParseOutput {
            detected: detected.clone(),
            records,
            coverage: output_coverage,
            metadata_integrity: checksums.metadata_integrity,
        };
        output.validate_and_sort()?;
        Ok(output)
    }
}

fn split_blocks<'a>(
    input: &'a str,
    scalars: &mut ScalarBudget,
) -> Result<Vec<Block<'a>>, LockfileError> {
    let mut blocks: Vec<Block<'_>> = Vec::new();
    for (line_index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            scalars.observe(line)?;
            let section = match line {
                "GEM" => Section::Gem,
                "GIT" => Section::Git,
                "PATH" => Section::Path,
                "PLATFORMS" => Section::Platforms,
                "DEPENDENCIES" => Section::Dependencies,
                "CHECKSUMS" => Section::Checksums,
                "RUBY VERSION" => Section::RubyVersion,
                "BUNDLED WITH" => Section::BundledWith,
                _ => {
                    return Err(parse_error(format!(
                        "unknown Bundler section `{line}` at line {}",
                        line_index + 1
                    )))
                }
            };
            blocks.push(Block {
                section,
                lines: Vec::new(),
            });
        } else if let Some(block) = blocks.last_mut() {
            if line.as_bytes().contains(&b'\t') {
                return Err(parse_error(format!(
                    "tab indentation is unsupported at line {}",
                    line_index + 1
                )));
            }
            block.lines.push((line_index + 1, line));
        } else {
            return Err(parse_error(format!(
                "content precedes the first section at line {}",
                line_index + 1
            )));
        }
    }
    require_single_section(&blocks, Section::Dependencies, "DEPENDENCIES")?;
    require_single_section(&blocks, Section::BundledWith, "BUNDLED WITH")?;
    for (section, name) in [
        (Section::Platforms, "PLATFORMS"),
        (Section::Checksums, "CHECKSUMS"),
        (Section::RubyVersion, "RUBY VERSION"),
    ] {
        if blocks
            .iter()
            .filter(|block| block.section == section)
            .count()
            > 1
        {
            return Err(parse_error(format!("duplicate {name} section")));
        }
    }
    Ok(blocks)
}

fn require_single_section(
    blocks: &[Block<'_>],
    section: Section,
    name: &str,
) -> Result<(), LockfileError> {
    let count = blocks
        .iter()
        .filter(|block| block.section == section)
        .count();
    if count != 1 {
        return Err(parse_error(format!(
            "expected exactly one {name} section, found {count}"
        )));
    }
    Ok(())
}

fn bundled_version(
    blocks: &[Block<'_>],
    scalars: &mut ScalarBudget,
) -> Result<String, LockfileError> {
    let block = blocks
        .iter()
        .find(|block| block.section == Section::BundledWith)
        .ok_or_else(|| parse_error("missing BUNDLED WITH section"))?;
    if block.lines.len() != 1 {
        return Err(parse_error("BUNDLED WITH must contain exactly one version"));
    }
    let version = block.lines[0].1.trim();
    if version.is_empty() {
        return Err(parse_error("BUNDLED WITH version is empty"));
    }
    scalars.observe(version)?;
    Ok(version.to_string())
}

fn ensure_detected_version(major: u64, detected: FormatVersion) -> Result<(), LockfileError> {
    let matches = matches!(
        (major, detected),
        (2, FormatVersion::Bundler2) | (3, FormatVersion::Bundler3) | (4, FormatVersion::Bundler4)
    );
    if matches {
        Ok(())
    } else {
        Err(model_error(
            "BUNDLED WITH version changed after format detection",
        ))
    }
}

fn parse_platforms(
    blocks: &[Block<'_>],
    scalars: &mut ScalarBudget,
) -> Result<Vec<String>, LockfileError> {
    let mut platforms = Vec::new();
    if let Some(block) = blocks
        .iter()
        .find(|block| block.section == Section::Platforms)
    {
        for (line_number, line) in &block.lines {
            require_indent(line, 2, *line_number)?;
            let platform = line.trim();
            scalars.observe(platform)?;
            if platform.is_empty() || !platforms.iter().any(|value| value == platform) {
                platforms.push(platform.to_string());
            } else {
                return Err(parse_error(format!(
                    "duplicate platform `{platform}` at line {line_number}"
                )));
            }
        }
    }
    platforms.sort_by_key(|value| std::cmp::Reverse(value.len()));
    Ok(platforms)
}

fn observe_ruby_version(
    blocks: &[Block<'_>],
    scalars: &mut ScalarBudget,
) -> Result<(), LockfileError> {
    if let Some(block) = blocks
        .iter()
        .find(|block| block.section == Section::RubyVersion)
    {
        for (_, line) in &block.lines {
            scalars.observe(line.trim())?;
        }
    }
    Ok(())
}

fn parse_source_block(
    block: &Block<'_>,
    platforms: &[String],
    specs: &mut Vec<PendingSpec>,
    coverage: &mut InputCoverage,
    scalars: &mut ScalarBudget,
) -> Result<(), LockfileError> {
    let source_kind = match block.section {
        Section::Gem => SourceKind::Registry,
        Section::Git => SourceKind::Git,
        Section::Path => SourceKind::Path,
        _ => return Err(model_error("non-source block reached source parser")),
    };
    let mut remote = None;
    let mut revision = None;
    let mut glob = None;
    let mut saw_specs = false;
    let mut current_spec = None;
    for (line_number, line) in &block.lines {
        let indent = indentation(line);
        let trimmed = line.trim();
        if indent == 2 && trimmed == "specs:" {
            scalars.observe("specs")?;
            if saw_specs {
                return Err(parse_error(format!(
                    "duplicate specs marker at line {line_number}"
                )));
            }
            saw_specs = true;
            current_spec = None;
        } else if !saw_specs && indent == 2 {
            let (key, value) = split_metadata(trimmed, *line_number)?;
            scalars.observe(key)?;
            scalars.observe(&value)?;
            match key {
                "remote" => set_once(&mut remote, value, "remote", *line_number)?,
                "revision" if source_kind == SourceKind::Git => {
                    set_once(&mut revision, value, "revision", *line_number)?
                }
                "glob" if source_kind == SourceKind::Path => {
                    set_once(&mut glob, value, "glob", *line_number)?
                }
                _ => {
                    return Err(parse_error(format!(
                        "unsupported source metadata `{key}` at line {line_number}"
                    )))
                }
            }
        } else if saw_specs && indent == 4 {
            coverage.discover_record()?;
            let (name, locked, lock_name) = parse_lock_name(trimmed, *line_number)?;
            scalars.observe(&name)?;
            scalars.observe(&locked)?;
            let (version, platform) = split_platform(&locked, platforms);
            let source_location = remote.clone().ok_or_else(|| {
                parse_error(format!("source block lacks remote at line {line_number}"))
            })?;
            let locator = format!("line {line_number}: {lock_name}");
            specs.push(PendingSpec {
                name,
                version,
                lock_name,
                platform,
                source_kind,
                source_location,
                immutable_revision: revision.as_deref().and_then(immutable_revision),
                locator,
                dependency_names: BTreeSet::new(),
                occurrence_index: specs.len() as u64,
            });
            coverage.recognize_record()?;
            current_spec = Some(specs.len() - 1);
        } else if saw_specs && indent == 6 {
            coverage.discover_non_record()?;
            scalars.observe(trimmed)?;
            let dependency = dependency_name(trimmed, *line_number)?;
            let index = current_spec.ok_or_else(|| {
                parse_error(format!("dependency precedes a spec at line {line_number}"))
            })?;
            specs[index].dependency_names.insert(dependency);
            coverage.recognize_non_record()?;
        } else {
            return Err(parse_error(format!(
                "unsupported source entry at line {line_number}"
            )));
        }
    }
    if !saw_specs {
        return Err(parse_error("source block lacks specs marker"));
    }
    Ok(())
}

fn parse_dependencies(
    blocks: &[Block<'_>],
    known_names: &BTreeSet<&str>,
    coverage: &mut InputCoverage,
    scalars: &mut ScalarBudget,
) -> Result<(), LockfileError> {
    let block = blocks
        .iter()
        .find(|block| block.section == Section::Dependencies)
        .ok_or_else(|| parse_error("missing DEPENDENCIES section"))?;
    for (line_number, line) in &block.lines {
        coverage.discover_non_record()?;
        require_indent(line, 2, *line_number)?;
        scalars.observe(line.trim())?;
        let name = dependency_name(line.trim(), *line_number)?;
        if !known_names.contains(name.as_str()) {
            return Err(parse_error(format!(
                "unmatched top-level dependency `{name}` at line {line_number}"
            )));
        }
        coverage.recognize_non_record()?;
    }
    Ok(())
}

fn parse_checksums(
    blocks: &[Block<'_>],
    specs: &[PendingSpec],
    bundled_version: &str,
    major: u64,
    minor: u64,
    coverage: &mut InputCoverage,
    scalars: &mut ScalarBudget,
) -> Result<ParsedChecksums, LockfileError> {
    let Some(block) = blocks
        .iter()
        .find(|block| block.section == Section::Checksums)
    else {
        return Ok(ParsedChecksums {
            by_lock_name: BTreeMap::new(),
            invalid_lock_names: BTreeSet::new(),
            metadata_integrity: Vec::new(),
        });
    };
    if major == 2 && minor < 5 {
        return Err(parse_error(
            "CHECKSUMS requires Bundler version 2.5 or newer",
        ));
    }

    let spec_counts = specs.iter().fold(BTreeMap::new(), |mut counts, spec| {
        *counts.entry(spec.lock_name.as_str()).or_insert(0usize) += 1;
        counts
    });
    let mut by_lock_name = BTreeMap::new();
    let mut invalid_lock_names = BTreeSet::new();
    let mut metadata_integrity = Vec::new();
    let mut saw_self = false;
    for (line_number, line) in &block.lines {
        coverage.discover_non_record()?;
        require_indent(line, 2, *line_number)?;
        let (name, version, lock_name, tail) = parse_checksum_line(line.trim(), *line_number)?;
        scalars.observe(&name)?;
        scalars.observe(&version)?;
        let (mut evidence, invalid) = parse_digest_list(&tail, *line_number, scalars)?;
        if name == "bundler" && !spec_counts.contains_key(lock_name.as_str()) {
            if major != 4 {
                return Err(parse_error(format!(
                    "Bundler self-checksum requires major 4 at line {line_number}"
                )));
            }
            if saw_self {
                return Err(parse_error("duplicate Bundler self-checksum"));
            }
            if version != bundled_version {
                return Err(parse_error(format!(
                    "self-checksum version `{version}` does not exactly match BUNDLED WITH `{bundled_version}`"
                )));
            }
            saw_self = true;
            if evidence.is_empty() {
                evidence.push(IntegrityEvidence {
                    algorithm: None,
                    value: None,
                    locator: format!("line {line_number}"),
                });
            }
            metadata_integrity.extend(evidence);
            coverage.recognize_non_record()?;
            continue;
        }
        match spec_counts.get(lock_name.as_str()).copied() {
            None => {
                return Err(parse_error(format!(
                    "checksum `{lock_name}` does not match a spec"
                )))
            }
            Some(1) => {}
            Some(_) => {
                return Err(parse_error(format!(
                    "checksum `{lock_name}` matches duplicate specs"
                )))
            }
        }
        if by_lock_name.insert(lock_name.clone(), evidence).is_some() {
            return Err(parse_error(format!(
                "duplicate checksum lock-name `{lock_name}`"
            )));
        }
        if invalid {
            invalid_lock_names.insert(lock_name);
        }
        coverage.recognize_non_record()?;
    }
    Ok(ParsedChecksums {
        by_lock_name,
        invalid_lock_names,
        metadata_integrity,
    })
}

fn integrity_for_spec(
    source_kind: SourceKind,
    checksums_present: bool,
    checksum: Option<Vec<IntegrityEvidence>>,
    invalid: bool,
) -> (IntegrityState, Vec<IntegrityEvidence>) {
    let evidence = checksum.unwrap_or_default();
    if invalid {
        return (IntegrityState::Invalid, evidence);
    }
    if !evidence.is_empty() {
        let state = if source_kind == SourceKind::Registry {
            IntegrityState::RequiredPresent
        } else {
            IntegrityState::OptionalPresent
        };
        return (state, evidence);
    }
    match (source_kind, checksums_present) {
        (SourceKind::Registry, true) => (IntegrityState::RequiredMissing, Vec::new()),
        (SourceKind::Registry, false) => (IntegrityState::UnavailableByFormat, Vec::new()),
        _ => (IntegrityState::UnavailableByFormat, Vec::new()),
    }
}

fn parse_checksum_line(
    line: &str,
    line_number: usize,
) -> Result<(String, String, String, String), LockfileError> {
    let close = line
        .find(')')
        .ok_or_else(|| parse_error(format!("checksum lacks `)` at line {line_number}")))?;
    let head = &line[..=close];
    let (name, version, lock_name) = parse_lock_name(head, line_number)?;
    let tail = line[close + 1..].trim().to_string();
    Ok((name, version, lock_name, tail))
}

fn parse_digest_list(
    raw: &str,
    line_number: usize,
    scalars: &mut ScalarBudget,
) -> Result<(Vec<IntegrityEvidence>, bool), LockfileError> {
    if raw.is_empty() {
        return Ok((Vec::new(), false));
    }
    let mut algorithms = BTreeSet::new();
    let mut evidence = Vec::new();
    let mut invalid = false;
    for token in raw.split(',') {
        let token = token.trim();
        let (algorithm, value) = token
            .split_once('=')
            .ok_or_else(|| parse_error(format!("invalid checksum token at line {line_number}")))?;
        let algorithm = algorithm.trim().to_ascii_lowercase();
        let value = value.trim().to_ascii_lowercase();
        scalars.observe(&algorithm)?;
        scalars.observe(&value)?;
        if algorithm.is_empty() || value.is_empty() {
            return Err(parse_error(format!(
                "empty checksum algorithm/value at line {line_number}"
            )));
        }
        if !algorithms.insert(algorithm.clone()) {
            return Err(parse_error(format!(
                "duplicate checksum algorithm `{algorithm}` at line {line_number}"
            )));
        }
        let expected = match algorithm.as_str() {
            "sha256" => Some(64),
            "sha384" => Some(96),
            "sha512" => Some(128),
            "sha1" => Some(40),
            "md5" => Some(32),
            _ => None,
        };
        invalid |= expected.is_none_or(|length| {
            value.len() != length || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
        evidence.push(IntegrityEvidence {
            algorithm: Some(algorithm),
            value: Some(value),
            locator: format!("line {line_number}"),
        });
    }
    Ok((evidence, invalid))
}

fn parse_lock_name(
    raw: &str,
    line_number: usize,
) -> Result<(String, String, String), LockfileError> {
    let (name, locked) = raw
        .rsplit_once(" (")
        .ok_or_else(|| parse_error(format!("invalid lock-name `{raw}` at line {line_number}")))?;
    let locked = locked
        .strip_suffix(')')
        .ok_or_else(|| parse_error(format!("invalid lock-name `{raw}` at line {line_number}")))?;
    if name.is_empty() || locked.is_empty() || name.chars().any(char::is_whitespace) {
        return Err(parse_error(format!(
            "invalid lock-name `{raw}` at line {line_number}"
        )));
    }
    Ok((name.to_string(), locked.to_string(), raw.to_string()))
}

fn split_platform(locked: &str, platforms: &[String]) -> (String, Option<String>) {
    for platform in platforms {
        if platform != "ruby" {
            if let Some(version) = locked.strip_suffix(&format!("-{platform}")) {
                if !version.is_empty() {
                    return (version.to_string(), Some(platform.clone()));
                }
            }
        }
    }
    (locked.to_string(), None)
}

fn dependency_name(raw: &str, line_number: usize) -> Result<String, LockfileError> {
    let name = raw
        .split_once(" (")
        .map_or(raw, |(name, _)| name)
        .trim_end_matches('!')
        .trim();
    if name.is_empty() || name.chars().any(char::is_whitespace) {
        return Err(parse_error(format!(
            "invalid dependency `{raw}` at line {line_number}"
        )));
    }
    Ok(name.to_string())
}

fn split_metadata(raw: &str, line_number: usize) -> Result<(&str, String), LockfileError> {
    let (key, value) = raw
        .split_once(':')
        .ok_or_else(|| parse_error(format!("invalid source metadata at line {line_number}")))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(parse_error(format!(
            "empty source metadata `{key}` at line {line_number}"
        )));
    }
    Ok((key, value.to_string()))
}

fn set_once(
    slot: &mut Option<String>,
    value: String,
    field: &str,
    line_number: usize,
) -> Result<(), LockfileError> {
    if slot.replace(value).is_some() {
        return Err(parse_error(format!(
            "duplicate `{field}` at line {line_number}"
        )));
    }
    Ok(())
}

fn indentation(line: &str) -> usize {
    line.bytes().take_while(|byte| *byte == b' ').count()
}

fn require_indent(line: &str, expected: usize, line_number: usize) -> Result<(), LockfileError> {
    if indentation(line) != expected {
        return Err(parse_error(format!(
            "expected {expected}-space indentation at line {line_number}"
        )));
    }
    Ok(())
}

fn immutable_revision(raw: &str) -> Option<String> {
    let valid_length = matches!(raw.len(), 40 | 64);
    (valid_length
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    .then(|| raw.to_string())
}

fn parse_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::Parse {
        syntax: "Bundler",
        detail: detail.into(),
    }
}

fn model_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::InvalidModel {
        detail: detail.into(),
    }
}

fn increment(value: &mut usize, label: &str) -> Result<(), LockfileError> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| model_error(format!("{label} count overflowed")))?;
    Ok(())
}
