use super::index::DatasetIndex;
use super::limits::{
    ensure_at_most, MAX_AGGREGATE_DATASET_BYTES, MAX_ALIASES_PER_ENTRY, MAX_CONFUSABLE_BYTES,
    MAX_CONFUSABLE_MAPPINGS, MAX_CONFUSABLE_TARGET_BYTES, MAX_DATASET_BYTES, MAX_KEYBOARD_DEGREE,
    MAX_KEYBOARD_EDGES, MAX_KEYBOARD_KEYS, MAX_SOURCES_PER_FILE,
};
use super::normalize::{segment_identity, SegmentedIdentity};
use super::TyposquatError;
use argus_core::Ecosystem;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const MAX_IDENTITIES_PER_ECOSYSTEM: usize = super::MAX_MATCH_COMPARISONS;
const MAX_AGGREGATE_IDENTITIES: usize = MAX_IDENTITIES_PER_ECOSYSTEM * DATA_FILES.len();

const MANIFEST_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/manifest.json");
const NPM_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/npm.json");
const PYPI_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/pypi.json");
const CRATES_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/crates-io.json");
const GO_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/go.json");
const NUGET_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/nuget.json");
const MAVEN_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/maven.json");
const RUBYGEMS_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/rubygems.json");
const COMPOSER_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/composer.json");
const KEYBOARD_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/keyboard-qwerty-us.json");
const CONFUSABLES_BYTES: &[u8] = include_bytes!("../../data/typosquat/v1/unicode-confusables.json");

const DATA_FILES: [(Ecosystem, &str, &[u8]); 8] = [
    (Ecosystem::Npm, "npm.json", NPM_BYTES),
    (Ecosystem::PyPi, "pypi.json", PYPI_BYTES),
    (Ecosystem::CratesIo, "crates-io.json", CRATES_BYTES),
    (Ecosystem::Go, "go.json", GO_BYTES),
    (Ecosystem::NuGet, "nuget.json", NUGET_BYTES),
    (Ecosystem::Maven, "maven.json", MAVEN_BYTES),
    (Ecosystem::RubyGems, "rubygems.json", RUBYGEMS_BYTES),
    (Ecosystem::Packagist, "composer.json", COMPOSER_BYTES),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetAudit {
    pub id: String,
    pub version: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetAudit {
    pub ecosystem: Ecosystem,
    pub dataset_id: String,
    pub dataset_version: u32,
    pub entry_count: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TyposquatDataAudit {
    pub manifest_id: String,
    pub dataset_version: u32,
    pub combined_legacy_source_order_sha256: String,
    pub assets: Vec<AssetAudit>,
}

#[derive(Debug)]
pub(crate) struct Assets {
    pub datasets: BTreeMap<Ecosystem, Dataset>,
    pub keyboard_edges: BTreeSet<(char, char)>,
    pub confusables: BTreeMap<char, String>,
    audit: TyposquatDataAudit,
}

#[derive(Debug)]
pub(crate) struct Dataset {
    pub id: String,
    pub version: u32,
    pub raw_sha256: String,
    pub entries: Vec<DatasetEntry>,
    pub index: DatasetIndex,
}

#[derive(Debug)]
pub(crate) struct DatasetEntry {
    pub display: String,
    pub identity: SegmentedIdentity,
    pub aliases: Vec<SegmentedIdentity>,
    pub canonical: String,
    pub legacy_priority: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    schema_version: u32,
    manifest_id: String,
    dataset_version: u32,
    generator_version: String,
    generated_at: String,
    combined_legacy_source_order_sha256: String,
    datasets: Vec<ManifestDataset>,
    keyboard: ManifestKeyboard,
    confusables: ManifestConfusables,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDataset {
    ecosystem: String,
    file: String,
    count: usize,
    raw_sha256: String,
    legacy_source_count: usize,
    legacy_source_order_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestKeyboard {
    file: String,
    layout_id: String,
    raw_sha256: String,
    edge_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestConfusables {
    file: String,
    profile_id: String,
    unicode_version: String,
    raw_sha256: String,
    source_sha256: String,
    mapping_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatasetFile {
    schema_version: u32,
    ecosystem: String,
    dataset_id: String,
    dataset_version: u32,
    as_of: String,
    normalization: String,
    namespace_semantics: String,
    sources: Vec<DatasetSource>,
    entries: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatasetSource {
    id: String,
    kind: SourceKind,
    uri: String,
    retrieved_at: String,
    artifact_sha256: String,
    method: String,
    license: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SourceKind {
    LegacyRustConst,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    canonical_name: String,
    aliases: Vec<String>,
    popularity: Popularity,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Popularity {
    source_id: String,
    metric: PopularityMetric,
    value: u64,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum PopularityMetric {
    LegacyPriority,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyboardFile {
    schema_version: u32,
    layout_id: String,
    layout_version: u32,
    alphabet: String,
    edge_semantics: String,
    edges: Vec<[String; 2]>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfusablesFile {
    schema_version: u32,
    profile_id: String,
    unicode_version: String,
    source_uri: String,
    retrieved_at: String,
    source_sha256: String,
    source_date: String,
    generator_version: String,
    normalization: String,
    mappings: Vec<ConfusableMapping>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfusableMapping {
    source: String,
    target: String,
}

static ASSETS: OnceLock<Result<Assets, TyposquatError>> = OnceLock::new();

pub fn validate_embedded_assets() -> Result<(), TyposquatError> {
    assets().map(|_| ())
}

pub fn asset_audit() -> Result<TyposquatDataAudit, TyposquatError> {
    Ok(assets()?.audit.clone())
}

pub fn dataset_audit(ecosystem: Ecosystem) -> Result<DatasetAudit, TyposquatError> {
    let dataset = dataset(ecosystem)?;
    Ok(DatasetAudit {
        ecosystem,
        dataset_id: dataset.id.clone(),
        dataset_version: dataset.version,
        entry_count: dataset.entries.len(),
        sha256: dataset.raw_sha256.clone(),
    })
}

pub(crate) fn assets() -> Result<&'static Assets, TyposquatError> {
    ASSETS
        .get_or_init(load_assets)
        .as_ref()
        .map_err(Clone::clone)
}

pub(crate) fn dataset(ecosystem: Ecosystem) -> Result<&'static Dataset, TyposquatError> {
    assets()?
        .datasets
        .get(&ecosystem)
        .ok_or_else(|| TyposquatError::InvalidEmbeddedData("dataset is missing".into()))
}

fn load_assets() -> Result<Assets, TyposquatError> {
    let manifest: ManifestFile = parse_json("manifest.json", MANIFEST_BYTES)?;
    validate_manifest_header(&manifest)?;
    let keyboard_edges = validate_keyboard(&manifest.keyboard)?;
    let confusables = validate_confusables(&manifest.confusables)?;
    let mut aggregate_bytes = 0usize;
    let mut aggregate_identities = 0usize;
    let mut datasets = BTreeMap::new();
    let mut source_order = String::new();
    let mut audit_assets = Vec::with_capacity(10);
    audit_assets.push(AssetAudit {
        id: manifest.keyboard.layout_id.clone(),
        version: "1".into(),
        sha256: manifest.keyboard.raw_sha256.clone(),
    });
    audit_assets.push(AssetAudit {
        id: manifest.confusables.profile_id.clone(),
        version: manifest.confusables.unicode_version.clone(),
        sha256: manifest.confusables.raw_sha256.clone(),
    });

    if manifest.datasets.len() != DATA_FILES.len() {
        return embedded("manifest must contain exactly eight datasets");
    }
    for (ecosystem, file, bytes) in DATA_FILES {
        aggregate_bytes = checked_add(aggregate_bytes, bytes.len(), "dataset bytes")?;
        ensure_at_most(bytes.len(), MAX_DATASET_BYTES, &format!("{file} bytes"))?;
        let record = manifest
            .datasets
            .iter()
            .find(|record| record.file == file)
            .ok_or_else(|| {
                TyposquatError::InvalidEmbeddedData(format!("{file} missing from manifest"))
            })?;
        let expected_ecosystem = ecosystem_id(ecosystem);
        if record.ecosystem != expected_ecosystem
            || record.raw_sha256 != sha256(bytes)
            || record.count != record.legacy_source_count
        {
            return embedded(format!("{file} manifest metadata mismatch"));
        }
        let raw: DatasetFile = parse_json(file, bytes)?;
        let dataset = validate_dataset(ecosystem, file, &raw, record, &confusables)?;
        let identity_count = dataset.entries.iter().try_fold(0usize, |count, entry| {
            checked_add(count, 1 + entry.aliases.len(), "dataset identities")
        })?;
        aggregate_identities = checked_add(
            aggregate_identities,
            identity_count,
            "aggregate dataset identities",
        )?;
        validate_dataset_identity_count(file, identity_count)?;
        source_order.push_str(match ecosystem {
            Ecosystem::CratesIo => "crates",
            _ => expected_ecosystem,
        });
        source_order.push('\n');
        let mut ranked: Vec<_> = dataset.entries.iter().collect();
        ranked.sort_by_key(|entry| entry.legacy_priority);
        for entry in ranked {
            source_order.push_str(&entry.display);
            source_order.push('\n');
        }
        audit_assets.push(AssetAudit {
            id: dataset.id.clone(),
            version: dataset.version.to_string(),
            sha256: record.raw_sha256.clone(),
        });
        if datasets.insert(ecosystem, dataset).is_some() {
            return embedded("duplicate ecosystem dataset");
        }
    }
    ensure_at_most(
        aggregate_bytes,
        MAX_AGGREGATE_DATASET_BYTES,
        "aggregate dataset bytes",
    )?;
    validate_aggregate_identity_count(aggregate_identities)?;
    if sha256(source_order.as_bytes()) != manifest.combined_legacy_source_order_sha256 {
        return embedded("combined frozen source-order hash mismatch");
    }

    audit_assets.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(Assets {
        datasets,
        keyboard_edges,
        confusables,
        audit: TyposquatDataAudit {
            manifest_id: manifest.manifest_id,
            dataset_version: manifest.dataset_version,
            combined_legacy_source_order_sha256: manifest.combined_legacy_source_order_sha256,
            assets: audit_assets,
        },
    })
}

fn validate_manifest_header(manifest: &ManifestFile) -> Result<(), TyposquatError> {
    if manifest.schema_version != 1
        || manifest.dataset_version != 1
        || manifest.manifest_id != "argus-typosquat-v1"
        || manifest.generator_version != "argus-typosquat-data-v1"
        || manifest.generated_at != "2026-07-27T10:19:38Z"
    {
        return embedded("unsupported manifest identity or version");
    }
    validate_sha256(
        "combined source-order hash",
        &manifest.combined_legacy_source_order_sha256,
    )
}

fn validate_dataset(
    ecosystem: Ecosystem,
    file: &str,
    raw: &DatasetFile,
    manifest: &ManifestDataset,
    confusables: &BTreeMap<char, String>,
) -> Result<Dataset, TyposquatError> {
    if raw.schema_version != 1
        || raw.dataset_version != 1
        || raw.ecosystem != ecosystem_id(ecosystem)
        || raw.dataset_id != format!("argus-popular-{}-v1", ecosystem_id(ecosystem))
        || raw.as_of != "2026-07-27"
        || raw.normalization != normalization_id(ecosystem)
        || raw.namespace_semantics != namespace_id(ecosystem)
    {
        return embedded(format!("{file} schema or identity mismatch"));
    }
    if raw.entries.len() != manifest.count {
        return embedded(format!("{file} count mismatch"));
    }
    ensure_at_most(raw.sources.len(), MAX_SOURCES_PER_FILE, "dataset sources")?;
    if raw.sources.is_empty() {
        return embedded(format!("{file} has no provenance source"));
    }
    let mut source_ids = BTreeSet::new();
    for source in &raw.sources {
        if source.kind != SourceKind::LegacyRustConst
            || source.id.is_empty()
            || !source.uri.starts_with("repo://")
            || source.retrieved_at != "2026-07-27T10:19:38Z"
            || source.artifact_sha256 != manifest.legacy_source_order_sha256
            || source.method.is_empty()
            || source.license != "Apache-2.0"
            || !source_ids.insert(source.id.as_str())
        {
            return embedded(format!("{file} has invalid legacy provenance"));
        }
        validate_sha256("legacy source hash", &source.artifact_sha256)?;
    }
    validate_sha256("raw dataset hash", &manifest.raw_sha256)?;
    validate_sha256("legacy source hash", &manifest.legacy_source_order_sha256)?;

    let mut identities = BTreeSet::new();
    let mut previous: Option<String> = None;
    let mut priorities = BTreeSet::new();
    let mut entries = Vec::with_capacity(raw.entries.len());
    for entry in &raw.entries {
        ensure_at_most(entry.aliases.len(), MAX_ALIASES_PER_ENTRY, "entry aliases")?;
        if entry.popularity.metric != PopularityMetric::LegacyPriority
            || entry.popularity.value == 0
            || !source_ids.contains(entry.popularity.source_id.as_str())
            || !priorities.insert(entry.popularity.value)
        {
            return embedded(format!("{file} has invalid entry metadata"));
        }
        let identity = segment_identity(ecosystem, &entry.canonical_name).map_err(|error| {
            TyposquatError::InvalidEmbeddedData(format!(
                "{file} invalid canonical name {:?}: {error}",
                entry.canonical_name
            ))
        })?;
        let canonical = identity.canonical();
        if previous.as_ref().is_some_and(|value| value >= &canonical) {
            return embedded(format!("{file} entries are not strictly canonical-sorted"));
        }
        previous = Some(canonical.clone());
        if !identities.insert(canonical.clone()) {
            return embedded(format!("{file} has duplicate normalized identity"));
        }
        let mut previous_alias: Option<String> = None;
        let mut aliases = Vec::with_capacity(entry.aliases.len());
        for alias in &entry.aliases {
            let alias_identity = segment_identity(ecosystem, alias).map_err(|error| {
                TyposquatError::InvalidEmbeddedData(format!("{file} invalid alias: {error}"))
            })?;
            let alias = alias_identity.canonical();
            if previous_alias.as_ref().is_some_and(|value| value >= &alias)
                || !identities.insert(alias.clone())
            {
                return embedded(format!("{file} has duplicate or unsorted alias"));
            }
            previous_alias = Some(alias);
            aliases.push(alias_identity);
        }
        entries.push(DatasetEntry {
            display: entry.canonical_name.clone(),
            identity,
            aliases,
            canonical,
            legacy_priority: entry.popularity.value,
        });
    }
    if priorities.len() != manifest.legacy_source_count
        || priorities
            .iter()
            .copied()
            .ne(1..=manifest.legacy_source_count as u64)
    {
        return embedded(format!("{file} legacy priorities are not contiguous"));
    }
    let identity_count = entries.iter().try_fold(0usize, |count, entry| {
        checked_add(count, 1 + entry.aliases.len(), "dataset identities")
    })?;
    validate_dataset_identity_count(file, identity_count)?;
    let index = DatasetIndex::build(ecosystem, &entries, confusables)?;
    Ok(Dataset {
        id: raw.dataset_id.clone(),
        version: raw.dataset_version,
        raw_sha256: manifest.raw_sha256.clone(),
        entries,
        index,
    })
}

fn validate_keyboard(
    manifest: &ManifestKeyboard,
) -> Result<BTreeSet<(char, char)>, TyposquatError> {
    if manifest.file != "keyboard-qwerty-us.json" || manifest.raw_sha256 != sha256(KEYBOARD_BYTES) {
        return embedded("keyboard manifest mismatch");
    }
    ensure_at_most(KEYBOARD_BYTES.len(), MAX_DATASET_BYTES, "keyboard bytes")?;
    let raw: KeyboardFile = parse_json(&manifest.file, KEYBOARD_BYTES)?;
    if raw.schema_version != 1
        || raw.layout_version != 1
        || raw.layout_id != "qwerty-us-v1"
        || raw.layout_id != manifest.layout_id
        || raw.edge_semantics != "unique-unordered-physical-neighbors-distance-lte-1.15"
    {
        return embedded("unsupported keyboard asset");
    }
    let alphabet: BTreeSet<char> = raw.alphabet.chars().collect();
    if alphabet.len() != raw.alphabet.chars().count() {
        return embedded("keyboard alphabet has duplicate keys");
    }
    ensure_at_most(alphabet.len(), MAX_KEYBOARD_KEYS, "keyboard keys")?;
    if raw.edges.len() != manifest.edge_count {
        return embedded("keyboard edge count mismatch");
    }
    ensure_at_most(raw.edges.len(), MAX_KEYBOARD_EDGES, "keyboard edges")?;
    let mut edges = BTreeSet::new();
    let mut degree = BTreeMap::<char, usize>::new();
    for edge in raw.edges {
        let left = one_scalar("keyboard edge", &edge[0])?;
        let right = one_scalar("keyboard edge", &edge[1])?;
        if left >= right || !alphabet.contains(&left) || !alphabet.contains(&right) {
            return embedded("keyboard edge is not canonical or in alphabet");
        }
        if !edges.insert((left, right)) {
            return embedded("duplicate keyboard edge");
        }
        for key in [left, right] {
            let value = degree.entry(key).or_default();
            *value = checked_add(*value, 1, "keyboard degree")?;
            ensure_at_most(*value, MAX_KEYBOARD_DEGREE, "keyboard degree")?;
        }
    }
    Ok(edges)
}

fn validate_confusables(
    manifest: &ManifestConfusables,
) -> Result<BTreeMap<char, String>, TyposquatError> {
    if manifest.file != "unicode-confusables.json"
        || manifest.raw_sha256 != sha256(CONFUSABLES_BYTES)
    {
        return embedded("confusables manifest mismatch");
    }
    ensure_at_most(
        CONFUSABLES_BYTES.len(),
        MAX_CONFUSABLE_BYTES,
        "confusable bytes",
    )?;
    let raw: ConfusablesFile = parse_json(&manifest.file, CONFUSABLES_BYTES)?;
    if raw.schema_version != 1
        || raw.profile_id != manifest.profile_id
        || raw.profile_id != "uts39-v1"
        || raw.unicode_version != "17.0.0"
        || raw.unicode_version != manifest.unicode_version
        || raw.source_uri != "https://www.unicode.org/Public/17.0.0/security/confusables.txt"
        || raw.source_sha256 != manifest.source_sha256
        || raw.source_sha256 != "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a"
        || raw.source_date != "2025-07-22T05:49:37Z"
        || raw.retrieved_at != "2026-07-27T10:19:38Z"
        || raw.generator_version != "argus-typosquat-data-v1"
        || !raw.normalization.starts_with("Unicode scalar substitution")
        || raw.mappings.len() != manifest.mapping_count
    {
        return embedded("unsupported confusables asset");
    }
    ensure_at_most(
        raw.mappings.len(),
        MAX_CONFUSABLE_MAPPINGS,
        "confusable mappings",
    )?;
    validate_sha256("confusables source hash", &raw.source_sha256)?;
    let mut mappings = BTreeMap::new();
    for mapping in raw.mappings {
        let source = one_scalar("confusable source", &mapping.source)?;
        if mapping.target.is_empty() {
            return embedded("confusable target is empty");
        }
        ensure_at_most(
            mapping.target.len(),
            MAX_CONFUSABLE_TARGET_BYTES,
            "confusable target bytes",
        )?;
        if mappings.insert(source, mapping.target).is_some() {
            return embedded("duplicate confusable source scalar");
        }
    }
    Ok(mappings)
}

fn parse_json<T: for<'de> Deserialize<'de>>(
    label: &str,
    bytes: &[u8],
) -> Result<T, TyposquatError> {
    super::strict_json::from_slice(bytes).map_err(|error| {
        TyposquatError::InvalidEmbeddedData(format!("{label} is not strict valid JSON: {error}"))
    })
}

fn one_scalar(label: &str, value: &str) -> Result<char, TyposquatError> {
    let mut characters = value.chars();
    let scalar = characters
        .next()
        .ok_or_else(|| TyposquatError::InvalidEmbeddedData(format!("{label} is empty")))?;
    if characters.next().is_some() {
        return embedded(format!("{label} must contain one Unicode scalar"));
    }
    Ok(scalar)
}

fn checked_add(left: usize, right: usize, label: &str) -> Result<usize, TyposquatError> {
    left.checked_add(right)
        .ok_or_else(|| TyposquatError::ResourceLimit(format!("{label} overflow")))
}

fn validate_dataset_identity_count(file: &str, count: usize) -> Result<(), TyposquatError> {
    if count > MAX_IDENTITIES_PER_ECOSYSTEM {
        limit(format!(
            "{file} exceeds {MAX_IDENTITIES_PER_ECOSYSTEM} canonical and alias identities"
        ))
    } else {
        Ok(())
    }
}

fn validate_aggregate_identity_count(count: usize) -> Result<(), TyposquatError> {
    if count > MAX_AGGREGATE_IDENTITIES {
        limit("aggregate dataset identity limit exceeded")
    } else {
        Ok(())
    }
}

fn validate_sha256(label: &str, hash: &str) -> Result<(), TyposquatError> {
    if hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        embedded(format!("{label} is not lowercase SHA-256"))
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn ecosystem_id(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "pypi",
        Ecosystem::CratesIo => "crates-io",
        Ecosystem::Go => "go",
        Ecosystem::NuGet => "nuget",
        Ecosystem::Maven => "maven",
        Ecosystem::RubyGems => "rubygems",
        Ecosystem::Packagist => "composer",
    }
}

fn normalization_id(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm-v1",
        Ecosystem::PyPi => "pep503-v1",
        Ecosystem::CratesIo => "crates-io-v1",
        Ecosystem::Go => "go-module-v1",
        Ecosystem::NuGet => "nuget-v1",
        Ecosystem::Maven => "maven-v1",
        Ecosystem::RubyGems => "rubygems-v1",
        Ecosystem::Packagist => "composer-v1",
    }
}

fn namespace_id(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm-scope-exact-leaf",
        Ecosystem::PyPi | Ecosystem::CratesIo | Ecosystem::NuGet | Ecosystem::RubyGems => {
            "registry-identity"
        }
        Ecosystem::Go => "go-equal-depth-one-segment",
        Ecosystem::Maven => "maven-legacy-leaf-any-group",
        Ecosystem::Packagist => "composer-vendor-package",
    }
}

fn embedded<T>(message: impl Into<String>) -> Result<T, TyposquatError> {
    Err(TyposquatError::InvalidEmbeddedData(message.into()))
}

fn limit<T>(message: impl Into<String>) -> Result<T, TyposquatError> {
    Err(TyposquatError::ResourceLimit(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_assets_have_frozen_counts_and_hash() {
        validate_embedded_assets().unwrap();
        let expected = [
            (Ecosystem::Npm, 35),
            (Ecosystem::PyPi, 67),
            (Ecosystem::CratesIo, 75),
            (Ecosystem::Go, 26),
            (Ecosystem::NuGet, 35),
            (Ecosystem::Maven, 38),
            (Ecosystem::RubyGems, 54),
            (Ecosystem::Packagist, 52),
        ];
        assert_eq!(expected.iter().map(|(_, count)| count).sum::<usize>(), 382);
        for (ecosystem, count) in expected {
            assert_eq!(dataset_audit(ecosystem).unwrap().entry_count, count);
        }
        assert_eq!(
            asset_audit().unwrap().combined_legacy_source_order_sha256,
            "f31adaca86d5df50ab15216ea677be24499552979963227878a45ac8f22765a5"
        );
    }

    #[test]
    fn audit_has_eight_datasets_and_two_signal_assets() {
        let audit = asset_audit().unwrap();
        assert_eq!(audit.assets.len(), 10);
        assert!(audit.assets.windows(2).all(|pair| pair[0].id < pair[1].id));
    }

    #[test]
    fn identity_work_limits_accept_equality_and_reject_plus_one() {
        assert!(validate_dataset_identity_count("test", MAX_IDENTITIES_PER_ECOSYSTEM).is_ok());
        assert!(validate_dataset_identity_count("test", MAX_IDENTITIES_PER_ECOSYSTEM + 1).is_err());
        assert!(validate_aggregate_identity_count(MAX_AGGREGATE_IDENTITIES).is_ok());
        assert!(validate_aggregate_identity_count(MAX_AGGREGATE_IDENTITIES + 1).is_err());
    }
}
