use super::{package_lock::parse_sri, LockfileParser};
use argus_core::{Ecosystem, PackageCoordinate};
use std::collections::{BTreeMap, BTreeSet};
use yaml_rust2::{yaml::Hash, Yaml};

use crate::{
    parse_yaml, BoundedInput, Coverage, DetectedLockfile, FormatVersion, IntegrityEvidence,
    IntegrityState, LockfileError, LockfileFormat, NormalizedDependency, NormalizedSource,
    ParseOutput, SourceKind,
};

pub struct PnpmParser;
pub static PARSER: PnpmParser = PnpmParser;
type PackageIdentity = (Option<String>, Option<String>, Option<String>);

impl LockfileParser for PnpmParser {
    fn format(&self) -> LockfileFormat {
        LockfileFormat::Pnpm
    }

    fn parse(
        &self,
        input: &BoundedInput<'_>,
        detected: &DetectedLockfile,
    ) -> Result<ParseOutput, LockfileError> {
        if detected.format != self.format()
            || !matches!(
                detected.version,
                FormatVersion::Pnpm5_4 | FormatVersion::Pnpm6_0 | FormatVersion::Pnpm9_0
            )
        {
            return Err(pnpm_error("detected format/version does not match parser"));
        }
        let yaml = parse_yaml(input)?;
        let root = yaml_hash(&yaml, "root")?;
        deny_unknown(
            root,
            &[
                "lockfileVersion",
                "settings",
                "overrides",
                "patchedDependencies",
                "time",
                "importers",
                "packages",
                "snapshots",
            ],
            0,
        )?;
        validate_root_metadata(root)?;
        if detected.version != FormatVersion::Pnpm9_0 && yaml_get(root, "snapshots").is_some() {
            return Err(partial(0, 1));
        }

        let mut coverage = inventory_coverage(root)?;
        let mut records = Vec::new();
        let mut templates = BTreeMap::new();
        if let Some(packages) = yaml_get(root, "packages") {
            parse_package_section(
                yaml_hash(packages, "packages")?,
                "packages",
                false,
                &mut records,
                &mut templates,
                &mut coverage,
            )?;
        }
        if let Some(snapshots) = yaml_get(root, "snapshots") {
            parse_package_section(
                yaml_hash(snapshots, "snapshots")?,
                "snapshots",
                true,
                &mut records,
                &mut templates,
                &mut coverage,
            )?;
        }

        let locked = records
            .iter()
            .filter_map(|record| {
                record.coordinate.as_ref().map(|coordinate| {
                    (
                        coordinate.original_name.clone(),
                        coordinate.original_version.clone(),
                    )
                })
            })
            .collect::<BTreeSet<_>>();
        if let Some(importers) = yaml_get(root, "importers") {
            traverse_importers(yaml_hash(importers, "importers")?, &locked, &mut coverage)?;
        }
        for section in ["packages", "snapshots"] {
            if let Some(entries) = yaml_get(root, section) {
                traverse_package_edges(yaml_hash(entries, section)?, &locked, &mut coverage)?;
            }
        }
        finish(detected, records, coverage)
    }
}

#[derive(Clone)]
struct SourceTemplate {
    sources: Vec<NormalizedSource>,
    integrity_state: IntegrityState,
    integrity: Vec<IntegrityEvidence>,
}

fn parse_package_section(
    entries: &Hash,
    section: &str,
    snapshot: bool,
    records: &mut Vec<NormalizedDependency>,
    templates: &mut BTreeMap<String, SourceTemplate>,
    coverage: &mut Coverage,
) -> Result<(), LockfileError> {
    for (raw_key, raw_entry) in entries {
        let key = yaml_string(raw_key, "package key")?;
        let entry = yaml_hash(raw_entry, key)?;
        deny_unknown(
            entry,
            &[
                "name",
                "version",
                "resolution",
                "dependencies",
                "optionalDependencies",
                "peerDependencies",
                "peerDependenciesMeta",
                "dependenciesMeta",
                "transitivePeerDependencies",
                "dev",
                "optional",
                "devOptional",
                "hasBin",
                "requiresBuild",
                "prepare",
                "engines",
                "cpu",
                "os",
                "bundledDependencies",
                "patched",
                "id",
            ],
            records.len(),
        )?;
        let (key_name, key_version, peer_condition) = package_identity(key)?;
        let name = yaml_optional_scalar(entry, "name")?
            .map(str::to_string)
            .or(key_name);
        let version = yaml_optional_scalar(entry, "version")?
            .map(str::to_string)
            .or(key_version);

        let template = if snapshot {
            templates
                .get(key)
                .cloned()
                .ok_or_else(|| partial(records.len(), 1))?
        } else {
            source_template(entry, key, name.as_deref(), version.as_deref(), section)?
        };
        let coordinate = match (&name, &version) {
            (Some(name), Some(version)) => Some(
                PackageCoordinate::new(Ecosystem::Npm, name, version)
                    .map_err(|error| pnpm_error(format!("invalid `{key}` coordinate: {error}")))?,
            ),
            _ if template
                .sources
                .iter()
                .all(|source| matches!(source.kind, SourceKind::Path | SourceKind::Workspace)) =>
            {
                None
            }
            _ => return Err(partial(records.len(), 1)),
        };
        let condition = validate_package_metadata(entry, peer_condition.as_deref())?;
        let record = NormalizedDependency {
            coordinate,
            format: LockfileFormat::Pnpm,
            sources: template.sources.clone(),
            integrity_state: template.integrity_state,
            integrity: template.integrity.clone(),
            raw_name: name.clone(),
            raw_version: version.clone(),
            locator: format!("{section}[{key:?}]"),
            condition,
            platform: None,
            occurrence_index: records.len() as u64,
        };
        if !snapshot {
            templates.insert(key.to_string(), template);
        }
        records.push(record);
        coverage.recognized_units = add_units(coverage.recognized_units, 1)?;
    }
    Ok(())
}

fn source_template(
    entry: &Hash,
    key: &str,
    name: Option<&str>,
    version: Option<&str>,
    section: &str,
) -> Result<SourceTemplate, LockfileError> {
    let locator = format!("{section}[{key:?}].resolution");
    let Some(resolution) = yaml_get(entry, "resolution") else {
        return if let (Some(name), Some(version)) = (name, version) {
            Ok(single_source_template(
                SourceKind::Registry,
                format!("npm:{name}@{version}"),
                &locator,
            ))
        } else {
            let kind = classify_location(key);
            if !matches!(kind, SourceKind::Path | SourceKind::Workspace) {
                return Err(partial(0, 1));
            }
            Ok(single_source_template(kind, key.to_string(), &locator))
        };
    };
    match resolution {
        Yaml::String(value) => Ok(single_source_template(
            classify_location(value),
            value.to_string(),
            &locator,
        )),
        Yaml::Hash(map) => parse_resolution_map(map, &locator, name, version),
        _ => Err(pnpm_error("resolution must be a string or mapping")),
    }
}

fn parse_resolution_map(
    resolution: &Hash,
    locator: &str,
    name: Option<&str>,
    version: Option<&str>,
) -> Result<SourceTemplate, LockfileError> {
    deny_unknown(
        resolution,
        &[
            "integrity",
            "tarball",
            "repo",
            "commit",
            "path",
            "type",
            "directory",
        ],
        0,
    )?;
    let integrity = yaml_optional_scalar(resolution, "integrity")?;
    let commit = yaml_optional_scalar(resolution, "commit")?;
    let mut sources = Vec::new();
    if let Some(tarball) = yaml_optional_scalar(resolution, "tarball")? {
        let kind = classify_location(tarball);
        if !matches!(kind, SourceKind::Registry | SourceKind::Url) {
            return Err(partial(0, 1));
        }
        sources.push(source(
            kind,
            tarball.to_string(),
            None,
            &format!("{locator}.tarball"),
        ));
    }
    if let Some(repo) = yaml_optional_scalar(resolution, "repo")? {
        sources.push(source(
            SourceKind::Git,
            repo.to_string(),
            commit.and_then(valid_commit),
            &format!("{locator}.repo"),
        ));
    }
    for field in ["path", "directory"] {
        if let Some(path) = yaml_optional_scalar(resolution, field)? {
            sources.push(source(
                SourceKind::Path,
                path.to_string(),
                None,
                &format!("{locator}.{field}"),
            ));
        }
    }
    if let Some(source_type) = yaml_optional_scalar(resolution, "type")? {
        if source_type != "git" || sources.iter().all(|source| source.kind != SourceKind::Git) {
            return Err(partial(0, 1));
        }
    }
    if commit.is_some() && sources.iter().all(|source| source.kind != SourceKind::Git) {
        return Err(partial(0, 1));
    }
    if sources.is_empty() {
        let (Some(name), Some(version)) = (name, version) else {
            return Err(partial(0, 1));
        };
        sources.push(source(
            SourceKind::Registry,
            format!("npm:{name}@{version}"),
            None,
            locator,
        ));
    }
    let requires_integrity = sources
        .iter()
        .any(|source| matches!(source.kind, SourceKind::Registry | SourceKind::Url));
    let (integrity_state, integrity) = if requires_integrity {
        integrity
            .map(|value| parse_sri(value, &format!("{locator}.integrity")))
            .unwrap_or((IntegrityState::RequiredMissing, Vec::new()))
    } else {
        (IntegrityState::UnavailableByFormat, Vec::new())
    };
    Ok(SourceTemplate {
        sources,
        integrity_state,
        integrity,
    })
}

fn single_source_template(kind: SourceKind, location: String, locator: &str) -> SourceTemplate {
    let revision = (kind == SourceKind::Git)
        .then(|| {
            location
                .rsplit_once('#')
                .and_then(|(_, value)| valid_commit(value))
        })
        .flatten();
    let integrity_state = if matches!(kind, SourceKind::Registry | SourceKind::Url) {
        IntegrityState::RequiredMissing
    } else {
        IntegrityState::UnavailableByFormat
    };
    SourceTemplate {
        sources: vec![source(kind, location, revision, locator)],
        integrity_state,
        integrity: Vec::new(),
    }
}

fn source(
    kind: SourceKind,
    location: String,
    immutable_revision: Option<String>,
    locator: &str,
) -> NormalizedSource {
    NormalizedSource {
        kind,
        location: Some(location),
        immutable_revision,
        locator: locator.to_string(),
    }
}

fn classify_location(value: &str) -> SourceKind {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("workspace:") || lower.starts_with("link:") {
        SourceKind::Workspace
    } else if lower.starts_with("file:") {
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
    }
}

fn npm_registry_url(value: &str) -> bool {
    value
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split_once('/').map(|(host, _)| host))
        .is_some_and(|host| {
            matches!(
                host,
                "registry.npmjs.org" | "registry.yarnpkg.com" | "npm.pkg.github.com"
            )
        })
}

fn package_identity(key: &str) -> Result<PackageIdentity, LockfileError> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let (base, condition) = match key.find('(') {
        Some(index) if key.ends_with(')') => (&key[..index], Some(key[index..].to_string())),
        Some(_) => return Err(pnpm_error(format!("invalid package key `{key}`"))),
        None => (key, None),
    };
    if is_local(base) {
        return Ok((None, None, condition));
    }
    let separator = if let Some(scoped) = base.strip_prefix('@') {
        let scope_end = scoped
            .find('/')
            .map(|index| index + 1)
            .ok_or_else(|| pnpm_error(format!("invalid scoped package key `{key}`")))?;
        let tail = &base[scope_end + 1..];
        tail.rfind('@')
            .or_else(|| tail.rfind('/'))
            .map(|index| scope_end + 1 + index)
    } else {
        base.rfind('@')
            .filter(|index| *index > 0)
            .or_else(|| base.rfind('/'))
    }
    .ok_or_else(|| pnpm_error(format!("invalid package key `{key}`")))?;
    let (name, version) = (&base[..separator], &base[separator + 1..]);
    if name.is_empty() || version.is_empty() {
        return Err(pnpm_error("empty package identity component"));
    }
    Ok((Some(name.to_string()), Some(version.to_string()), condition))
}

fn traverse_importers(
    importers: &Hash,
    locked: &BTreeSet<(String, String)>,
    coverage: &mut Coverage,
) -> Result<(), LockfileError> {
    for (key, raw) in importers {
        yaml_string(key, "importer key")?;
        let importer = yaml_hash(raw, "importer")?;
        deny_unknown(
            importer,
            &[
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "specifiers",
                "dependenciesMeta",
                "publishDirectory",
            ],
            coverage.recognized_units,
        )?;
        for section in ["dependencies", "devDependencies", "optionalDependencies"] {
            if let Some(edges) = yaml_get(importer, section) {
                traverse_edges(yaml_hash(edges, section)?, locked, true, coverage)?;
            }
        }
        if let Some(specifiers) = yaml_get(importer, "specifiers") {
            for (name, value) in yaml_hash(specifiers, "specifiers")? {
                yaml_string(name, "specifier name")?;
                yaml_scalar(value, "specifier")?;
            }
        }
        if let Some(metadata) = yaml_get(importer, "dependenciesMeta") {
            for (name, value) in yaml_hash(metadata, "dependenciesMeta")? {
                yaml_string(name, "dependenciesMeta name")?;
                let value = yaml_hash(value, "dependenciesMeta entry")?;
                deny_unknown(value, &["injected"], coverage.recognized_units)?;
                if value
                    .values()
                    .any(|value| !matches!(value, Yaml::Boolean(_)))
                {
                    return Err(pnpm_error("dependenciesMeta values must be boolean"));
                }
            }
        }
        yaml_optional_scalar(importer, "publishDirectory")?;
    }
    Ok(())
}

fn traverse_package_edges(
    entries: &Hash,
    locked: &BTreeSet<(String, String)>,
    coverage: &mut Coverage,
) -> Result<(), LockfileError> {
    for raw in entries.values() {
        let entry = yaml_hash(raw, "package entry")?;
        for section in ["dependencies", "optionalDependencies", "peerDependencies"] {
            if let Some(edges) = yaml_get(entry, section) {
                traverse_edges(
                    yaml_hash(edges, section)?,
                    locked,
                    section != "peerDependencies",
                    coverage,
                )?;
            }
        }
    }
    Ok(())
}

fn traverse_edges(
    edges: &Hash,
    locked: &BTreeSet<(String, String)>,
    resolve: bool,
    coverage: &mut Coverage,
) -> Result<(), LockfileError> {
    for (raw_name, raw_ref) in edges {
        let name = yaml_string(raw_name, "dependency name")?;
        let reference = match raw_ref {
            Yaml::Hash(value) => {
                deny_unknown(value, &["specifier", "version"], coverage.recognized_units)?;
                yaml_optional_scalar(value, "specifier")?;
                yaml_required_scalar(value, "version")?
            }
            value => yaml_scalar(value, "dependency reference")?,
        };
        if reference.is_empty() {
            return Err(partial(coverage.recognized_units, 1));
        }
        if resolve {
            validate_reference(name, reference, locked)
                .map_err(|_| partial(coverage.recognized_units, 1))?;
        }
        coverage.recognized_units = add_units(coverage.recognized_units, 1)?;
    }
    Ok(())
}

fn validate_reference(
    name: &str,
    reference: &str,
    locked: &BTreeSet<(String, String)>,
) -> Result<(), LockfileError> {
    if is_local(reference)
        || reference.starts_with("git")
        || reference.starts_with("ssh:")
        || reference.starts_with("github:")
    {
        return Ok(());
    }
    let reference = reference.strip_prefix("npm:").unwrap_or(reference);
    let identity_reference = reference
        .split_once('(')
        .map_or(reference, |(identity, _)| identity);
    let (target_name, version) =
        if identity_reference.starts_with('/') || identity_reference.contains('@') {
            match package_identity(reference)? {
                (Some(name), Some(version), _) => (name, version),
                _ => return Err(pnpm_error("dependency reference lacks package identity")),
            }
        } else {
            (name.to_string(), identity_reference.to_string())
        };
    locked
        .contains(&(target_name, version))
        .then_some(())
        .ok_or_else(|| pnpm_error("dependency reference does not resolve to a package record"))
}

fn validate_package_metadata(
    entry: &Hash,
    peer_condition: Option<&str>,
) -> Result<Option<String>, LockfileError> {
    for field in [
        "dev",
        "optional",
        "devOptional",
        "hasBin",
        "requiresBuild",
        "prepare",
        "patched",
    ] {
        if let Some(value) = yaml_get(entry, field) {
            if !matches!(value, Yaml::Boolean(_)) {
                return Err(pnpm_error(format!("`{field}` must be boolean")));
            }
        }
    }
    for field in [
        "cpu",
        "os",
        "bundledDependencies",
        "transitivePeerDependencies",
    ] {
        if let Some(value) = yaml_get(entry, field) {
            for item in value
                .as_vec()
                .ok_or_else(|| pnpm_error(format!("`{field}` must be an array")))?
            {
                yaml_scalar(item, field)?;
            }
        }
    }
    if let Some(engines) = yaml_get(entry, "engines") {
        for (name, constraint) in yaml_hash(engines, "engines")? {
            yaml_string(name, "engine name")?;
            yaml_scalar(constraint, "engine constraint")?;
        }
    }
    for (section, allowed) in [
        ("peerDependenciesMeta", &["optional"][..]),
        ("dependenciesMeta", &["injected"][..]),
    ] {
        if let Some(metadata) = yaml_get(entry, section) {
            for (name, value) in yaml_hash(metadata, section)? {
                yaml_string(name, "metadata dependency")?;
                let value = yaml_hash(value, "metadata entry")?;
                deny_unknown(value, allowed, 0)?;
                if value
                    .values()
                    .any(|value| !matches!(value, Yaml::Boolean(_)))
                {
                    return Err(pnpm_error(format!("{section} values must be boolean")));
                }
            }
        }
    }
    let mut parts = Vec::new();
    if let Some(value) = peer_condition {
        parts.push(format!("peers={value}"));
    }
    for field in ["cpu", "os"] {
        if let Some(value) = yaml_get(entry, field) {
            let values = value
                .as_vec()
                .ok_or_else(|| pnpm_error(format!("`{field}` must be an array")))?
                .iter()
                .map(|value| yaml_scalar(value, field))
                .collect::<Result<Vec<_>, _>>()?;
            parts.push(format!("{field}={}", values.join(",")));
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join(";")))
}

fn validate_root_metadata(root: &Hash) -> Result<(), LockfileError> {
    if let Some(settings) = yaml_get(root, "settings") {
        deny_unknown(
            yaml_hash(settings, "settings")?,
            &[
                "autoInstallPeers",
                "excludeLinksFromLockfile",
                "peersSuffixMaxLength",
                "injectWorkspacePackages",
                "linkWorkspacePackages",
                "dedupePeerDependents",
            ],
            0,
        )?;
    }
    for field in ["overrides", "patchedDependencies", "time"] {
        if let Some(value) = yaml_get(root, field) {
            yaml_hash(value, field)?;
        }
    }
    Ok(())
}

fn is_local(value: &str) -> bool {
    ["link:", "workspace:", "file:"]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

fn valid_commit(value: &str) -> Option<String> {
    (matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| value.to_string())
}

fn finish(
    detected: &DetectedLockfile,
    records: Vec<NormalizedDependency>,
    mut coverage: Coverage,
) -> Result<ParseOutput, LockfileError> {
    if records.len() != coverage.record_units {
        return Err(LockfileError::CoverageMismatch {
            detail: "emitted pnpm records differ from input record units".to_string(),
        });
    }
    coverage.unsupported_units = coverage
        .total_units
        .saturating_sub(coverage.recognized_units);
    let mut output = ParseOutput {
        detected: detected.clone(),
        coverage,
        records,
        metadata_integrity: Vec::new(),
    };
    output.validate_and_sort()?;
    Ok(output)
}

fn inventory_coverage(root: &Hash) -> Result<Coverage, LockfileError> {
    let mut record_units = 0usize;
    let mut edge_units = 0usize;
    for section in ["packages", "snapshots"] {
        if let Some(entries) = yaml_get(root, section) {
            let entries = yaml_hash(entries, section)?;
            record_units = add_units(record_units, entries.len())?;
            for entry in entries.values() {
                edge_units = add_units(
                    edge_units,
                    count_edges(
                        yaml_hash(entry, "package entry")?,
                        &["dependencies", "optionalDependencies", "peerDependencies"],
                    )?,
                )?;
            }
        }
    }
    if let Some(importers) = yaml_get(root, "importers") {
        for importer in yaml_hash(importers, "importers")?.values() {
            edge_units = add_units(
                edge_units,
                count_edges(
                    yaml_hash(importer, "importer")?,
                    &["dependencies", "devDependencies", "optionalDependencies"],
                )?,
            )?;
        }
    }
    Ok(Coverage {
        total_units: add_units(record_units, edge_units)?,
        recognized_units: 0,
        unsupported_units: 0,
        record_units,
        traversed_non_record_units: edge_units,
    })
}

fn count_edges(owner: &Hash, sections: &[&str]) -> Result<usize, LockfileError> {
    let mut total = 0usize;
    for section in sections {
        if let Some(edges) = yaml_get(owner, section) {
            total = add_units(total, yaml_hash(edges, section)?.len())?;
        }
    }
    Ok(total)
}

fn add_units(left: usize, right: usize) -> Result<usize, LockfileError> {
    left.checked_add(right)
        .ok_or_else(|| pnpm_error("coverage count overflowed"))
}

fn yaml_hash<'a>(value: &'a Yaml, label: &str) -> Result<&'a Hash, LockfileError> {
    value
        .as_hash()
        .ok_or_else(|| pnpm_error(format!("`{label}` must be a mapping")))
}

fn yaml_get<'a>(map: &'a Hash, key: &str) -> Option<&'a Yaml> {
    map.get(&Yaml::String(key.to_string()))
}

fn yaml_string<'a>(value: &'a Yaml, label: &str) -> Result<&'a str, LockfileError> {
    value
        .as_str()
        .ok_or_else(|| pnpm_error(format!("`{label}` must be a string")))
}

fn yaml_scalar<'a>(value: &'a Yaml, label: &str) -> Result<&'a str, LockfileError> {
    match value {
        Yaml::String(value) | Yaml::Real(value) => Ok(value),
        _ => Err(pnpm_error(format!("`{label}` must be a scalar string"))),
    }
}

fn yaml_required_scalar<'a>(map: &'a Hash, key: &str) -> Result<&'a str, LockfileError> {
    yaml_optional_scalar(map, key)?.ok_or_else(|| pnpm_error(format!("`{key}` is required")))
}

fn yaml_optional_scalar<'a>(map: &'a Hash, key: &str) -> Result<Option<&'a str>, LockfileError> {
    match yaml_get(map, key) {
        Some(value) => yaml_scalar(value, key).map(Some),
        None => Ok(None),
    }
}

fn deny_unknown(map: &Hash, allowed: &[&str], recognized: usize) -> Result<(), LockfileError> {
    for key in map.keys() {
        let key = yaml_string(key, "mapping key")?;
        if !allowed.contains(&key) {
            return Err(partial(recognized, 1));
        }
    }
    Ok(())
}

fn partial(recognized: usize, unsupported: usize) -> LockfileError {
    LockfileError::PartialAnalysis {
        total_units: recognized.saturating_add(unsupported),
        recognized_units: recognized,
        unsupported_units: unsupported,
    }
}

fn pnpm_error(detail: impl Into<String>) -> LockfileError {
    LockfileError::Parse {
        syntax: "pnpm YAML",
        detail: detail.into(),
    }
}
