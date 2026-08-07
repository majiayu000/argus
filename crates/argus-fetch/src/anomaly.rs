//! Deterministic npm metadata anomaly evaluation (`npm-anomaly-v1`).

use crate::packument::Packument;
use anyhow::{anyhow, bail, Context, Result};
use argus_core::rules::{NpmRapidPublishParameters, NpmVersionShapeParameters};
use argus_core::{Finding, Severity};
use argus_transport::Transport;
use chrono::{DateTime, Duration, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use url::Url;

pub(crate) const POLICY_ID: &str = "npm-anomaly-v1";
const MAXIMUM_SEARCH_OBJECTS: usize = 250;
const MAXIMUM_SEARCH_BYTES: u64 = 2 * 1024 * 1024;
const CACHE_TTL_MINUTES: i64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl NormalizedVersion {
    fn parse(raw: &str) -> Option<Self> {
        let parsed = match Version::parse(raw) {
            Ok(parsed) => parsed,
            Err(_) => return None,
        };
        if !parsed.pre.is_empty() {
            return None;
        }
        Some(Self {
            major: parsed.major,
            minor: parsed.minor,
            patch: parsed.patch,
        })
    }
}

impl std::fmt::Display for NormalizedVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone)]
struct VersionEvent {
    version: NormalizedVersion,
    published_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JumpClass {
    Major,
    Minor,
}

#[cfg(test)]
pub(crate) fn version_shape_findings(
    packument: &Packument,
    target_version: &str,
) -> Result<Vec<Finding>> {
    version_shape_findings_with_parameters(
        packument,
        target_version,
        NpmVersionShapeParameters::default(),
    )
}

fn version_shape_findings_with_parameters(
    packument: &Packument,
    target_version: &str,
    parameters: NpmVersionShapeParameters,
) -> Result<Vec<Finding>> {
    let times = packument
        .time
        .as_ref()
        .ok_or_else(|| anyhow!("metadata anomaly detection requires packument `time`"))?;
    let target_time = required_time(times, target_version)?;
    let target = match NormalizedVersion::parse(target_version) {
        Some(target) => target,
        None => {
            return Ok(vec![unassessed_finding(
                packument,
                target_version,
                "target version is not a stable SemVer",
            )]);
        }
    };

    let mut normalized_events = BTreeMap::<NormalizedVersion, DateTime<Utc>>::new();
    for raw_version in packument.versions.keys() {
        let Some(version) = NormalizedVersion::parse(raw_version) else {
            continue;
        };
        let published_at = required_time(times, raw_version)?;
        match normalized_events.entry(version) {
            Entry::Vacant(entry) => {
                entry.insert(published_at);
            }
            Entry::Occupied(entry) if *entry.get() == published_at => {}
            Entry::Occupied(entry) => {
                bail!(
                    "normalized version `{version}` has conflicting publication times: {} and {}",
                    entry.get().to_rfc3339(),
                    published_at.to_rfc3339()
                );
            }
        }
    }

    let mut predecessors = normalized_events
        .iter()
        .filter_map(|(version, published_at)| {
            (*version != target && *published_at < target_time).then_some(VersionEvent {
                version: *version,
                published_at: *published_at,
            })
        })
        .collect::<Vec<_>>();
    if normalized_events
        .iter()
        .any(|(version, published_at)| *version != target && *published_at == target_time)
    {
        return Ok(Vec::new());
    }
    predecessors.sort_by(|left, right| {
        (left.published_at, left.version).cmp(&(right.published_at, right.version))
    });

    if predecessors.len() < parameters.minimum_predecessors() {
        return Ok(vec![unassessed_finding(
            packument,
            target_version,
            &format!(
                "requires at least {} earlier stable versions; found {}",
                parameters.minimum_predecessors(),
                predecessors.len()
            ),
        )]);
    }

    let history_days = target_time
        .signed_duration_since(predecessors[0].published_at)
        .num_days();
    if history_days < i64::from(parameters.minimum_history_days()) {
        return Ok(vec![unassessed_finding(
            packument,
            target_version,
            &format!(
                "requires at least {} days of history; found {history_days}",
                parameters.minimum_history_days()
            ),
        )]);
    }

    let predecessor = predecessors
        .last()
        .ok_or_else(|| anyhow!("version-shape predecessor vanished after cardinality check"))?;
    if target <= predecessor.version {
        return Ok(Vec::new());
    }

    let delay = target_time.signed_duration_since(predecessor.published_at);
    if delay <= Duration::zero()
        || delay > Duration::hours(i64::from(parameters.maximum_jump_delay_hours()))
    {
        return Ok(Vec::new());
    }

    let Some(target_jump_class) = jump_class(predecessor.version, target, parameters) else {
        return Ok(Vec::new());
    };
    let baseline_start = predecessors
        .len()
        .checked_sub(parameters.baseline_transitions() + 1)
        .ok_or_else(|| anyhow!("version-shape baseline cardinality underflow"))?;
    let baseline_repeats_shape = predecessors[baseline_start..].windows(2).any(|pair| {
        jump_class(pair[0].version, pair[1].version, parameters) == Some(target_jump_class)
    });
    if baseline_repeats_shape {
        return Ok(Vec::new());
    }

    let threshold = match target_jump_class {
        JumpClass::Major => format!("major_delta>={}", parameters.major_jump_threshold()),
        JumpClass::Minor => format!(
            "same_major_minor_delta>={}",
            parameters.minor_jump_threshold()
        ),
    };
    let mut finding = Finding::new(
        "version-shape-anomaly",
        Severity::Medium,
        format!(
            "policy={POLICY_ID}; target={target}@{}; predecessor={}@{}; delay_hours={}; \
             threshold={threshold}; baseline_transitions={}",
            target_time.to_rfc3339(),
            predecessor.version,
            predecessor.published_at.to_rfc3339(),
            delay.num_hours(),
            parameters.baseline_transitions()
        ),
    );
    finding.evidence = Some(vec![
        format!("policy={POLICY_ID}"),
        format!("package_name={}", packument.name),
        format!("target_version={target}"),
        format!("target_published_at={}", target_time.to_rfc3339()),
        format!("predecessor_version={}", predecessor.version),
        format!(
            "predecessor_published_at={}",
            predecessor.published_at.to_rfc3339()
        ),
        format!("threshold={threshold}"),
    ]);
    Ok(vec![finding])
}

fn required_time(times: &BTreeMap<String, String>, version: &str) -> Result<DateTime<Utc>> {
    let raw = times
        .get(version)
        .ok_or_else(|| anyhow!("packument `time` is missing version `{version}`"))?;
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .with_context(|| format!("packument `time[{version}]` is not RFC3339"))
}

fn jump_class(
    predecessor: NormalizedVersion,
    target: NormalizedVersion,
    parameters: NpmVersionShapeParameters,
) -> Option<JumpClass> {
    if target.major
        >= predecessor
            .major
            .saturating_add(parameters.major_jump_threshold())
    {
        return Some(JumpClass::Major);
    }
    if target.major == predecessor.major
        && target.minor
            >= predecessor
                .minor
                .saturating_add(parameters.minor_jump_threshold())
    {
        return Some(JumpClass::Minor);
    }
    None
}

fn unassessed_finding(packument: &Packument, target_version: &str, reason: &str) -> Finding {
    let mut finding = Finding::new(
        "npm-version-shape-unassessed",
        Severity::Info,
        format!("policy={POLICY_ID}; status=unassessed; reason={reason}"),
    );
    finding.evidence = Some(vec![
        format!("policy={POLICY_ID}"),
        format!("package_name={}", packument.name),
        format!("target_version={target_version}"),
        "status=unassessed".to_string(),
        format!("reason={reason}"),
    ]);
    finding
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    total: usize,
    objects: Vec<SearchObject>,
}

#[derive(Debug, Deserialize)]
struct SearchObject {
    package: SearchPackage,
}

#[derive(Debug, Deserialize)]
struct SearchPackage {
    name: String,
    version: String,
    date: String,
    publisher: SearchPublisher,
}

#[derive(Debug, Deserialize)]
struct SearchPublisher {
    username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    fetched_at: DateTime<Utc>,
    body: String,
}

pub(crate) fn metadata_findings(
    packument: &Packument,
    target_version: &str,
    registry: &str,
    cache_dir: Option<&Path>,
    transport: &dyn Transport,
    rules: &argus_rules::RuleSession,
) -> Result<Vec<Finding>> {
    metadata_findings_with_parameters_at(
        packument,
        target_version,
        registry,
        cache_dir,
        transport,
        Utc::now(),
        rules.npm_version_shape_parameters()?,
        rules.npm_rapid_publish_parameters()?,
    )
}

#[allow(clippy::too_many_arguments)]
fn metadata_findings_with_parameters_at(
    packument: &Packument,
    target_version: &str,
    registry: &str,
    cache_dir: Option<&Path>,
    transport: &dyn Transport,
    now: DateTime<Utc>,
    version_parameters: NpmVersionShapeParameters,
    rapid_parameters: NpmRapidPublishParameters,
) -> Result<Vec<Finding>> {
    let times = packument
        .time
        .as_ref()
        .ok_or_else(|| anyhow!("metadata anomaly detection requires packument `time`"))?;
    let target_published_at = required_time(times, target_version)?;
    let publisher = packument
        .versions
        .get(target_version)
        .ok_or_else(|| anyhow!("target version `{target_version}` is missing from packument"))?
        .npm_user
        .as_ref()
        .map(|user| user.name.trim())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            anyhow!("metadata anomaly detection requires versions[{target_version}]._npmUser.name")
        })?;

    let mut findings =
        version_shape_findings_with_parameters(packument, target_version, version_parameters)?;
    findings.extend(rapid_publish_findings(
        packument,
        target_version,
        publisher,
        target_published_at,
        registry,
        cache_dir,
        transport,
        now,
        rapid_parameters,
    )?);
    Ok(findings)
}

#[allow(clippy::too_many_arguments)]
fn rapid_publish_findings(
    packument: &Packument,
    target_version: &str,
    publisher: &str,
    target_published_at: DateTime<Utc>,
    registry: &str,
    cache_dir: Option<&Path>,
    transport: &dyn Transport,
    now: DateTime<Utc>,
    parameters: NpmRapidPublishParameters,
) -> Result<Vec<Finding>> {
    let registry_base = normalized_registry_base(registry)?;
    let response = load_search_response(
        &registry_base,
        publisher,
        target_published_at,
        cache_dir,
        transport,
        now,
    )?;
    let window_start = target_published_at - Duration::hours(i64::from(parameters.window_hours()));
    let mut events = BTreeSet::new();

    for object in response.objects {
        let package = object.package;
        if package.publisher.username != publisher {
            continue;
        }
        let published_at = DateTime::parse_from_rfc3339(&package.date)
            .map(|value| value.with_timezone(&Utc))
            .with_context(|| {
                format!(
                    "npm search date for {}@{} is not RFC3339",
                    package.name, package.version
                )
            })?;
        if published_at < window_start || published_at > target_published_at {
            continue;
        }
        events.insert((
            package.name,
            package.version,
            published_at,
            package.publisher.username,
        ));
    }

    let package_names = events
        .iter()
        .map(|(name, _, _, _)| name.clone())
        .collect::<BTreeSet<_>>();
    let observed = package_names.len();
    if observed < parameters.package_threshold() {
        let mut finding = Finding::new(
            "npm-rapid-publish-unassessed",
            Severity::Info,
            format!(
                "policy={POLICY_ID}; status=unassessed; publisher={publisher}; \
                 window_hours={}; observed_distinct_packages={observed}; \
                 reason=npm search candidates do not prove publisher activity completeness",
                parameters.window_hours()
            ),
        );
        finding.evidence = Some(vec![
            format!("policy={POLICY_ID}"),
            format!("package_name={}", packument.name),
            format!("target_version={target_version}"),
            "status=unassessed".to_string(),
            format!("publisher={publisher}"),
            format!("target_published_at={}", target_published_at.to_rfc3339()),
            format!("observed_distinct_packages={observed}"),
        ]);
        return Ok(vec![finding]);
    }

    let package_list = package_names.into_iter().collect::<Vec<_>>().join(",");
    let mut finding = Finding::new(
        "rapid-publish-window",
        Severity::Medium,
        format!(
            "policy={POLICY_ID}; publisher={publisher}; target_published_at={}; \
             window_hours={}; distinct_packages={observed}; \
             threshold={}; packages={}",
            target_published_at.to_rfc3339(),
            parameters.window_hours(),
            parameters.package_threshold(),
            package_list
        ),
    );
    finding.evidence = Some(vec![
        format!("policy={POLICY_ID}"),
        format!("package_name={}", packument.name),
        format!("target_version={target_version}"),
        format!("publisher={publisher}"),
        format!("target_published_at={}", target_published_at.to_rfc3339()),
        format!("distinct_packages={observed}"),
        format!("packages={package_list}"),
    ]);
    Ok(vec![finding])
}

fn normalized_registry_base(registry: &str) -> Result<Url> {
    let mut base =
        Url::parse(registry).with_context(|| format!("parse npm registry URL {registry}"))?;
    if base.host_str().is_none() {
        bail!("npm registry URL has no host: {registry}");
    }
    if base.scheme() != "https" {
        bail!("npm metadata anomaly registry URL must use HTTPS: {registry}");
    }
    if !base.username().is_empty() || base.password().is_some() {
        bail!("npm registry URL must not contain credentials");
    }
    if base.query().is_some() || base.fragment().is_some() {
        bail!("npm registry URL must not contain query or fragment");
    }
    let path = base.path().to_string();
    if !path.ends_with('/') {
        base.set_path(&format!("{path}/"));
    }
    Ok(base)
}

fn search_url(base: &Url, publisher: &str) -> Result<Url> {
    let mut endpoint = base
        .join("-/v1/search")
        .context("join npm search endpoint to registry base")?;
    endpoint
        .query_pairs_mut()
        .append_pair("text", publisher)
        .append_pair("size", &MAXIMUM_SEARCH_OBJECTS.to_string())
        .append_pair("from", "0")
        .append_pair("quality", "0")
        .append_pair("popularity", "0")
        .append_pair("maintenance", "1");
    validate_search_url(base, endpoint.as_str())?;
    Ok(endpoint)
}

fn validate_search_url(base: &Url, candidate: &str) -> Result<()> {
    let candidate =
        Url::parse(candidate).with_context(|| format!("parse npm search URL {candidate}"))?;
    if candidate.origin() != base.origin() {
        bail!("npm search URL escaped registry origin: {candidate}");
    }
    if !candidate.path().starts_with(base.path()) {
        bail!(
            "npm search URL escaped registry base path `{}`: {candidate}",
            base.path()
        );
    }
    if candidate.fragment().is_some() {
        bail!("npm search URL must not contain a fragment: {candidate}");
    }
    Ok(())
}

fn load_search_response(
    registry_base: &Url,
    publisher: &str,
    target_published_at: DateTime<Utc>,
    cache_dir: Option<&Path>,
    transport: &dyn Transport,
    now: DateTime<Utc>,
) -> Result<SearchResponse> {
    let cache_path = cache_dir.map(|dir| {
        dir.join(format!(
            "{}.json",
            cache_key(registry_base, publisher, target_published_at)
        ))
    });
    if let Some(path) = &cache_path {
        if let Some(body) = read_cache(path, now, target_published_at)? {
            return parse_search_response(&body);
        }
    }

    let endpoint = search_url(registry_base, publisher)?;
    let body = transport
        .get_redirect_checked(endpoint.as_str(), MAXIMUM_SEARCH_BYTES, &|candidate| {
            validate_search_url(registry_base, candidate)
        })
        .with_context(|| format!("fetch npm search candidates for publisher `{publisher}`"))?;
    let response = parse_search_response(&body)?;
    if let Some(path) = &cache_path {
        write_cache(path, now, &body)?;
    }
    Ok(response)
}

fn parse_search_response(body: &[u8]) -> Result<SearchResponse> {
    if body.len() as u64 > MAXIMUM_SEARCH_BYTES {
        bail!("npm search response exceeded {MAXIMUM_SEARCH_BYTES} byte cap");
    }
    let response: SearchResponse =
        serde_json::from_slice(body).context("parse npm search response")?;
    if response.total > MAXIMUM_SEARCH_OBJECTS {
        bail!(
            "npm search response total {} exceeds one-page cap {MAXIMUM_SEARCH_OBJECTS}",
            response.total
        );
    }
    if response.objects.len() > MAXIMUM_SEARCH_OBJECTS {
        bail!(
            "npm search response contains {} objects, exceeding cap {MAXIMUM_SEARCH_OBJECTS}",
            response.objects.len()
        );
    }
    if response.objects.len() != response.total {
        bail!(
            "npm search response is truncated or inconsistent: total={}, objects={}",
            response.total,
            response.objects.len()
        );
    }
    Ok(response)
}

fn cache_key(base: &Url, publisher: &str, target_published_at: DateTime<Utc>) -> String {
    let identity = format!(
        "{}\n{publisher}\n{}\n{POLICY_ID}",
        base.as_str(),
        target_published_at.to_rfc3339()
    );
    let digest = Sha256::digest(identity.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_cache(
    path: &Path,
    now: DateTime<Utc>,
    target_published_at: DateTime<Utc>,
) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect metadata cache {}", path.display()))
        }
    };
    if metadata.file_type().is_symlink() {
        bail!("metadata cache entry is a symlink: {}", path.display());
    }
    if !metadata.is_file() {
        bail!("metadata cache entry is not a file: {}", path.display());
    }
    let bytes = match argus_core::fs::read_bounded_regular_file(
        path,
        (MAXIMUM_SEARCH_BYTES + 4096) as usize,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(error).with_context(|| format!("read metadata cache {}", path.display()))
        }
    };
    let entry: CacheEntry = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse metadata cache {}", path.display()))?;
    if !cache_entry_is_reusable(entry.fetched_at, now, target_published_at)
        .with_context(|| format!("validate metadata cache time {}", path.display()))?
    {
        return Ok(None);
    }
    let body = entry.body.into_bytes();
    parse_search_response(&body)
        .with_context(|| format!("revalidate metadata cache {}", path.display()))?;
    Ok(Some(body))
}

fn cache_entry_is_reusable(
    fetched_at: DateTime<Utc>,
    now: DateTime<Utc>,
    target_published_at: DateTime<Utc>,
) -> Result<bool> {
    let age = now.signed_duration_since(fetched_at);
    if age < Duration::zero() {
        bail!("metadata cache fetched_at is in the future");
    }
    Ok(age <= Duration::minutes(CACHE_TTL_MINUTES) && fetched_at >= target_published_at)
}

fn write_cache(path: &Path, fetched_at: DateTime<Utc>, body: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("metadata cache path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create metadata cache directory {}", parent.display()))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect metadata cache directory {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!(
            "metadata cache directory must be a real directory: {}",
            parent.display()
        );
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            bail!("metadata cache entry is a symlink: {}", path.display());
        }
        if !metadata.is_file() {
            bail!("metadata cache entry is not a file: {}", path.display());
        }
    }
    let body = std::str::from_utf8(body).context("npm search response is not UTF-8 JSON")?;
    let entry = CacheEntry {
        fetched_at,
        body: body.to_string(),
    };
    let bytes = serde_json::to_vec(&entry).context("serialize metadata cache entry")?;
    argus_core::fs::atomic_write_bytes(path, &bytes, ".argus-metadata-cache-")
        .with_context(|| format!("atomically replace metadata cache {}", path.display()))
}

#[cfg(test)]
#[path = "anomaly/tests.rs"]
mod tests;
