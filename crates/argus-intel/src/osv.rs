use crate::osv_profile::{profile, SchemaProfile};
use anyhow::{bail, Context, Result};
use argus_core::{canonicalize_package_name, Ecosystem, PackageCoordinate};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::sync::LazyLock;

pub const SUPPORTED_SCHEMA_VERSIONS: &[&str] = &[
    "1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.3.1", "1.4.0", "1.5.0", "1.6.0", "1.6.1", "1.6.2",
    "1.6.3", "1.6.4", "1.6.5", "1.6.6", "1.6.7", "1.7.0", "1.7.2", "1.7.3", "1.7.4", "1.7.5",
    "1.8.0",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsvRecord {
    pub schema_version: String,
    pub id: String,
    #[serde(deserialize_with = "deserialize_utc")]
    pub modified: DateTime<Utc>,
    #[serde(default, deserialize_with = "deserialize_present_optional_utc")]
    pub published: Option<DateTime<Utc>>,
    #[serde(default, deserialize_with = "deserialize_present_optional_utc")]
    pub withdrawn: Option<DateTime<Utc>>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub related: Vec<String>,
    #[serde(default)]
    pub upstream: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub summary: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub details: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub severity: Vec<OsvSeverity>,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub affected: Vec<OsvAffected>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub references: Vec<OsvReference>,
    #[serde(default)]
    pub credits: Vec<OsvCredit>,
    #[serde(default, deserialize_with = "deserialize_optional_object")]
    pub database_specific: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsvAffected {
    pub package: OsvPackage,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_optional_object")]
    pub ecosystem_specific: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "deserialize_optional_object")]
    pub database_specific: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub repo: Option<String>,
    pub events: Vec<OsvEvent>,
    #[serde(default, deserialize_with = "deserialize_optional_object")]
    pub database_specific: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsvEvent {
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub introduced: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub fixed: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub last_affected: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub limit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub reference_type: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsvCredit {
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub contact: Option<Vec<String>>,
    #[serde(rename = "type")]
    #[serde(default, deserialize_with = "deserialize_present_optional")]
    pub credit_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OsvIntervalMatch {
    pub introduced: String,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
    pub limit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsvRangeMatch {
    pub range_type: String,
    pub intervals: Vec<OsvIntervalMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsvAffectedMatch {
    pub affected_index: usize,
    pub exact_versions: Vec<String>,
    pub ranges: Vec<OsvRangeMatch>,
    pub severity: Vec<OsvSeverity>,
}

pub fn parse_osv_record(bytes: &[u8]) -> Result<OsvRecord> {
    let mut value: Value = serde_json::from_slice(bytes).context("parse OSV advisory JSON")?;
    let (schema_profile, schema_version) = validate_version_shape(&mut value)?;
    let record: OsvRecord =
        serde_json::from_value(value).context("parse OSV advisory JSON schema")?;
    validate_common(&record, schema_profile, &schema_version)?;
    Ok(record)
}

pub(crate) fn parse_record(bytes: &[u8]) -> Result<OsvRecord> {
    parse_osv_record(bytes)
}

pub fn match_osv_affected(
    record: &OsvRecord,
    coordinate: &PackageCoordinate,
) -> Result<Vec<OsvAffectedMatch>> {
    validate_osv_coordinate(coordinate)?;
    let mut matches = Vec::new();
    for (affected_index, affected) in record.affected.iter().enumerate() {
        let Some(ecosystem) = crate::normalize::ecosystem_from_osv(&affected.package.ecosystem)
        else {
            continue;
        };
        if ecosystem != coordinate.ecosystem
            || canonicalize_package_name(ecosystem, &affected.package.name)?
                != coordinate.canonical_name
        {
            continue;
        }
        let mut exact_versions = Vec::new();
        for version in &affected.versions {
            if crate::matcher::compare_versions(ecosystem, &coordinate.version, version)?
                == std::cmp::Ordering::Equal
            {
                exact_versions.push(version.clone());
            }
        }
        exact_versions.sort();
        exact_versions.dedup();
        let expected_range = match ecosystem {
            Ecosystem::Npm | Ecosystem::CratesIo | Ecosystem::Go => "SEMVER",
            Ecosystem::PyPi
            | Ecosystem::NuGet
            | Ecosystem::Maven
            | Ecosystem::RubyGems
            | Ecosystem::Packagist => "ECOSYSTEM",
        };
        let mut ranges = Vec::new();
        for range in &affected.ranges {
            if range.range_type != expected_range || range.repo.is_some() {
                bail!(
                    "advisory `{}` uses unsupported range for {}",
                    record.id,
                    ecosystem.osv_name()
                );
            }
            let intervals = matching_intervals(ecosystem, &coordinate.version, &range.events)?;
            if !intervals.is_empty() {
                ranges.push(OsvRangeMatch {
                    range_type: range.range_type.clone(),
                    intervals,
                });
            }
        }
        ranges.sort_by(|left, right| {
            (&left.range_type, &left.intervals).cmp(&(&right.range_type, &right.intervals))
        });
        ranges.dedup_by(|left, right| {
            left.range_type == right.range_type && left.intervals == right.intervals
        });
        if !exact_versions.is_empty() || !ranges.is_empty() {
            matches.push(OsvAffectedMatch {
                affected_index,
                exact_versions,
                ranges,
                severity: affected.severity.clone(),
            });
        }
    }
    Ok(matches)
}

pub fn validate_osv_coordinate(coordinate: &PackageCoordinate) -> Result<()> {
    coordinate
        .validate()
        .context("validate package coordinate before OSV matching")?;
    validate_exact_version_shape(coordinate.ecosystem, &coordinate.version)?;
    crate::matcher::parse_version(coordinate.ecosystem, &coordinate.version)
        .context("validate queried package exact version")
}

fn validate_exact_version_shape(ecosystem: Ecosystem, raw: &str) -> Result<()> {
    if raw.chars().any(char::is_whitespace) {
        bail!("exact package version must not contain whitespace");
    }
    match ecosystem {
        Ecosystem::Go => {
            let value = raw.strip_prefix('v').unwrap_or(raw);
            let core = value.split_once(['-', '+']).map_or(value, |(core, _)| core);
            if core.split('.').count() != 3 {
                bail!("exact Go version must have major, minor, and patch components");
            }
        }
        Ecosystem::Maven if raw.as_bytes().windows(2).any(|pair| pair == b"${") => {
            bail!("unresolved Maven property expression is not an exact resolved package version");
        }
        Ecosystem::Maven
            if raw.starts_with(['[', '('])
                || raw.ends_with([']', ')'])
                || raw.contains([',', '*'])
                || raw.eq_ignore_ascii_case("LATEST")
                || raw.eq_ignore_ascii_case("RELEASE") =>
        {
            bail!("Maven version ranges are not exact package versions");
        }
        _ => {}
    }
    Ok(())
}

fn matching_intervals(
    ecosystem: Ecosystem,
    candidate: &str,
    events: &[OsvEvent],
) -> Result<Vec<OsvIntervalMatch>> {
    let mut introduced: Option<&str> = None;
    let mut matches = Vec::new();
    for event in events {
        if let Some(start) = event.introduced.as_deref() {
            introduced = Some(start);
            continue;
        }
        let start = introduced
            .take()
            .ok_or_else(|| anyhow::anyhow!("OSV range closes before introduced"))?;
        if interval_contains(ecosystem, candidate, start, event)? {
            matches.push(OsvIntervalMatch {
                introduced: start.to_string(),
                fixed: event.fixed.clone(),
                last_affected: event.last_affected.clone(),
                limit: event.limit.clone(),
            });
        }
    }
    if let Some(start) = introduced {
        let after_start = start == "0"
            || crate::matcher::compare_versions(ecosystem, candidate, start)?
                != std::cmp::Ordering::Less;
        if after_start {
            matches.push(OsvIntervalMatch {
                introduced: start.to_string(),
                fixed: None,
                last_affected: None,
                limit: None,
            });
        }
    }
    Ok(matches)
}

fn interval_contains(
    ecosystem: Ecosystem,
    candidate: &str,
    introduced: &str,
    closing: &OsvEvent,
) -> Result<bool> {
    let after_start = introduced == "0"
        || crate::matcher::compare_versions(ecosystem, candidate, introduced)?
            != std::cmp::Ordering::Less;
    let (end, inclusive) = if let Some(value) = closing.fixed.as_deref() {
        (value, false)
    } else if let Some(value) = closing.limit.as_deref() {
        (value, false)
    } else if let Some(value) = closing.last_affected.as_deref() {
        (value, true)
    } else {
        bail!("OSV range closing event has no boundary");
    };
    let order = crate::matcher::compare_versions(ecosystem, candidate, end)?;
    Ok(after_start && (order == std::cmp::Ordering::Less || (inclusive && order.is_eq())))
}

fn validate_version_shape(value: &mut Value) -> Result<(&'static SchemaProfile, String)> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("OSV advisory must be a JSON object"))?;
    let version = match object.get("schema_version") {
        None => {
            object.insert(
                "schema_version".to_string(),
                Value::String("1.0.0".to_string()),
            );
            "1.0.0".to_string()
        }
        Some(Value::String(version)) if !version.is_empty() => version.clone(),
        Some(_) => bail!("OSV schema_version must be a non-empty string"),
    };
    if !SUPPORTED_SCHEMA_VERSIONS.contains(&version.as_str()) {
        bail!("unsupported OSV schema_version `{version}`");
    }
    let profile_version = match version.as_str() {
        "1.3.1" => "1.3.0",
        "1.6.1" | "1.6.2" | "1.6.3" | "1.6.4" | "1.6.5" | "1.6.6" | "1.6.7" => "1.6.0",
        "1.7.5" | "1.8.0" => "1.7.4",
        supported => supported,
    };
    let schema_profile = profile(profile_version)
        .ok_or_else(|| anyhow::anyhow!("unsupported OSV schema_version `{version}`"))?;
    reject_unless(
        object,
        "database_specific",
        schema_profile.fields.top_database_specific,
        &version,
    )?;
    reject_unless(
        object,
        "credits",
        schema_profile.fields.credits_and_top_severity,
        &version,
    )?;
    reject_unless(
        object,
        "severity",
        schema_profile.fields.credits_and_top_severity,
        &version,
    )?;
    reject_unless(object, "upstream", schema_profile.fields.upstream, &version)?;
    for field in ["aliases", "severity", "affected", "references"] {
        reject_null_unless(
            object,
            field,
            schema_profile.fields.nullable_core_collections,
            &version,
        )?;
    }

    if let Some(affected) = object.get("affected").and_then(Value::as_array) {
        for item in affected {
            let Some(item) = item.as_object() else {
                continue;
            };
            reject_unless(
                item,
                "severity",
                schema_profile.fields.affected_severity_and_credit_type,
                &version,
            )?;
            if let Some(ranges) = item.get("ranges").and_then(Value::as_array) {
                for range in ranges {
                    let Some(range) = range.as_object() else {
                        continue;
                    };
                    reject_unless(
                        range,
                        "database_specific",
                        schema_profile.fields.last_affected_and_range_database,
                        &version,
                    )?;
                    if !schema_profile.fields.last_affected_and_range_database
                        && range
                            .get("events")
                            .and_then(Value::as_array)
                            .is_some_and(|events| {
                                events.iter().any(|event| {
                                    event
                                        .as_object()
                                        .is_some_and(|event| event.contains_key("last_affected"))
                                })
                            })
                    {
                        bail!("field `last_affected` is not defined by OSV schema {version}");
                    }
                }
            }
        }
    }
    if !schema_profile.fields.affected_severity_and_credit_type
        && object
            .get("credits")
            .and_then(Value::as_array)
            .is_some_and(|credits| {
                credits.iter().any(|credit| {
                    credit
                        .as_object()
                        .is_some_and(|credit| credit.contains_key("type"))
                })
            })
    {
        bail!("field `credits[].type` is not defined by OSV schema {version}");
    }
    Ok((schema_profile, version))
}

fn reject_unless(
    object: &Map<String, Value>,
    field: &str,
    allowed: bool,
    version: &str,
) -> Result<()> {
    if object.contains_key(field) && !allowed {
        bail!("field `{field}` is not defined by OSV schema {version}");
    }
    Ok(())
}

fn reject_null_unless(
    object: &Map<String, Value>,
    field: &str,
    allowed: bool,
    version: &str,
) -> Result<()> {
    if object.get(field).is_some_and(Value::is_null) && !allowed {
        bail!("field `{field}` must not be null in OSV schema {version}");
    }
    Ok(())
}

fn validate_common(
    record: &OsvRecord,
    schema_profile: &SchemaProfile,
    schema_version: &str,
) -> Result<()> {
    validate_text("advisory id", &record.id)?;
    schema_profile.validate_id(&record.id)?;
    if record.affected.is_empty() {
        bail!("advisory `{}` has no affected packages", record.id);
    }
    for alias in &record.aliases {
        validate_text("advisory alias", alias)?;
    }
    for related in &record.related {
        validate_text("related advisory id", related)?;
    }
    for upstream in &record.upstream {
        validate_text("upstream advisory id", upstream)?;
    }
    validate_severities(&record.severity, schema_profile, schema_version)?;
    for affected in &record.affected {
        validate_text("OSV package ecosystem", &affected.package.ecosystem)?;
        schema_profile.validate_ecosystem(&affected.package.ecosystem)?;
        validate_text("OSV package name", &affected.package.name)?;
        let _audit_only = (
            &affected.package.purl,
            &affected.severity,
            &affected.ecosystem_specific,
            &affected.database_specific,
        );
        for version in &affected.versions {
            validate_text("OSV exact version", version)?;
        }
        validate_severities(&affected.severity, schema_profile, schema_version)?;
        if !record.severity.is_empty() && !affected.severity.is_empty() {
            bail!("top-level and affected-level severity cannot both be present");
        }
        for range in &affected.ranges {
            validate_text("OSV range type", &range.range_type)?;
            let _audit_only = &range.database_specific;
            if range.events.is_empty() {
                bail!("advisory `{}` affected range has no events", record.id);
            }
        }
        let required_ranges = schema_profile.fields.required_affected_range_types;
        if !required_ranges.is_empty()
            && affected.versions.is_empty()
            && !affected
                .ranges
                .iter()
                .any(|range| required_ranges.contains(&range.range_type.as_str()))
        {
            bail!(
                "OSV schema {} affected entry requires versions when it has no supported range",
                schema_profile.version
            );
        }
    }
    // Touch closed-schema fields so their presence is deliberately accepted,
    // rather than accidentally becoming an unreviewed ignored field.
    let _audit_only = (
        record.modified,
        &record.published,
        &record.summary,
        &record.details,
        &record.severity,
        &record.references,
        &record.credits,
        &record.database_specific,
    );
    for reference in &record.references {
        if !schema_profile
            .reference_types
            .contains(&reference.reference_type.as_str())
        {
            bail!(
                "unsupported OSV reference type `{}`",
                reference.reference_type
            );
        }
        validate_url("reference URL", &reference.url)?;
    }
    for credit in &record.credits {
        validate_text("credit name", &credit.name)?;
        if let Some(contacts) = &credit.contact {
            for contact in contacts {
                // OSV deliberately treats contact values as free-form strings:
                // they may be URLs, email addresses, or service handles.
                validate_text("credit contact", contact)?;
            }
        }
        if credit.credit_type.as_deref().is_some_and(|credit_type| {
            !matches!(
                credit_type,
                "FINDER"
                    | "REPORTER"
                    | "ANALYST"
                    | "COORDINATOR"
                    | "REMEDIATION_DEVELOPER"
                    | "REMEDIATION_REVIEWER"
                    | "REMEDIATION_VERIFIER"
                    | "TOOL"
                    | "SPONSOR"
                    | "OTHER"
            )
        }) {
            bail!("unsupported OSV credit type");
        }
    }
    validate_generic_ranges(record)?;
    Ok(())
}

fn validate_severities(
    severities: &[OsvSeverity],
    schema_profile: &SchemaProfile,
    schema_version: &str,
) -> Result<()> {
    for severity in severities {
        if !schema_profile
            .severity_types
            .contains(&severity.severity_type.as_str())
        {
            bail!("unsupported OSV severity type `{}`", severity.severity_type);
        }
        validate_severity_score(&severity.severity_type, &severity.score)?;
        if schema_version == "1.8.0" {
            if severity
                .source
                .as_deref()
                .is_some_and(|source| !matches!(source, "NVD" | "CNA" | "SELF"))
            {
                bail!("unsupported OSV severity source");
            }
        } else if severity.source.is_some() {
            bail!("OSV severity source was introduced in schema 1.8.0");
        }
    }
    Ok(())
}

fn validate_generic_ranges(record: &OsvRecord) -> Result<()> {
    for affected in &record.affected {
        for range in &affected.ranges {
            if !matches!(range.range_type.as_str(), "GIT" | "SEMVER" | "ECOSYSTEM") {
                bail!(
                    "advisory `{}` has unsupported OSV range type `{}`",
                    record.id,
                    range.range_type
                );
            }
            if range.range_type == "GIT" && range.repo.is_none() {
                bail!("advisory `{}` GIT range is missing repo", record.id);
            }
            if let Some(repo) = &range.repo {
                validate_text("OSV range repo", repo)?;
            }
            if range.events.is_empty() {
                bail!("advisory `{}` affected range has no events", record.id);
            }
            let mut saw_introduced = false;
            let mut interval_open = false;
            for (index, event) in range.events.iter().enumerate() {
                let fields = [
                    event.introduced.as_deref(),
                    event.fixed.as_deref(),
                    event.last_affected.as_deref(),
                    event.limit.as_deref(),
                ];
                if fields.iter().filter(|field| field.is_some()).count() != 1 {
                    bail!("range event {index} must contain exactly one event field");
                }
                let value =
                    fields.into_iter().flatten().next().ok_or_else(|| {
                        anyhow::anyhow!("range event {index} lost its event value")
                    })?;
                validate_text("OSV range event value", value)?;
                if event.introduced.is_some() {
                    if interval_open {
                        bail!("range event {index} introduces before closing the prior interval");
                    }
                    saw_introduced = true;
                    interval_open = true;
                } else {
                    if !interval_open {
                        bail!("range event {index} closes before introduced");
                    }
                    interval_open = false;
                }
            }
            if !saw_introduced {
                bail!("advisory `{}` range has no introduced event", record.id);
            }
        }
    }
    Ok(())
}

static CVSS_V2: LazyLock<std::result::Result<Regex, String>> = LazyLock::new(|| {
    Regex::new(
        r"^((AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))/)*(AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))$",
    )
    .map_err(|error| error.to_string())
});

static CVSS_V3: LazyLock<std::result::Result<Regex, String>> = LazyLock::new(|| {
    Regex::new(
        r"^CVSS:3[.][01]/((AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$",
    )
    .map_err(|error| error.to_string())
});

static CVSS_V4: LazyLock<std::result::Result<Regex, String>> = LazyLock::new(|| {
    Regex::new(
        r"^CVSS:4[.]0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN](/E:[XAPU])?(/CR:[XHML])?(/IR:[XHML])?(/AR:[XHML])?(/MAV:[XNALP])?(/MAC:[XLH])?(/MAT:[XNP])?(/MPR:[XNLH])?(/MUI:[XNPA])?(/MVC:[XNLH])?(/MVI:[XNLH])?(/MVA:[XNLH])?(/MSC:[XNLH])?(/MSI:[XNLHS])?(/MSA:[XNLHS])?(/S:[XNP])?(/AU:[XNY])?(/R:[XAUI])?(/V:[XDC])?(/RE:[XLMH])?(/U:(X|Clear|Green|Amber|Red))?$",
    )
    .map_err(|error| error.to_string())
});

fn validate_severity_score(severity_type: &str, score: &str) -> Result<()> {
    validate_text("severity score", score)?;
    let valid = match severity_type {
        "CVSS_V2" => score_matches(&CVSS_V2, score)?,
        "CVSS_V3" => score_matches(&CVSS_V3, score)?,
        "CVSS_V4" => score_matches(&CVSS_V4, score)?,
        "Ubuntu" => matches!(score, "negligible" | "low" | "medium" | "high" | "critical"),
        _ => false,
    };
    if !valid {
        bail!("invalid {severity_type} severity score `{score}`");
    }
    Ok(())
}

fn score_matches(
    compiled: &LazyLock<std::result::Result<Regex, String>>,
    score: &str,
) -> Result<bool> {
    match &**compiled {
        Ok(regex) => Ok(regex.is_match(score)),
        Err(error) => bail!("compile built-in OSV severity grammar: {error}"),
    }
}

fn validate_url(label: &str, value: &str) -> Result<()> {
    validate_text(label, value)?;
    url::Url::parse(value).with_context(|| format!("parse {label} `{value}`"))?;
    Ok(())
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<T>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_optional_object<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Map<String, Value>>, D::Error>
where
    D: Deserializer<'de>,
{
    match Value::deserialize(deserializer)? {
        Value::Object(object) => Ok(Some(object)),
        Value::Null => Err(serde::de::Error::custom(
            "OSV schema object field must not be null",
        )),
        _ => Err(serde::de::Error::custom(
            "OSV schema object field must be an object",
        )),
    }
}

fn deserialize_utc<'de, D>(deserializer: D) -> std::result::Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    parse_utc(&raw).map_err(serde::de::Error::custom)
}

fn deserialize_present_optional_utc<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    parse_utc(&raw).map(Some).map_err(serde::de::Error::custom)
}

fn deserialize_present_optional<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn parse_utc(raw: &str) -> Result<DateTime<Utc>> {
    if !raw.ends_with('Z') {
        bail!("OSV timestamp must use UTC `Z` form");
    }
    raw.parse::<DateTime<Utc>>()
        .with_context(|| format!("parse OSV UTC timestamp `{raw}`"))
}

pub(crate) fn validate_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{label} is empty");
    }
    if value.chars().any(char::is_control) {
        bail!("{label} contains a control character");
    }
    Ok(())
}
