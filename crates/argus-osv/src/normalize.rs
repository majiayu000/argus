use crate::model::{
    parse_modified, validate_scalar, AdvisoryEvidence, AdvisoryReference, AffectedEvidence,
    CoordinateQuery, CoordinateSet, NormalizedAdvisory, OsvError, OsvErrorKind, RangeEvidence,
    MAX_ID_BYTES, MAX_REFERENCE_URL_BYTES,
};
use crate::severity::{normalize_severities, SeverityEvidence, SeveritySource};
use argus_intel::{match_osv_affected, OsvRecord};
use argus_lockfile::{NormalizedDependency, SourceKind};
use url::Url;

pub const OSV_API_BASE: &str = "https://api.osv.dev";

pub fn collect_lockfile_coordinates(
    records: &[NormalizedDependency],
) -> Result<CoordinateSet, OsvError> {
    let mut queries = Vec::new();
    let mut excluded_local_records = 0usize;
    for record in records {
        if record.sources.is_empty() {
            return Err(OsvError::incomplete(format!(
                "lockfile record at `{}` has no source evidence",
                record.locator
            )));
        }
        for source in &record.sources {
            source.validate().map_err(|error| {
                OsvError::incomplete(format!(
                    "invalid source evidence at `{}`: {error}",
                    record.locator
                ))
            })?;
        }
        let local = record
            .sources
            .iter()
            .all(|source| matches!(source.kind, SourceKind::Path | SourceKind::Workspace));
        let root_without_identity = record.coordinate.is_none()
            && record
                .sources
                .iter()
                .all(|source| source.kind == SourceKind::UnavailableByFormat)
            && (record.raw_name.is_none() || record.raw_version.is_none());
        if local || root_without_identity {
            excluded_local_records = excluded_local_records
                .checked_add(1)
                .ok_or_else(|| OsvError::limit("excluded local record count overflowed"))?;
            continue;
        }
        let coordinate = record.coordinate.clone().ok_or_else(|| {
            OsvError::incomplete(format!(
                "external lockfile record at `{}` has no complete coordinate",
                record.locator
            ))
        })?;
        queries.push(CoordinateQuery::new(coordinate, [record.locator.clone()])?);
    }
    CoordinateSet::new(queries, excluded_local_records)
}

pub fn normalize_advisory(
    record: &OsvRecord,
    query: &CoordinateQuery,
    batch_summary_modified: &str,
    detail_modified: &str,
) -> Result<NormalizedAdvisory, OsvError> {
    query.validate()?;
    validate_scalar("primary advisory id", &record.id, MAX_ID_BYTES)?;
    if record.withdrawn.is_some() {
        return Err(OsvError::new(
            OsvErrorKind::SnapshotRace,
            format!("hydrated advisory `{}` is withdrawn", record.id),
        ));
    }

    let matched = match_osv_affected(record, &query.coordinate).map_err(|error| {
        OsvError::malformed(format!(
            "match advisory `{}` against queried coordinate: {error}",
            record.id
        ))
    })?;
    if matched.is_empty() {
        return Err(OsvError::new(
            OsvErrorKind::SnapshotRace,
            format!(
                "hydrated advisory `{}` no longer matches queried coordinate",
                record.id
            ),
        ));
    }

    let mut aliases = record.aliases.clone();
    for alias in &aliases {
        validate_scalar("advisory alias", alias, MAX_ID_BYTES)?;
    }
    aliases.sort();
    aliases.dedup();

    let mut affected = matched
        .iter()
        .map(|affected_match| {
            let mut ranges = affected_match
                .ranges
                .iter()
                .flat_map(|range| {
                    range.intervals.iter().map(|interval| RangeEvidence {
                        affected_index: affected_match.affected_index,
                        range_type: range.range_type.clone(),
                        introduced: interval.introduced.clone(),
                        fixed: interval.fixed.clone(),
                        last_affected: interval.last_affected.clone(),
                        limit: interval.limit.clone(),
                    })
                })
                .collect::<Vec<_>>();
            ranges.sort();
            ranges.dedup();
            AffectedEvidence {
                affected_index: affected_match.affected_index,
                exact_versions: affected_match.exact_versions.clone(),
                ranges,
            }
        })
        .collect::<Vec<_>>();
    affected.sort();
    affected.dedup();

    let severity = normalize_severities(&record.severity, &matched)?;
    Ok(NormalizedAdvisory {
        coordinate: query.coordinate.clone(),
        primary_id: record.id.clone(),
        aliases,
        evidence: AdvisoryEvidence {
            locators: query.locators.clone(),
            affected,
        },
        severity,
        references: normalize_references(record)?,
        batch_summary_modified: batch_summary_modified.to_string(),
        detail_modified: detail_modified.to_string(),
        database_modified: record.modified,
        published: record.published,
        source_url: advisory_source_url(&record.id),
    })
}

fn normalize_references(record: &OsvRecord) -> Result<Vec<AdvisoryReference>, OsvError> {
    let mut references = Vec::new();
    for reference in &record.references {
        validate_scalar(
            "advisory reference URL",
            &reference.url,
            MAX_REFERENCE_URL_BYTES,
        )?;
        let parsed = Url::parse(&reference.url).map_err(|error| {
            OsvError::malformed(format!(
                "invalid advisory reference URL `{}`: {error}",
                reference.url
            ))
        })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(OsvError::malformed(format!(
                "advisory reference URL `{}` is not HTTP(S)",
                reference.url
            )));
        }
        references.push(AdvisoryReference {
            reference_type: reference.reference_type.clone(),
            url: parsed.to_string(),
        });
    }
    references.sort();
    references.dedup();
    Ok(references)
}

pub(crate) fn advisory_source_url(primary_id: &str) -> String {
    let mut encoded = String::with_capacity(primary_id.len());
    for byte in primary_id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    format!("{OSV_API_BASE}/v1/vulns/{encoded}")
}

pub(crate) fn validate_normalized_advisory(
    advisory: &NormalizedAdvisory,
    summary_modified: &str,
) -> Result<(), OsvError> {
    if advisory.batch_summary_modified != summary_modified {
        return Err(OsvError::malformed(
            "cached advisory batch modified does not match its query summary",
        ));
    }
    let summary_interval = parse_modified(&advisory.batch_summary_modified)?;
    let detail_interval = parse_modified(&advisory.detail_modified)?;
    if !summary_interval.contains(detail_interval.start) {
        return Err(OsvError::new(
            OsvErrorKind::SnapshotRace,
            "cached detail modified is outside its batch summary precision interval",
        ));
    }
    if detail_interval.start != advisory.database_modified {
        return Err(OsvError::malformed(
            "cached raw detail modified does not match normalized database_modified",
        ));
    }
    if advisory.source_url != advisory_source_url(&advisory.primary_id) {
        return Err(OsvError::malformed(
            "cached advisory source URL is not the fixed OSV detail URL",
        ));
    }
    let maximum_index = advisory
        .evidence
        .affected
        .iter()
        .map(|affected| affected.affected_index)
        .max()
        .ok_or_else(|| OsvError::malformed("cached advisory has no affected evidence"))?;
    if maximum_index > 100_000 {
        return Err(OsvError::limit(
            "cached affected evidence index exceeds maximum 100000",
        ));
    }
    let mut affected = Vec::with_capacity(maximum_index + 1);
    for index in 0..=maximum_index {
        affected.push(
            match advisory
                .evidence
                .affected
                .iter()
                .find(|value| value.affected_index == index)
            {
                Some(value) => affected_value(advisory, value),
                None => unmatched_affected_value(advisory),
            },
        );
    }
    let severity = advisory
        .severity
        .evidence
        .iter()
        .map(severity_value)
        .collect::<Vec<_>>();
    let references = advisory
        .references
        .iter()
        .map(|reference| serde_json::json!({"type":reference.reference_type,"url":reference.url}))
        .collect::<Vec<_>>();
    let mut raw = serde_json::json!({
        "schema_version":"1.8.0",
        "id":advisory.primary_id,
        "modified":advisory.detail_modified,
        "aliases":advisory.aliases,
        "severity":severity,
        "affected":affected,
        "references":references
    });
    if let Some(published) = advisory.published {
        raw["published"] = serde_json::json!(published);
    }
    let bytes = serde_json::to_vec(&raw)
        .map_err(|error| OsvError::malformed(format!("serialize cached advisory: {error}")))?;
    let record = argus_intel::parse_osv_record(&bytes)
        .map_err(|error| OsvError::malformed(format!("parse cached advisory: {error}")))?;
    let query = CoordinateQuery::new(
        advisory.coordinate.clone(),
        advisory.evidence.locators.clone(),
    )?;
    let normalized = normalize_advisory(
        &record,
        &query,
        &advisory.batch_summary_modified,
        &advisory.detail_modified,
    )?;
    if &normalized != advisory {
        return Err(OsvError::malformed(
            "cached advisory differs from exact normalized OSV evidence",
        ));
    }
    Ok(())
}

fn affected_value(advisory: &NormalizedAdvisory, affected: &AffectedEvidence) -> serde_json::Value {
    let ranges = affected
        .ranges
        .iter()
        .map(|range| {
            let mut events = vec![serde_json::json!({"introduced":range.introduced})];
            for (field, value) in [
                ("fixed", range.fixed.as_ref()),
                ("last_affected", range.last_affected.as_ref()),
                ("limit", range.limit.as_ref()),
            ] {
                if let Some(value) = value {
                    events.push(serde_json::json!({(field):value}));
                }
            }
            serde_json::json!({"type":range.range_type,"events":events})
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "package":{"ecosystem":advisory.coordinate.ecosystem.osv_name(),
            "name":advisory.coordinate.canonical_name},
        "versions":affected.exact_versions,
        "ranges":ranges
    })
}

fn unmatched_affected_value(advisory: &NormalizedAdvisory) -> serde_json::Value {
    let ecosystem = if advisory.coordinate.ecosystem.osv_name() == "npm" {
        "PyPI"
    } else {
        "npm"
    };
    serde_json::json!({
        "package":{"ecosystem":ecosystem,"name":"argus-unmatched-cache-placeholder"},
        "versions":["0"]
    })
}

fn severity_value(evidence: &SeverityEvidence) -> serde_json::Value {
    let mut value = serde_json::json!({
        "type":evidence.severity_type,
        "score":evidence.score
    });
    if let Some(source) = evidence.source {
        value["source"] = serde_json::json!(match source {
            SeveritySource::Nvd => "NVD",
            SeveritySource::Cna => "CNA",
            SeveritySource::SelfReported => "SELF",
        });
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::{Ecosystem, PackageCoordinate};
    use argus_intel::parse_osv_record;
    use argus_lockfile::{IntegrityState, LockfileFormat, NormalizedSource};

    fn query() -> CoordinateQuery {
        CoordinateQuery::new(
            PackageCoordinate::new(Ecosystem::Npm, "demo", "1.5.0").unwrap(),
            ["z:2".to_string(), "a:1".to_string(), "a:1".to_string()],
        )
        .unwrap()
    }

    #[test]
    fn model_contract_keeps_only_matching_sibling_evidence() {
        let raw = br#"{
          "schema_version":"1.8.0",
          "id":"GHSA-DEMO",
          "modified":"2026-07-19T00:00:00Z",
          "aliases":["CVE-2","CVE-1","CVE-1"],
          "affected":[{
            "package":{"ecosystem":"npm","name":"demo"},
            "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","source":"NVD"}],
            "versions":["1.5.0","2.0.0"],
            "ranges":[
              {"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.6.0"},{"introduced":"2.0.0"},{"fixed":"3.0.0"}]},
              {"type":"SEMVER","events":[{"introduced":"4.0.0"},{"fixed":"5.0.0"}]}
            ]
          }]
        }"#;
        let advisory = normalize_advisory(
            &parse_osv_record(raw).unwrap(),
            &query(),
            "2026-07-19T00:00:00Z",
            "2026-07-19T00:00:00Z",
        )
        .unwrap();
        assert_eq!(advisory.aliases, ["CVE-1", "CVE-2"]);
        assert_eq!(advisory.evidence.locators, ["a:1", "z:2"]);
        assert_eq!(advisory.evidence.affected.len(), 1);
        assert_eq!(advisory.evidence.affected[0].exact_versions, ["1.5.0"]);
        assert_eq!(advisory.evidence.affected[0].ranges.len(), 1);
        assert_eq!(advisory.evidence.affected[0].ranges[0].introduced, "1.0.0");
    }

    #[test]
    fn model_contract_excludes_local_and_rejects_external_incomplete_records() {
        let local = NormalizedDependency {
            coordinate: None,
            format: LockfileFormat::PackageLock,
            sources: vec![NormalizedSource {
                kind: SourceKind::Workspace,
                location: Some(".".to_string()),
                immutable_revision: None,
                locator: "packages.root".to_string(),
            }],
            integrity_state: IntegrityState::OptionalAbsent,
            integrity: vec![],
            raw_name: None,
            raw_version: None,
            locator: "packages.root".to_string(),
            condition: None,
            platform: None,
            occurrence_index: 0,
        };
        let mut external = local.clone();
        external.sources[0].kind = SourceKind::Registry;
        external.sources[0].location = Some("https://registry.npmjs.org".to_string());
        let mut empty_sources = local.clone();
        empty_sources.sources.clear();
        assert_eq!(
            collect_lockfile_coordinates(&[local])
                .unwrap()
                .excluded_local_records,
            1
        );
        assert_eq!(
            collect_lockfile_coordinates(&[external]).unwrap_err().kind,
            OsvErrorKind::IncompleteAnalysis
        );
        assert_eq!(
            collect_lockfile_coordinates(&[empty_sources])
                .unwrap_err()
                .kind,
            OsvErrorKind::IncompleteAnalysis
        );
    }
}
