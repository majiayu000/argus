//! SARIF 2.1.0 adapter for complete vulnerability query reports.

use crate::sarif;
use anyhow::{anyhow, Result};
use argus_core::{Finding, Severity};
use argus_osv::report::VulnerabilityReport;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub(crate) fn render_report(report: &VulnerabilityReport, cache_label: &str) -> Result<Value> {
    let severities = collect_rule_severities(report);
    let indices = severities
        .keys()
        .enumerate()
        .map(|(index, rule_id)| (rule_id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let rules = severities
        .iter()
        .map(|(rule_id, severity)| {
            json!({
                "id": rule_id,
                "name": sarif::rule_name(rule_id),
                "shortDescription": {"text": format!("Argus vulnerability result: {rule_id}")},
                "help": {"text": "Argus queried an exact package coordinate against OSV."},
                "helpUri": "https://osv.dev",
                "defaultConfiguration": {"level": sarif::sarif_level(*severity)}
            })
        })
        .collect();
    let mut advisory_index = 0usize;
    let mut results = Vec::with_capacity(report.findings.len());
    for finding in &report.findings {
        let rule_index = indices
            .get(finding.rule_id.as_str())
            .copied()
            .ok_or_else(|| anyhow!("SARIF rule index missing for `{}`", finding.rule_id))?;
        let advisory = if finding.rule_id == "known-vulnerability" {
            let value = report.advisories.get(advisory_index).ok_or_else(|| {
                anyhow!("known-vulnerability finding has no matching advisory evidence")
            })?;
            advisory_index += 1;
            Some(value)
        } else {
            None
        };
        let uri = advisory
            .and_then(|value| value.evidence.locators.first())
            .map(|value| sarif::normalize_uri(value))
            .or_else(|| advisory.map(|value| sarif::normalize_uri(&value.coordinate.purl)))
            .unwrap_or_else(|| sarif::normalize_uri(cache_label));
        let fingerprint = fingerprint(report, finding, advisory_index, &uri);
        let mut properties = Map::new();
        properties.insert("decision".to_string(), json!(report.decision.as_str()));
        properties.insert(
            "argus_severity".to_string(),
            json!(sarif::severity_name(finding.severity)),
        );
        properties.insert("cache_label".to_string(), json!(cache_label));
        if let Some(advisory) = advisory {
            properties.insert("coordinate".to_string(), json!(advisory.coordinate));
            properties.insert("primary_id".to_string(), json!(advisory.primary_id));
            properties.insert("aliases".to_string(), json!(advisory.aliases));
            properties.insert(
                "normalized_severity".to_string(),
                json!(advisory.severity.level),
            );
            properties.insert(
                "severity_base_score".to_string(),
                json!(advisory.severity.base_score),
            );
            properties.insert(
                "severity_evidence".to_string(),
                json!(advisory.severity.evidence),
            );
            properties.insert(
                "batch_summary_modified".to_string(),
                json!(advisory.batch_summary_modified),
            );
            properties.insert(
                "detail_modified".to_string(),
                json!(advisory.detail_modified),
            );
            properties.insert(
                "database_modified".to_string(),
                json!(advisory.database_modified),
            );
            properties.insert("source_url".to_string(), json!(advisory.source_url));
            properties.insert("evidence".to_string(), json!(advisory.evidence));
            properties.insert("references".to_string(), json!(advisory.references));
        }
        results.push(json!({
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index,
            "level": sarif::sarif_level(finding.severity),
            "message": {"text": finding.detail},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": uri}}
            }],
            "partialFingerprints": {"argusVulnerability/v1": fingerprint},
            "properties": properties
        }));
    }
    if advisory_index != report.advisories.len() {
        return Err(anyhow!(
            "vulnerability advisories do not match rendered findings"
        ));
    }
    Ok(sarif::render_document(
        rules,
        results,
        Some(json!({
            "argusVulnerability": report.evidence,
            "cache_label": cache_label
        })),
    ))
}

fn collect_rule_severities(report: &VulnerabilityReport) -> BTreeMap<String, Severity> {
    let mut rules = BTreeMap::new();
    for finding in &report.findings {
        rules
            .entry(finding.rule_id.clone())
            .and_modify(|severity| {
                if sarif::severity_rank(finding.severity) > sarif::severity_rank(*severity) {
                    *severity = finding.severity;
                }
            })
            .or_insert(finding.severity);
    }
    rules
}

fn fingerprint(
    report: &VulnerabilityReport,
    finding: &Finding,
    advisory_index: usize,
    uri: &str,
) -> String {
    let material = format!(
        "v1\0{}\0{}\0{}\0{}\0{}",
        finding.rule_id,
        report.decision.as_str(),
        uri,
        advisory_index,
        finding.detail
    );
    format!("{:016x}", sarif::fnv1a64(material.as_bytes()))
}
