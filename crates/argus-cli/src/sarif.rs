//! Deterministic SARIF 2.1.0 rendering for completed scan reports.

use anyhow::{anyhow, Result};
use argus_core::{ArtifactKind, Finding, ScanReport, Severity};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFORMATION_URI: &str = "https://github.com/majiayu000/argus";
const RULE_HELP_URI: &str = "https://github.com/majiayu000/argus#rule-coverage-milestone-0";
const AGENT_RULE_HELP_URI: &str =
    "https://github.com/majiayu000/argus#agent-surface-rule-coverage-gh-57";

pub(crate) fn render_reports(reports: &[ScanReport]) -> Result<Value> {
    let rule_severities = collect_rule_severities(reports);
    let rule_indices: BTreeMap<&str, usize> = rule_severities
        .keys()
        .enumerate()
        .map(|(index, rule_id)| (rule_id.as_str(), index))
        .collect();
    let rules = rule_severities
        .iter()
        .map(|(rule_id, severity)| rule_descriptor(rule_id, *severity))
        .collect::<Vec<_>>();
    let mut results = Vec::new();
    for report in reports {
        for finding in &report.findings {
            let rule_index = rule_indices
                .get(finding.rule_id.as_str())
                .copied()
                .ok_or_else(|| anyhow!("SARIF rule index missing for `{}`", finding.rule_id))?;
            results.push(result(report, finding, rule_index));
        }
    }

    Ok(json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "argus",
                    "fullName": "argus supply-chain install guard",
                    "version": env!("CARGO_PKG_VERSION"),
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "informationUri": INFORMATION_URI,
                    "rules": rules
                }
            },
            "invocations": [{"executionSuccessful": true}],
            "results": results
        }]
    }))
}

fn collect_rule_severities(reports: &[ScanReport]) -> BTreeMap<String, Severity> {
    let mut rules = BTreeMap::new();
    for finding in reports.iter().flat_map(|report| &report.findings) {
        rules
            .entry(finding.rule_id.clone())
            .and_modify(|severity| {
                if severity_rank(finding.severity) > severity_rank(*severity) {
                    *severity = finding.severity;
                }
            })
            .or_insert(finding.severity);
    }
    rules
}

fn rule_descriptor(rule_id: &str, severity: Severity) -> Value {
    let help_uri = if rule_id.starts_with("AGT-")
        || matches!(
            rule_id,
            "capability-manifest"
                | "capability-misfit"
                | "agent-config-write"
                | "hook-persistence"
                | "injection-override"
                | "concealment"
                | "obfuscation"
        ) {
        AGENT_RULE_HELP_URI
    } else {
        RULE_HELP_URI
    };
    json!({
        "id": rule_id,
        "name": rule_name(rule_id),
        "shortDescription": {"text": format!("Argus finding: {rule_id}")},
        "help": {"text": format!("Argus rule `{rule_id}` reported this finding.")},
        "helpUri": help_uri,
        "defaultConfiguration": {"level": sarif_level(severity)}
    })
}

fn rule_name(rule_id: &str) -> String {
    rule_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn result(report: &ScanReport, finding: &Finding, rule_index: usize) -> Value {
    let (uri, line) = finding_location(report, finding);
    let mut physical_location = Map::new();
    physical_location.insert("artifactLocation".to_string(), json!({"uri": uri}));
    if let Some(start_line) = line {
        physical_location.insert("region".to_string(), json!({"startLine": start_line}));
    }

    json!({
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": sarif_level(finding.severity),
        "message": {"text": finding.detail},
        "locations": [{"physicalLocation": physical_location}],
        "partialFingerprints": {
            "argusFinding/v1": finding_fingerprint(report, finding, &uri, line)
        },
        "properties": result_properties(report, finding)
    })
}

fn result_properties(report: &ScanReport, finding: &Finding) -> Value {
    let mut properties = Map::new();
    properties.insert(
        "artifact_kind".to_string(),
        json!(artifact_kind(report.artifact)),
    );
    properties.insert("decision".to_string(), json!(report.decision.as_str()));
    properties.insert(
        "argus_severity".to_string(),
        json!(severity_name(finding.severity)),
    );
    if let Some(package_name) = report.package_name.as_deref() {
        properties.insert("package_name".to_string(), json!(package_name));
    }
    if let Some(package_version) = report.package_version.as_deref() {
        properties.insert("package_version".to_string(), json!(package_version));
    }
    if let Some(capability) = finding.capability.as_deref() {
        properties.insert("capability".to_string(), json!(capability));
    }
    if let Some(evidence) = finding.evidence.as_ref() {
        properties.insert("evidence".to_string(), json!(evidence));
    }
    if let Some(resolved_host) = finding.resolved_host.as_deref() {
        properties.insert("resolved_host".to_string(), json!(resolved_host));
    }
    Value::Object(properties)
}

fn finding_location(report: &ScanReport, finding: &Finding) -> (String, Option<u64>) {
    if let Some((path, line)) = finding
        .evidence
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find_map(|entry| parse_evidence_location(entry))
    {
        return (normalize_uri(&path), Some(line));
    }
    if let Some(location) = finding
        .location
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        return (normalize_uri(artifact_path(location)), None);
    }
    (normalize_uri(&report.path.to_string_lossy()), None)
}

fn artifact_path(location: &str) -> &str {
    location.strip_suffix(":scripts").unwrap_or(location)
}

fn parse_evidence_location(evidence: &str) -> Option<(String, u64)> {
    let (path, line) = evidence.rsplit_once(':')?;
    if path.is_empty() {
        return None;
    }
    let line = line.parse::<u64>().ok()?;
    (line > 0).then(|| (path.to_string(), line))
}

fn normalize_uri(path: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let normalized = path.replace('\\', "/");
    let mut uri = String::with_capacity(normalized.len());
    for byte in normalized.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[usize::from(byte >> 4)]));
            uri.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    uri
}

fn finding_fingerprint(
    report: &ScanReport,
    finding: &Finding,
    uri: &str,
    line: Option<u64>,
) -> String {
    let material = format!(
        "v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        finding.rule_id,
        artifact_kind(report.artifact),
        uri,
        line.map_or_else(String::new, |value| value.to_string()),
        report.package_name.as_deref().unwrap_or(""),
        report.package_version.as_deref().unwrap_or(""),
        finding.detail
    );
    format!("{:016x}", fnv1a64(material.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

fn artifact_kind(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::PackageDir => "package-dir",
        ArtifactKind::Lockfile => "lockfile",
        ArtifactKind::AgentSurface => "agent-surface",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::{Decision, Finding};
    use std::path::PathBuf;

    fn report(artifact: ArtifactKind, path: &str, findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            artifact,
            path: PathBuf::from(path),
            package_name: Some("demo".to_string()),
            package_version: Some("1.2.3".to_string()),
            decision: Decision::Block,
            findings,
        }
    }

    fn first_result(document: &Value) -> &Value {
        &document["runs"][0]["results"][0]
    }

    fn render(reports: &[ScanReport]) -> Value {
        render_reports(reports).expect("render SARIF test document")
    }

    #[test]
    fn package_snapshot_uses_artifact_location_without_fake_line() {
        let document = render(&[report(
            ArtifactKind::PackageDir,
            "fixtures/demo",
            vec![
                Finding::new("lifecycle-script", Severity::High, "postinstall").at("package.json"),
            ],
        )]);
        let result = first_result(&document);
        assert_eq!(document["$schema"], SARIF_SCHEMA);
        assert_eq!(document["version"], "2.1.0");
        assert_eq!(
            document["runs"][0]["tool"]["driver"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(result["ruleId"], "lifecycle-script");
        assert_eq!(result["level"], "error");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "package.json"
        );
        assert!(result["locations"][0]["physicalLocation"]
            .get("region")
            .is_none());
        assert_eq!(result["properties"]["package_name"], "demo");
    }

    #[test]
    fn semantic_package_location_maps_to_real_uri_encoded_artifact() {
        let document = render(&[report(
            ArtifactKind::PackageDir,
            "fixtures/demo",
            vec![Finding::new("remote-download", Severity::High, "curl").at("package.json:scripts")],
        )]);
        assert_eq!(
            first_result(&document)["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "package.json"
        );
        assert_eq!(
            normalize_uri("dir name/#frag?.js"),
            "dir%20name/%23frag%3F.js"
        );
        assert_eq!(normalize_uri("配置.json"), "%E9%85%8D%E7%BD%AE.json");
    }

    #[test]
    fn lockfile_snapshot_preserves_artifact_kind() {
        let document = render(&[report(
            ArtifactKind::Lockfile,
            "package-lock.json",
            vec![Finding::new(
                "lockfile-http-resolved",
                Severity::High,
                "plain HTTP resolved URL",
            )],
        )]);
        let result = first_result(&document);
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "package-lock.json"
        );
        assert!(result["locations"][0]["physicalLocation"]
            .get("region")
            .is_none());
        assert_eq!(result["properties"]["artifact_kind"], "lockfile");
    }

    #[test]
    fn agent_surface_snapshot_maps_evidence_line_and_capability() {
        let finding = Finding::new("capability-manifest", Severity::Medium, "network egress")
            .at("scripts/fetch.sh")
            .with_capability(
                "net_egress",
                vec!["scripts/fetch.sh:7".to_string()],
                Some("api.example.com".to_string()),
            );
        let document = render(&[report(ArtifactKind::AgentSurface, "skill", vec![finding])]);
        let result = first_result(&document);
        assert_eq!(result["level"], "warning");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "scripts/fetch.sh"
        );
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            7
        );
        assert_eq!(result["properties"]["capability"], "net_egress");
        assert_eq!(result["properties"]["resolved_host"], "api.example.com");
    }

    #[test]
    fn provenance_snapshot_uses_report_artifact_and_stable_rule() {
        let document = render(&[report(
            ArtifactKind::PackageDir,
            "downloads/demo.tgz",
            vec![Finding::new(
                "provenance-signature-invalid",
                Severity::High,
                "signature rejected",
            )],
        )]);
        let result = first_result(&document);
        assert_eq!(result["ruleId"], "provenance-signature-invalid");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "downloads/demo.tgz"
        );
        assert!(result["locations"][0]["physicalLocation"]
            .get("region")
            .is_none());
    }

    #[test]
    fn same_location_multiple_rules_keep_distinct_ids_and_fingerprints() {
        let document = render(&[report(
            ArtifactKind::PackageDir,
            "fixture",
            vec![
                Finding::new("remote-download", Severity::High, "curl").at("install.js"),
                Finding::new("shell-pipe-execution", Severity::High, "pipe").at("install.js"),
            ],
        )]);
        let results = document["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_ne!(results[0]["ruleId"], results[1]["ruleId"]);
        assert_ne!(
            results[0]["partialFingerprints"]["argusFinding/v1"],
            results[1]["partialFingerprints"]["argusFinding/v1"]
        );
    }

    #[test]
    fn clean_report_is_a_successful_empty_run() {
        let mut clean = report(ArtifactKind::PackageDir, "clean", Vec::new());
        clean.decision = Decision::Allow;
        let document = render(&[clean]);
        assert_eq!(
            document["runs"][0]["invocations"][0]["executionSuccessful"],
            json!(true)
        );
        assert_eq!(document["runs"][0]["tool"]["driver"]["rules"], json!([]));
        assert_eq!(document["runs"][0]["results"], json!([]));
    }

    #[test]
    fn fingerprint_is_repeatable() {
        let input = report(
            ArtifactKind::PackageDir,
            "fixture",
            vec![Finding::new("remote-download", Severity::High, "curl").at("index.js")],
        );
        assert_eq!(render(std::slice::from_ref(&input)), render(&[input]));
    }

    #[test]
    fn evidence_parser_rejects_missing_or_zero_line() {
        assert_eq!(
            parse_evidence_location("file.rs:12"),
            Some(("file.rs".to_string(), 12))
        );
        assert_eq!(parse_evidence_location("file.rs:0"), None);
        assert_eq!(parse_evidence_location("audit evidence"), None);
    }
}
