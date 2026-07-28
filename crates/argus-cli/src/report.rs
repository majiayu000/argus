//! Generic text, JSON, and SARIF report output.

use crate::{intel, sarif, Format};
use anyhow::Result;
use argus_core::{Decision, RuleExecutionMetadata, ScanReport};
use std::process::ExitCode;

/// Exit codes are part of the CLI contract.
///
/// - `0` — `allow` (clean)
/// - `1` — `block`
/// - `2` — `allow-with-approval`
pub(crate) fn emit_report(report: &ScanReport, format: Format) -> Result<ExitCode> {
    match format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        Format::Sarif => println!(
            "{}",
            serde_json::to_string_pretty(&sarif::render_reports(std::slice::from_ref(report))?)?
        ),
        Format::Text => print_report_text(report),
    }
    let code = match report.decision {
        Decision::Allow => 0,
        Decision::Block => 1,
        Decision::AllowWithApproval => 2,
    };
    Ok(ExitCode::from(code))
}

pub(crate) fn print_report_text(report: &ScanReport) {
    print!("{}", render_report_text(report));
}

pub(crate) fn render_report_text(report: &ScanReport) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(
        output,
        "decision: {}  package: {}",
        report.decision.as_str(),
        report.package_name.as_deref().unwrap_or("<unnamed>"),
    )
    .expect("writing a report to String cannot fail");
    writeln!(output, "path: {}", report.path.display())
        .expect("writing a report to String cannot fail");
    if let Some(status) = &report.intelligence {
        output.push_str(&intel::render_status_text(status));
    }
    if let Some(rules) = &report.rules {
        output.push_str(&render_rules_text(rules));
    }
    if report.findings.is_empty() {
        writeln!(output, "findings: none").expect("writing a report to String cannot fail");
        return output;
    }
    writeln!(output, "findings:").expect("writing a report to String cannot fail");
    for finding in &report.findings {
        let location = finding.location.as_deref().unwrap_or("");
        writeln!(
            output,
            "  - [{}] {} — {} ({})",
            severity_tag(finding),
            finding.rule_id,
            finding.detail,
            location
        )
        .expect("writing a report to String cannot fail");
        if let Some(evidence) = finding.evidence.as_ref() {
            writeln!(output, "    evidence: {}", evidence.join(", "))
                .expect("writing a report to String cannot fail");
        }
    }
    output
}

pub(crate) fn render_rules_text(rules: &RuleExecutionMetadata) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(output, "rules_digest: {}", rules.digest).expect("write String");
    writeln!(
        output,
        "rules_external: count={} files={}",
        rules.external_rule_count,
        display_values(&rules.loaded_external_files)
    )
    .expect("write String");
    writeln!(
        output,
        "rules_disabled: {}",
        display_values(&rules.disabled_rule_ids)
    )
    .expect("write String");
    writeln!(
        output,
        "rules_overrides: {}",
        display_values(&rules.applied_overrides)
    )
    .expect("write String");
    output
}

fn display_values(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

fn severity_tag(finding: &argus_core::Finding) -> &'static str {
    match finding.severity {
        argus_core::Severity::Critical => "CRIT",
        argus_core::Severity::High => "HIGH",
        argus_core::Severity::Medium => "MED ",
        argus_core::Severity::Low => "LOW ",
        argus_core::Severity::Info => "INFO",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::{ArtifactKind, Finding, RuleExecutionMetadata, Severity};
    use std::path::PathBuf;

    fn anomaly_report() -> ScanReport {
        let mut finding = Finding::new(
            "version-shape-anomaly",
            Severity::Medium,
            "policy=npm-anomaly-v1; target=3.0.0@2025-02-21T00:00:00Z",
        );
        finding.evidence = Some(vec![
            "policy=npm-anomaly-v1".to_string(),
            "target_version=3.0.0".to_string(),
        ]);
        ScanReport {
            artifact: ArtifactKind::PackageDir,
            path: PathBuf::from("@scope/demo@3.0.0"),
            package_name: Some("@scope/demo".to_string()),
            package_version: Some("3.0.0".to_string()),
            decision: Decision::AllowWithApproval,
            findings: vec![finding],
            coordinate: None,
            intelligence: None,
            rules: None,
        }
    }

    #[test]
    fn npm_anomaly_render_preserves_text_json_and_sarif_evidence() {
        let report = anomaly_report();
        let text = render_report_text(&report);
        assert!(text.contains("version-shape-anomaly"));
        assert!(text.contains("evidence: policy=npm-anomaly-v1"));

        let json = serde_json::to_value(&report).expect("serialize anomaly report");
        assert_eq!(json["findings"][0]["evidence"][1], "target_version=3.0.0");

        let sarif = sarif::render_reports(&[report]).expect("render anomaly SARIF");
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["evidence"][0],
            "policy=npm-anomaly-v1"
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["decision"],
            "allow-with-approval"
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "%40scope/demo%403.0.0"
        );
    }

    #[test]
    fn clean_text_report_keeps_rule_audit_metadata() {
        let mut report = anomaly_report();
        report.decision = Decision::Allow;
        report.findings.clear();
        report.rules = Some(RuleExecutionMetadata {
            digest: "a".repeat(64),
            loaded_external_files: vec!["rules.yaml".to_string()],
            external_rule_count: 1,
            disabled_rule_ids: vec!["external-demo".to_string()],
            applied_overrides: vec!["external-demo=off".to_string()],
            external_rules: Vec::new(),
        });
        let text = render_report_text(&report);
        assert!(text.contains(&format!("rules_digest: {}", "a".repeat(64))));
        assert!(text.contains("rules_external: count=1 files=rules.yaml"));
        assert!(text.contains("rules_disabled: external-demo"));
        assert!(text.contains("rules_overrides: external-demo=off"));
        assert!(text.contains("findings: none"));
    }
}
