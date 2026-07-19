//! Explicit, bounded OSV package and lockfile query commands.

use crate::router::{VulnsCommonArgs, VulnsFormat, VulnsOp};
use crate::sarif_vulns;
use anyhow::{bail, Context, Result};
use argus_core::{Decision, PackageCoordinate};
use argus_lockfile::{
    parse_lockfile, BoundedInput, DetectionRequest, FormatHint, ParseOutput, MAX_INPUT_BYTES,
};
use argus_osv::cache::SecureCache;
use argus_osv::client::HttpsOsvTransport;
use argus_osv::report::{OsvReportBuilder, ReportBuilder, VulnerabilityReport};
use argus_osv::resolver::{AdvisoryResolver, OsvResolver, ResolveRequest};
use argus_osv::severity::SeveritySource;
use argus_osv::{collect_lockfile_coordinates, CoordinateQuery, CoordinateSet};
use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const CACHE_LABEL: &str = "<argus-osv-cache>";

pub(crate) fn cmd_vulns(op: VulnsOp) -> Result<ExitCode> {
    let (coordinates, common) = match op {
        VulnsOp::Package {
            ecosystem,
            name,
            version,
            common,
        } => {
            let coordinate = PackageCoordinate::new(ecosystem.into(), name, version)
                .context("validate exact package coordinate")?;
            let query = CoordinateQuery::new(coordinate, std::iter::empty())
                .context("validate OSV package coordinate")?;
            (CoordinateSet::new(vec![query], 0)?, common)
        }
        VulnsOp::Lockfile {
            path,
            lockfile_format,
            common,
        } => {
            let parsed = parse_lockfile_path(&path, lockfile_format.map(FormatHint::from))?;
            (
                collect_lockfile_coordinates(&parsed.records)
                    .context("normalize lockfile OSV coordinates")?,
                common,
            )
        }
    };
    resolve_and_emit(coordinates, common)
}

fn resolve_and_emit(coordinates: CoordinateSet, common: VulnsCommonArgs) -> Result<ExitCode> {
    let trusted_root = trusted_cache_root(&common.cache_dir)?;
    let cache = SecureCache::new(trusted_root);
    let now = Utc::now();
    if common.offline
        && cache
            .load_at(&common.cache_dir, now)
            .context("validate offline OSV cache")?
            .is_none()
    {
        bail!("offline cache snapshot is missing");
    }
    let resolver = OsvResolver::new(cache, &common.cache_dir);
    let transport = (!common.offline).then(HttpsOsvTransport::new);
    let snapshot = resolver
        .resolve(
            ResolveRequest {
                coordinates: &coordinates,
                offline: common.offline,
                allow_stale: common.allow_stale,
                max_age_seconds: common.max_age_seconds,
                now,
            },
            transport
                .as_ref()
                .map(|value| value as &dyn argus_osv::client::OsvTransport),
        )
        .context("resolve complete OSV vulnerability snapshot")?;
    let report = OsvReportBuilder::new(common.fail_on_severity.map(Into::into))?
        .build(&snapshot)
        .context("build complete vulnerability report")?;
    emit_report(&report, common.format)
}

fn trusted_cache_root(cache_dir: &Path) -> Result<PathBuf> {
    if cache_dir.is_absolute() {
        return cache_dir
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow::anyhow!("cache directory must have a trusted parent"));
    }
    std::env::current_dir().context("open trusted cache root")
}

fn parse_lockfile_path(path: &Path, explicit_format: Option<FormatHint>) -> Result<ParseOutput> {
    if !path.is_file() {
        bail!("lockfile path is not a file: {}", path.display());
    }
    let file =
        std::fs::File::open(path).with_context(|| format!("open lockfile {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((MAX_INPUT_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read lockfile {}", path.display()))?;
    let path_label = path.to_string_lossy();
    let input = BoundedInput::new(&bytes, &path_label)
        .with_context(|| format!("bound lockfile {}", path.display()))?;
    let basename = path.file_name().and_then(|name| name.to_str());
    if basename.is_none() && explicit_format.is_none() {
        bail!(
            "lockfile basename is not UTF-8; pass --lockfile-format for {}",
            path.display()
        );
    }
    parse_lockfile(
        &input,
        DetectionRequest {
            basename,
            explicit_format,
        },
    )
    .with_context(|| format!("parse lockfile {}", path.display()))
}

fn emit_report(report: &VulnerabilityReport, format: VulnsFormat) -> Result<ExitCode> {
    match format {
        VulnsFormat::Text => print!("{}", render_text(report)?),
        VulnsFormat::Json => println!("{}", serde_json::to_string_pretty(&json_report(report)?)?),
        VulnsFormat::Sarif => println!(
            "{}",
            serde_json::to_string_pretty(&sarif_vulns::render_report(report, CACHE_LABEL)?)?
        ),
    }
    Ok(ExitCode::from(match report.decision {
        Decision::Allow => 0,
        Decision::Block => 1,
        Decision::AllowWithApproval => 2,
    }))
}

fn json_report(report: &VulnerabilityReport) -> Result<Value> {
    let mut value = serde_json::to_value(report).context("serialize vulnerability report")?;
    value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("vulnerability report did not serialize as an object"))?
        .insert("cache_label".to_string(), json!(CACHE_LABEL));
    Ok(value)
}

fn render_text(report: &VulnerabilityReport) -> Result<String> {
    let evidence = &report.evidence;
    let mut output = String::new();
    writeln!(output, "decision: {}", report.decision.as_str()).expect("write String");
    writeln!(output, "status: {}", status_name(evidence.status)).expect("write String");
    writeln!(
        output,
        "source_mode: {}",
        source_mode_name(evidence.source_mode)
    )
    .expect("write String");
    writeln!(output, "cache: {CACHE_LABEL}").expect("write String");
    writeln!(
        output,
        "coordinates: queried={} excluded_local={}",
        evidence.queried_coordinates, evidence.excluded_local_records
    )
    .expect("write String");
    writeln!(
        output,
        "advisories: active={} oldest_fetched_at={} newest_fetched_at={} maximum_age_seconds={}",
        evidence.active_advisories,
        evidence.oldest_fetched_at.to_rfc3339(),
        evidence.newest_fetched_at.to_rfc3339(),
        evidence.maximum_age_seconds
    )
    .expect("write String");
    if report.findings.is_empty() {
        writeln!(output, "findings: none").expect("write String");
    } else {
        writeln!(output, "findings:").expect("write String");
        let mut advisory_index = 0usize;
        for finding in &report.findings {
            writeln!(
                output,
                "  - [{}] {} — {}",
                severity_name(finding.severity),
                finding.rule_id,
                finding.detail
            )
            .expect("write String");
            if finding.rule_id == "known-vulnerability" {
                let advisory = report.advisories.get(advisory_index).ok_or_else(|| {
                    anyhow::anyhow!("known-vulnerability finding has no matching advisory evidence")
                })?;
                advisory_index += 1;
                render_advisory_text(&mut output, advisory)?;
            } else if let Some(locators) = &finding.evidence {
                writeln!(output, "    locators: {}", locators.join(", ")).expect("write String");
            }
        }
        if advisory_index != report.advisories.len() {
            bail!("vulnerability advisories do not match rendered findings");
        }
    }
    Ok(output)
}

fn render_advisory_text(
    output: &mut String,
    advisory: &argus_osv::NormalizedAdvisory,
) -> Result<()> {
    writeln!(
        output,
        "    coordinate: ecosystem={} name={} version={} purl={}",
        advisory.coordinate.ecosystem.osv_name(),
        advisory.coordinate.canonical_name,
        advisory.coordinate.version,
        advisory.coordinate.purl
    )
    .expect("write String");
    writeln!(output, "    primary_id: {}", advisory.primary_id).expect("write String");
    writeln!(output, "    aliases: {}", display_values(&advisory.aliases)).expect("write String");
    writeln!(
        output,
        "    locators: {}",
        display_values(&advisory.evidence.locators)
    )
    .expect("write String");
    if advisory.evidence.affected.is_empty() {
        writeln!(output, "    matched_ranges: none").expect("write String");
    } else {
        writeln!(output, "    matched_ranges:").expect("write String");
        for affected in &advisory.evidence.affected {
            writeln!(
                output,
                "      - {}",
                serde_json::to_string(affected).context("serialize matched affected evidence")?
            )
            .expect("write String");
        }
    }
    writeln!(
        output,
        "    normalized_severity: {} base_score={}",
        severity_level_name(advisory.severity.level),
        advisory.severity.base_score.as_deref().unwrap_or("none")
    )
    .expect("write String");
    if advisory.severity.evidence.is_empty() {
        writeln!(output, "    raw_severity: none").expect("write String");
    } else {
        writeln!(output, "    raw_severity:").expect("write String");
        for severity in &advisory.severity.evidence {
            writeln!(
                output,
                "      - type={} score={} source={}",
                severity.severity_type,
                severity.score,
                severity.source.map(severity_source_name).unwrap_or("none")
            )
            .expect("write String");
        }
    }
    writeln!(
        output,
        "    database_modified: {}",
        advisory
            .database_modified
            .to_rfc3339_opts(SecondsFormat::AutoSi, true)
    )
    .expect("write String");
    writeln!(
        output,
        "    batch_summary_modified: {}",
        advisory.batch_summary_modified
    )
    .expect("write String");
    writeln!(output, "    detail_modified: {}", advisory.detail_modified).expect("write String");
    writeln!(output, "    source_url: {}", advisory.source_url).expect("write String");
    Ok(())
}

fn display_values(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

fn severity_name(severity: argus_core::Severity) -> &'static str {
    match severity {
        argus_core::Severity::Critical => "CRIT",
        argus_core::Severity::High => "HIGH",
        argus_core::Severity::Medium => "MED ",
        argus_core::Severity::Low => "LOW ",
        argus_core::Severity::Info => "INFO",
    }
}

fn status_name(status: argus_core::VulnerabilityQueryStatus) -> &'static str {
    match status {
        argus_core::VulnerabilityQueryStatus::CompleteNoMatch => "complete_no_match",
        argus_core::VulnerabilityQueryStatus::CompleteWithFindings => "complete_with_findings",
        argus_core::VulnerabilityQueryStatus::CompleteStale => "complete_stale",
    }
}

fn source_mode_name(mode: argus_core::VulnerabilitySourceMode) -> &'static str {
    match mode {
        argus_core::VulnerabilitySourceMode::Network => "network",
        argus_core::VulnerabilitySourceMode::Cache => "cache",
        argus_core::VulnerabilitySourceMode::Mixed => "mixed",
        argus_core::VulnerabilitySourceMode::OfflineFresh => "offline_fresh",
        argus_core::VulnerabilitySourceMode::OfflineStale => "offline_stale",
    }
}

fn severity_level_name(level: argus_osv::severity::SeverityLevel) -> &'static str {
    match level {
        argus_osv::severity::SeverityLevel::Unknown => "unknown",
        argus_osv::severity::SeverityLevel::None => "none",
        argus_osv::severity::SeverityLevel::Low => "low",
        argus_osv::severity::SeverityLevel::Medium => "medium",
        argus_osv::severity::SeverityLevel::High => "high",
        argus_osv::severity::SeverityLevel::Critical => "critical",
    }
}

fn severity_source_name(source: SeveritySource) -> &'static str {
    match source {
        SeveritySource::Nvd => "NVD",
        SeveritySource::Cna => "CNA",
        SeveritySource::SelfReported => "SELF",
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn vulns_help_contract_is_exposed() {
        use clap::CommandFactory as _;
        let command = crate::Cli::command();
        let vulns = command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == "vulns")
            .expect("vulns subcommand");
        assert!(vulns
            .get_subcommands()
            .any(|subcommand| subcommand.get_name() == "package"));
        assert!(vulns
            .get_subcommands()
            .any(|subcommand| subcommand.get_name() == "lockfile"));
        let parsed = crate::Cli::try_parse_from([
            "argus",
            "vulns",
            "package",
            "--ecosystem",
            "npm",
            "--name",
            "demo",
            "--version",
            "1.0.0",
            "--cache-dir",
            "cache",
        ]);
        assert!(parsed.is_ok());
    }
}
