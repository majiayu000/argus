//! Explicit, bounded OSV package and lockfile query commands.

use crate::router::{VulnsCommonArgs, VulnsOp};
use crate::sarif_vulns;
use anyhow::{bail, Context, Result};
use argus_core::{Decision, PackageCoordinate};
use argus_lockfile::FormatHint;
use argus_osv::cache::SecureCache;
use argus_osv::client::HttpsOsvTransport;
use argus_osv::report::{OsvReportBuilder, ReportBuilder, VulnerabilityReport};
use argus_osv::resolver::{AdvisoryResolver, OsvResolver, ResolveRequest};
use argus_osv::severity::SeveritySource;
use argus_osv::{collect_lockfile_coordinates, CoordinateQuery, CoordinateSet};
use argus_rules::RuleSession;
use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const CACHE_LABEL: &str = "<argus-osv-cache>";

pub(crate) fn cmd_vulns(op: VulnsOp) -> Result<ExitCode> {
    match op {
        VulnsOp::Package {
            ecosystem,
            name,
            version,
            common,
        } => {
            validate_vulnerability_overrides(&common.rule_override)?;
            let rules = RuleSession::load_typed(None, common.rule_override.clone())
                .context("load effective rules")?;
            let coordinate = PackageCoordinate::new(ecosystem.into(), name, version)
                .context("validate exact package coordinate")?;
            let query = CoordinateQuery::new(coordinate, std::iter::empty())
                .context("validate OSV package coordinate")?;
            resolve_and_emit(CoordinateSet::new(vec![query], 0)?, common, &rules)
        }
        VulnsOp::Lockfile {
            path,
            lockfile_format,
            common,
        } => {
            validate_vulnerability_overrides(&common.rule_override)?;
            let rules = RuleSession::load_typed(None, common.rule_override.clone())
                .context("load effective rules")?;
            let parsed =
                crate::read_and_parse_lockfile(&path, lockfile_format.map(FormatHint::from))?;
            resolve_and_emit(
                collect_lockfile_coordinates(&parsed.records)
                    .context("normalize lockfile OSV coordinates")?,
                common,
                &rules,
            )
        }
    }
}

fn validate_vulnerability_overrides(overrides: &[argus_core::rules::RuleOverride]) -> Result<()> {
    for rule_override in overrides {
        if !matches!(
            rule_override.id.as_str(),
            "known-vulnerability" | "vulnerability-data-stale"
        ) {
            bail!(
                "standalone vulnerability queries accept overrides only for \
                 `known-vulnerability` and `vulnerability-data-stale`"
            );
        }
    }
    Ok(())
}

fn resolve_and_emit(
    coordinates: CoordinateSet,
    common: VulnsCommonArgs,
    rules: &RuleSession,
) -> Result<ExitCode> {
    let snapshot = resolve_snapshot(
        &coordinates,
        &common.cache_dir,
        common.offline,
        common.allow_stale,
        common.max_age_seconds,
    )?;
    let mut report = OsvReportBuilder::new(common.fail_on_severity.map(Into::into))?
        .build(&snapshot)
        .context("build complete vulnerability report")?;
    normalize_vulnerability_report(&mut report, rules);
    emit_report(&report, common.format)
}

/// Shared resolution core used by the standalone `vulns` commands and the
/// `--osv` flag on scan/fetch commands (#136).
fn resolve_snapshot(
    coordinates: &CoordinateSet,
    cache_dir: &Path,
    offline: bool,
    allow_stale: bool,
    max_age_seconds: u64,
) -> Result<argus_osv::resolver::ResolvedSnapshot> {
    let trusted_root = trusted_cache_root(cache_dir)?;
    let cache = SecureCache::new(trusted_root);
    let now = Utc::now();
    if offline
        && cache
            .load_at(cache_dir, now)
            .context("validate offline OSV cache")?
            .is_none()
    {
        bail!("offline cache snapshot is missing");
    }
    let resolver = OsvResolver::new(cache, cache_dir);
    let transport = (!offline).then(HttpsOsvTransport::new);
    resolver
        .resolve(
            ResolveRequest {
                coordinates,
                offline,
                allow_stale,
                max_age_seconds,
                now,
            },
            transport
                .as_ref()
                .map(|value| value as &dyn argus_osv::client::OsvTransport),
        )
        .context("resolve complete OSV vulnerability snapshot")
}

/// OSV lookup flags flattened into `scan` and every fetch subcommand,
/// mirroring `ScanIntelArgs`: opt-in, cache-dir required, folded into the
/// report's findings and decision before emission.
#[derive(clap::Args, Debug)]
pub(crate) struct ScanVulnsArgs {
    /// Also query OSV for known vulnerabilities of the resolved package
    /// coordinate and fold the results into the decision.
    #[arg(long = "osv", requires = "osv_cache_dir")]
    pub(crate) osv: bool,
    /// Secure OSV cache directory (required with --osv).
    #[arg(long = "osv-cache-dir", value_name = "DIR")]
    pub(crate) osv_cache_dir: Option<std::path::PathBuf>,
    /// With --osv: disable network access; require a complete cache snapshot.
    #[arg(long = "osv-offline", requires = "osv")]
    pub(crate) osv_offline: bool,
    /// With --osv-offline: authorize complete stale cache data.
    #[arg(long = "osv-allow-stale", requires = "osv_offline")]
    pub(crate) osv_allow_stale: bool,
    /// With --osv: maximum fresh-cache age in seconds.
    #[arg(
        long = "osv-max-age-seconds",
        default_value_t = 86_400,
        value_parser = clap::value_parser!(u64).range(0..=2_592_000)
    )]
    pub(crate) osv_max_age_seconds: u64,
    /// With --osv: block when an active advisory meets or exceeds this
    /// normalized severity.
    #[arg(long = "osv-fail-on-severity", value_enum, requires = "osv")]
    pub(crate) osv_fail_on_severity: Option<crate::router::VulnsSeverity>,
}

/// Fold OSV advisory findings for the report's resolved coordinate into the
/// scan report. The advisory sub-decision keeps the standalone `vulns`
/// threshold semantics (advisories alone require approval; meeting
/// --osv-fail-on-severity blocks) and the final decision is the stricter of
/// the scan decision and the advisory decision.
pub(crate) fn apply_osv_query(
    report: &mut argus_core::ScanReport,
    args: &ScanVulnsArgs,
    rules: &RuleSession,
) -> Result<()> {
    if !args.osv {
        return Ok(());
    }
    let cache_dir = args
        .osv_cache_dir
        .as_deref()
        .expect("clap enforces --osv-cache-dir with --osv");
    let Some(coordinate) = report.coordinate.clone() else {
        bail!(
            "--osv requires a trusted resolved package coordinate; this scan did not produce one              (use a fetch command, or query lockfiles via `argus vulns lockfile`)"
        );
    };
    coordinate
        .validate()
        .context("revalidate scanned package coordinate before OSV query")?;
    let query = CoordinateQuery::new(coordinate, std::iter::empty())
        .context("validate OSV package coordinate")?;
    let coordinates = CoordinateSet::new(vec![query], 0)?;
    let snapshot = resolve_snapshot(
        &coordinates,
        cache_dir,
        args.osv_offline,
        args.osv_allow_stale,
        args.osv_max_age_seconds,
    )?;
    let mut vulnerability = OsvReportBuilder::new(args.osv_fail_on_severity.map(Into::into))?
        .build(&snapshot)
        .context("build vulnerability report for scanned coordinate")?;
    normalize_vulnerability_report(&mut vulnerability, rules);
    report.findings.extend(vulnerability.findings);
    report.decision = stricter(report.decision, vulnerability.decision);
    Ok(())
}

fn normalize_vulnerability_report(report: &mut VulnerabilityReport, rules: &RuleSession) {
    let threshold_decision = report.decision;
    rules.normalize_findings(&mut report.findings);
    report.decision = if report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "known-vulnerability")
    {
        threshold_decision
    } else if report.findings.is_empty() {
        Decision::Allow
    } else {
        Decision::AllowWithApproval
    };
    report.rules = rules.metadata().cloned();
}

fn stricter(left: Decision, right: Decision) -> Decision {
    fn rank(decision: Decision) -> u8 {
        match decision {
            Decision::Block => 2,
            Decision::AllowWithApproval => 1,
            Decision::Allow => 0,
        }
    }
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
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

fn emit_report(report: &VulnerabilityReport, format: crate::Format) -> Result<ExitCode> {
    match format {
        crate::Format::Text => print!("{}", render_text(report)?),
        crate::Format::Json => println!("{}", serde_json::to_string_pretty(&json_report(report)?)?),
        crate::Format::Sarif => println!(
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
    if let Some(rules) = &report.rules {
        output.push_str(&crate::report::render_rules_text(rules));
    }
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
        if advisory_index != 0 && advisory_index != report.advisories.len() {
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

#[cfg(test)]
mod scan_vulns_tests {
    use super::*;
    use argus_core::{ArtifactKind, ScanReport};

    fn args(osv: bool) -> ScanVulnsArgs {
        ScanVulnsArgs {
            osv,
            osv_cache_dir: osv.then(|| std::path::PathBuf::from("/tmp/does-not-matter")),
            osv_offline: false,
            osv_allow_stale: false,
            osv_max_age_seconds: 86_400,
            osv_fail_on_severity: None,
        }
    }

    fn report() -> ScanReport {
        ScanReport {
            artifact: ArtifactKind::PackageDir,
            path: "demo@1.0.0".into(),
            package_name: Some("demo".into()),
            package_version: Some("1.0.0".into()),
            decision: Decision::Allow,
            findings: Vec::new(),
            coordinate: None,
            intelligence: None,
            rules: None,
        }
    }

    #[test]
    fn without_osv_flag_is_a_no_op() {
        let mut r = report();
        let rules = RuleSession::builtin().unwrap();
        apply_osv_query(&mut r, &args(false), &rules).unwrap();
        assert!(r.findings.is_empty());
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn osv_without_resolved_coordinate_fails_closed() {
        let mut r = report();
        let rules = RuleSession::builtin().unwrap();
        let err = apply_osv_query(&mut r, &args(true), &rules).unwrap_err();
        assert!(
            format!("{err:#}").contains("trusted resolved package coordinate"),
            "got: {err:#}"
        );
    }

    #[test]
    fn stricter_takes_the_worse_decision() {
        use Decision::{Allow, AllowWithApproval, Block};
        assert_eq!(stricter(Allow, Block), Block);
        assert_eq!(stricter(Block, Allow), Block);
        assert_eq!(stricter(Allow, AllowWithApproval), AllowWithApproval);
        assert_eq!(
            stricter(AllowWithApproval, AllowWithApproval),
            AllowWithApproval
        );
        assert_eq!(stricter(Allow, Allow), Allow);
    }
}
