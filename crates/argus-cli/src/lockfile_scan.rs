//! `argus lockfile-scan`: fetch and statically scan every dependency a
//! lockfile resolves (GH-144).
//!
//! The single-package commands (`fetch`, `pypi-fetch`, …) answer "is this one
//! package safe". The CI question is "is anything in this dependency tree
//! unsafe", and until now no path answered it: the lockfile path only checked
//! integrity and queried OSV, never fetching the resolved artifacts.
//!
//! This command walks the deterministic scan targets from
//! `argus_lockfile::build_scan_targets`, dispatches each registry-fetchable
//! coordinate to its ecosystem's [`EcosystemFetcher`], and aggregates the
//! per-package reports into one decision and exit code.
//!
//! Targets the lockfile could not resolve to a fetchable coordinate are
//! **reported, not dropped**. A dependency that was skipped is unscanned
//! surface, and a summary that omitted it would present partial coverage as a
//! clean tree.

use anyhow::{Context, Result};
use argus_core::{Decision, Ecosystem, ExecutionContext, Finding, ScanReport, Severity};
use argus_lockfile::FormatHint;
use argus_lockfile::{LockfileScanTarget, LockfileScanTargetChange, LockfileScanTargetKind};
use argus_pipeline::{CommonFetchOptions, EcosystemFetcher};
use argus_rules::RuleSession;
use argus_transport::Transport;
use chrono::Utc;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Why a resolved dependency never reached a scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SkipReason {
    /// The lockfile points at a path/workspace member, not a registry artifact.
    LocalDependency,
    /// The entry's source shape is not a supported registry coordinate.
    UnsupportedSource,
    /// The lockfile carries conflicting resolutions for the same name.
    ConflictingResolution,
    /// The coordinate is registry-fetchable but argus has no fetcher for that
    /// ecosystem yet.
    NoFetcherForEcosystem,
    /// The target is registry-fetchable but carries no complete coordinate.
    IncompleteCoordinate,
}

impl SkipReason {
    fn describe(self) -> &'static str {
        match self {
            Self::LocalDependency => "local/path dependency, not a registry artifact",
            Self::UnsupportedSource => "source shape is not a supported registry coordinate",
            Self::ConflictingResolution => "lockfile carries conflicting resolutions",
            Self::NoFetcherForEcosystem => "no argus fetcher for this ecosystem",
            Self::IncompleteCoordinate => "target carries no complete name@version coordinate",
        }
    }
}

/// One dependency that was not scanned, retained so coverage stays visible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SkippedTarget {
    pub(crate) locator: String,
    pub(crate) ecosystem: Option<Ecosystem>,
    pub(crate) reason: SkipReason,
    pub(crate) detail: String,
}

/// One dependency whose fetch or scan failed.
///
/// A failure is not an absence of findings: the package is unassessed, so the
/// aggregate decision must not read as clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FailedTarget {
    pub(crate) locator: String,
    pub(crate) ecosystem: Ecosystem,
    pub(crate) error: String,
}

/// A base artifact that could not supply evidence for a required version
/// comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ComparisonFailure {
    pub(crate) base_locator: String,
    pub(crate) current_locator: String,
    pub(crate) ecosystem: Option<Ecosystem>,
    pub(crate) error: String,
}

/// One side of an assessed base/current package change.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct VersionEndpoint {
    pub(crate) purl: String,
    pub(crate) decision: Decision,
}

/// Static finding changes between two successfully assessed package versions.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct VersionChangeAssessment {
    pub(crate) base: VersionEndpoint,
    pub(crate) current: VersionEndpoint,
    pub(crate) introduced: Vec<Finding>,
    pub(crate) resolved: Vec<Finding>,
}

/// Aggregate result over every dependency a lockfile resolves.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LockfileScanOutcome {
    pub(crate) lockfile: PathBuf,
    /// Worst decision across every scanned package, escalated to `block` when
    /// any package failed to be assessed.
    pub(crate) decision: Decision,
    pub(crate) targets_total: usize,
    pub(crate) scanned: usize,
    pub(crate) reports: Vec<ScanReport>,
    pub(crate) skipped: Vec<SkippedTarget>,
    pub(crate) failed: Vec<FailedTarget>,
    /// Number of changed coordinates that require a base/current assessment.
    pub(crate) comparisons_total: usize,
    pub(crate) version_changes: Vec<VersionChangeAssessment>,
    pub(crate) comparison_failed: Vec<ComparisonFailure>,
}

impl LockfileScanOutcome {
    /// Derive the aggregate decision.
    ///
    /// Fetch/scan failures escalate to `block` rather than being folded into
    /// the scanned packages' decisions: an unassessed dependency is missing
    /// evidence, and reporting it as `allow` would be a silent downgrade.
    fn derive(lockfile: PathBuf, parts: Parts) -> Self {
        let Parts {
            targets_total,
            reports,
            skipped,
            failed,
            comparisons_total,
            version_changes,
            comparison_failed,
        } = parts;
        let mut outcome = Self {
            lockfile,
            decision: Decision::Allow,
            targets_total,
            scanned: reports.len(),
            reports,
            skipped,
            failed,
            comparisons_total,
            version_changes,
            comparison_failed,
        };
        outcome.refresh_decision();
        outcome
    }

    fn refresh_decision(&mut self) {
        self.decision = if self.failed.is_empty() && self.comparison_failed.is_empty() {
            self.reports
                .iter()
                .map(|report| report.decision)
                .fold(Decision::Allow, worst_decision)
        } else {
            Decision::Block
        };
    }
}

struct Parts {
    targets_total: usize,
    reports: Vec<ScanReport>,
    skipped: Vec<SkippedTarget>,
    failed: Vec<FailedTarget>,
    comparisons_total: usize,
    version_changes: Vec<VersionChangeAssessment>,
    comparison_failed: Vec<ComparisonFailure>,
}

fn worst_decision(left: Decision, right: Decision) -> Decision {
    fn rank(decision: Decision) -> u8 {
        match decision {
            Decision::Allow => 0,
            Decision::AllowWithApproval => 1,
            Decision::Block => 2,
        }
    }
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
}

/// A target resolved to a concrete fetch job.
struct FetchJob {
    locator: String,
    ecosystem: Ecosystem,
    spec: String,
}

/// Classify every target into a fetch job or an explicit skip.
fn plan(targets: &[LockfileScanTarget]) -> (Vec<FetchJob>, Vec<SkippedTarget>) {
    let mut jobs = Vec::new();
    let mut skipped = Vec::new();
    for target in targets {
        let locator = scan_locator(target);
        let reason = match target.kind {
            LockfileScanTargetKind::LocalExcluded => Some(SkipReason::LocalDependency),
            LockfileScanTargetKind::Unsupported => Some(SkipReason::UnsupportedSource),
            LockfileScanTargetKind::Conflicting => Some(SkipReason::ConflictingResolution),
            LockfileScanTargetKind::RegistryFetchable => None,
        };
        if let Some(reason) = reason {
            skipped.push(SkippedTarget {
                locator,
                ecosystem: target.ecosystem,
                reason,
                detail: reason.describe().to_string(),
            });
            continue;
        }

        let (Some(ecosystem), Some(name), Some(version)) = (
            target.ecosystem,
            target.name.as_deref(),
            target.version.as_deref(),
        ) else {
            skipped.push(SkippedTarget {
                locator,
                ecosystem: target.ecosystem,
                reason: SkipReason::IncompleteCoordinate,
                detail: SkipReason::IncompleteCoordinate.describe().to_string(),
            });
            continue;
        };
        if fetcher_for(ecosystem).is_none() {
            skipped.push(SkippedTarget {
                locator,
                ecosystem: Some(ecosystem),
                reason: SkipReason::NoFetcherForEcosystem,
                detail: SkipReason::NoFetcherForEcosystem.describe().to_string(),
            });
            continue;
        }
        jobs.push(FetchJob {
            locator,
            ecosystem,
            spec: spec_for(ecosystem, name, version),
        });
    }
    (jobs, skipped)
}

fn scan_locator(target: &LockfileScanTarget) -> String {
    target
        .locators
        .first()
        .cloned()
        .or_else(|| target.name.clone())
        .unwrap_or_else(|| "<unnamed>".to_string())
}

/// Render the ecosystem's native `fetch` spec for a coordinate.
fn spec_for(ecosystem: Ecosystem, name: &str, version: &str) -> String {
    match ecosystem {
        // Maven coordinates are `group:artifact:version`; the lockfile target
        // already carries `group:artifact` as the name.
        Ecosystem::Maven => format!("{name}:{version}"),
        _ => format!("{name}@{version}"),
    }
}

fn target_locator(target: &LockfileScanTarget) -> String {
    target
        .coordinate
        .as_ref()
        .map(|coordinate| coordinate.purl.clone())
        .or_else(|| target.locators.first().cloned())
        .or_else(|| target.name.clone())
        .unwrap_or_else(|| "<unnamed>".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FindingIdentity {
    rule_id: String,
    severity: u8,
    location: Option<String>,
    capability: Option<String>,
    resolved_host: Option<String>,
}

impl From<&Finding> for FindingIdentity {
    fn from(finding: &Finding) -> Self {
        let severity = match finding.severity {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        };
        Self {
            rule_id: finding.rule_id.clone(),
            severity,
            location: finding.location.clone(),
            capability: finding.capability.clone(),
            resolved_host: finding.resolved_host.clone(),
        }
    }
}

fn finding_delta(base: &[Finding], current: &[Finding]) -> (Vec<Finding>, Vec<Finding>) {
    let base_ids: BTreeSet<_> = base.iter().map(FindingIdentity::from).collect();
    let current_ids: BTreeSet<_> = current.iter().map(FindingIdentity::from).collect();
    let mut introduced_ids = BTreeSet::new();
    let introduced = current
        .iter()
        .filter(|finding| {
            let identity = FindingIdentity::from(*finding);
            !base_ids.contains(&identity) && introduced_ids.insert(identity)
        })
        .cloned()
        .collect();
    let mut resolved_ids = BTreeSet::new();
    let resolved = base
        .iter()
        .filter(|finding| {
            let identity = FindingIdentity::from(*finding);
            !current_ids.contains(&identity) && resolved_ids.insert(identity)
        })
        .cloned()
        .collect();
    (introduced, resolved)
}

fn report_for_target<'a>(
    reports: &'a [ScanReport],
    target: &LockfileScanTarget,
) -> Option<&'a ScanReport> {
    let coordinate = target.coordinate.as_ref()?;
    reports
        .iter()
        .find(|report| report.coordinate.as_ref() == Some(coordinate))
}

fn comparison_error(target: &LockfileScanTarget, outcome: &LockfileScanOutcome) -> String {
    let locator = scan_locator(target);
    if let Some(failure) = outcome
        .failed
        .iter()
        .find(|failure| failure.locator == locator)
    {
        return failure.error.clone();
    }
    if let Some(skip) = outcome.skipped.iter().find(|skip| skip.locator == locator) {
        return skip.detail.clone();
    }
    "base scan produced no report for the resolved coordinate".to_string()
}

fn assess_version_changes(
    changes: &[LockfileScanTargetChange],
    current: &LockfileScanOutcome,
    base: &LockfileScanOutcome,
) -> (Vec<VersionChangeAssessment>, Vec<ComparisonFailure>) {
    let mut assessed = Vec::new();
    let mut failed = Vec::new();
    for change in changes {
        let Some(current_report) = report_for_target(&current.reports, &change.current) else {
            // A failed or skipped current target is already visible in the
            // primary coverage result. There is no active report to compare.
            continue;
        };
        let Some(base_report) = report_for_target(&base.reports, &change.base) else {
            failed.push(ComparisonFailure {
                base_locator: target_locator(&change.base),
                current_locator: target_locator(&change.current),
                ecosystem: change.current.ecosystem,
                error: comparison_error(&change.base, base),
            });
            continue;
        };
        let (introduced, resolved) = finding_delta(&base_report.findings, &current_report.findings);
        assessed.push(VersionChangeAssessment {
            base: VersionEndpoint {
                purl: target_locator(&change.base),
                decision: base_report.decision,
            },
            current: VersionEndpoint {
                purl: target_locator(&change.current),
                decision: current_report.decision,
            },
            introduced,
            resolved,
        });
    }
    (assessed, failed)
}

/// The fetcher for an ecosystem, or `None` when argus has no pipeline for it.
fn fetcher_for(ecosystem: Ecosystem) -> Option<&'static dyn EcosystemFetcher> {
    match ecosystem {
        Ecosystem::Npm => Some(&argus_fetch::NpmFetcher),
        Ecosystem::PyPi => Some(&argus_pypi::PypiFetcher),
        Ecosystem::CratesIo => Some(&argus_crates::CratesFetcher),
        Ecosystem::Go => Some(&argus_go::GoFetcher),
        Ecosystem::NuGet => Some(&argus_nuget::NugetFetcher),
        Ecosystem::Maven => Some(&argus_maven::MavenFetcher),
        Ecosystem::RubyGems => Some(&argus_rubygems::GemsFetcher),
        Ecosystem::Packagist => Some(&argus_composer::ComposerFetcher),
    }
}

/// Fetch and scan every registry-fetchable target through the caller's
/// worker pool, preserving lockfile order in the aggregated output.
pub(crate) fn scan_targets(
    lockfile: &Path,
    targets: &[LockfileScanTarget],
    cache_dir: Option<&Path>,
    transport: &(dyn Transport + Sync),
    rules: &RuleSession,
    execution: &ExecutionContext,
) -> Result<LockfileScanOutcome> {
    let (jobs, skipped) = plan(targets);

    enum Outcome {
        Scanned(Box<ScanReport>),
        Failed(FailedTarget),
    }

    let mut reports = Vec::new();
    let mut failed = Vec::new();
    execution.execute_ordered(
        &jobs,
        None,
        |_index, job| -> Result<Outcome> {
            let fetcher = fetcher_for(job.ecosystem).context("planned job must have a fetcher")?;
            let opts = CommonFetchOptions {
                registry: fetcher.default_registry().to_string(),
                cache_dir: cache_dir.map(Path::to_path_buf),
            };
            match fetcher.fetch_and_scan_with_context(&job.spec, &opts, transport, rules, execution)
            {
                Ok(report) => Ok(Outcome::Scanned(Box::new(report))),
                // One unreachable dependency must not abort the sweep: the
                // other packages still carry findings CI needs. The failure is
                // retained and escalates the aggregate decision to `block`.
                Err(error) => Ok(Outcome::Failed(FailedTarget {
                    locator: job.locator.clone(),
                    ecosystem: job.ecosystem,
                    error: format!("{error:#}"),
                })),
            }
        },
        |_index, outcome| {
            match outcome {
                Outcome::Scanned(report) => reports.push(*report),
                Outcome::Failed(failure) => failed.push(failure),
            }
            Ok(())
        },
    )?;

    Ok(LockfileScanOutcome::derive(
        lockfile.to_path_buf(),
        Parts {
            targets_total: targets.len(),
            reports,
            skipped,
            failed,
            comparisons_total: 0,
            version_changes: Vec::new(),
            comparison_failed: Vec::new(),
        },
    ))
}

/// `argus lockfile-scan` arguments.
#[derive(clap::Args, Debug)]
pub(crate) struct LockfileScanArgs {
    pub(crate) path: PathBuf,
    /// Explicit lockfile format, validated together with the basename.
    #[arg(long, value_enum)]
    pub(crate) lockfile_format: Option<crate::router::LockfileFormatArg>,
    /// Scan only dependencies added or changed against this base lockfile.
    #[arg(long, value_name = "FILE")]
    pub(crate) base: Option<PathBuf>,
    /// Explicit format for `--base`, when its basename is ambiguous.
    #[arg(long, value_enum, requires = "base")]
    pub(crate) base_lockfile_format: Option<crate::router::LockfileFormatArg>,
    /// Persistent scratch parent reused across every dependency fetch.
    #[arg(long)]
    pub(crate) cache_dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = crate::Format::Text)]
    pub(crate) format: crate::Format,
    #[command(flatten)]
    pub(crate) rules: crate::rule_args::RuleArgs,
    #[command(flatten)]
    pub(crate) intel: crate::intel::ScanIntelArgs,
    #[command(flatten)]
    pub(crate) execution: crate::execution::ExecutionArgs,
}

/// Command entry point: parse, plan, sweep, and emit.
pub(crate) fn run(args: LockfileScanArgs) -> Result<ExitCode> {
    let scan_started_at = Utc::now();
    let execution = args.execution.resolve()?;
    let rules = args.rules.load()?;
    let path = args.path.as_path();

    let parsed = crate::read_and_parse_lockfile(path, args.lockfile_format.map(FormatHint::from))?;
    let targets = argus_lockfile::build_scan_targets(&parsed)
        .with_context(|| format!("build scan targets from {}", path.display()))?;

    let delta = match args.base.as_deref() {
        Some(base_path) => {
            let base_parsed = crate::read_and_parse_lockfile(
                base_path,
                args.base_lockfile_format.map(FormatHint::from),
            )?;
            let base_targets = argus_lockfile::build_scan_targets(&base_parsed)
                .with_context(|| format!("build scan targets from {}", base_path.display()))?;
            Some(argus_lockfile::diff_scan_targets(&base_targets, &targets))
        }
        None => None,
    };
    let current_targets: Vec<_> = match delta.as_ref() {
        Some(delta) => delta
            .added
            .iter()
            .cloned()
            .chain(delta.changed.iter().map(|change| change.current.clone()))
            .collect(),
        None => targets,
    };

    let transport = argus_transport::HttpTransport::new();
    let mut outcome = scan_targets(
        path,
        &current_targets,
        args.cache_dir.as_deref(),
        &transport,
        &rules,
        &execution,
    )?;
    if let Some(database_path) = args.intel.malicious_db.as_deref() {
        crate::intel::apply_malicious_snapshot_to_reports(
            &mut outcome.reports,
            Some(database_path),
            scan_started_at,
        )?;
        for report in &mut outcome.reports {
            rules.finalize_package(report);
        }
    }

    if let (Some(base_path), Some(delta)) = (args.base.as_deref(), delta.as_ref()) {
        let base_targets: Vec<_> = delta
            .changed
            .iter()
            .map(|change| change.base.clone())
            .collect();
        let base_outcome = scan_targets(
            base_path,
            &base_targets,
            args.cache_dir.as_deref(),
            &transport,
            &rules,
            &execution,
        )?;
        let (version_changes, comparison_failed) =
            assess_version_changes(&delta.changed, &outcome, &base_outcome);
        outcome.comparisons_total = delta.changed.len();
        outcome.version_changes = version_changes;
        outcome.comparison_failed = comparison_failed;
    }
    outcome.refresh_decision();
    emit(&outcome, args.format)
}

/// Emit the aggregate outcome and map it to the CLI's exit-code contract.
///
/// SARIF groups by package for free: `sarif::render_reports` already takes a
/// slice of reports, one run per package.
pub(crate) fn emit(outcome: &LockfileScanOutcome, format: crate::Format) -> Result<ExitCode> {
    match format {
        crate::Format::Json => println!("{}", serde_json::to_string_pretty(outcome)?),
        crate::Format::Sarif => println!(
            "{}",
            serde_json::to_string_pretty(&crate::sarif::render_reports(&outcome.reports)?)?
        ),
        crate::Format::Text => print!("{}", render_text(outcome)),
    }
    let code = match outcome.decision {
        Decision::Allow => 0,
        Decision::Block => 1,
        Decision::AllowWithApproval => 2,
    };
    Ok(ExitCode::from(code))
}

/// Human-readable summary. Coverage is stated first so a reader sees what was
/// *not* scanned before reading the findings.
pub(crate) fn render_text(outcome: &LockfileScanOutcome) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    let _ = writeln!(
        output,
        "decision: {}  lockfile: {}",
        decision_label(outcome.decision),
        outcome.lockfile.display()
    );
    let _ = writeln!(
        output,
        "coverage: scanned {} of {} resolved targets ({} skipped, {} failed)",
        outcome.scanned,
        outcome.targets_total,
        outcome.skipped.len(),
        outcome.failed.len()
    );
    if outcome.comparisons_total > 0 {
        let _ = writeln!(
            output,
            "comparison: assessed {} of {} changed targets ({} base failures)",
            outcome.version_changes.len(),
            outcome.comparisons_total,
            outcome.comparison_failed.len()
        );
    }

    if !outcome.version_changes.is_empty() {
        let _ = writeln!(output, "\nversion changes:");
        for change in &outcome.version_changes {
            let _ = writeln!(output, "  {} -> {}", change.base.purl, change.current.purl);
            if change.introduced.is_empty() && change.resolved.is_empty() {
                let _ = writeln!(output, "    no finding changes");
            }
            for finding in &change.introduced {
                let _ = writeln!(
                    output,
                    "    + [{}] {}: {}",
                    crate::report::severity_tag(finding),
                    finding.rule_id,
                    finding.detail
                );
            }
            for finding in &change.resolved {
                let _ = writeln!(
                    output,
                    "    - [{}] {}: {}",
                    crate::report::severity_tag(finding),
                    finding.rule_id,
                    finding.detail
                );
            }
        }
    }

    for report in &outcome.reports {
        if report.findings.is_empty() {
            continue;
        }
        let _ = writeln!(
            output,
            "\n{} {}",
            decision_label(report.decision),
            report.path.display()
        );
        for finding in &report.findings {
            let _ = writeln!(
                output,
                "  [{}] {}: {}",
                crate::report::severity_tag(finding),
                finding.rule_id,
                finding.detail
            );
        }
    }

    if !outcome.failed.is_empty() {
        let _ = writeln!(output, "\nunassessed (fetch or scan failed):");
        for failure in &outcome.failed {
            let _ = writeln!(output, "  {} — {}", failure.locator, failure.error);
        }
    }
    if !outcome.comparison_failed.is_empty() {
        let _ = writeln!(output, "\ncomparison unavailable:");
        for failure in &outcome.comparison_failed {
            let _ = writeln!(
                output,
                "  {} -> {} — {}",
                failure.base_locator, failure.current_locator, failure.error
            );
        }
    }
    if !outcome.skipped.is_empty() {
        let _ = writeln!(output, "\nnot scanned:");
        for skip in &outcome.skipped {
            let _ = writeln!(output, "  {} — {}", skip.locator, skip.detail);
        }
    }
    output
}

fn decision_label(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Block => "block",
        Decision::AllowWithApproval => "allow-with-approval",
    }
}

#[cfg(test)]
mod tests;
