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
use argus_core::{Decision, Ecosystem, ExecutionContext, ScanReport};
use argus_lockfile::FormatHint;
use argus_lockfile::{LockfileScanTarget, LockfileScanTargetKind};
use argus_pipeline::{CommonFetchOptions, EcosystemFetcher};
use argus_rules::RuleSession;
use argus_transport::Transport;
use serde::Serialize;
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
        } = parts;
        let decision = if failed.is_empty() {
            reports
                .iter()
                .map(|report| report.decision)
                .fold(Decision::Allow, worst_decision)
        } else {
            Decision::Block
        };
        Self {
            lockfile,
            decision,
            targets_total,
            scanned: reports.len(),
            reports,
            skipped,
            failed,
        }
    }
}

struct Parts {
    targets_total: usize,
    reports: Vec<ScanReport>,
    skipped: Vec<SkippedTarget>,
    failed: Vec<FailedTarget>,
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
        let locator = target
            .locators
            .first()
            .cloned()
            .or_else(|| target.name.clone())
            .unwrap_or_else(|| "<unnamed>".to_string());
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

/// Render the ecosystem's native `fetch` spec for a coordinate.
fn spec_for(ecosystem: Ecosystem, name: &str, version: &str) -> String {
    match ecosystem {
        // Maven coordinates are `group:artifact:version`; the lockfile target
        // already carries `group:artifact` as the name.
        Ecosystem::Maven => format!("{name}:{version}"),
        _ => format!("{name}@{version}"),
    }
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
        },
    ))
}

/// `argus lockfile-scan` arguments.
#[derive(clap::Args, Debug)]
pub(crate) struct LockfileScanArgs {
    pub(crate) path: PathBuf,
    /// Explicit lockfile format, validated together with the basename.
    #[arg(long, value_enum)]
    pub(crate) lockfile_format: Option<crate::LockfileFormatArg>,
    /// Scan only dependencies added or changed against this base lockfile.
    #[arg(long, value_name = "FILE")]
    pub(crate) base: Option<PathBuf>,
    /// Explicit format for `--base`, when its basename is ambiguous.
    #[arg(long, value_enum, requires = "base")]
    pub(crate) base_lockfile_format: Option<crate::LockfileFormatArg>,
    /// Persistent scratch parent reused across every dependency fetch.
    #[arg(long)]
    pub(crate) cache_dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = crate::Format::Text)]
    pub(crate) format: crate::Format,
    #[command(flatten)]
    pub(crate) rules: crate::rule_args::RuleArgs,
    #[command(flatten)]
    pub(crate) execution: crate::execution::ExecutionArgs,
}

/// Command entry point: parse, plan, sweep, and emit.
pub(crate) fn run(args: LockfileScanArgs) -> Result<ExitCode> {
    let execution = args.execution.resolve()?;
    let rules = args.rules.load()?;
    let path = args.path.as_path();

    let parsed = crate::read_and_parse_lockfile(path, args.lockfile_format.map(FormatHint::from))?;
    let targets = argus_lockfile::build_scan_targets(&parsed)
        .with_context(|| format!("build scan targets from {}", path.display()))?;

    // `--base` narrows the sweep to what this change introduces. The delta is
    // computed from the *current* side of each change so a CI run never scans
    // the base artifact while reporting current-lockfile results.
    let targets = match args.base.as_deref() {
        Some(base_path) => {
            let base_parsed = crate::read_and_parse_lockfile(
                base_path,
                args.base_lockfile_format.map(FormatHint::from),
            )?;
            let base_targets = argus_lockfile::build_scan_targets(&base_parsed)
                .with_context(|| format!("build scan targets from {}", base_path.display()))?;
            let delta = argus_lockfile::diff_scan_targets(&base_targets, &targets);
            delta
                .added
                .into_iter()
                .chain(delta.changed.into_iter().map(|change| change.current))
                .collect()
        }
        None => targets,
    };

    let transport = argus_transport::HttpTransport::new();
    let outcome = scan_targets(
        path,
        &targets,
        args.cache_dir.as_deref(),
        &transport,
        &rules,
        &execution,
    )?;
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
