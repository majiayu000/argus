//! Static detection rules for agent supply-chain surfaces (GH-57).
//!
//! Scans MCP configs, skill definitions, hook scripts, and high-context
//! instruction files (`AGENTS.md` / `CLAUDE.md`) for injection language,
//! dangerous capability combinations, and high-risk configuration flags.
//!
//! Like `argus-rules`, every rule is a pure function over collected file
//! contents: nothing from the scanned tree is ever executed. Traversal errors
//! and unreadable protected surfaces are hard errors so incomplete scans never
//! produce a clean decision.

use anyhow::{bail, Context, Result};
use argus_core::{ArtifactKind, Finding, ScanReport};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod baseline;
mod capability;
mod collection;
mod config;
mod decision;
mod injection;
mod judge;
mod rule_runtime;
mod snapshot;
mod surface;

use collection::{collect_surface_files, path_identity, project_semantic};
pub use judge::{LlmJudge, LlmJudgeRequest, LlmJudgeResponse};
pub use surface::{classify, CoordinatePolicy, ScanRootContext, ScanRootEntryType, SurfaceKind};

/// One text file collected from the scanned tree, with its surface class.
pub struct SurfaceFile {
    pub rel: String,
    pub content: String,
    pub kind: SurfaceKind,
}

/// How a scan interacts with an AGT-02 description-drift baseline.
///
/// - `None` — GH-57 behavior: AGT-02 is inert (no baseline = no drift check).
/// - `Check` — compare current descriptions against the approved baseline
///   and emit AGT-02 findings on drift.
/// - `Update` — (re)write the baseline from the current surface and mark it
///   approved; no AGT-02 drift comparison runs (this defines the trust base).
#[derive(Clone, Copy)]
pub enum BaselineMode<'a> {
    None,
    Check(&'a Path),
    Update(&'a Path),
}

#[derive(Clone, Copy)]
pub enum SnapshotMode<'a> {
    None,
    Check(&'a Path),
    Update(&'a Path),
}

pub struct AgentScanOutcome {
    pub report: ScanReport,
    pub operational_error: Option<anyhow::Error>,
    pub snapshot_entry_count: Option<usize>,
}

struct DiscoveredEntry {
    logical_path: String,
    absolute_path: PathBuf,
    entry_type: snapshot::EntryType,
    surface_kind: Option<SurfaceKind>,
}

/// Top-level entry: scan a directory (or single file) as an agent surface.
///
/// Thin wrapper over [`scan_agent_surface_with_baseline`] with no baseline —
/// identical to GH-57 behavior.
pub fn scan_agent_surface(path: &Path) -> Result<ScanReport> {
    let rules = argus_rules::RuleSession::builtin()?;
    let execution = argus_core::ExecutionContext::serial()?;
    scan_agent_surface_inner(path, BaselineMode::None, None, &rules, &execution)
}

/// Scan an agent surface, optionally checking or updating an AGT-02 baseline.
///
/// Injection / capability / config rules always run. In `Update` mode the
/// baseline file is (re)written and drift comparison is skipped. In `Check`
/// mode an unreadable/unparseable baseline yields an info finding and the
/// other rules still run (no panic, no silent "no drift").
pub fn scan_agent_surface_with_baseline(path: &Path, mode: BaselineMode) -> Result<ScanReport> {
    let rules = argus_rules::RuleSession::builtin()?;
    let execution = argus_core::ExecutionContext::serial()?;
    scan_agent_surface_inner(path, mode, None, &rules, &execution)
}

/// Scan an agent surface and run an explicitly supplied semantic judge after
/// the deterministic rules. The judge may add a finding but cannot remove or
/// downgrade deterministic findings.
pub fn scan_agent_surface_with_judge(
    path: &Path,
    mode: BaselineMode,
    judge: &dyn LlmJudge,
) -> Result<ScanReport> {
    let rules = argus_rules::RuleSession::builtin()?;
    let execution = argus_core::ExecutionContext::serial()?;
    scan_agent_surface_inner(path, mode, Some(judge), &rules, &execution)
}

/// Scan with optional AGT-04 comparison or approval.
pub fn scan_agent_surface_with_snapshot(
    path: &Path,
    baseline_mode: BaselineMode<'_>,
    snapshot_mode: SnapshotMode<'_>,
    judge: Option<&dyn LlmJudge>,
) -> Result<AgentScanOutcome> {
    let rules = argus_rules::RuleSession::builtin()?;
    scan_agent_surface_with_snapshot_and_rules(path, baseline_mode, snapshot_mode, judge, &rules)
}

pub fn scan_agent_surface_with_snapshot_and_rules(
    path: &Path,
    baseline_mode: BaselineMode<'_>,
    snapshot_mode: SnapshotMode<'_>,
    judge: Option<&dyn LlmJudge>,
    rules: &argus_rules::RuleSession,
) -> Result<AgentScanOutcome> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_agent_surface_with_snapshot_and_rules_and_context(
        path,
        baseline_mode,
        snapshot_mode,
        judge,
        rules,
        &execution,
    )
}

pub fn scan_agent_surface_with_snapshot_and_rules_and_context(
    path: &Path,
    baseline_mode: BaselineMode<'_>,
    snapshot_mode: SnapshotMode<'_>,
    judge: Option<&dyn LlmJudge>,
    rules: &argus_rules::RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<AgentScanOutcome> {
    if matches!(snapshot_mode, SnapshotMode::None) {
        return scan_agent_surface_inner(path, baseline_mode, judge, rules, execution).map(
            |report| AgentScanOutcome {
                report,
                operational_error: None,
                snapshot_entry_count: None,
            },
        );
    }
    scan_snapshot_mode(path, baseline_mode, snapshot_mode, judge, rules, execution)
}

fn scan_agent_surface_inner(
    path: &Path,
    mode: BaselineMode,
    judge: Option<&dyn LlmJudge>,
    rules: &argus_rules::RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<ScanReport> {
    // Exclude the baseline file itself from the scanned tree so it is never
    // self-hashed (product edge case: baseline may live inside the tree).
    let exclude = match mode {
        BaselineMode::Check(p) | BaselineMode::Update(p) => Some(path_identity(p)),
        BaselineMode::None => None,
    };
    let collected = collect_surface_files(path, exclude.as_deref())?;
    let files = collected.files;
    let mut findings = collected.findings;
    rule_runtime::scan_files_with_context(rules, &files, &mut findings, execution)?;
    injection::run(&files, &mut findings);
    capability::run(&files, &mut findings)?;
    config::run(path, &files, &mut findings);

    match mode {
        BaselineMode::None => {}
        BaselineMode::Update(target) => {
            let snapshot = baseline::Baseline::from_entries(baseline::extract_entries(&files));
            baseline::save(target, &snapshot)?;
        }
        BaselineMode::Check(source) => match baseline::load(source) {
            Ok(approved) => baseline::check_drift(&approved, &files, &mut findings),
            Err(e) => findings.push(
                Finding::new(
                    baseline::RULE_BASELINE_UNREADABLE,
                    argus_core::Severity::Info,
                    format!("baseline unreadable/unparseable: {e:#}"),
                )
                .at(source.display().to_string()),
            ),
        },
    }

    let mut report = ScanReport {
        artifact: ArtifactKind::AgentSurface,
        path: path.to_path_buf(),
        package_name: None,
        package_version: None,
        decision: decision::derive(&findings),
        findings,
        coordinate: None,
        intelligence: None,
        rules: None,
        vulnerability: None,
        risk: None,
    };
    rules.finalize_agent(&mut report);

    if let Some(judge) = judge {
        let request = LlmJudgeRequest::from_scan(&files, &report)?;
        let response = judge.judge(&request).context("run external LLM judge")?;
        report.findings.push(response.into_finding()?);
        rules.finalize_agent(&mut report);
    }

    Ok(report)
}

fn scan_snapshot_mode(
    path: &Path,
    baseline_mode: BaselineMode<'_>,
    snapshot_mode: SnapshotMode<'_>,
    judge: Option<&dyn LlmJudge>,
    rules: &argus_rules::RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<AgentScanOutcome> {
    let (context, discovered, canonical_root) = discover_complete(path)?;
    let target = match snapshot_mode {
        SnapshotMode::Check(path) | SnapshotMode::Update(path) => path,
        SnapshotMode::None => unreachable!(),
    };
    let excluded = guard_snapshot_target(&canonical_root, path, target, &context, &discovered)?;
    let current = capture_inventory(&discovered, excluded.as_deref())?;
    let inventory_findings = match snapshot_mode {
        SnapshotMode::Check(source) => snapshot::compare(&snapshot::load(source)?, &current),
        SnapshotMode::Update(_) => Vec::new(),
        SnapshotMode::None => unreachable!(),
    };
    let baseline_excluded = match baseline_mode {
        BaselineMode::Check(path) | BaselineMode::Update(path) => Some(path_identity(path)),
        BaselineMode::None => None,
    };
    let mut semantic_findings = Vec::new();
    let post_inventory: Result<()> = (|| {
        let collected = project_semantic(
            &discovered,
            excluded.as_deref(),
            baseline_excluded.as_deref(),
        )?;
        let files = collected.files;
        semantic_findings.extend(collected.findings);
        rule_runtime::scan_files_with_context(rules, &files, &mut semantic_findings, execution)?;
        injection::run(&files, &mut semantic_findings);
        capability::run(&files, &mut semantic_findings)?;
        config::run(path, &files, &mut semantic_findings);
        apply_baseline(baseline_mode, &files, &mut semantic_findings)?;
        if let Some(judge) = judge {
            let report = rule_runtime::report(
                path,
                join_findings(&semantic_findings, &inventory_findings),
                rules,
            );
            let request = LlmJudgeRequest::from_scan(&files, &report)?;
            let response = judge.judge(&request).context("run external LLM judge")?;
            semantic_findings.push(response.into_finding()?);
        }
        Ok(())
    })();
    if let Err(error) = post_inventory {
        return Ok(rule_runtime::incomplete(
            path,
            semantic_findings,
            inventory_findings,
            error,
            rules,
        ));
    }
    let report = rule_runtime::report(
        path,
        join_findings(&semantic_findings, &inventory_findings),
        rules,
    );
    if let SnapshotMode::Update(target) = snapshot_mode {
        if let Err(error) = snapshot::save(target, &current) {
            return Ok(rule_runtime::incomplete(
                path,
                semantic_findings,
                inventory_findings,
                error,
                rules,
            ));
        }
    }
    Ok(AgentScanOutcome {
        report,
        operational_error: None,
        snapshot_entry_count: matches!(snapshot_mode, SnapshotMode::Update(_))
            .then_some(current.len()),
    })
}

fn join_findings(semantic: &[Finding], inventory: &[Finding]) -> Vec<Finding> {
    semantic.iter().chain(inventory).cloned().collect()
}

fn apply_baseline(
    mode: BaselineMode<'_>,
    files: &[SurfaceFile],
    findings: &mut Vec<Finding>,
) -> Result<()> {
    match mode {
        BaselineMode::None => {}
        BaselineMode::Update(target) => {
            let approved = baseline::Baseline::from_entries(baseline::extract_entries(files));
            baseline::save(target, &approved)?;
        }
        BaselineMode::Check(source) => match baseline::load(source) {
            Ok(approved) => baseline::check_drift(&approved, files, findings),
            Err(error) => findings.push(
                Finding::new(
                    baseline::RULE_BASELINE_UNREADABLE,
                    argus_core::Severity::Info,
                    format!("baseline unreadable/unparseable: {error:#}"),
                )
                .at(source.display().to_string()),
            ),
        },
    }
    Ok(())
}

fn discover_complete(path: &Path) -> Result<(ScanRootContext, Vec<DiscoveredEntry>, PathBuf)> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect agent scan root {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("agent scan root `{}` is a symlink", path.display());
    }
    let root_type = if metadata.is_file() {
        ScanRootEntryType::File
    } else if metadata.is_dir() {
        std::fs::read_dir(path)
            .with_context(|| format!("read agent scan root {}", path.display()))?;
        ScanRootEntryType::Directory
    } else {
        bail!("agent scan root is neither a file nor directory");
    };
    let canonical = std::fs::canonicalize(path)?;
    let context = ScanRootContext::from_canonical_scan_root(&canonical, root_type)
        .context("build strict UTF-8 scan root context")?;
    let mut raw = Vec::new();
    if root_type == ScanRootEntryType::File {
        raw.push((
            strict_file_name(&canonical)?,
            canonical.clone(),
            snapshot::EntryType::File,
        ));
    } else {
        for entry in walkdir::WalkDir::new(&canonical)
            .follow_links(false)
            .min_depth(1)
        {
            let entry =
                entry.with_context(|| format!("walk agent scan root {}", path.display()))?;
            let absolute = entry.path().to_path_buf();
            let logical = strict_relative_path(&canonical, &absolute)?;
            let metadata = std::fs::symlink_metadata(&absolute)
                .with_context(|| format!("inspect discovered entry `{logical}`"))?;
            let entry_type = if metadata.file_type().is_symlink() {
                snapshot::EntryType::Symlink
            } else if metadata.is_file() {
                snapshot::EntryType::File
            } else if metadata.is_dir() {
                snapshot::EntryType::Directory
            } else {
                bail!("unsupported filesystem entry `{logical}`");
            };
            raw.push((logical, absolute, entry_type));
        }
    }
    let skill_dirs = raw_skill_dirs(&raw);
    let discovered = raw
        .into_iter()
        .map(
            |(logical_path, absolute_path, entry_type)| DiscoveredEntry {
                surface_kind: classify(
                    CoordinatePolicy::SnapshotRootAware(&context),
                    &logical_path,
                    &skill_dirs,
                ),
                logical_path,
                absolute_path,
                entry_type,
            },
        )
        .collect();
    Ok((context, discovered, canonical))
}

fn raw_skill_dirs(raw: &[(String, PathBuf, snapshot::EntryType)]) -> Vec<String> {
    raw.iter()
        .filter_map(|(logical, _, entry_type)| {
            (*entry_type == snapshot::EntryType::File)
                .then(|| skill_dir(logical))
                .flatten()
        })
        .collect()
}

fn skill_dir(logical: &str) -> Option<String> {
    let name = logical.rsplit('/').next().unwrap_or(logical);
    name.eq_ignore_ascii_case("SKILL.md")
        .then(|| logical.strip_suffix(name).unwrap_or("").to_string())
}

fn strict_file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("agent scan root has no valid UTF-8 file name"))
}

fn strict_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root)?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(value) = component else {
            bail!("discovered path is not strictly relative");
        };
        parts.push(
            value
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("discovered path is not valid UTF-8"))?,
        );
    }
    if parts.is_empty() {
        bail!("discovered path is empty");
    }
    Ok(parts.join("/"))
}

fn guard_snapshot_target(
    canonical_root: &Path,
    original_root: &Path,
    target: &Path,
    context: &ScanRootContext,
    discovered: &[DiscoveredEntry],
) -> Result<Option<PathBuf>> {
    let identity = strict_path_identity(target)?;
    let root_is_file = std::fs::symlink_metadata(original_root)?.is_file();
    let logical = if root_is_file && identity == canonical_root {
        Some(strict_file_name(canonical_root)?)
    } else if !root_is_file && identity.starts_with(canonical_root) {
        Some(strict_relative_path(canonical_root, &identity)?)
    } else {
        None
    };
    if let Some(logical) = logical {
        let skill_dirs: Vec<_> = discovered
            .iter()
            .filter_map(|entry| skill_dir(&entry.logical_path))
            .collect();
        if classify(
            CoordinatePolicy::SnapshotRootAware(context),
            &logical,
            &skill_dirs,
        )
        .is_some()
        {
            bail!("snapshot target `{logical}` is a protected agent surface");
        }
        return Ok(Some(identity));
    }
    Ok(None)
}

fn strict_path_identity(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("snapshot target must name a file"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(std::fs::canonicalize(parent)?.join(name))
}

fn capture_inventory(
    discovered: &[DiscoveredEntry],
    exclusion: Option<&Path>,
) -> Result<snapshot::Snapshot> {
    let mut entries = BTreeMap::new();
    for entry in discovered {
        if exclusion.is_some_and(|path| entry.absolute_path == path) {
            continue;
        }
        if entry.surface_kind.is_some() {
            entries.insert(
                entry.logical_path.clone(),
                snapshot::capture_entry(&entry.absolute_path, entry.entry_type)?,
            );
        }
    }
    Ok(snapshot::Snapshot::new(entries))
}
