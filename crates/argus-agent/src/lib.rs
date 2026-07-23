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
use std::io::Read;
use std::path::{Path, PathBuf};

mod atomic_write;
mod baseline;
mod capability;
mod config;
mod decision;
mod injection;
mod judge;
mod snapshot;
mod surface;

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

/// Maximum size we attempt to read as text (matches argus-rules).
const TEXT_MAX_BYTES: u64 = 1024 * 1024;

struct Candidate {
    rel: String,
    state: CandidateState,
}

enum CandidateState {
    Bytes(Vec<u8>),
    Oversized(u64),
    MetadataError(String),
    ReadError(String),
    Symlink,
    SymlinkTargetError(String),
}

/// Top-level entry: scan a directory (or single file) as an agent surface.
///
/// Thin wrapper over [`scan_agent_surface_with_baseline`] with no baseline —
/// identical to GH-57 behavior.
pub fn scan_agent_surface(path: &Path) -> Result<ScanReport> {
    scan_agent_surface_inner(path, BaselineMode::None, None)
}

/// Scan an agent surface, optionally checking or updating an AGT-02 baseline.
///
/// Injection / capability / config rules always run. In `Update` mode the
/// baseline file is (re)written and drift comparison is skipped. In `Check`
/// mode an unreadable/unparseable baseline yields an info finding and the
/// other rules still run (no panic, no silent "no drift").
pub fn scan_agent_surface_with_baseline(path: &Path, mode: BaselineMode) -> Result<ScanReport> {
    scan_agent_surface_inner(path, mode, None)
}

/// Scan an agent surface and run an explicitly supplied semantic judge after
/// the deterministic rules. The judge may add a finding but cannot remove or
/// downgrade deterministic findings.
pub fn scan_agent_surface_with_judge(
    path: &Path,
    mode: BaselineMode,
    judge: &dyn LlmJudge,
) -> Result<ScanReport> {
    scan_agent_surface_inner(path, mode, Some(judge))
}

/// Scan with optional AGT-04 comparison or approval.
pub fn scan_agent_surface_with_snapshot(
    path: &Path,
    baseline_mode: BaselineMode<'_>,
    snapshot_mode: SnapshotMode<'_>,
    judge: Option<&dyn LlmJudge>,
) -> Result<AgentScanOutcome> {
    if matches!(snapshot_mode, SnapshotMode::None) {
        return scan_agent_surface_inner(path, baseline_mode, judge).map(|report| {
            AgentScanOutcome {
                report,
                operational_error: None,
                snapshot_entry_count: None,
            }
        });
    }
    scan_snapshot_mode(path, baseline_mode, snapshot_mode, judge)
}

fn scan_agent_surface_inner(
    path: &Path,
    mode: BaselineMode,
    judge: Option<&dyn LlmJudge>,
) -> Result<ScanReport> {
    // Exclude the baseline file itself from the scanned tree so it is never
    // self-hashed (product edge case: baseline may live inside the tree).
    let exclude = match mode {
        BaselineMode::Check(p) | BaselineMode::Update(p) => Some(path_identity(p)),
        BaselineMode::None => None,
    };
    let files = collect_surface_files(path, exclude.as_deref())?;

    let mut findings: Vec<Finding> = Vec::new();
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
    };

    if let Some(judge) = judge {
        let request = LlmJudgeRequest::from_scan(&files, &report)?;
        let response = judge.judge(&request).context("run external LLM judge")?;
        report.findings.push(response.into_finding()?);
        report.decision = decision::derive(&report.findings);
    }

    Ok(report)
}

fn scan_snapshot_mode(
    path: &Path,
    baseline_mode: BaselineMode<'_>,
    snapshot_mode: SnapshotMode<'_>,
    judge: Option<&dyn LlmJudge>,
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
        let files = project_semantic(
            &discovered,
            excluded.as_deref(),
            baseline_excluded.as_deref(),
        )?;
        injection::run(&files, &mut semantic_findings);
        capability::run(&files, &mut semantic_findings)?;
        config::run(path, &files, &mut semantic_findings);
        apply_baseline(baseline_mode, &files, &mut semantic_findings)?;
        if let Some(judge) = judge {
            let report = report(path, join_findings(&semantic_findings, &inventory_findings));
            let request = LlmJudgeRequest::from_scan(&files, &report)?;
            let response = judge.judge(&request).context("run external LLM judge")?;
            semantic_findings.push(response.into_finding()?);
        }
        Ok(())
    })();
    if let Err(error) = post_inventory {
        return Ok(incomplete(
            path,
            semantic_findings,
            inventory_findings,
            error,
        ));
    }
    let report = report(path, join_findings(&semantic_findings, &inventory_findings));
    if let SnapshotMode::Update(target) = snapshot_mode {
        if let Err(error) = snapshot::save(target, &current) {
            return Ok(incomplete(
                path,
                semantic_findings,
                inventory_findings,
                error,
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

fn report(path: &Path, findings: Vec<Finding>) -> ScanReport {
    ScanReport {
        artifact: ArtifactKind::AgentSurface,
        path: path.to_path_buf(),
        package_name: None,
        package_version: None,
        decision: decision::derive(&findings),
        findings,
        coordinate: None,
        intelligence: None,
    }
}

fn incomplete(
    path: &Path,
    semantic: Vec<Finding>,
    inventory: Vec<Finding>,
    error: anyhow::Error,
) -> AgentScanOutcome {
    let mut report = report(path, join_findings(&semantic, &inventory));
    report.decision = argus_core::Decision::Block;
    AgentScanOutcome {
        report,
        operational_error: Some(error),
        snapshot_entry_count: None,
    }
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
    let context = ScanRootContext::from_canonical_scan_root(&canonical, root_type);
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

fn project_semantic(
    discovered: &[DiscoveredEntry],
    snapshot_exclusion: Option<&Path>,
    baseline_exclusion: Option<&Path>,
) -> Result<Vec<SurfaceFile>> {
    let mut files = Vec::new();
    for entry in discovered {
        if entry.entry_type == snapshot::EntryType::Directory
            || entry.surface_kind == Some(SurfaceKind::InventoryOnly)
            || entry.surface_kind.is_none()
            || snapshot_exclusion.is_some_and(|path| entry.absolute_path == path)
            || is_excluded(&entry.absolute_path, baseline_exclusion)
        {
            continue;
        }
        if entry.entry_type == snapshot::EntryType::Symlink {
            bail!(
                "protected agent surface `{}` is a symlink",
                entry.logical_path
            );
        }
        let metadata = std::fs::symlink_metadata(&entry.absolute_path)?;
        files.push(materialize_candidate(
            collect_candidate(
                &entry.absolute_path,
                entry.logical_path.clone(),
                metadata.len(),
            ),
            entry.surface_kind.expect("semantic kind checked"),
        )?);
    }
    Ok(files)
}

fn collect_surface_files(root: &Path, exclude: Option<&Path>) -> Result<Vec<SurfaceFile>> {
    let root_metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("inspect agent scan root {}", root.display()))?;
    if root_metadata.file_type().is_symlink() {
        bail!(
            "agent scan root `{}` is a symlink; refusing incomplete scan",
            root.display()
        );
    }
    let mut candidates: Vec<Candidate> = Vec::new();

    if root_metadata.is_file() {
        if !is_excluded(root, exclude) {
            let rel = root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let candidate = collect_candidate(root, rel, root_metadata.len());
            if let CandidateState::ReadError(error) = &candidate.state {
                bail!(
                    "read agent scan root {}: {error}; refusing incomplete scan",
                    root.display()
                );
            }
            candidates.push(candidate);
        }
    } else if root_metadata.is_dir() {
        // Opening the root separately distinguishes a completely unreadable
        // root from a deeper entry that becomes unreadable during traversal.
        std::fs::read_dir(root)
            .with_context(|| format!("read agent scan root {}", root.display()))?;

        // Vendored dependency trees drown the signal (a real ~/.claude scan
        // surfaced hundreds of node_modules hits); the package supply chain
        // is argus's existing scanners' job, not the agent surface's.
        let walker = walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                name != "node_modules" && name != ".git"
            });
        for entry in walker {
            let entry =
                entry.with_context(|| format!("walk agent scan root {}", root.display()))?;
            let file_type = entry.file_type();
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let abs = entry.path();
            if is_excluded(abs, exclude) {
                continue; // never self-hash the baseline file
            }
            let rel = abs
                .strip_prefix(root)
                .unwrap_or(abs)
                .to_string_lossy()
                .replace('\\', "/");
            if file_type.is_symlink() {
                let state = match std::fs::metadata(abs) {
                    Ok(metadata) if metadata.is_dir() => {
                        bail!(
                            "agent scan tree contains directory symlink `{rel}`; \
                             refusing incomplete scan"
                        );
                    }
                    Ok(_) => CandidateState::Symlink,
                    Err(error) => CandidateState::SymlinkTargetError(error.to_string()),
                };
                candidates.push(Candidate { rel, state });
                continue;
            }
            let candidate = match entry.metadata() {
                Ok(metadata) => collect_candidate(abs, rel, metadata.len()),
                Err(error) => Candidate {
                    rel,
                    state: CandidateState::MetadataError(error.to_string()),
                },
            };
            candidates.push(candidate);
        }
    } else {
        bail!(
            "agent scan root is neither a file nor directory: {}",
            root.display()
        );
    }

    classify_candidates(candidates)
}

fn collect_candidate(path: &Path, rel: String, metadata_len: u64) -> Candidate {
    let state = if metadata_len > TEXT_MAX_BYTES {
        CandidateState::Oversized(metadata_len)
    } else {
        match read_limited(path) {
            Ok(state) => state,
            Err(error) => CandidateState::ReadError(format!("{error:#}")),
        }
    };
    Candidate { rel, state }
}

fn classify_candidates(candidates: Vec<Candidate>) -> Result<Vec<SurfaceFile>> {
    // Directories that contain a SKILL.md: scripts underneath are skill scripts.
    let skill_dirs: Vec<String> = candidates
        .iter()
        .filter_map(|candidate| {
            let file_name = candidate.rel.rsplit('/').next().unwrap_or(&candidate.rel);
            file_name.eq_ignore_ascii_case("SKILL.md").then(|| {
                candidate
                    .rel
                    .strip_suffix(file_name)
                    .unwrap_or("")
                    .to_string()
            })
        })
        .collect();

    let mut files = Vec::new();
    for Candidate { rel, state } in candidates {
        let kind = classify(CoordinatePolicy::LegacyRootRelative, &rel, &skill_dirs);
        if matches!(&state, CandidateState::SymlinkTargetError(_))
            && is_protected_tree_path(&rel, &skill_dirs)
        {
            let CandidateState::SymlinkTargetError(error) = state else {
                unreachable!();
            };
            bail!(
                "inspect protected agent tree symlink `{rel}` target: {error}; \
                 refusing incomplete scan"
            );
        }
        if kind == Some(SurfaceKind::InventoryOnly) {
            continue;
        }
        let Some(kind) = kind else {
            continue;
        };
        files.push(materialize_candidate(Candidate { rel, state }, kind)?);
    }
    Ok(files)
}

fn materialize_candidate(candidate: Candidate, kind: SurfaceKind) -> Result<SurfaceFile> {
    let Candidate { rel, state } = candidate;
    let bytes = match state {
        CandidateState::Bytes(bytes) => bytes,
        CandidateState::Oversized(size) => bail!(
            "protected agent surface `{rel}` is at least {size} bytes, exceeds scan limit \
             {TEXT_MAX_BYTES}; refusing incomplete scan"
        ),
        CandidateState::MetadataError(error) => {
            bail!("inspect protected agent surface `{rel}`: {error}; refusing incomplete scan")
        }
        CandidateState::ReadError(error) => {
            bail!("read protected agent surface `{rel}`: {error}; refusing incomplete scan")
        }
        CandidateState::Symlink | CandidateState::SymlinkTargetError(_) => {
            bail!("protected agent surface `{rel}` is a symlink; refusing incomplete scan")
        }
    };
    if argus_rules::looks_binary(&bytes) {
        bail!("protected agent surface `{rel}` appears binary; refusing incomplete scan");
    }
    let content = String::from_utf8(bytes).with_context(|| {
        format!("protected agent surface `{rel}` is not valid UTF-8; refusing incomplete scan")
    })?;
    Ok(SurfaceFile { rel, content, kind })
}

fn is_protected_tree_path(rel: &str, skill_dirs: &[String]) -> bool {
    rel.split('/').any(|segment| segment == ".claude")
        || rel == "hooks"
        || rel.starts_with("hooks/")
        || skill_dirs.iter().any(|dir| rel.starts_with(dir))
}

/// True only for the declared baseline path itself. A different symlink alias
/// that resolves to the same target must still be classified so protected
/// surfaces cannot bypass completeness checks by pointing at the baseline.
fn is_excluded(candidate: &Path, exclude: Option<&Path>) -> bool {
    let Some(exclude) = exclude else {
        return false;
    };
    if path_identity(candidate) == exclude {
        return true;
    }
    if std::fs::symlink_metadata(exclude).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return false;
    }
    if std::fs::symlink_metadata(candidate).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return false;
    }
    match std::fs::canonicalize(candidate) {
        Ok(abs) => std::fs::canonicalize(exclude).is_ok_and(|excluded| abs == excluded),
        Err(_) => false,
    }
}

fn path_identity(path: &Path) -> std::path::PathBuf {
    let Some(file_name) = path.file_name() else {
        return path.to_path_buf();
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::canonicalize(parent)
        .map(|parent| parent.join(file_name))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn read_limited(path: &Path) -> Result<CandidateState> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open agent surface {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(TEXT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read agent surface {}", path.display()))?;
    if bytes.len() as u64 > TEXT_MAX_BYTES {
        return Ok(CandidateState::Oversized(bytes.len() as u64));
    }
    Ok(CandidateState::Bytes(bytes))
}
