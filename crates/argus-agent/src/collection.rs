//! Fail-closed collection and materialization of semantic agent surfaces.

use crate::{
    classify, skill_dir, snapshot, CoordinatePolicy, DiscoveredEntry, SurfaceFile, SurfaceKind,
};
use anyhow::{bail, Context, Result};
use argus_core::{Finding, Severity};
use std::io::Read;
use std::path::{Path, PathBuf};

const TEXT_MAX_BYTES: u64 = 1024 * 1024;
const NATIVE_HEADER_BYTES: u64 = 4096;

struct Candidate {
    rel: String,
    state: CandidateState,
}

enum CandidateState {
    Bytes(Vec<u8>),
    NativeExecutable(&'static str),
    Oversized(u64),
    MetadataError(String),
    ReadError(String),
    Symlink,
    SymlinkTargetError(String),
}

pub(super) struct CollectedSurface {
    pub(super) files: Vec<SurfaceFile>,
    pub(super) findings: Vec<Finding>,
}

enum MaterializedCandidate {
    Text(SurfaceFile),
    NativeExecutable(Finding),
}

pub(super) fn project_semantic(
    discovered: &[DiscoveredEntry],
    snapshot_exclusion: Option<&Path>,
    baseline_exclusion: Option<&Path>,
) -> Result<CollectedSurface> {
    let mut files = Vec::new();
    let mut findings = Vec::new();
    let skill_dirs: Vec<_> = discovered
        .iter()
        .filter_map(|entry| skill_dir(&entry.logical_path))
        .collect();
    for entry in discovered {
        if entry.entry_type == snapshot::EntryType::Directory
            || entry.surface_kind.is_none()
            || snapshot_exclusion.is_some_and(|path| entry.absolute_path == path)
            || is_excluded(&entry.absolute_path, baseline_exclusion)
        {
            continue;
        }
        if entry.surface_kind == Some(SurfaceKind::InventoryOnly) {
            if entry.entry_type == snapshot::EntryType::File
                && is_native_candidate_tree(&entry.logical_path, &skill_dirs)
            {
                let metadata = std::fs::symlink_metadata(&entry.absolute_path)?;
                if let Some(finding) = materialize_native_candidate(collect_candidate(
                    &entry.absolute_path,
                    entry.logical_path.clone(),
                    metadata.len(),
                ))? {
                    findings.push(finding);
                }
            }
            continue;
        }
        if entry.entry_type == snapshot::EntryType::Symlink {
            bail!(
                "protected agent surface `{}` is a symlink",
                entry.logical_path
            );
        }
        let metadata = std::fs::symlink_metadata(&entry.absolute_path)?;
        push_materialized(
            &mut files,
            &mut findings,
            materialize_candidate(
                collect_candidate(
                    &entry.absolute_path,
                    entry.logical_path.clone(),
                    metadata.len(),
                ),
                entry.surface_kind.expect("semantic kind checked"),
            )?,
        );
    }
    Ok(CollectedSurface { files, findings })
}

pub(super) fn collect_surface_files(
    root: &Path,
    exclude: Option<&Path>,
) -> Result<CollectedSurface> {
    let root_metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("inspect agent scan root {}", root.display()))?;
    if root_metadata.file_type().is_symlink() {
        bail!(
            "agent scan root `{}` is a symlink; refusing incomplete scan",
            root.display()
        );
    }
    let mut candidates = Vec::new();

    if root_metadata.is_file() {
        if !is_excluded(root, exclude) {
            let rel = root
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
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
        std::fs::read_dir(root)
            .with_context(|| format!("read agent scan root {}", root.display()))?;
        let walker = walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                let name = entry.file_name().to_string_lossy();
                name != "node_modules" && name != ".git"
            });
        for entry in walker {
            let entry =
                entry.with_context(|| format!("walk agent scan root {}", root.display()))?;
            let file_type = entry.file_type();
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let absolute = entry.path();
            if is_excluded(absolute, exclude) {
                continue;
            }
            let rel = absolute
                .strip_prefix(root)
                .unwrap_or(absolute)
                .to_string_lossy()
                .replace('\\', "/");
            if file_type.is_symlink() {
                let state = match std::fs::metadata(absolute) {
                    Ok(metadata) if metadata.is_dir() => bail!(
                        "agent scan tree contains directory symlink `{rel}`; refusing incomplete scan"
                    ),
                    Ok(_) => CandidateState::Symlink,
                    Err(error) => CandidateState::SymlinkTargetError(error.to_string()),
                };
                candidates.push(Candidate { rel, state });
                continue;
            }
            candidates.push(match entry.metadata() {
                Ok(metadata) => collect_candidate(absolute, rel, metadata.len()),
                Err(error) => Candidate {
                    rel,
                    state: CandidateState::MetadataError(error.to_string()),
                },
            });
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
        match read_prefix(path) {
            Ok(bytes) => native_executable_format(&bytes)
                .map(CandidateState::NativeExecutable)
                .unwrap_or(CandidateState::Oversized(metadata_len)),
            Err(error) => CandidateState::ReadError(format!("{error:#}")),
        }
    } else {
        match read_limited(path) {
            Ok(CandidateState::Bytes(bytes)) => native_executable_format(&bytes)
                .map(CandidateState::NativeExecutable)
                .unwrap_or(CandidateState::Bytes(bytes)),
            Ok(state) => state,
            Err(error) => CandidateState::ReadError(format!("{error:#}")),
        }
    };
    Candidate { rel, state }
}

fn classify_candidates(candidates: Vec<Candidate>) -> Result<CollectedSurface> {
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
    let mut findings = Vec::new();
    for Candidate { rel, state } in candidates {
        let kind = classify(CoordinatePolicy::LegacyRootRelative, &rel, &skill_dirs);
        if matches!(&state, CandidateState::SymlinkTargetError(_))
            && is_protected_tree_path(&rel, &skill_dirs)
        {
            let CandidateState::SymlinkTargetError(error) = state else {
                unreachable!();
            };
            bail!(
                "inspect protected agent tree symlink `{rel}` target: {error}; refusing incomplete scan"
            );
        }
        let Some(kind) = kind else {
            continue;
        };
        if kind == SurfaceKind::InventoryOnly {
            if is_native_candidate_tree(&rel, &skill_dirs) {
                if let Some(finding) = materialize_native_candidate(Candidate { rel, state })? {
                    findings.push(finding);
                }
            }
            continue;
        }
        push_materialized(
            &mut files,
            &mut findings,
            materialize_candidate(Candidate { rel, state }, kind)?,
        );
    }
    Ok(CollectedSurface { files, findings })
}

fn push_materialized(
    files: &mut Vec<SurfaceFile>,
    findings: &mut Vec<Finding>,
    candidate: MaterializedCandidate,
) {
    match candidate {
        MaterializedCandidate::Text(file) => files.push(file),
        MaterializedCandidate::NativeExecutable(finding) => findings.push(finding),
    }
}

fn materialize_candidate(candidate: Candidate, kind: SurfaceKind) -> Result<MaterializedCandidate> {
    let Candidate { rel, state } = candidate;
    let bytes = match state {
        CandidateState::Bytes(bytes) => bytes,
        CandidateState::NativeExecutable(format) => {
            return Ok(MaterializedCandidate::NativeExecutable(
                native_executable_finding(rel, format),
            ));
        }
        CandidateState::Oversized(size) => bail!(
            "protected agent surface `{rel}` is at least {size} bytes, exceeds scan limit {TEXT_MAX_BYTES}; refusing incomplete scan"
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
    Ok(MaterializedCandidate::Text(SurfaceFile {
        rel,
        content,
        kind,
    }))
}

fn materialize_native_candidate(candidate: Candidate) -> Result<Option<Finding>> {
    let Candidate { rel, state } = candidate;
    match state {
        CandidateState::NativeExecutable(format) => {
            Ok(Some(native_executable_finding(rel, format)))
        }
        CandidateState::MetadataError(error) => {
            bail!("inspect protected agent asset `{rel}`: {error}; refusing incomplete scan")
        }
        CandidateState::ReadError(error) => {
            bail!("read protected agent asset `{rel}`: {error}; refusing incomplete scan")
        }
        CandidateState::Bytes(_)
        | CandidateState::Oversized(_)
        | CandidateState::Symlink
        | CandidateState::SymlinkTargetError(_) => Ok(None),
    }
}

fn native_executable_finding(rel: String, format: &str) -> Finding {
    Finding::new(
        "agent-native-executable",
        Severity::Medium,
        format!(
            "agent surface ships a native {format} executable; binary semantics were not inspected"
        ),
    )
    .at(rel)
}

fn is_protected_tree_path(rel: &str, skill_dirs: &[String]) -> bool {
    rel.split('/').any(|segment| segment == ".claude")
        || rel == "hooks"
        || rel.starts_with("hooks/")
        || skill_dirs
            .iter()
            .any(|directory| rel.starts_with(directory))
}

fn is_native_candidate_tree(rel: &str, skill_dirs: &[String]) -> bool {
    if rel.starts_with("hooks/")
        || skill_dirs
            .iter()
            .any(|directory| rel.starts_with(directory))
    {
        return true;
    }
    let mut previous = None;
    rel.split('/').any(|segment| {
        let is_claude_hook = previous == Some(".claude") && segment == "hooks";
        previous = Some(segment);
        is_claude_hook
    })
}

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
        Ok(absolute) => std::fs::canonicalize(exclude).is_ok_and(|excluded| absolute == excluded),
        Err(_) => false,
    }
}

pub(super) fn path_identity(path: &Path) -> PathBuf {
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

fn read_prefix(path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open agent surface {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(NATIVE_HEADER_BYTES)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read agent surface {}", path.display()))?;
    Ok(bytes)
}

fn native_executable_format(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x7fELF") {
        return Some("ELF");
    }
    if matches!(
        bytes.get(..4),
        Some(
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        )
    ) {
        return Some("Mach-O");
    }
    bytes.starts_with(b"MZ").then_some("PE/DOS")
}

#[cfg(test)]
mod tests {
    use super::native_executable_format;

    #[test]
    fn recognizes_supported_native_executable_headers() {
        assert_eq!(native_executable_format(b"\x7fELFrest"), Some("ELF"));
        for magic in [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xbe, 0xba, 0xfe, 0xca],
            [0xca, 0xfe, 0xba, 0xbf],
            [0xbf, 0xba, 0xfe, 0xca],
        ] {
            assert_eq!(native_executable_format(&magic), Some("Mach-O"));
        }
        assert_eq!(native_executable_format(b"MZpayload"), Some("PE/DOS"));
    }

    #[test]
    fn rejects_non_executable_binary_and_truncated_headers() {
        assert_eq!(native_executable_format(b"\0opaque"), None);
        assert_eq!(native_executable_format(b"\x7fEL"), None);
        assert_eq!(native_executable_format(b"M"), None);
        assert_eq!(native_executable_format(b"#!/bin/sh\nexit 0\n"), None);
    }
}
