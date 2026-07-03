//! Static detection rules for agent supply-chain surfaces (GH-57).
//!
//! Scans MCP configs, skill definitions, hook scripts, and high-context
//! instruction files (`AGENTS.md` / `CLAUDE.md`) for injection language,
//! dangerous capability combinations, and high-risk configuration flags.
//!
//! Like `argus-rules`, every rule is a pure function over collected file
//! contents: nothing from the scanned tree is ever executed. Unreadable
//! files are skipped per-file instead of failing the whole scan.

use anyhow::Result;
use argus_core::{ArtifactKind, Finding, ScanReport};
use std::path::Path;

mod capability;
mod config;
mod decision;
mod injection;
mod surface;

pub use surface::{classify, SurfaceKind};

/// One text file collected from the scanned tree, with its surface class.
pub struct SurfaceFile {
    pub rel: String,
    pub content: String,
    pub kind: SurfaceKind,
}

/// Maximum size we attempt to read as text (matches argus-rules).
const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Top-level entry: scan a directory (or single file) as an agent surface.
pub fn scan_agent_surface(path: &Path) -> Result<ScanReport> {
    let files = collect_surface_files(path)?;

    let mut findings: Vec<Finding> = Vec::new();
    injection::run(&files, &mut findings);
    capability::run(&files, &mut findings);
    config::run(path, &files, &mut findings);

    let decision = decision::derive(&findings);

    Ok(ScanReport {
        artifact: ArtifactKind::AgentSurface,
        path: path.to_path_buf(),
        package_name: None,
        package_version: None,
        decision,
        findings,
    })
}

fn collect_surface_files(root: &Path) -> Result<Vec<SurfaceFile>> {
    let mut raw: Vec<(String, String)> = Vec::new();
    if root.is_file() {
        if let Some(content) = read_text(root) {
            let rel = root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            raw.push((rel, content));
        }
    } else {
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue, // unreadable entry: skip, keep scanning
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let abs = entry.path();
            match entry.metadata() {
                Ok(m) if m.len() > TEXT_MAX_BYTES => continue,
                Err(_) => continue,
                _ => {}
            }
            let Some(content) = read_text(abs) else {
                continue;
            };
            let rel = abs
                .strip_prefix(root)
                .unwrap_or(abs)
                .to_string_lossy()
                .replace('\\', "/");
            raw.push((rel, content));
        }
    }

    // Directories that contain a SKILL.md: scripts underneath are skill scripts.
    let skill_dirs: Vec<String> = raw
        .iter()
        .filter(|(rel, _)| rel == "SKILL.md" || rel.ends_with("/SKILL.md"))
        .map(|(rel, _)| rel.trim_end_matches("SKILL.md").to_string())
        .collect();

    Ok(raw
        .into_iter()
        .filter_map(|(rel, content)| {
            classify(&rel, &skill_dirs).map(|kind| SurfaceFile { rel, content, kind })
        })
        .collect())
}

fn read_text(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if argus_rules::looks_binary(&bytes) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_string_outside_agent_shapes_is_not_scanned() {
        // Product invariant P6: defensive quotes in ordinary source files
        // must not fire — src/main.rs is not an agent surface shape.
        let dir = tempdir();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/main.rs"),
            "// test fixture: \"ignore previous instructions\"",
        )
        .unwrap();
        let report = scan_agent_surface(&dir).unwrap();
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.decision, argus_core::Decision::Allow);
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "argus-agent-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
