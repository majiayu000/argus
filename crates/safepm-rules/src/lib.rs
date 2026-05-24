//! Static detection rules for safepm.
//!
//! Each rule is a pure function that takes a [`PackageContext`] (for
//! directory scans) or a parsed lockfile, and appends `Finding`s.
//!
//! The top-level entry points are [`scan_package_dir`] and
//! [`scan_lockfile`]. They never execute any code from the scanned
//! artifact — files are read as text or treated as opaque bytes.

use anyhow::{Context, Result};
use safepm_core::{ArtifactKind, Decision, Finding, ScanReport};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod binary;
mod content;
mod decision;
mod lifecycle;
mod lockfile;
mod name;

pub use lockfile::scan_lockfile;

/// Parsed `package.json` view used by rules. Only fields the rules need.
#[derive(Debug, Clone, Deserialize)]
pub struct PackageJson {
    pub name: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub scripts: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: BTreeMap<String, String>,
}

/// One text file collected from a package directory.
#[derive(Debug, Clone)]
pub struct TextFile {
    pub rel: String,
    pub content: String,
}

/// Context shared by directory-scan rules.
pub struct PackageContext {
    pub root: PathBuf,
    pub package: PackageJson,
    pub text_files: Vec<TextFile>,
    pub binary_files: Vec<String>,
}

/// Maximum size we attempt to read as text. Larger files are treated as binary.
const TEXT_MAX_BYTES: u64 = 1 * 1024 * 1024;

/// Top-level entry: scan a package directory, return a full report.
pub fn scan_package_dir(path: &Path) -> Result<ScanReport> {
    let pkg_json_path = path.join("package.json");
    let pkg_json_raw = std::fs::read_to_string(&pkg_json_path)
        .with_context(|| format!("read package.json at {}", pkg_json_path.display()))?;
    let package: PackageJson = serde_json::from_str(&pkg_json_raw)
        .with_context(|| format!("parse package.json at {}", pkg_json_path.display()))?;

    let (text_files, binary_files) = collect_files(path)?;

    let ctx = PackageContext {
        root: path.to_path_buf(),
        package: package.clone(),
        text_files,
        binary_files,
    };

    let mut findings: Vec<Finding> = Vec::new();
    lifecycle::run(&ctx, &mut findings);
    content::run(&ctx, &mut findings);
    binary::run(&ctx, &mut findings);
    name::run(&ctx, &mut findings);

    let decision = decision::derive(&ctx, &findings);

    Ok(ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: path.to_path_buf(),
        package_name: package.name.clone(),
        package_version: package.version.clone(),
        decision,
        findings,
    })
}

fn collect_files(root: &Path) -> Result<(Vec<TextFile>, Vec<String>)> {
    let mut texts = Vec::new();
    let mut bins = Vec::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let abs = entry.path();
        let rel = abs
            .strip_prefix(root)
            .unwrap_or(abs)
            .to_string_lossy()
            .replace('\\', "/");
        let meta = entry.metadata()?;
        if meta.len() > TEXT_MAX_BYTES {
            bins.push(rel);
            continue;
        }
        let bytes = match std::fs::read(abs) {
            Ok(b) => b,
            Err(_) => {
                bins.push(rel);
                continue;
            }
        };
        if looks_binary(&bytes) {
            bins.push(rel);
        } else {
            let content = String::from_utf8_lossy(&bytes).into_owned();
            texts.push(TextFile { rel, content });
        }
    }
    Ok((texts, bins))
}

/// Cheap binary heuristic: NUL byte in first 4 KiB, or extension is a known
/// native artifact suffix.
fn looks_binary(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(4096)];
    head.contains(&0)
}

/// File extensions that should always be treated as native artifacts even when
/// the underlying file happens to be ASCII (fixtures use placeholder text).
pub const NATIVE_BIN_EXTS: &[&str] = &[
    ".so", ".dll", ".dylib", ".node", ".exe",
];

pub fn has_native_bin_ext(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    NATIVE_BIN_EXTS.iter().any(|ext| lower.ends_with(ext))
}

/// Combine all script bodies into one string for cheap regex sweeps.
pub fn all_script_bodies(pkg: &PackageJson) -> String {
    let mut s = String::new();
    for (k, v) in &pkg.scripts {
        s.push_str(k);
        s.push('\n');
        s.push_str(v);
        s.push('\n');
    }
    s
}

/// Derive a decision externally (used by tests + corpus runner).
pub fn derive_decision(ctx: &PackageContext, findings: &[Finding]) -> Decision {
    decision::derive(ctx, findings)
}
