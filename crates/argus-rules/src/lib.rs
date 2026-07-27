//! Static detection rules for argus.
//!
//! Each rule is a pure function that takes a [`PackageContext`] and appends
//! `Finding`s. Lockfiles are normalized and evaluated by `argus-lockfile`.
//!
//! The top-level entry point is [`scan_package_dir`]. It never executes code
//! from the scanned artifact — files are read as text or treated as opaque
//! bytes.

use anyhow::{Context, Result};
use argus_core::{ArtifactKind, Decision, Finding, ScanReport};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod binary;
mod content;
mod decision;
mod lifecycle;
mod name;
mod session;

pub use content::scan_text_file;
pub use decision::derive_from_findings as derive_decision_from_findings;
pub use name::{levenshtein, push_typosquat_findings};
pub use session::{
    RuleSession, MAX_EXTERNAL_EVIDENCE_BYTES, MAX_EXTERNAL_FINDINGS, MAX_EXTERNAL_INPUT_BYTES,
    MAX_EXTERNAL_SCAN_FILES, MAX_RULE_DIRECTORY_BYTES, MAX_RULE_FILES, MAX_RULE_FILE_BYTES,
};

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
const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Top-level entry: scan a package directory, return a full report.
pub fn scan_package_dir(path: &Path) -> Result<ScanReport> {
    scan_package_dir_inner(path).map(|(report, _)| report)
}

fn scan_package_dir_inner(path: &Path) -> Result<(ScanReport, PackageJson)> {
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
    lifecycle::run(&ctx, &mut findings)?;
    content::run(&ctx, &mut findings)?;
    binary::run(&ctx, &mut findings);
    name::run(&ctx, &mut findings);

    let decision = decision::derive(&ctx, &findings);

    Ok((
        ScanReport {
            artifact: ArtifactKind::PackageDir,
            path: path.to_path_buf(),
            package_name: package.name.clone(),
            package_version: package.version.clone(),
            decision,
            findings,
            coordinate: None,
            intelligence: None,
            rules: None,
        },
        package,
    ))
}

/// Scan a package directory with one explicitly constructed immutable rule
/// session. External matching and overrides are completed before return.
pub fn scan_package_dir_with_rules(path: &Path, rules: &RuleSession) -> Result<ScanReport> {
    let (mut report, package) = scan_package_dir_inner(path)?;
    rules.scan_directory(path, &mut report.findings)?;
    for (name, body) in &package.scripts {
        rules.scan_bytes(
            &format!(
                "package.json:scripts/{}.sh",
                encode_virtual_path_segment(name)
            ),
            body.as_bytes(),
            &mut report.findings,
        )?;
    }
    rules.validate_external_limits(&report.findings)?;
    rules.finalize_package(&mut report);
    Ok(report)
}

fn encode_virtual_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
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

/// Cheap binary heuristic: NUL byte in first 4 KiB. Exposed so
/// per-ecosystem crates (`argus-pypi`, future `argus-crates`) can reuse
/// the same heuristic when walking their own extracted artifact trees.
pub fn looks_binary(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(4096)];
    head.contains(&0)
}

/// File extensions that should always be treated as native artifacts even when
/// the underlying file happens to be ASCII (fixtures use placeholder text).
pub const NATIVE_BIN_EXTS: &[&str] = &[".so", ".dll", ".dylib", ".node", ".exe"];

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
