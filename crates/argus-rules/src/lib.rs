//! Static detection rules for argus.
//!
//! Each rule is a pure function that takes a [`PackageContext`] and appends
//! `Finding`s. Lockfiles are normalized and evaluated by `argus-lockfile`.
//!
//! The top-level entry point is [`scan_package_dir`]. It never executes code
//! from the scanned artifact — files are read as text or treated as opaque
//! bytes.

use anyhow::{Context, Result};
use argus_core::{ArtifactKind, Decision, ExecutionContext, Finding, ScanReport};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

mod binary;
mod content;
mod decision;
mod lifecycle;
mod name;
mod session;
mod session_execution;
pub mod typosquat;

pub use content::scan_text_file;
pub use decision::derive_from_findings as derive_decision_from_findings;
pub use session::{
    RuleSession, MAX_EXTERNAL_EVIDENCE_BYTES, MAX_EXTERNAL_FINDINGS, MAX_EXTERNAL_INPUT_BYTES,
    MAX_EXTERNAL_SCAN_FILES, MAX_RULE_DIRECTORY_BYTES, MAX_RULE_FILES, MAX_RULE_FILE_BYTES,
};
pub use session_execution::ExternalScanBudget;

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
    let rules = RuleSession::builtin()?;
    scan_package_dir_with_rules(path, &rules)
}

fn scan_package_dir_inner_with_limit(
    path: &Path,
    package_json_limit: usize,
    rules: &RuleSession,
    execution: &ExecutionContext,
) -> Result<(ScanReport, PackageJson)> {
    let pkg_json_path = path.join("package.json");
    let file = std::fs::File::open(&pkg_json_path)
        .with_context(|| format!("open package.json at {}", pkg_json_path.display()))?;
    let mut bytes = Vec::new();
    file.take(package_json_limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read package.json at {}", pkg_json_path.display()))?;
    if bytes.len() > package_json_limit {
        anyhow::bail!("package manifest exceeds {package_json_limit} bytes");
    }
    let pkg_json_raw = String::from_utf8(bytes).with_context(|| {
        format!(
            "package.json is not valid UTF-8 at {}",
            pkg_json_path.display()
        )
    })?;
    let package: PackageJson = serde_json::from_str(&pkg_json_raw)
        .with_context(|| format!("parse package.json at {}", pkg_json_path.display()))?;

    let (per_file, mut binary_files) =
        scan_text_files_with_context(path, TEXT_MAX_BYTES, execution, |file| {
            let mut lifecycle_findings = Vec::new();
            lifecycle::scan_text_file(file, &mut lifecycle_findings);
            let content_findings = content::scan_npm_text_file(file)?;
            Ok((
                lifecycle_findings,
                content_findings,
                has_native_bin_ext(&file.rel).then(|| file.rel.clone()),
            ))
        })?;

    let ctx = PackageContext {
        root: path.to_path_buf(),
        package: package.clone(),
        text_files: Vec::new(),
        binary_files: Vec::new(),
    };

    let mut findings: Vec<Finding> = Vec::new();
    lifecycle::run(&ctx, &mut findings)?;
    let mut content_findings = Vec::new();
    for (mut lifecycle_findings, mut per_file_findings, native_path) in per_file {
        findings.append(&mut lifecycle_findings);
        content_findings.append(&mut per_file_findings);
        if let Some(rel) = native_path {
            binary_files.push(rel);
        }
    }
    findings.append(&mut content_findings);
    let binary_ctx = PackageContext {
        root: path.to_path_buf(),
        package: package.clone(),
        text_files: Vec::new(),
        binary_files,
    };
    binary::run(&binary_ctx, &mut findings);
    name::run(&ctx, rules, &mut findings)?;

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
    let execution = ExecutionContext::serial().context("build serial scan execution context")?;
    scan_package_dir_with_rules_and_context(path, rules, &execution)
}

/// Scan a package directory in an invocation-local execution context.
pub fn scan_package_dir_with_context(
    path: &Path,
    execution: &ExecutionContext,
) -> Result<ScanReport> {
    let rules = RuleSession::builtin()?;
    scan_package_dir_with_rules_and_context(path, &rules, execution)
}

/// Scan a package directory with explicit rules and invocation-local workers.
pub fn scan_package_dir_with_rules_and_context(
    path: &Path,
    rules: &RuleSession,
    execution: &ExecutionContext,
) -> Result<ScanReport> {
    let (mut report, package) =
        scan_package_dir_inner_with_limit(path, MAX_EXTERNAL_INPUT_BYTES, rules, execution)?;
    rules.scan_directory_with_virtual_inputs_and_context(
        path,
        package.scripts.len(),
        package.scripts.iter().map(|(name, body)| {
            (
                format!(
                    "package.json:scripts/{}.sh",
                    encode_virtual_path_segment(name)
                ),
                body.as_bytes(),
            )
        }),
        &mut report.findings,
        execution,
    )?;
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

/// Discover regular files serially, then bounded-read, classify, and process
/// them in stable path order through the invocation-local worker pool.
///
/// Only each worker's small owned result is retained. File contents remain
/// live for the duration of that worker call and are dropped before the next
/// bounded window starts.
pub fn scan_text_files_with_context<O, Work>(
    root: &Path,
    text_max_bytes: u64,
    execution: &ExecutionContext,
    work: Work,
) -> Result<(Vec<O>, Vec<String>)>
where
    O: Send,
    Work: Fn(&TextFile) -> Result<O> + Sync,
{
    let mut inputs = Vec::new();
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
        inputs.push((rel, abs.to_path_buf()));
    }
    inputs.sort_by(|left, right| left.0.cmp(&right.0));

    enum Processed<O> {
        Text(O),
        Binary(String),
    }
    let mut outputs = Vec::new();
    let mut bins = Vec::new();
    execution.execute_ordered(
        &inputs,
        None,
        |_index, (rel, abs)| -> Result<Processed<O>> {
            match read_text_file_bounded(rel, abs, text_max_bytes)? {
                Some(file) => Ok(Processed::Text(work(&file)?)),
                None => Ok(Processed::Binary(rel.clone())),
            }
        },
        |_index, processed| {
            match processed {
                Processed::Text(output) => outputs.push(output),
                Processed::Binary(rel) => bins.push(rel),
            }
            Ok(())
        },
    )?;
    Ok((outputs, bins))
}

/// Read at most `text_max_bytes + 1` bytes and classify a single discovered
/// path. Returning `None` preserves the existing unreadable, oversized, and
/// binary-file treatment while closing metadata/read TOCTOU gaps.
pub fn read_text_file_bounded(
    rel: &str,
    path: &Path,
    text_max_bytes: u64,
) -> Result<Option<TextFile>> {
    let read_limit = text_max_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("text input byte limit overflow"))?;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let mut bytes = Vec::new();
    if file.take(read_limit).read_to_end(&mut bytes).is_err() {
        return Ok(None);
    }
    if bytes.len() as u64 > text_max_bytes || looks_binary(&bytes) {
        return Ok(None);
    }
    Ok(Some(TextFile {
        rel: rel.to_string(),
        content: String::from_utf8_lossy(&bytes).into_owned(),
    }))
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
