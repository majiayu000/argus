//! Static detection rules for argus.
//!
//! Each rule is a pure function that takes a [`PackageContext`] and appends
//! `Finding`s. Lockfiles are normalized and evaluated by `argus-lockfile`.
//!
//! The top-level entry point is [`scan_package_dir`]. It never executes code
//! from the scanned artifact — files are read as text or treated as opaque
//! bytes.

use anyhow::{bail, Context, Result};
use argus_core::fs::read_bounded_utf8_regular_file;
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
pub mod obfuscation;
mod session;
mod session_execution;
pub mod typosquat;

pub use content::{scan_text_file, scan_text_file_checked};
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
const TEXT_MAX_BYTES: usize = 1024 * 1024;
const MAX_PACKAGE_FILES: usize = 100_000;
const MAX_PACKAGE_DEPTH: usize = 128;
const MAX_TOTAL_TEXT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
struct ScanBudget {
    files: usize,
    text_bytes: usize,
}

impl ScanBudget {
    fn observe_file(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_PACKAGE_DEPTH {
            bail!("package path depth {depth} exceeds maximum {MAX_PACKAGE_DEPTH}");
        }
        self.files = self
            .files
            .checked_add(1)
            .context("package file count overflow")?;
        if self.files > MAX_PACKAGE_FILES {
            bail!("package file count exceeds maximum {MAX_PACKAGE_FILES}");
        }
        Ok(())
    }

    fn observe_text(&mut self, bytes: usize) -> Result<()> {
        self.text_bytes = self
            .text_bytes
            .checked_add(bytes)
            .context("package text byte count overflow")?;
        if self.text_bytes > MAX_TOTAL_TEXT_BYTES {
            bail!("package text bytes exceed maximum {MAX_TOTAL_TEXT_BYTES}");
        }
        Ok(())
    }
}

/// Paths whose contents npm content rules depend on. Anything here that was
/// not read is missing evidence, so the scan must fail rather than report a
/// clean package.
fn is_npm_security_relevant(rel: &str) -> bool {
    const EXECUTABLE_EXTS: &[&str] = &[
        ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".sh", ".bash", ".py",
    ];
    let lower = rel.to_ascii_lowercase();
    lower == "package.json"
        || lower.ends_with("/package.json")
        || EXECUTABLE_EXTS.iter().any(|ext| lower.ends_with(ext))
}

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
    let pkg_json_raw = read_bounded_utf8_regular_file(&pkg_json_path, package_json_limit)
        .with_context(|| format!("read package.json at {}", pkg_json_path.display()))?;
    let package: PackageJson = serde_json::from_str(&pkg_json_raw)
        .with_context(|| format!("parse package.json at {}", pkg_json_path.display()))?;

    let (per_file, skipped) =
        scan_text_files_with_context(path, TEXT_MAX_BYTES as u64, execution, |file| {
            let mut lifecycle_findings = Vec::new();
            lifecycle::scan_text_file(file, &mut lifecycle_findings);
            let content_findings = content::scan_npm_text_file(file)?;
            Ok((
                lifecycle_findings,
                content_findings,
                has_native_bin_ext(&file.rel).then(|| file.rel.clone()),
            ))
        })?;

    skipped.require_scanned("npm package", is_npm_security_relevant)?;
    let mut binary_files = skipped.binary;

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
            vulnerability: None,
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
) -> Result<(Vec<O>, SkippedFiles)>
where
    O: Send,
    Work: Fn(&TextFile) -> Result<O> + Sync,
{
    let mut budget = ScanBudget::default();
    let mut inputs = Vec::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        budget.observe_file(entry.depth())?;
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
        Text(O, usize),
        Skipped(String, SkipReason),
    }
    let mut outputs = Vec::new();
    let mut skipped = SkippedFiles::default();
    execution.execute_ordered(
        &inputs,
        None,
        |_index, (rel, abs)| -> Result<Processed<O>> {
            match read_text_file_bounded(rel, abs, text_max_bytes)? {
                TextFileOutcome::Text(file) => {
                    let bytes = file.content.len();
                    Ok(Processed::Text(work(&file)?, bytes))
                }
                TextFileOutcome::Skipped(reason) => Ok(Processed::Skipped(rel.clone(), reason)),
            }
        },
        |_index, processed| {
            match processed {
                Processed::Text(output, bytes) => {
                    budget.observe_text(bytes)?;
                    outputs.push(output);
                }
                Processed::Skipped(rel, reason) => skipped.record(rel, reason),
            }
            Ok(())
        },
    )?;
    Ok((outputs, skipped))
}

/// Why a discovered path never reached the content rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Content exceeded the caller's text limit.
    Oversized,
    /// The path could not be opened or read.
    Unreadable,
    /// Content is a native artifact, not text.
    Binary,
}

/// Paths dropped before rule evaluation, grouped by reason.
///
/// Oversized and unreadable paths are *not* scan results — a scanner that
/// treats them as "nothing found" reports a clean package it never read. Each
/// ecosystem must run [`SkippedFiles::require_scanned`] over the paths whose
/// contents its rules depend on.
#[derive(Debug, Default, Clone)]
pub struct SkippedFiles {
    /// Native artifacts, which binary rules consume as evidence.
    pub binary: Vec<String>,
    /// Paths over the text limit, whose contents were never examined.
    pub oversized: Vec<String>,
    /// Paths that could not be opened or read.
    pub unreadable: Vec<String>,
}

impl SkippedFiles {
    fn record(&mut self, rel: String, reason: SkipReason) {
        match reason {
            SkipReason::Binary => self.binary.push(rel),
            SkipReason::Oversized => self.oversized.push(rel),
            SkipReason::Unreadable => self.unreadable.push(rel),
        }
    }

    /// Fail closed when a path the caller's rules depend on was never read.
    ///
    /// `ecosystem` names the scanner in the error; `is_security_relevant`
    /// decides which relative paths carry detection signal.
    pub fn require_scanned<Relevant>(
        &self,
        ecosystem: &str,
        is_security_relevant: Relevant,
    ) -> Result<()>
    where
        Relevant: Fn(&str) -> bool,
    {
        for rel in &self.oversized {
            if is_security_relevant(rel) {
                bail!("security-relevant {ecosystem} file `{rel}` exceeds text scan limit");
            }
        }
        for rel in &self.unreadable {
            if is_security_relevant(rel) {
                bail!("security-relevant {ecosystem} file `{rel}` could not be read");
            }
        }
        Ok(())
    }
}

/// Outcome of classifying one discovered path.
#[derive(Debug, Clone)]
pub enum TextFileOutcome {
    /// Content was read within the limit and is text.
    Text(TextFile),
    /// Content never reached the rules, with the reason preserved so callers
    /// can distinguish "not text" from "not read".
    Skipped(SkipReason),
}

/// Read at most `text_max_bytes + 1` bytes and classify a single discovered
/// path, closing metadata/read TOCTOU gaps by reading through one descriptor.
///
/// The reason a path was skipped is carried out rather than collapsed into a
/// single "not text" answer: an unreadable or oversized security-relevant file
/// is missing evidence, not an absence of findings.
pub fn read_text_file_bounded(
    rel: &str,
    path: &Path,
    text_max_bytes: u64,
) -> Result<TextFileOutcome> {
    let read_limit = text_max_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("text input byte limit overflow"))?;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(TextFileOutcome::Skipped(SkipReason::Unreadable)),
    };
    let mut bytes = Vec::new();
    if file.take(read_limit).read_to_end(&mut bytes).is_err() {
        return Ok(TextFileOutcome::Skipped(SkipReason::Unreadable));
    }
    if bytes.len() as u64 > text_max_bytes {
        return Ok(TextFileOutcome::Skipped(SkipReason::Oversized));
    }
    if looks_binary(&bytes) {
        return Ok(TextFileOutcome::Skipped(SkipReason::Binary));
    }
    Ok(TextFileOutcome::Text(TextFile {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_package_manifest_fails_closed() {
        let directory = tempfile::tempdir().expect("test directory");
        std::fs::write(
            directory.path().join("package.json"),
            vec![b' '; TEXT_MAX_BYTES + 1],
        )
        .expect("write oversized manifest");
        let error = scan_package_dir(directory.path()).expect_err("oversized package.json");
        assert!(format!("{error:#}").contains("exceeds 1048576 byte limit"));
    }

    #[test]
    fn package_scan_budget_rejects_each_first_excess_unit() {
        let mut files = ScanBudget {
            files: MAX_PACKAGE_FILES,
            text_bytes: 0,
        };
        assert!(files.observe_file(1).is_err());

        let mut text = ScanBudget {
            files: 0,
            text_bytes: MAX_TOTAL_TEXT_BYTES,
        };
        assert!(text.observe_text(1).is_err());

        assert!(ScanBudget::default()
            .observe_file(MAX_PACKAGE_DEPTH + 1)
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn package_manifest_symlink_fails_closed() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("test directory");
        let target = directory.path().join("manifest.json");
        std::fs::write(&target, r#"{"name":"demo","version":"1.0.0"}"#).expect("write target");
        symlink(&target, directory.path().join("package.json")).expect("create symlink");
        assert!(scan_package_dir(directory.path()).is_err());
    }
}
