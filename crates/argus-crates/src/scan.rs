//! Walk an extracted `.crate` tree and produce a `ScanReport`.
//!
//! What runs here:
//! - Ecosystem-agnostic content rules from `argus-rules` (credential-access,
//!   ai-context-poisoning, etc.) against every text file.
//! - Crates-specific rules from `crate::rules` against `build.rs` and
//!   proc-macro entry points.
//! - Cargo.toml manifest parsing for name, version, and proc-macro flag.

use crate::{finding, rules};
use anyhow::{Context, Result};
use argus_archive::extract_tarball;
use argus_core::{ArtifactKind, Finding, ScanReport, Severity};
use argus_rules::{looks_binary, scan_text_file, scan_text_files_with_context, RuleSession};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use syn::parse::Parser;
use syn::visit::Visit;

mod macro_expansion;

/// Crate paths whose contents the crates.io rules read.
fn is_crate_security_relevant(rel: &str) -> bool {
    rel.ends_with(".rs") || rel == "Cargo.toml" || rel.ends_with("/Cargo.toml")
}

const TEXT_MAX_BYTES: u64 = 1024 * 1024;
const MAX_PROC_MACRO_SOURCE_FILES: usize = 1024;
const MAX_PROC_MACRO_MODULE_DECLARATIONS: usize = 8192;
const MAX_PROC_MACRO_RESOLUTION_EDGES: usize = 4096;
const MAX_PROC_MACRO_META_DEPTH: usize = 128;
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
#[cfg(windows)]
const WINDOWS_ERROR_CANT_RESOLVE_FILENAME: i32 = 1921;

/// Top-level: extract `.crate` + scan everything inside.
pub fn scan_crate_archive(
    crate_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<ScanReport> {
    let rules = RuleSession::builtin()?;
    scan_crate_archive_with_rules(crate_bytes, dest_root, max_extracted_bytes, &rules)
}

pub fn scan_crate_archive_with_rules(
    crate_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
) -> Result<ScanReport> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_crate_archive_with_rules_and_context(
        crate_bytes,
        dest_root,
        max_extracted_bytes,
        rules,
        &execution,
    )
}

pub fn scan_crate_archive_with_rules_and_context(
    crate_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<ScanReport> {
    let pkg_dir = extract_tarball(crate_bytes, dest_root, max_extracted_bytes)
        .context("safe-extract .crate")?;
    let builtin = RuleSession::builtin()?;
    let mut scan = scan_extracted_crate_with_rules_and_context(&pkg_dir, &builtin, execution)?;
    rules
        .scan_directory_with_context(dest_root, &mut scan.findings, execution)
        .context("run configured rules on extracted .crate archive")?;
    rules.validate_external_limits(&scan.findings)?;
    rules.normalize_findings(&mut scan.findings);
    let decision = argus_rules::derive_decision_from_findings(&scan.findings);
    let mut report = ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: pkg_dir,
        package_name: scan.name,
        package_version: scan.version,
        decision,
        findings: scan.findings,
        coordinate: None,
        intelligence: None,
        rules: None,
        vulnerability: None,
        risk: None,
    };
    rules.finalize_package(&mut report);
    Ok(report)
}

pub fn scan_extracted_crate(pkg_dir: &Path) -> Result<crate::ArtifactScan> {
    let rules = RuleSession::builtin()?;
    scan_extracted_crate_with_rules(pkg_dir, &rules)
}

pub fn scan_extracted_crate_with_rules(
    pkg_dir: &Path,
    rules: &RuleSession,
) -> Result<crate::ArtifactScan> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_extracted_crate_with_rules_and_context(pkg_dir, rules, &execution)
}

pub fn scan_extracted_crate_with_rules_and_context(
    pkg_dir: &Path,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<crate::ArtifactScan> {
    let mut findings: Vec<Finding> = Vec::new();
    let manifest = read_top_level_manifest(pkg_dir)?;
    let (name, version) = manifest
        .as_ref()
        .and_then(cargo_manifest_name_version)
        .unwrap_or((None, None));
    let is_proc_macro = manifest
        .as_ref()
        .map(cargo_manifest_is_proc_macro)
        .unwrap_or(false);
    let proc_macro_source_files = manifest
        .as_ref()
        .map(|manifest| collect_proc_macro_source_files(pkg_dir, manifest))
        .transpose()?
        .unwrap_or_default();
    let build_script_rel = manifest
        .as_ref()
        .map(cargo_manifest_build_script)
        .transpose()?
        .flatten();
    let mut build_script_seen: Option<String> = None;

    let (file_results, skipped) =
        scan_text_files_with_context(pkg_dir, TEXT_MAX_BYTES, execution, |file| {
            let mut per_file = Vec::new();
            scan_text_file(file, &mut per_file);
            let is_build_script = build_script_rel.as_deref() == Some(file.rel.as_str());
            if is_build_script {
                scan_build_rs(&file.content, &file.rel, &mut per_file);
                scan_rust_source(&file.content, &file.rel, &mut per_file);
            } else {
                if file.rel.ends_with(".rs") {
                    scan_rust_source(&file.content, &file.rel, &mut per_file);
                }
                if proc_macro_source_files.contains(&file.rel) {
                    scan_proc_macro_source(&file.content, &file.rel, &mut per_file);
                }
            }
            Ok::<_, anyhow::Error>((per_file, is_build_script.then(|| file.rel.clone())))
        })?;
    skipped.require_scanned("crate", is_crate_security_relevant)?;
    for (mut per_file, build_script) in file_results {
        build_script_seen = build_script_seen.take().or(build_script);
        findings.append(&mut per_file);
    }

    // Structural meta-findings.
    if let Some(rel) = build_script_seen {
        findings.push(finding(
            "build-rs-execution",
            Severity::Info,
            format!("crate declares build script `{rel}` — runs at consumer compile time"),
        ));
    }
    if is_proc_macro {
        findings.push(finding(
            "proc-macro-crate",
            Severity::Info,
            "crate declares `[lib] proc-macro = true` — code runs at consumer compile time",
        ));
    }

    rules
        .scan_directory_with_context(pkg_dir, &mut findings, execution)
        .context("run configured rules on extracted .crate")?;
    rules.validate_external_limits(&findings)?;
    rules.normalize_findings(&mut findings);

    Ok(crate::ArtifactScan {
        findings,
        name,
        version,
    })
}

#[derive(Debug, Deserialize)]
struct CargoManifest {
    package: Option<CargoPackage>,
    lib: Option<CargoLib>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: Option<String>,
    version: Option<String>,
    build: Option<CargoBuildField>,
    edition: Option<toml::Value>,
}

#[derive(Debug, Deserialize)]
struct CargoLib {
    #[serde(rename = "proc-macro")]
    proc_macro: Option<bool>,
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CargoBuildField {
    Bool(bool),
    Path(String),
}

fn read_top_level_manifest(pkg_dir: &Path) -> Result<Option<CargoManifest>> {
    let manifest_path = pkg_dir.join("Cargo.toml");
    // Read through one no-follow descriptor: a `Cargo.toml` symlinked out of
    // the extracted tree must not be followed, and the regular-file check
    // belongs on the descriptor that is actually read.
    let content = match argus_core::fs::read_bounded_utf8_regular_file(
        &manifest_path,
        TEXT_MAX_BYTES as usize,
    ) {
        Ok(content) => content,
        Err(_error) if !manifest_path.exists() => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", manifest_path.display()))
        }
    };
    toml::from_str(&content).with_context(|| format!("parse {}", manifest_path.display()))
}

fn cargo_manifest_name_version(
    manifest: &CargoManifest,
) -> Option<(Option<String>, Option<String>)> {
    let package = manifest.package.as_ref()?;
    Some((package.name.clone(), package.version.clone()))
}

fn cargo_manifest_is_proc_macro(manifest: &CargoManifest) -> bool {
    manifest
        .lib
        .as_ref()
        .and_then(|lib| lib.proc_macro)
        .unwrap_or(false)
}

fn cargo_manifest_proc_macro_lib_path(manifest: &CargoManifest) -> Result<Option<String>> {
    if !cargo_manifest_is_proc_macro(manifest) {
        return Ok(None);
    }
    let path = manifest
        .lib
        .as_ref()
        .and_then(|lib| lib.path.as_deref())
        .unwrap_or("src/lib.rs");
    normalize_manifest_relative_path(path, "Cargo.toml lib.path").map(Some)
}

fn cargo_manifest_build_script(manifest: &CargoManifest) -> Result<Option<String>> {
    let Some(package) = manifest.package.as_ref() else {
        return Ok(Some("build.rs".to_string()));
    };
    match package.build.as_ref() {
        Some(CargoBuildField::Bool(false)) => Ok(None),
        Some(CargoBuildField::Bool(true)) | None => Ok(Some("build.rs".to_string())),
        Some(CargoBuildField::Path(path)) => {
            normalize_manifest_relative_path(path, "Cargo.toml package.build").map(Some)
        }
    }
}

fn normalize_manifest_relative_path(raw: &str, field: &str) -> Result<String> {
    if raw.is_empty() {
        anyhow::bail!("{field} path is empty");
    }
    if raw.contains('\\') {
        anyhow::bail!("{field} path must use forward slashes");
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        anyhow::bail!("{field} path must be relative");
    }

    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                anyhow::bail!("{field} path must not contain `..`")
            }
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("{field} path must be relative")
            }
        }
    }
    if parts.is_empty() {
        anyhow::bail!("{field} path is empty");
    }
    Ok(parts.join("/"))
}

mod proc_macro_modules;
use proc_macro_modules::*;

fn scan_build_rs(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    if rules::build_rs_subprocess_regex().is_match(content) {
        findings.push(finding(
            "build-rs-subprocess",
            Severity::Critical,
            format!("`{rel}` invokes std::process::Command at compile time"),
        ));
    }
    let executable_code = rules::mask_rust_comments_and_literals(content);
    if rules::build_rs_network_regex().is_match(&executable_code) {
        findings.push(finding(
            "build-rs-network",
            Severity::Critical,
            format!("`{rel}` reaches the network at compile time (reqwest/ureq/hyper/TcpStream)"),
        ));
    }
}

fn scan_proc_macro_source(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    let executable_code = rules::mask_rust_comments_and_literals(content);
    if rules::build_rs_network_regex().is_match(&executable_code) {
        findings.push(finding(
            "proc-macro-network",
            Severity::Critical,
            format!(
                "`{rel}` reaches the network from proc-macro source that runs at consumer compile time"
            ),
        ));
    }
}

fn scan_rust_source(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    let has_include_bytes = rules::include_bytes_regex().is_match(content);
    let has_xor_loop = rules::xor_loop_regex().is_match(content);
    if has_include_bytes && has_xor_loop {
        findings.push(finding(
            "build-rs-include-bytes",
            Severity::Critical,
            format!("`{rel}` embeds a binary blob via `include_bytes!` and contains an XOR decrypt loop — classic payload-decryption shape"),
        ));
    } else if has_xor_loop {
        findings.push(finding(
            "xor-decryption-loop",
            Severity::High,
            format!("`{rel}` contains a byte-by-byte XOR decrypt loop"),
        ));
    } else if has_include_bytes {
        findings.push(finding(
            "embedded-binary-blob",
            Severity::Info,
            format!("`{rel}` embeds binary bytes via `include_bytes!` — legitimate for fonts/configs but worth a glance"),
        ));
    }
}

#[cfg(test)]
mod tests;
