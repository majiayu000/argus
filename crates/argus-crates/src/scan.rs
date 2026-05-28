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
use argus_core::{ArtifactKind, Finding, ScanReport, Severity};
use argus_fetch::extract_tarball;
use argus_rules::{looks_binary, scan_text_file, TextFile};
use serde::Deserialize;
use std::path::{Component, Path};

const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Top-level: extract `.crate` + scan everything inside.
pub fn scan_crate_archive(
    crate_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<ScanReport> {
    let pkg_dir = extract_tarball(crate_bytes, dest_root, max_extracted_bytes)
        .context("safe-extract .crate")?;
    let scan = scan_extracted_crate(&pkg_dir)?;
    let decision = argus_rules::derive_decision_from_findings(&scan.findings);
    Ok(ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: pkg_dir,
        package_name: scan.name,
        package_version: scan.version,
        decision,
        findings: scan.findings,
    })
}

pub fn scan_extracted_crate(pkg_dir: &Path) -> Result<crate::ArtifactScan> {
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
    let build_script_rel = manifest
        .as_ref()
        .map(cargo_manifest_build_script)
        .transpose()?
        .flatten();
    let mut build_script_seen: Option<String> = None;

    for entry in walkdir::WalkDir::new(pkg_dir).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let abs = entry.path();
        let rel = abs
            .strip_prefix(pkg_dir)
            .unwrap_or(abs)
            .to_string_lossy()
            .replace('\\', "/");
        let meta = entry.metadata()?;
        if meta.len() > TEXT_MAX_BYTES {
            continue;
        }
        let bytes = match std::fs::read(abs) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if looks_binary(&bytes) {
            continue;
        }
        let content = String::from_utf8_lossy(&bytes).into_owned();

        // Generic content rules everywhere.
        scan_text_file(
            &TextFile {
                rel: rel.clone(),
                content: content.clone(),
            },
            &mut findings,
        );

        if build_script_rel.as_deref() == Some(rel.as_str()) {
            build_script_seen = Some(rel.clone());
            scan_build_rs(&content, &rel, &mut findings);
            // build.rs is also a Rust source file — apply the
            // include_bytes! + XOR-loop detectors. The first version of
            // TrapDoor's payload sat in build.rs itself, the second
            // hid it in a sibling module, so we run the source-level
            // checks against both declared build scripts and every other `.rs`.
            scan_rust_source(&content, &rel, &mut findings);
        } else if rel.ends_with(".rs") {
            scan_rust_source(&content, &rel, &mut findings);
        }
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
}

#[derive(Debug, Deserialize)]
struct CargoLib {
    #[serde(rename = "proc-macro")]
    proc_macro: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CargoBuildField {
    Bool(bool),
    Path(String),
}

fn read_top_level_manifest(pkg_dir: &Path) -> Result<Option<CargoManifest>> {
    let manifest_path = pkg_dir.join("Cargo.toml");
    let content = match std::fs::read_to_string(&manifest_path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("read {}", manifest_path.display()));
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

fn cargo_manifest_build_script(manifest: &CargoManifest) -> Result<Option<String>> {
    let Some(package) = manifest.package.as_ref() else {
        return Ok(Some("build.rs".to_string()));
    };
    match package.build.as_ref() {
        Some(CargoBuildField::Bool(false)) => Ok(None),
        Some(CargoBuildField::Bool(true)) | None => Ok(Some("build.rs".to_string())),
        Some(CargoBuildField::Path(path)) => normalize_manifest_relative_path(path).map(Some),
    }
}

fn normalize_manifest_relative_path(raw: &str) -> Result<String> {
    if raw.is_empty() {
        anyhow::bail!("Cargo.toml package.build path is empty");
    }
    if raw.contains('\\') {
        anyhow::bail!("Cargo.toml package.build path must use forward slashes");
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        anyhow::bail!("Cargo.toml package.build path must be relative");
    }

    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                anyhow::bail!("Cargo.toml package.build path must not contain `..`")
            }
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("Cargo.toml package.build path must be relative")
            }
        }
    }
    if parts.is_empty() {
        anyhow::bail!("Cargo.toml package.build path is empty");
    }
    Ok(parts.join("/"))
}

fn scan_build_rs(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    if rules::build_rs_subprocess_regex().is_match(content) {
        findings.push(finding(
            "build-rs-subprocess",
            Severity::Critical,
            format!("`{rel}` invokes std::process::Command at compile time"),
        ));
    }
    if rules::build_rs_network_regex().is_match(content) {
        findings.push(finding(
            "build-rs-network",
            Severity::Critical,
            format!("`{rel}` reaches the network at compile time (reqwest/ureq/hyper/TcpStream)"),
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
mod tests {
    use super::*;

    #[test]
    fn parse_cargo_basic() -> Result<()> {
        let manifest_toml = r#"
[package]
name = "demo"
version = "1.2.3"
edition = "2021"
"#;
        let manifest: CargoManifest = toml::from_str(manifest_toml)?;
        let (n, v) = cargo_manifest_name_version(&manifest).context("package fields")?;
        assert_eq!(n.as_deref(), Some("demo"));
        assert_eq!(v.as_deref(), Some("1.2.3"));
        Ok(())
    }

    #[test]
    fn detect_proc_macro_lib() -> Result<()> {
        let manifest_toml = r#"
[package]
name = "x"
version = "1.0.0"

[lib]
proc-macro = true
"#;
        let manifest: CargoManifest = toml::from_str(manifest_toml)?;
        assert!(cargo_manifest_is_proc_macro(&manifest));
        Ok(())
    }

    #[test]
    fn benign_lib_section_is_not_proc_macro() -> Result<()> {
        let manifest_toml = r#"
[package]
name = "x"
version = "1.0.0"

[lib]
name = "x_inner"
"#;
        let manifest: CargoManifest = toml::from_str(manifest_toml)?;
        assert!(!cargo_manifest_is_proc_macro(&manifest));
        Ok(())
    }

    #[test]
    fn custom_build_script_path_is_parsed() -> Result<()> {
        let manifest: CargoManifest = toml::from_str(
            r#"
[package]
name = "x"
version = "1.0.0"
build = "build/main.rs"
"#,
        )?;
        assert_eq!(
            cargo_manifest_build_script(&manifest)?.as_deref(),
            Some("build/main.rs")
        );
        Ok(())
    }

    #[test]
    fn build_false_disables_build_script() -> Result<()> {
        let manifest: CargoManifest = toml::from_str(
            r#"
[package]
name = "x"
version = "1.0.0"
build = false
"#,
        )?;
        assert_eq!(cargo_manifest_build_script(&manifest)?, None);
        Ok(())
    }

    #[test]
    fn custom_build_script_path_rejects_traversal() -> Result<()> {
        let err = match normalize_manifest_relative_path("../build.rs") {
            Ok(path) => anyhow::bail!("parent traversal was accepted as {path}"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains(".."), "got: {err}");
        Ok(())
    }
}
