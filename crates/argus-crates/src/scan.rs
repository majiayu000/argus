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
use argus_rules::{looks_binary, scan_text_file, TextFile};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

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
        coordinate: None,
        intelligence: None,
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
            if proc_macro_source_files.contains(&rel) {
                scan_proc_macro_source(&content, &rel, &mut findings);
            }
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

fn collect_proc_macro_source_files(
    pkg_dir: &Path,
    manifest: &CargoManifest,
) -> Result<BTreeSet<String>> {
    let Some(root_rel) = cargo_manifest_proc_macro_lib_path(manifest)? else {
        return Ok(BTreeSet::new());
    };
    let mut source_files = BTreeSet::new();
    let mut pending = vec![root_rel.clone()];

    while let Some(rel) = pending.pop() {
        if !source_files.insert(rel.clone()) {
            continue;
        }
        let abs = pkg_dir.join(&rel);
        let bytes = std::fs::read(&abs)
            .with_context(|| format!("read proc-macro source {}", abs.display()))?;
        if bytes.len() as u64 > TEXT_MAX_BYTES || looks_binary(&bytes) {
            continue;
        }
        let content = String::from_utf8_lossy(&bytes);
        let masked = rules::mask_rust_comments_and_literals(&content);
        let module_base = rust_module_base(Path::new(&rel), &root_rel);

        for captures in rules::rust_module_decl_regex().captures_iter(&masked) {
            let Some(module_name) = captures.get(1).map(|capture| capture.as_str()) else {
                continue;
            };
            let flat = module_base.join(format!("{module_name}.rs"));
            let nested = module_base.join(module_name).join("mod.rs");
            let flat_exists = pkg_dir.join(&flat).is_file();
            let nested_exists = pkg_dir.join(&nested).is_file();
            if flat_exists && nested_exists {
                anyhow::bail!(
                    "proc-macro module `{module_name}` is ambiguous: both {} and {} exist",
                    flat.display(),
                    nested.display()
                );
            }
            let module = if flat_exists {
                Some(flat)
            } else if nested_exists {
                Some(nested)
            } else {
                None
            };
            if let Some(module) = module {
                pending.push(path_to_manifest_rel(&module)?);
            }
        }
    }

    Ok(source_files)
}

fn rust_module_base(current: &Path, root_rel: &str) -> PathBuf {
    let parent = current.parent().unwrap_or_else(|| Path::new(""));
    if current == Path::new(root_rel) || current.file_name().is_some_and(|name| name == "mod.rs") {
        parent.to_path_buf()
    } else {
        parent.join(current.file_stem().unwrap_or_default())
    }
}

fn path_to_manifest_rel(path: &Path) -> Result<String> {
    let raw = path.to_string_lossy().replace('\\', "/");
    normalize_manifest_relative_path(&raw, "resolved proc-macro module")
}

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
mod tests {
    use super::*;

    fn scan_test_tree(files: &[(&str, &str)]) -> Result<crate::ArtifactScan> {
        let root = tempfile::tempdir()?;
        for (rel, content) in files {
            let path = root.path().join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, content)?;
        }
        scan_extracted_crate(root.path())
    }

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
        let err = match normalize_manifest_relative_path("../build.rs", "Cargo.toml package.build")
        {
            Ok(path) => anyhow::bail!("parent traversal was accepted as {path}"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains(".."), "got: {err}");
        Ok(())
    }

    #[test]
    fn proc_macro_source_graph_excludes_disabled_build_and_auxiliary_targets() -> Result<()> {
        let manifest = r#"
[package]
name = "bounded-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#;
        let network = r#"fn probe() { reqwest::get("https://inert.example.invalid"); }"#;
        let scan = scan_test_tree(&[
            ("Cargo.toml", manifest),
            ("src/lib.rs", "mod active;"),
            ("src/active.rs", "pub fn expand() {}"),
            ("src/unrelated.rs", network),
            ("src/bin/tool.rs", network),
            ("build.rs", network),
            ("tests/network.rs", network),
            ("examples/network.rs", network),
            ("benches/network.rs", network),
        ])?;
        let rule_ids: Vec<&str> = scan
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();

        assert!(
            !rule_ids.contains(&"proc-macro-network"),
            "got: {rule_ids:?}"
        );
        assert!(!rule_ids.contains(&"build-rs-network"), "got: {rule_ids:?}");
        Ok(())
    }

    #[test]
    fn proc_macro_custom_build_ignores_inactive_default_build_rs() -> Result<()> {
        let manifest = r#"
[package]
name = "custom-build-derive"
version = "1.0.0"
build = "tools/generate.rs"

[lib]
proc-macro = true
"#;
        let custom = r#"fn main() { reqwest::get("https://active-build.example.invalid"); }"#;
        let inactive = r#"fn main() { reqwest::get("https://inactive-build.example.invalid"); }"#;
        let scan = scan_test_tree(&[
            ("Cargo.toml", manifest),
            ("src/lib.rs", ""),
            ("tools/generate.rs", custom),
            ("build.rs", inactive),
        ])?;
        let build_findings: Vec<&Finding> = scan
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "build-rs-network")
            .collect();

        assert_eq!(build_findings.len(), 1, "got: {:?}", scan.findings);
        assert!(build_findings[0].detail.contains("tools/generate.rs"));
        assert!(
            !scan
                .findings
                .iter()
                .any(|finding| finding.rule_id == "proc-macro-network"),
            "got: {:?}",
            scan.findings
        );
        Ok(())
    }

    #[test]
    fn proc_macro_custom_lib_path_follows_only_declared_modules() -> Result<()> {
        let manifest = r#"
[package]
name = "custom-root-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
path = "macro/entry.rs"
"#;
        let network = r#"pub fn expand() { ureq::get("https://macro.example.invalid").call(); }"#;
        let scan = scan_test_tree(&[
            ("Cargo.toml", manifest),
            ("macro/entry.rs", "mod support;"),
            ("macro/support.rs", network),
            ("macro/unrelated.rs", network),
            ("src/lib.rs", network),
        ])?;
        let findings: Vec<&Finding> = scan
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "proc-macro-network")
            .collect();

        assert_eq!(findings.len(), 1, "got: {:?}", scan.findings);
        assert!(findings[0].detail.contains("macro/support.rs"));
        Ok(())
    }

    #[test]
    fn proc_macro_inert_network_text_does_not_block() -> Result<()> {
        let manifest = r#"
[package]
name = "documented-derive"
version = "1.0.0"

[lib]
proc-macro = true
"#;
        let source = r##"
// reqwest::get("https://line.example.invalid");
/* outer /* ureq::get("nested") */ block */
const NORMAL: &str = "hyper::Client(\"normal\")";
const RAW: &str = r#"std::net::TcpStream::connect("raw")"#;
const BYTES: &[u8] = b"reqwest::blocking::get(\"bytes\")";
const RAW_BYTES: &[u8] = br#"ureq::post("raw bytes")"#;
const CHARACTER: char = 'r';
"##;
        let scan = scan_test_tree(&[("Cargo.toml", manifest), ("src/lib.rs", source)])?;

        assert!(
            !scan
                .findings
                .iter()
                .any(|finding| finding.rule_id == "proc-macro-network"),
            "got: {:?}",
            scan.findings
        );
        Ok(())
    }

    #[test]
    fn build_script_inert_network_text_does_not_trigger_network_rule() -> Result<()> {
        let manifest = r#"
[package]
name = "documented-build"
version = "1.0.0"
"#;
        let build_rs = r##"
// reqwest::get("https://line.example.invalid");
/* outer /* ureq::get("nested") */ block */
const EXAMPLE: &str = r#"std::net::TcpStream::connect("raw")"#;
fn main() {}
"##;
        let scan = scan_test_tree(&[
            ("Cargo.toml", manifest),
            ("build.rs", build_rs),
            ("src/lib.rs", ""),
        ])?;

        assert!(
            !scan
                .findings
                .iter()
                .any(|finding| finding.rule_id == "build-rs-network"),
            "got: {:?}",
            scan.findings
        );
        Ok(())
    }
}
