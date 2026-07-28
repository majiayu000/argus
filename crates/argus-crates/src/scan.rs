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
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

const TEXT_MAX_BYTES: u64 = 1024 * 1024;

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

    let (file_results, _) =
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
    let file = match std::fs::File::open(&manifest_path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("open {}", manifest_path.display()));
        }
    };
    let mut bytes = Vec::new();
    file.take(TEXT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    if bytes.len() as u64 > TEXT_MAX_BYTES {
        anyhow::bail!(
            "{} exceeds text input cap {TEXT_MAX_BYTES} bytes",
            manifest_path.display()
        );
    }
    let content = String::from_utf8(bytes)
        .with_context(|| format!("{} is not valid UTF-8", manifest_path.display()))?;
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
    let canonical_pkg_dir = std::fs::canonicalize(pkg_dir)
        .with_context(|| format!("canonicalize crate root {}", pkg_dir.display()))?;
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
        let content = std::str::from_utf8(&bytes)
            .with_context(|| format!("proc-macro source is not UTF-8: {}", abs.display()))?;
        let module_base = rust_module_base(Path::new(&rel), &root_rel);

        for declaration in rules::rust_module_declarations(content)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("parse proc-macro modules in {}", abs.display()))?
        {
            let module = if let Some(explicit_path) = declaration.explicit_path {
                resolve_explicit_module_path(&canonical_pkg_dir, Path::new(&rel), &explicit_path)?
            } else {
                resolve_conventional_module_path(pkg_dir, &module_base, &declaration.name)?
            };
            pending.push(path_to_manifest_rel(&module)?);
        }
    }

    Ok(source_files)
}

fn resolve_conventional_module_path(
    pkg_dir: &Path,
    module_base: &Path,
    module_name: &str,
) -> Result<PathBuf> {
    let flat = module_base.join(format!("{module_name}.rs"));
    let nested = module_base.join(module_name).join("mod.rs");
    let flat_exists = pkg_dir.join(&flat).is_file();
    let nested_exists = pkg_dir.join(&nested).is_file();
    match (flat_exists, nested_exists) {
        (true, false) => Ok(flat),
        (false, true) => Ok(nested),
        (true, true) => anyhow::bail!(
            "proc-macro module `{module_name}` is ambiguous: both {} and {} exist",
            flat.display(),
            nested.display()
        ),
        (false, false) => anyhow::bail!(
            "proc-macro module `{module_name}` is missing: expected {} or {}",
            flat.display(),
            nested.display()
        ),
    }
}

fn resolve_explicit_module_path(
    canonical_pkg_dir: &Path,
    declaring_source: &Path,
    explicit_path: &str,
) -> Result<PathBuf> {
    let explicit = Path::new(explicit_path);
    if explicit.as_os_str().is_empty() || explicit.is_absolute() {
        anyhow::bail!("proc-macro #[path] must be a non-empty relative path: `{explicit_path}`");
    }
    let declaring_dir = declaring_source.parent().unwrap_or_else(|| Path::new(""));
    let candidate = canonical_pkg_dir.join(declaring_dir).join(explicit);
    let canonical_candidate = std::fs::canonicalize(&candidate)
        .with_context(|| format!("resolve proc-macro #[path] {}", candidate.display()))?;
    if !canonical_candidate.starts_with(canonical_pkg_dir) {
        anyhow::bail!(
            "proc-macro #[path] escapes crate root: `{explicit_path}` from {}",
            declaring_source.display()
        );
    }
    if !canonical_candidate.is_file() {
        anyhow::bail!(
            "proc-macro #[path] is not a file: {}",
            canonical_candidate.display()
        );
    }
    canonical_candidate
        .strip_prefix(canonical_pkg_dir)
        .map(Path::to_path_buf)
        .with_context(|| {
            format!(
                "make proc-macro #[path] relative to crate root: {}",
                canonical_candidate.display()
            )
        })
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

    #[test]
    fn proc_macro_path_module_outside_lib_root_blocks() -> Result<()> {
        let manifest = r#"
[package]
name = "path-derive"
version = "1.0.0"
edition = "2021"
build = false

[lib]
proc-macro = true
"#;
        let lib_rs = r##"
use proc_macro::TokenStream;
#[path = r#"../shared/network.rs"#]
mod r#network;
#[proc_macro]
pub fn expand(input: TokenStream) -> TokenStream {
    r#network::probe();
    input
}
"##;
        let network_rs = r#"
pub fn probe() {
    let _connection =
        std::net::TcpStream::connect("collector.example.invalid:443");
}
"#;
        let scan = scan_test_tree(&[
            ("Cargo.toml", manifest),
            ("src/lib.rs", lib_rs),
            ("shared/network.rs", network_rs),
        ])?;
        let finding = scan
            .findings
            .iter()
            .find(|finding| finding.rule_id == "proc-macro-network")
            .context("proc-macro-network finding")?;

        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.detail.contains("shared/network.rs"));
        assert_eq!(
            argus_rules::derive_decision_from_findings(&scan.findings),
            argus_core::Decision::Block
        );
        Ok(())
    }

    #[test]
    fn proc_macro_path_module_errors_are_propagated() -> Result<()> {
        let manifest = r#"
[package]
name = "broken-path-derive"
version = "1.0.0"
[lib]
proc-macro = true
"#;
        let missing = match scan_test_tree(&[
            ("Cargo.toml", manifest),
            ("src/lib.rs", "#[path = \"missing.rs\"] mod missing;"),
        ]) {
            Ok(_) => anyhow::bail!("missing #[path] unexpectedly scanned"),
            Err(error) => error,
        };
        assert!(format!("{missing:#}").contains("resolve proc-macro #[path]"));

        let invalid = match scan_test_tree(&[
            ("Cargo.toml", manifest),
            ("src/lib.rs", "#[path = 42] mod invalid;"),
        ]) {
            Ok(_) => anyhow::bail!("non-string #[path] unexpectedly scanned"),
            Err(error) => error,
        };
        assert!(format!("{invalid:#}").contains("parse proc-macro modules"));
        Ok(())
    }
}
