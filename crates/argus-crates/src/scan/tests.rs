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
    let err = match normalize_manifest_relative_path("../build.rs", "Cargo.toml package.build") {
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

#[test]
fn oversized_rust_source_fails_closed() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("Cargo.toml"),
        "[package]\nname='large'\nversion='1.0.0'\n",
    )?;
    std::fs::write(
        directory.path().join("build.rs"),
        vec![b'/'; (TEXT_MAX_BYTES + 1) as usize],
    )?;
    let error = match scan_extracted_crate(directory.path()) {
        Ok(_) => anyhow::bail!("oversized build.rs was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("exceeds text scan limit"));
    Ok(())
}
