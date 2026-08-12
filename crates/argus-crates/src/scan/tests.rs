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

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(unix)]
fn create_directory_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_directory_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

fn proc_macro_findings_for_source_membership(
    root: &Path,
    source_files: &BTreeSet<String>,
) -> Result<Vec<Finding>> {
    let execution = argus_core::ExecutionContext::serial()?;
    let (per_file_findings, skipped) =
        scan_text_files_with_context(root, TEXT_MAX_BYTES, &execution, |file| {
            let mut findings = Vec::new();
            if source_files.contains(&file.rel) {
                scan_proc_macro_source(&file.content, &file.rel, &mut findings);
            }
            Ok::<_, anyhow::Error>(findings)
        })?;
    skipped.require_scanned("crate", is_crate_security_relevant)?;
    Ok(per_file_findings.into_iter().flatten().collect())
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
#[path = r#"../shared/nested/../network.rs"#]
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
        ("shared/nested/placeholder.txt", ""),
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
fn proc_macro_nested_source_enforces_exact_text_limit() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::write(directory.path().join("src/lib.rs"), "mod bounded;")?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "bounded-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;
    let bounded_path = directory.path().join("src/bounded.rs");

    std::fs::write(&bounded_path, vec![b' '; TEXT_MAX_BYTES as usize])?;
    let source_files = collect_proc_macro_source_files(directory.path(), &manifest)?;
    assert!(source_files.contains("src/bounded.rs"));

    std::fs::write(&bounded_path, vec![b' '; (TEXT_MAX_BYTES + 1) as usize])?;
    let error = collect_proc_macro_source_files(directory.path(), &manifest)
        .expect_err("oversized nested proc-macro source must fail closed");
    let detail = format!("{error:#}");
    assert!(detail.contains("read proc-macro source"), "got: {detail}");
    assert!(
        detail.contains("exceeds 1048576 byte limit"),
        "got: {detail}"
    );
    Ok(())
}

#[test]
fn proc_macro_binary_nested_source_fails_closed() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::write(directory.path().join("src/lib.rs"), "mod binary;")?;
    std::fs::write(directory.path().join("src/binary.rs"), [0, 1, 2])?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "binary-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let error = collect_proc_macro_source_files(directory.path(), &manifest)
        .expect_err("binary nested proc-macro source must fail closed");
    assert!(
        format!("{error:#}").contains("proc-macro source appears binary"),
        "got: {error:#}"
    );
    Ok(())
}

#[test]
fn proc_macro_link_classification_uses_link_metadata_flags() {
    assert!(!link_metadata_indicates_symlink_or_reparse(false, 0));
    assert!(link_metadata_indicates_symlink_or_reparse(true, 0));
    assert!(link_metadata_indicates_symlink_or_reparse(
        false,
        WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    ));
    assert!(!link_metadata_indicates_symlink_or_reparse(false, 0x20));
}

#[test]
fn proc_macro_present_candidate_wins_over_unavailable_sibling_and_is_validated() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::write(directory.path().join("src/foo.rs"), "")?;
    let canonical_pkg_dir = std::fs::canonicalize(directory.path())?;
    let flat = PathBuf::from("src/foo.rs");
    let nested = PathBuf::from("src/foo/mod.rs");

    let resolved = resolve_classified_conventional_module_path(
        &canonical_pkg_dir,
        "foo",
        flat.clone(),
        ConventionalCandidateAvailability::Present,
        nested,
        ConventionalCandidateAvailability::Unavailable(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )),
    )?;

    assert_eq!(resolved, flat);
    Ok(())
}

#[test]
fn proc_macro_zero_present_candidates_propagates_permission_error() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let canonical_pkg_dir = std::fs::canonicalize(directory.path())?;

    let error = resolve_classified_conventional_module_path(
        &canonical_pkg_dir,
        "foo",
        PathBuf::from("src/foo.rs"),
        ConventionalCandidateAvailability::Unavailable(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )),
        PathBuf::from("src/foo/mod.rs"),
        ConventionalCandidateAvailability::Unavailable(std::io::Error::from(
            std::io::ErrorKind::NotFound,
        )),
    )
    .expect_err("zero present candidates must propagate an operational error");
    let detail = format!("{error:#}");
    assert!(detail.contains("src/foo.rs"), "got: {detail}");
    assert!(!detail.contains("module `foo` is missing"), "got: {detail}");
    assert_eq!(
        error
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::PermissionDenied)
    );
    Ok(())
}

#[test]
fn proc_macro_zero_present_candidates_propagates_unknown_error() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let canonical_pkg_dir = std::fs::canonicalize(directory.path())?;

    let error = resolve_classified_conventional_module_path(
        &canonical_pkg_dir,
        "foo",
        PathBuf::from("src/foo.rs"),
        ConventionalCandidateAvailability::Unavailable(std::io::Error::from(
            std::io::ErrorKind::NotFound,
        )),
        PathBuf::from("src/foo/mod.rs"),
        ConventionalCandidateAvailability::Unavailable(std::io::Error::other(
            "synthetic candidate inspection failure",
        )),
    )
    .expect_err("unknown candidate failure must not collapse to missing");
    let detail = format!("{error:#}");
    assert!(detail.contains("src/foo/mod.rs"), "got: {detail}");
    assert!(
        detail.contains("synthetic candidate inspection failure"),
        "got: {detail}"
    );
    assert!(!detail.contains("module `foo` is missing"), "got: {detail}");
    assert_eq!(
        error
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::Other)
    );
    Ok(())
}

#[test]
fn proc_macro_zero_present_absence_like_candidates_remain_missing() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    let canonical_pkg_dir = std::fs::canonicalize(directory.path())?;

    let error = resolve_conventional_module_path(&canonical_pkg_dir, Path::new("src"), "foo")
        .expect_err("two absent conventional candidates must remain missing");
    let detail = format!("{error:#}");
    assert!(detail.contains("module `foo` is missing"), "got: {detail}");
    Ok(())
}

#[cfg(windows)]
#[test]
fn proc_macro_source_case_variant_is_not_treated_as_reparse_point() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::write(
        directory.path().join("src/lib.rs"),
        "#[path = \"SUPPORT.RS\"] mod support;",
    )?;
    std::fs::write(
        directory.path().join("src/support.rs"),
        r#"pub fn probe() {
            let _connection = std::net::TcpStream::connect("collector.example.invalid:443");
        }"#,
    )?;
    std::fs::write(directory.path().join("src/conventional.rs"), "")?;

    // The dedicated Windows CI runner must provide case-insensitive lookup;
    // failure here would make the regression test incapable of exercising it.
    let case_variant_path = directory.path().join("SRC/LIB.RS");
    std::fs::symlink_metadata(&case_variant_path).with_context(|| {
        format!(
            "inspect case-variant proc-macro source {}",
            case_variant_path.display()
        )
    })?;

    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "case-variant-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
path = "SRC/LIB.RS"
"#,
    )?;
    let source_files = collect_proc_macro_source_files(directory.path(), &manifest)?;

    assert_eq!(
        source_files,
        BTreeSet::from(["src/lib.rs".to_string(), "src/support.rs".to_string()])
    );
    let canonical_pkg_dir = std::fs::canonicalize(directory.path())?;
    assert_eq!(
        resolve_conventional_module_path(&canonical_pkg_dir, Path::new("src"), "CONVENTIONAL")?,
        PathBuf::from("src/conventional.rs")
    );

    let execution = argus_core::ExecutionContext::serial()?;
    let (per_file_findings, skipped) =
        scan_text_files_with_context(directory.path(), TEXT_MAX_BYTES, &execution, |file| {
            let mut findings = Vec::new();
            if source_files.contains(&file.rel) {
                scan_proc_macro_source(&file.content, &file.rel, &mut findings);
            }
            Ok::<_, anyhow::Error>(findings)
        })?;
    skipped.require_scanned("crate", is_crate_security_relevant)?;
    let findings = per_file_findings.into_iter().flatten().collect::<Vec<_>>();
    let finding = findings
        .iter()
        .find(|finding| finding.rule_id == "proc-macro-network")
        .context("case-variant support file must reach proc-macro scanning")?;
    assert!(finding.detail.contains("src/support.rs"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn proc_macro_root_source_symlink_fails_closed() -> Result<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::write(directory.path().join("real.rs"), "")?;
    symlink("../real.rs", directory.path().join("src/lib.rs"))?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "linked-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let error = collect_proc_macro_source_files(directory.path(), &manifest)
        .expect_err("symlinked proc-macro root must fail closed");
    assert!(
        format!("{error:#}").contains("symlink or reparse point"),
        "got: {error:#}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn proc_macro_explicit_path_dangling_file_symlink_fails_closed() -> Result<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::create_dir_all(directory.path().join("shared"))?;
    std::fs::write(
        directory.path().join("src/lib.rs"),
        "#[path = \"../shared/linked.rs\"] mod linked;",
    )?;
    symlink("missing.rs", directory.path().join("shared/linked.rs"))?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "linked-path-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let error = collect_proc_macro_source_files(directory.path(), &manifest)
        .expect_err("dangling symlinked explicit proc-macro module must fail closed");
    assert!(
        format!("{error:#}").contains("symlink or reparse point"),
        "got: {error:#}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn proc_macro_explicit_path_checks_symlink_component_before_parent() -> Result<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::create_dir_all(outside.path().join("target"))?;
    std::fs::write(
        directory.path().join("src/lib.rs"),
        "#[path = \"link/../outside.rs\"] mod outside;",
    )?;
    std::fs::write(
        directory.path().join("src/outside.rs"),
        r#"pub fn decoy() {
            let _connection = std::net::TcpStream::connect("decoy.example.invalid:443");
        }"#,
    )?;
    std::fs::write(outside.path().join("outside.rs"), "")?;
    symlink(
        outside.path().join("target"),
        directory.path().join("src/link"),
    )?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "linked-parent-path-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let error = collect_proc_macro_source_files(directory.path(), &manifest)
        .expect_err("symlink component before `..` must fail before scanning the in-root decoy");
    let detail = format!("{error:#}");
    assert!(detail.contains("symlink or reparse point"), "got: {detail}");
    assert!(detail.contains("src/link"), "got: {detail}");
    Ok(())
}

#[test]
fn proc_macro_explicit_path_parent_escape_fails_closed() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::write(
        directory.path().join("src/lib.rs"),
        "#[path = \"../../outside.rs\"] mod outside;",
    )?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "parent-escape-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let error = collect_proc_macro_source_files(directory.path(), &manifest)
        .expect_err("explicit module parent escape must fail closed");
    assert!(
        format!("{error:#}").contains("proc-macro module path escapes crate root"),
        "got: {error:#}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn proc_macro_conventional_symlinked_parent_escape_fails_closed() -> Result<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::write(directory.path().join("src/lib.rs"), "mod linked;")?;
    std::fs::write(outside.path().join("mod.rs"), "")?;
    symlink(outside.path(), directory.path().join("src/linked"))?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "linked-parent-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let error = collect_proc_macro_source_files(directory.path(), &manifest)
        .expect_err("symlinked conventional module parent must fail closed");
    assert!(
        format!("{error:#}").contains("symlink or reparse point"),
        "got: {error:#}"
    );
    Ok(())
}

#[test]
fn proc_macro_conventional_flat_module_ignores_non_directory_nested_obstruction() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::write(directory.path().join("src/lib.rs"), "mod foo;")?;
    std::fs::write(
        directory.path().join("src/foo.rs"),
        r#"pub fn probe() {
            let _connection = std::net::TcpStream::connect("collector.example.invalid:443");
        }"#,
    )?;
    std::fs::write(directory.path().join("src/foo"), "not a directory")?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "flat-module-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let source_files = collect_proc_macro_source_files(directory.path(), &manifest)?;
    assert_eq!(
        source_files,
        BTreeSet::from(["src/foo.rs".to_string(), "src/lib.rs".to_string()])
    );

    let mut findings = Vec::new();
    let foo_rel = "src/foo.rs";
    assert!(source_files.contains(foo_rel));
    let foo_source = std::fs::read_to_string(directory.path().join(foo_rel))?;
    scan_proc_macro_source(&foo_source, foo_rel, &mut findings);
    let finding = findings
        .iter()
        .find(|finding| finding.rule_id == "proc-macro-network")
        .context("flat module must reach proc-macro scanning")?;
    assert!(finding.detail.contains(foo_rel));
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn proc_macro_conventional_flat_module_ignores_self_loop_nested_alternative() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src/foo"))?;
    std::fs::write(directory.path().join("src/lib.rs"), "mod foo;")?;
    std::fs::write(
        directory.path().join("src/foo.rs"),
        r#"pub fn probe() {
            let _connection = std::net::TcpStream::connect("collector.example.invalid:443");
        }"#,
    )?;
    let loop_path = directory.path().join("src/foo/mod.rs");
    create_file_symlink(Path::new("mod.rs"), &loop_path)?;
    let link_metadata = std::fs::symlink_metadata(&loop_path)?;
    assert!(metadata_is_symlink_or_reparse(&link_metadata));
    let loop_error = std::fs::metadata(&loop_path)
        .expect_err("self-loop conventional alternative must not resolve");
    #[cfg(unix)]
    assert_eq!(
        rustix::io::Errno::from_io_error(&loop_error),
        Some(rustix::io::Errno::LOOP),
        "got: {loop_error}"
    );
    #[cfg(windows)]
    assert_eq!(
        loop_error.raw_os_error(),
        Some(WINDOWS_ERROR_CANT_RESOLVE_FILENAME),
        "got: {loop_error}"
    );

    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "flat-module-self-loop-alternative-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;
    let source_files = collect_proc_macro_source_files(directory.path(), &manifest)?;
    assert_eq!(
        source_files,
        BTreeSet::from(["src/foo.rs".to_string(), "src/lib.rs".to_string()])
    );
    let findings = proc_macro_findings_for_source_membership(directory.path(), &source_files)?;
    assert!(
        findings.iter().any(|finding| {
            finding.rule_id == "proc-macro-network" && finding.detail.contains("src/foo.rs")
        }),
        "got: {findings:?}"
    );
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn proc_macro_conventional_flat_module_ignores_linked_empty_nested_parent() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    let empty_directory = directory.path().join("empty");
    std::fs::create_dir_all(&empty_directory)?;
    let canonical_empty_directory = std::fs::canonicalize(&empty_directory)?;
    std::fs::write(
        directory.path().join("Cargo.toml"),
        r#"
[package]
name = "flat-module-linked-empty-parent-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;
    std::fs::write(directory.path().join("src/lib.rs"), "mod foo;")?;
    std::fs::write(
        directory.path().join("src/foo.rs"),
        r#"pub fn probe() {
            let _connection = std::net::TcpStream::connect("collector.example.invalid:443");
        }"#,
    )?;
    let linked_parent = directory.path().join("src/foo");
    create_directory_symlink(&canonical_empty_directory, &linked_parent)?;
    let link_metadata = std::fs::symlink_metadata(&linked_parent)?;
    assert!(metadata_is_symlink_or_reparse(&link_metadata));
    let followed_parent_metadata = std::fs::metadata(&linked_parent).with_context(|| {
        format!(
            "follow linked conventional module parent {}",
            linked_parent.display()
        )
    })?;
    assert!(
        followed_parent_metadata.is_dir(),
        "linked conventional parent must resolve to the existing directory: {}",
        linked_parent.display()
    );
    let nested_path = linked_parent.join("mod.rs");
    let missing_error = std::fs::metadata(&nested_path)
        .expect_err("linked empty directory must not contain the nested alternative");
    assert_eq!(missing_error.kind(), std::io::ErrorKind::NotFound);

    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "flat-module-linked-empty-parent-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;
    let canonical_pkg_dir = std::fs::canonicalize(directory.path())?;
    assert_eq!(
        resolve_conventional_module_path(&canonical_pkg_dir, Path::new("src"), "foo")?,
        PathBuf::from("src/foo.rs")
    );
    let source_files = collect_proc_macro_source_files(directory.path(), &manifest)?;
    assert_eq!(
        source_files,
        BTreeSet::from(["src/foo.rs".to_string(), "src/lib.rs".to_string()])
    );
    let findings = proc_macro_findings_for_source_membership(directory.path(), &source_files)?;
    let finding = findings
        .iter()
        .find(|finding| finding.rule_id == "proc-macro-network")
        .context("selected flat source must reach proc-macro membership and scanning")?;
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.detail.contains("src/foo.rs"));
    Ok(())
}

#[test]
fn proc_macro_conventional_module_rejects_two_regular_candidates_as_ambiguous() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src/foo"))?;
    std::fs::write(directory.path().join("src/foo.rs"), "")?;
    std::fs::write(directory.path().join("src/foo/mod.rs"), "")?;
    let canonical_pkg_dir = std::fs::canonicalize(directory.path())?;

    let error = resolve_conventional_module_path(&canonical_pkg_dir, Path::new("src"), "foo")
        .expect_err("two complete conventional candidates must remain ambiguous");
    let detail = format!("{error:#}");
    assert!(detail.contains("ambiguous"), "got: {detail}");
    assert!(detail.contains("src/foo.rs"), "got: {detail}");
    assert!(detail.contains("src/foo/mod.rs"), "got: {detail}");
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn proc_macro_conventional_module_rejects_linked_present_alternative_as_ambiguous() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src/foo"))?;
    std::fs::write(directory.path().join("src/foo.rs"), "")?;
    std::fs::write(directory.path().join("src/real.rs"), "")?;
    let linked_alternative = directory.path().join("src/foo/mod.rs");
    create_file_symlink(Path::new("../real.rs"), &linked_alternative)?;
    assert!(metadata_is_symlink_or_reparse(&std::fs::symlink_metadata(
        &linked_alternative
    )?));
    assert!(std::fs::metadata(&linked_alternative)?.is_file());
    let canonical_pkg_dir = std::fs::canonicalize(directory.path())?;

    let error = resolve_conventional_module_path(&canonical_pkg_dir, Path::new("src"), "foo")
        .expect_err("a resolvable linked alternative is present for ambiguity classification");
    assert!(format!("{error:#}").contains("ambiguous"), "got: {error:#}");
    Ok(())
}

#[cfg(unix)]
#[test]
fn proc_macro_conventional_flat_module_ignores_dangling_nested_alternative() -> Result<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src/foo"))?;
    std::fs::write(directory.path().join("src/lib.rs"), "mod foo;")?;
    std::fs::write(
        directory.path().join("src/foo.rs"),
        r#"pub fn probe() {
            let _connection = std::net::TcpStream::connect("collector.example.invalid:443");
        }"#,
    )?;
    symlink("missing.rs", directory.path().join("src/foo/mod.rs"))?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "flat-module-dangling-alternative-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let source_files = collect_proc_macro_source_files(directory.path(), &manifest)?;
    assert_eq!(
        source_files,
        BTreeSet::from(["src/foo.rs".to_string(), "src/lib.rs".to_string()])
    );
    let mut findings = Vec::new();
    let foo_rel = "src/foo.rs";
    let foo_source = std::fs::read_to_string(directory.path().join(foo_rel))?;
    scan_proc_macro_source(&foo_source, foo_rel, &mut findings);
    assert!(
        findings.iter().any(|finding| {
            finding.rule_id == "proc-macro-network" && finding.detail.contains(foo_rel)
        }),
        "got: {findings:?}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn proc_macro_conventional_flat_module_ignores_dangling_nested_parent() -> Result<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    std::fs::write(
        directory.path().join("Cargo.toml"),
        r#"
[package]
name = "flat-module-dangling-parent-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;
    std::fs::write(directory.path().join("src/lib.rs"), "mod foo;")?;
    std::fs::write(
        directory.path().join("src/foo.rs"),
        r#"pub fn probe() {
            let _connection = std::net::TcpStream::connect("collector.example.invalid:443");
        }"#,
    )?;
    symlink("missing-dir", directory.path().join("src/foo"))?;

    let scan = scan_extracted_crate(directory.path())?;
    let finding = scan
        .findings
        .iter()
        .find(|finding| finding.rule_id == "proc-macro-network")
        .context("flat source must be scanned when nested parent link is dangling")?;
    assert!(finding.detail.contains("src/foo.rs"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn proc_macro_conventional_nested_module_ignores_dangling_flat_alternative() -> Result<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src/foo"))?;
    std::fs::write(directory.path().join("src/lib.rs"), "mod foo;")?;
    std::fs::write(
        directory.path().join("src/foo/mod.rs"),
        r#"pub fn probe() {
            let _connection = std::net::TcpStream::connect("collector.example.invalid:443");
        }"#,
    )?;
    symlink("missing.rs", directory.path().join("src/foo.rs"))?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "nested-module-dangling-alternative-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let source_files = collect_proc_macro_source_files(directory.path(), &manifest)?;
    assert_eq!(
        source_files,
        BTreeSet::from(["src/foo/mod.rs".to_string(), "src/lib.rs".to_string()])
    );
    let mut findings = Vec::new();
    let foo_rel = "src/foo/mod.rs";
    let foo_source = std::fs::read_to_string(directory.path().join(foo_rel))?;
    scan_proc_macro_source(&foo_source, foo_rel, &mut findings);
    assert!(
        findings.iter().any(|finding| {
            finding.rule_id == "proc-macro-network" && finding.detail.contains(foo_rel)
        }),
        "got: {findings:?}"
    );
    Ok(())
}

#[cfg(any(unix, windows))]
#[test]
fn proc_macro_conventional_resolvable_leaf_symlink_fails_closed() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src/foo"))?;
    std::fs::write(directory.path().join("src/lib.rs"), "mod foo;")?;
    std::fs::write(directory.path().join("src/real.rs"), "")?;
    create_file_symlink(
        Path::new("../real.rs"),
        &directory.path().join("src/foo/mod.rs"),
    )?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "linked-conventional-alternative-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let error = collect_proc_macro_source_files(directory.path(), &manifest)
        .expect_err("resolvable conventional leaf symlink must fail closed");
    assert!(
        format!("{error:#}").contains("symlink or reparse point"),
        "got: {error:#}"
    );
    Ok(())
}

#[test]
fn proc_macro_module_graph_enforces_source_file_limit() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "many-modules-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;
    let mut root_source = String::new();
    for index in 0..MAX_PROC_MACRO_SOURCE_FILES - 1 {
        root_source.push_str(&format!("mod module_{index};\n"));
        std::fs::write(directory.path().join(format!("src/module_{index}.rs")), "")?;
    }
    std::fs::write(directory.path().join("src/lib.rs"), &root_source)?;

    let source_files = collect_proc_macro_source_files(directory.path(), &manifest)?;
    assert_eq!(source_files.len(), MAX_PROC_MACRO_SOURCE_FILES);

    let overflow_index = MAX_PROC_MACRO_SOURCE_FILES - 1;
    root_source.push_str(&format!("mod module_{overflow_index};\n"));
    std::fs::write(
        directory
            .path()
            .join(format!("src/module_{overflow_index}.rs")),
        "",
    )?;
    std::fs::write(directory.path().join("src/lib.rs"), root_source)?;
    let error = collect_proc_macro_source_files(directory.path(), &manifest)
        .expect_err("oversized proc-macro module graph must fail closed");
    assert!(
        format!("{error:#}").contains("module graph exceeds 1024 source files"),
        "got: {error:#}"
    );
    Ok(())
}

#[test]
fn proc_macro_duplicate_declarations_are_deduplicated_before_enqueue() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("src"))?;
    let root_source = "mod repeated;\n".repeat(MAX_PROC_MACRO_SOURCE_FILES * 4);
    std::fs::write(directory.path().join("src/lib.rs"), root_source)?;
    std::fs::write(directory.path().join("src/repeated.rs"), "")?;
    let manifest: CargoManifest = toml::from_str(
        r#"
[package]
name = "duplicate-modules-derive"
version = "1.0.0"
build = false

[lib]
proc-macro = true
"#,
    )?;

    let source_files = collect_proc_macro_source_files(directory.path(), &manifest)?;
    assert_eq!(
        source_files,
        BTreeSet::from(["src/lib.rs".to_string(), "src/repeated.rs".to_string()])
    );
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
