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
use std::path::Path;

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
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut is_proc_macro = false;
    let mut has_build_rs = false;

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

        let base = std::path::Path::new(&rel)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if base == "Cargo.toml" && depth(&rel) == 0 {
            // Top-level Cargo.toml is the manifest for this crate.
            // `extract_tarball` strips the `<name>-<version>/` prefix and
            // returns the inner dir, so files at the package root have
            // depth 0 in `rel`.
            if let Some((n, v)) = parse_cargo_toml_name_version(&content) {
                name = name.or(Some(n));
                version = version.or(Some(v));
            }
            if cargo_toml_is_proc_macro(&content) {
                is_proc_macro = true;
            }
        } else if base == "build.rs" && depth(&rel) == 0 {
            has_build_rs = true;
            scan_build_rs(&content, &rel, &mut findings);
            // build.rs is also a Rust source file — apply the
            // include_bytes! + XOR-loop detectors. The first version of
            // TrapDoor's payload sat in build.rs itself, the second
            // hid it in a sibling module, so we run the source-level
            // checks against both `build.rs` and every other `.rs`.
            scan_rust_source(&content, &rel, &mut findings);
        } else if rel.ends_with(".rs") {
            scan_rust_source(&content, &rel, &mut findings);
        }
    }

    // Structural meta-findings.
    if has_build_rs {
        findings.push(finding(
            "build-rs-execution",
            Severity::Info,
            "crate ships a `build.rs` script — runs at consumer compile time",
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

fn depth(rel: &str) -> usize {
    rel.matches('/').count()
}

fn parse_cargo_toml_name_version(s: &str) -> Option<(String, String)> {
    let package_section = s.find("[package]")?;
    let body = &s[package_section..];
    let name = scrape_string_field(body, "name")?;
    let version = scrape_string_field(body, "version")?;
    Some((name, version))
}

fn cargo_toml_is_proc_macro(s: &str) -> bool {
    let Some(lib_section) = s.find("[lib]") else {
        return false;
    };
    // Stop the section at the next bracketed header.
    let body = &s[lib_section..];
    let body_end = body[5..].find('[').map(|i| 5 + i).unwrap_or(body.len());
    let lib_body = &body[..body_end];
    lib_body.lines().any(|line| {
        let t = line.trim();
        t.starts_with("proc-macro") && t.contains('=') && t.contains("true")
    })
}

fn scrape_string_field(body: &str, field: &str) -> Option<String> {
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(field) {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                if let Some(unquoted) = rest
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| rest.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                {
                    return Some(unquoted.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cargo_basic() {
        let toml = r#"
[package]
name = "demo"
version = "1.2.3"
edition = "2021"
"#;
        let (n, v) = parse_cargo_toml_name_version(toml).unwrap();
        assert_eq!(n, "demo");
        assert_eq!(v, "1.2.3");
    }

    #[test]
    fn detect_proc_macro_lib() {
        let toml = r#"
[package]
name = "x"
version = "1.0.0"

[lib]
proc-macro = true
"#;
        assert!(cargo_toml_is_proc_macro(toml));
    }

    #[test]
    fn benign_lib_section_is_not_proc_macro() {
        let toml = r#"
[package]
name = "x"
version = "1.0.0"

[lib]
name = "x_inner"
"#;
        assert!(!cargo_toml_is_proc_macro(toml));
    }

    #[test]
    fn depth_helper() {
        // `rel` is computed AFTER stripping the extracted-root prefix, so
        // the top-level Cargo.toml has depth 0.
        assert_eq!(depth("Cargo.toml"), 0);
        assert_eq!(depth("src/lib.rs"), 1);
        assert_eq!(depth("src/util/mod.rs"), 2);
    }
}
