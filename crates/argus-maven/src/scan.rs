//! `.jar` (ZIP) extraction and scan.
//!
//! A `.jar` is a ZIP archive of compiled `.class` bytecode plus resources.
//! argus inspects only the textual/structured surfaces:
//! - `META-INF/MANIFEST.MF` (RFC822 key:value — `Main-Class`, version);
//! - any embedded text resource (scanned with the generic content rules);
//! - embedded build/launcher scripts (`.sh`/`.bat`/`.ps1`).
//!
//! The `.class` bytecode is NOT disassembled. To make this explicit (so a
//! clean report is never mistaken for a clean-bytecode guarantee, U-29) we
//! always emit `maven-bytecode-not-inspected` (Info).
//!
//! Safety mirrors the pypi wheel extractor: walk ZIP entries, reject path
//! traversal, reject symlinks, and cap total extracted size.

use crate::{finding, rules};
use anyhow::{Context, Result};
use argus_core::{ArtifactScan, Finding, Severity};
use argus_rules::{read_text_file_bounded, scan_text_file, RuleSession, TextFile};
use std::path::Path;

const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Extract a `.jar` (ZIP) into `dest_root` and scan everything.
///
/// `has_main_class_launcher` callers may inspect the returned `main_class`
/// to drive the structural `maven-executable-jar` meta-finding.
pub fn scan_maven_jar(
    jar_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<ArtifactScan> {
    let rules = RuleSession::builtin()?;
    scan_maven_jar_with_rules(jar_bytes, dest_root, max_extracted_bytes, &rules)
}

pub fn scan_maven_jar_with_rules(
    jar_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
) -> Result<ArtifactScan> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_maven_jar_with_rules_and_context(
        jar_bytes,
        dest_root,
        max_extracted_bytes,
        rules,
        &execution,
    )
}

pub fn scan_maven_jar_with_rules_and_context(
    jar_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<ArtifactScan> {
    let mut budget = argus_rules::ExternalScanBudget::default();
    scan_maven_jar_with_rules_budget_and_context(
        jar_bytes,
        dest_root,
        max_extracted_bytes,
        rules,
        execution,
        &mut budget,
    )
}

pub(crate) fn scan_maven_jar_with_rules_budget_and_context(
    jar_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
    external_budget: &mut argus_rules::ExternalScanBudget,
) -> Result<ArtifactScan> {
    argus_archive::extract_zip(jar_bytes, dest_root, max_extracted_bytes, "jar entry")
        .context("extract jar")?;

    let mut findings: Vec<Finding> = Vec::new();

    // Walk the extracted tree and apply rules.
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut main_class: Option<String> = None;
    let mut has_launcher_script = false;

    let mut inputs = Vec::new();
    for entry in walkdir::WalkDir::new(dest_root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let abs = entry.path();
        let rel = abs
            .strip_prefix(dest_root)
            .unwrap_or(abs)
            .to_string_lossy()
            .replace('\\', "/");

        inputs.push((rel, abs.to_path_buf()));
    }
    inputs.sort_by(|left, right| left.0.cmp(&right.0));
    execution.execute_ordered(
        &inputs,
        None,
        |_index, (rel, abs)| -> Result<(Vec<Finding>, Option<JarManifest>, bool)> {
            let mut per_file = Vec::new();
            let has_launcher = rules::is_embedded_build_script(rel);
            if has_launcher {
                per_file.push(
                    finding(
                        "maven-embedded-build-script",
                        Severity::Medium,
                        format!("jar bundles an embedded build/launcher script `{rel}`"),
                    )
                    .at(rel.clone()),
                );
            }
            let Some(file) = read_text_file_bounded(rel, abs, TEXT_MAX_BYTES)? else {
                return Ok((per_file, None, has_launcher));
            };
            let content = file.content;
            let manifest =
                if rel == "META-INF/MANIFEST.MF" || rel.ends_with("/META-INF/MANIFEST.MF") {
                    Some(parse_jar_manifest(&content))
                } else {
                    scan_text_file(
                        &TextFile {
                            rel: rel.clone(),
                            content,
                        },
                        &mut per_file,
                    );
                    None
                };
            Ok((per_file, manifest, has_launcher))
        },
        |_index, (mut per_file, manifest, has_launcher)| {
            has_launcher_script |= has_launcher;
            if let Some(parsed) = manifest {
                if let Some(found_main) = parsed.main_class {
                    main_class = Some(found_main);
                }
                name = name.take().or(parsed.implementation_title);
                version = version.take().or(parsed.implementation_version);
            }
            findings.append(&mut per_file);
            Ok(())
        },
    )?;

    // Structural meta-finding: an executable jar (Main-Class declared) that
    // also ships a top-level launcher script. Info-only.
    if main_class.is_some() && has_launcher_script {
        findings.push(finding(
            "maven-executable-jar",
            Severity::Info,
            "jar declares a Main-Class and bundles a launcher script",
        ));
    }

    // HONESTY meta-finding (U-29 visibility): emitted ALWAYS so a clean
    // report is never read as a clean-bytecode guarantee.
    findings.push(finding(
        "maven-bytecode-not-inspected",
        Severity::Info,
        ".class bytecode was not disassembled; a clean report covers only \
         textual/structured surfaces (MANIFEST.MF, pom.xml, embedded text)",
    ));

    rules
        .scan_directory_with_budget_and_context(
            dest_root,
            &mut findings,
            execution,
            external_budget,
        )
        .context("run configured rules on extracted Maven jar")?;
    rules.validate_external_limits(&findings)?;
    rules.normalize_findings(&mut findings);

    Ok(ArtifactScan {
        findings,
        name,
        version,
    })
}

/// Parsed fields of interest from a jar `META-INF/MANIFEST.MF`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct JarManifest {
    pub main_class: Option<String>,
    pub implementation_title: Option<String>,
    pub implementation_version: Option<String>,
}

/// Parse the RFC822-style `MANIFEST.MF`. Keys are case-sensitive per the JAR
/// spec; values follow `Key: value`. We ignore continuation lines (rare for
/// the fields we care about) for simplicity.
pub fn parse_jar_manifest(content: &str) -> JarManifest {
    let mut m = JarManifest::default();
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("Main-Class:") {
            m.main_class = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Implementation-Title:") {
            m.implementation_title = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Implementation-Version:") {
            m.implementation_version = Some(v.trim().to_string());
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_main_class_and_version() {
        let mf = "Manifest-Version: 1.0\r\n\
                  Main-Class: com.example.App\r\n\
                  Implementation-Title: example\r\n\
                  Implementation-Version: 1.2.3\r\n";
        let m = parse_jar_manifest(mf);
        assert_eq!(m.main_class.as_deref(), Some("com.example.App"));
        assert_eq!(m.implementation_title.as_deref(), Some("example"));
        assert_eq!(m.implementation_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn manifest_without_main_class() {
        let mf = "Manifest-Version: 1.0\nBuilt-By: ci\n";
        let m = parse_jar_manifest(mf);
        assert_eq!(m, JarManifest::default());
    }
}
