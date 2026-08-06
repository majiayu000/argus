//! Wheel (`.whl` = ZIP) extraction and scan.
//!
//! Unlike sdists, wheels do not execute code at install time — `pip` just
//! unpacks them. The attack surface is **import time**: any top-level
//! `*.py` file in the wheel is executed when the consumer imports the
//! package. PyTorch Lightning's 2026-04 compromise lived exactly here
//! (`_runtime/` hidden directory, obfuscated payload that ran on import).
//!
//! Safety mirrors the tarball extractor: we walk the ZIP entries,
//! reject path traversal, reject symlinks (ZIP can encode them as
//! external file attributes), and cap the total extracted size.

use crate::{finding, rules, ArtifactScan};
use anyhow::{Context, Result};
use argus_core::{Finding, Severity};
use argus_rules::{scan_text_file_checked, scan_text_files_with_context, RuleSession};
use std::path::Path;

/// Wheel paths whose contents the PyPI rules read.
fn is_wheel_security_relevant(rel: &str) -> bool {
    rel.ends_with(".py")
        || rel.ends_with(".pyi")
        || rel.ends_with(".pth")
        || rel.ends_with(".dist-info/METADATA")
        || rel.ends_with(".dist-info/METADATA.txt")
}

const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Extract a `.whl` (ZIP) into `dest_root` and scan everything.
pub fn scan_wheel_zip(
    wheel_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<ArtifactScan> {
    let rules = RuleSession::builtin()?;
    scan_wheel_zip_with_rules(wheel_bytes, dest_root, max_extracted_bytes, &rules)
}

pub fn scan_wheel_zip_with_rules(
    wheel_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
) -> Result<ArtifactScan> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_wheel_zip_with_rules_and_context(
        wheel_bytes,
        dest_root,
        max_extracted_bytes,
        rules,
        &execution,
    )
}

pub fn scan_wheel_zip_with_rules_and_context(
    wheel_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<ArtifactScan> {
    let mut budget = argus_rules::ExternalScanBudget::default();
    scan_wheel_zip_with_rules_budget_and_context(
        wheel_bytes,
        dest_root,
        max_extracted_bytes,
        rules,
        execution,
        &mut budget,
    )
}

pub(crate) fn scan_wheel_zip_with_rules_budget_and_context(
    wheel_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
    external_budget: &mut argus_rules::ExternalScanBudget,
) -> Result<ArtifactScan> {
    argus_archive::extract_zip(wheel_bytes, dest_root, max_extracted_bytes, "wheel entry")
        .context("extract wheel")?;

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut findings: Vec<Finding> = Vec::new();

    let (file_results, skipped) = scan_text_files_with_context(
        dest_root,
        TEXT_MAX_BYTES,
        execution,
        |file| {
            let mut per_file = Vec::new();
            let metadata = if file.rel.ends_with(".dist-info/METADATA")
                || file.rel.ends_with(".dist-info/METADATA.txt")
            {
                parse_metadata_name_version(&file.content)
            } else {
                scan_text_file_checked(file, &mut per_file)?;
                if (file.rel.ends_with(".py") || file.rel.ends_with(".pyi"))
                    && rules::import_time_hook_regex().is_match(&file.content)
                {
                    per_file.push(finding(
                        "import-time-hook",
                        Severity::Critical,
                        format!(
                            "wheel Python file `{}` rewrites sys.modules or __builtins__ at module load",
                            file.rel
                        ),
                    ));
                }
                None
            };
            Ok::<_, anyhow::Error>((per_file, metadata))
        },
    )?;
    skipped.require_scanned("wheel", is_wheel_security_relevant)?;
    for (mut per_file, metadata) in file_results {
        if let Some((found_name, found_version)) = metadata {
            name = name.take().or(Some(found_name));
            version = version.take().or(Some(found_version));
        }
        findings.append(&mut per_file);
    }

    rules
        .scan_directory_with_budget_and_context(
            dest_root,
            &mut findings,
            execution,
            external_budget,
        )
        .context("run configured rules on extracted wheel")?;
    rules.validate_external_limits(&findings)?;
    rules.normalize_findings(&mut findings);

    Ok(ArtifactScan {
        findings,
        name,
        version,
    })
}

fn parse_metadata_name_version(s: &str) -> Option<(String, String)> {
    let mut name = None;
    let mut version = None;
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("Name:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        }
    }
    Some((name?, version?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metadata() {
        let m = "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n";
        let (n, v) = parse_metadata_name_version(m).unwrap();
        assert_eq!(n, "requests");
        assert_eq!(v, "2.31.0");
    }
}
