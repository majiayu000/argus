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
use argus_rules::{looks_binary, scan_text_file, TextFile};
use std::path::Path;

const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Extract a `.whl` (ZIP) into `dest_root` and scan everything.
pub fn scan_wheel_zip(
    wheel_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<ArtifactScan> {
    argus_archive::extract_zip(wheel_bytes, dest_root, max_extracted_bytes, "wheel entry")
        .context("extract wheel")?;

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut findings: Vec<Finding> = Vec::new();

    // Now walk the extracted dir and apply rules. Two distinct kinds of
    // files matter:
    // - `*.dist-info/METADATA` for the package name + version
    // - any `*.py` for import-time hooks + generic rules
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

        // METADATA gives us name + version.
        if rel.ends_with(".dist-info/METADATA") || rel.ends_with(".dist-info/METADATA.txt") {
            if let Some((n, v)) = parse_metadata_name_version(&content) {
                name = name.or(Some(n));
                version = version.or(Some(v));
            }
            continue;
        }

        // Ecosystem-agnostic content rules.
        scan_text_file(
            &TextFile {
                rel: rel.clone(),
                content: content.clone(),
            },
            &mut findings,
        );

        // Import-time hook detection for any Python source.
        if (rel.ends_with(".py") || rel.ends_with(".pyi"))
            && rules::import_time_hook_regex().is_match(&content)
        {
            findings.push(finding(
                "import-time-hook",
                Severity::Critical,
                format!(
                    "wheel Python file `{rel}` rewrites sys.modules or __builtins__ at module load"
                ),
            ));
        }
    }

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
