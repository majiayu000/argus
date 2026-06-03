//! ZIP extraction and scanning for Composer packages.
//!
//! The ZIP-safe extractor is copied verbatim from `argus-pypi/src/wheel.rs`
//! (zip::ZipArchive + enclosed_name() + Component checks + unix_mode symlink
//! rejection + take(remaining+1) byte cap). Per U-04 we do NOT refactor pypi.
//!
//! GitHub zipballs wrap all content under a single top-level directory
//! (`<vendor>-<package>-<sha>/`). After extraction the walkdir loop strips
//! the `dest_root` prefix, so the wrapper directory is just a path component
//! and is handled transparently.

use crate::metadata::{ComposerManifest, ComposerVersionObj, ScriptValue};
use crate::{finding, rules};
use anyhow::{anyhow, bail, Context, Result};
use argus_core::{ArtifactKind, Finding, ScanReport, Severity};
use argus_rules::{looks_binary, scan_text_file, TextFile};
use std::io::Read;
use std::path::{Component, Path};

const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Composer event hook names we scan for lifecycle triggers.
const LIFECYCLE_EVENTS: &[&str] = &[
    "pre-install-cmd",
    "post-install-cmd",
    "pre-update-cmd",
    "post-update-cmd",
    "pre-autoload-dump",
    "post-autoload-dump",
];

/// Top-level: safe-extract the Composer ZIP, scan `composer.json` and all
/// PHP source files, return a `ScanReport`.
pub fn scan_composer_zip(
    zip_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    version_obj: &ComposerVersionObj,
) -> Result<ScanReport> {
    // --- 1. Safe ZIP extraction (copied from wheel.rs) ---
    extract_zip_safe(zip_bytes, dest_root, max_extracted_bytes)
        .context("safe-extract Composer zip")?;

    // --- 2. Walk extracted tree ---
    let mut findings: Vec<Finding> = Vec::new();
    let mut composer_json_content: Option<String> = None;

    // Track the shallowest composer.json depth seen so we only capture the root manifest.
    let mut composer_json_depth: Option<usize> = None;

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

        // Capture the shallowest composer.json as the root manifest.
        // depth = number of '/' separators in the rel path.
        if rel == "composer.json" || rel.ends_with("/composer.json") {
            let depth = rel.chars().filter(|&c| c == '/').count();
            let is_shallowest = match composer_json_depth {
                None => true,
                Some(d) => depth < d,
            };
            if is_shallowest {
                composer_json_depth = Some(depth);
                composer_json_content = Some(content.clone());
            }
            continue; // processed separately below
        }

        // Ecosystem-agnostic content rules on every text file.
        scan_text_file(
            &TextFile {
                rel: rel.clone(),
                content: content.clone(),
            },
            &mut findings,
        );

        // PHP-specific dynamic-exec rules.
        if rel.ends_with(".php") || rel.ends_with(".phtml") {
            rules::scan_php_file(&content, &rel, &mut findings);
        }
    }

    // --- 3. Parse and scan composer.json ---
    let (name, version) =
        parse_composer_json(composer_json_content.as_deref(), &mut findings, version_obj);

    // --- 4. Scan inline scripts from p2 registry metadata (belt+suspenders) ---
    if let Some(scripts) = &version_obj.scripts {
        scan_scripts_map(scripts, &mut findings);
    }

    let decision = argus_rules::derive_decision_from_findings(&findings);
    Ok(ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: dest_root.to_path_buf(),
        package_name: name,
        package_version: version,
        decision,
        findings,
    })
}

// ---------------------------------------------------------------------------
// ZIP safe extractor (copied from argus-pypi/src/wheel.rs, U-04 compliant)
// ---------------------------------------------------------------------------

fn extract_zip_safe(zip_bytes: &[u8], dest_root: &Path, max_extracted_bytes: u64) -> Result<()> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("open Composer zip")?;

    let mut total: u64 = 0;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("read zip entry {i}"))?;

        // Path safety: reject any entry whose path is absolute or contains `..`.
        let path = match file.enclosed_name() {
            Some(p) => p.to_owned(),
            None => {
                bail!(
                    "zip entry {} has an unsafe path; refusing to extract",
                    file.name()
                );
            }
        };
        for comp in path.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    bail!("zip entry `{}` traverses parent dir", path.display())
                }
                _ => bail!("zip entry `{}` has unsafe path component", path.display()),
            }
        }

        if file.is_dir() {
            let dest = dest_root.join(&path);
            std::fs::create_dir_all(&dest).with_context(|| format!("mkdir {}", dest.display()))?;
            continue;
        }

        // Reject symlinks encoded as external file attributes.
        let mode = file.unix_mode().unwrap_or(0);
        // POSIX: S_IFLNK = 0o120000
        if (mode & 0o170000) == 0o120000 {
            bail!("refusing to extract symlink zip entry `{}`", path.display());
        }

        let remaining = max_extracted_bytes
            .checked_sub(total)
            .ok_or_else(|| anyhow!("zip size accounting overflow"))?;

        let dest = dest_root.join(&path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir parent {}", parent.display()))?;
        }
        let mut out =
            std::fs::File::create(&dest).with_context(|| format!("create {}", dest.display()))?;
        let mut limited = (&mut file).take(remaining + 1);
        let written = std::io::copy(&mut limited, &mut out)
            .with_context(|| format!("write {}", dest.display()))?;
        if written > remaining {
            bail!(
                "zip extracted size exceeds cap {max_extracted_bytes} (entry {} overran)",
                path.display()
            );
        }
        total = total
            .checked_add(written)
            .ok_or_else(|| anyhow!("zip size accounting overflow"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// composer.json parsing and scanning
// ---------------------------------------------------------------------------

/// Return true if `rel` is a root-level `composer.json` (with or without
/// a GitHub-zipball wrapper directory as the first path component).
///
/// Accepted forms:
/// - `"composer.json"` (bare root)
/// - `"<wrapper-dir>/composer.json"` where `<wrapper-dir>` contains a `-`
///   (GitHub zipball convention: `vendor-pkg-abc123/composer.json`)
///
/// Rejected: `"src/composer.json"` (source directory, no `-` in dir name),
/// `"a/b/composer.json"` (deeper nesting).
#[cfg(test)]
fn is_root_composer_json(rel: &str) -> bool {
    // Direct root.
    if rel == "composer.json" {
        return true;
    }
    // GitHub zipball wrapper: exactly one '/' and wrapper dir contains '-'.
    let slash_count = rel.chars().filter(|&c| c == '/').count();
    if slash_count != 1 || !rel.ends_with("/composer.json") {
        return false;
    }
    // The dir component (everything before the '/') must contain '-'.
    let dir = &rel[..rel.len() - "/composer.json".len()];
    dir.contains('-')
}

/// Parse `composer.json`, push lifecycle-script findings, and return
/// (package_name, package_version) for the ScanReport.
fn parse_composer_json(
    content: Option<&str>,
    findings: &mut Vec<Finding>,
    version_obj: &ComposerVersionObj,
) -> (Option<String>, Option<String>) {
    let content = match content {
        Some(c) => c,
        None => return (None, None),
    };

    let manifest: ComposerManifest = match serde_json::from_str(content) {
        Ok(m) => m,
        Err(e) => {
            findings.push(finding(
                "composer-manifest-parse-error",
                Severity::Info,
                format!("failed to parse composer.json: {e}"),
            ));
            return (None, None);
        }
    };

    // Scan lifecycle scripts from composer.json.
    if let Some(scripts) = &manifest.scripts {
        scan_scripts_map(scripts, findings);
    }

    // autoload.files: emit Info structural finding.
    if let Some(autoload) = &manifest.autoload {
        if !autoload.files.is_empty() {
            findings.push(finding(
                "autoload-files-execution",
                Severity::Info,
                format!(
                    "composer.json autoload.files declares {} file(s) that execute on \
                     autoloader build: {}",
                    autoload.files.len(),
                    autoload.files.join(", ")
                ),
            ));
        }
    }

    let name = manifest.name.clone();
    let version = manifest
        .version
        .clone()
        .or_else(|| Some(version_obj.version.clone()));
    (name, version)
}

/// Scan a `scripts` map from either `composer.json` or p2 metadata.
/// Deduplicates: only emits a finding for each event once, so running
/// against both sources doesn't double-fire.
fn scan_scripts_map(
    scripts: &std::collections::BTreeMap<String, ScriptValue>,
    findings: &mut Vec<Finding>,
) {
    for event in LIFECYCLE_EVENTS {
        if let Some(sv) = scripts.get(*event) {
            let cmds = sv.commands();
            // Only emit if this event hasn't already produced a finding.
            let already_fired = findings.iter().any(|f| {
                (f.rule_id == "lifecycle-script" || f.rule_id == "lifecycle-script-shell")
                    && f.detail.contains(event)
            });
            if !already_fired {
                rules::scan_script_hook(event, &cmds, findings);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_root_composer_json_direct() {
        assert!(is_root_composer_json("composer.json"));
    }

    #[test]
    fn is_root_composer_json_wrapped() {
        assert!(is_root_composer_json("vendor-pkg-abc123/composer.json"));
    }

    #[test]
    fn is_root_composer_json_nested_false() {
        assert!(!is_root_composer_json("src/composer.json"));
        assert!(!is_root_composer_json("a/b/composer.json"));
    }

    #[test]
    fn extract_zip_safe_rejects_path_traversal() {
        let zip_bytes = make_zip_with_entry("../../etc/passwd", b"evil");
        let dir = tempfile::tempdir().unwrap();
        let result = extract_zip_safe(&zip_bytes, dir.path(), 10 * 1024 * 1024);
        assert!(result.is_err(), "expected path traversal to be rejected");
    }

    #[test]
    fn extract_zip_safe_rejects_absolute_path() {
        let zip_bytes = make_zip_with_entry("/etc/passwd", b"evil");
        let dir = tempfile::tempdir().unwrap();
        let result = extract_zip_safe(&zip_bytes, dir.path(), 10 * 1024 * 1024);
        assert!(result.is_err(), "expected absolute path to be rejected");
    }

    #[test]
    fn extract_zip_safe_enforces_byte_cap() {
        let large = vec![0u8; 1024];
        let zip_bytes = make_zip_with_entry("data.bin", &large);
        let dir = tempfile::tempdir().unwrap();
        // Cap at 512 bytes — must fail.
        let result = extract_zip_safe(&zip_bytes, dir.path(), 512);
        assert!(result.is_err(), "expected size cap to be enforced");
    }

    /// Build a minimal ZIP with one entry for testing.
    fn make_zip_with_entry(name: &str, body: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer.start_file(name, opts).unwrap();
            writer.write_all(body).unwrap();
            writer.finish().unwrap();
        }
        buf
    }
}
