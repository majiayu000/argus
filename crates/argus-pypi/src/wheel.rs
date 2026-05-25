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
use anyhow::{anyhow, bail, Context, Result};
use argus_core::{Finding, Severity};
use argus_rules::{looks_binary, scan_text_file, TextFile};
use std::io::Read;
use std::path::{Component, Path};

const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Extract a `.whl` (ZIP) into `dest_root` and scan everything.
pub fn scan_wheel_zip(
    wheel_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<ArtifactScan> {
    let reader = std::io::Cursor::new(wheel_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("open wheel as ZIP")?;

    let mut total: u64 = 0;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut findings: Vec<Finding> = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("read wheel entry {i}"))?;

        // Path safety: reject any entry path that is absolute or contains
        // `..`. ZIP names are not necessarily UTF-8, but `enclosed_name`
        // returns `Some` only if the path is safe to extract under a root.
        let path = match file.enclosed_name() {
            Some(p) => p.to_owned(),
            None => {
                bail!(
                    "wheel entry {} has an unsafe path; refusing to extract",
                    file.name()
                );
            }
        };
        for comp in path.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    bail!("wheel entry `{}` traverses parent dir", path.display())
                }
                _ => bail!("wheel entry `{}` has unsafe path component", path.display()),
            }
        }

        if file.is_dir() {
            let dest = dest_root.join(&path);
            std::fs::create_dir_all(&dest).with_context(|| format!("mkdir {}", dest.display()))?;
            continue;
        }

        // External attributes can mark an entry as a symlink. We refuse.
        let mode = file.unix_mode().unwrap_or(0);
        // POSIX: S_IFLNK = 0o120000
        if (mode & 0o170000) == 0o120000 {
            bail!(
                "refusing to extract symlink wheel entry `{}`",
                path.display()
            );
        }

        let remaining = max_extracted_bytes
            .checked_sub(total)
            .ok_or_else(|| anyhow!("wheel size accounting overflow"))?;

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
                "wheel extracted size exceeds cap {max_extracted_bytes} (entry {} overran)",
                path.display()
            );
        }
        total = total
            .checked_add(written)
            .ok_or_else(|| anyhow!("wheel size accounting overflow"))?;
    }

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
