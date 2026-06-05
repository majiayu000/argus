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
use anyhow::{anyhow, bail, Context, Result};
use argus_core::{ArtifactScan, Finding, Severity};
use argus_rules::{looks_binary, scan_text_file, TextFile};
use std::io::Read;
use std::path::{Component, Path};

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
    let reader = std::io::Cursor::new(jar_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("open jar as ZIP")?;

    let mut total: u64 = 0;
    let mut findings: Vec<Finding> = Vec::new();

    // Path-safe extraction, identical discipline to the pypi wheel extractor.
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("read jar entry {i}"))?;

        let path = match file.enclosed_name() {
            Some(p) => p.to_owned(),
            None => {
                bail!(
                    "jar entry {} has an unsafe path; refusing to extract",
                    file.name()
                );
            }
        };
        for comp in path.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    bail!("jar entry `{}` traverses parent dir", path.display())
                }
                _ => bail!("jar entry `{}` has unsafe path component", path.display()),
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
            bail!("refusing to extract symlink jar entry `{}`", path.display());
        }

        let remaining = max_extracted_bytes
            .checked_sub(total)
            .ok_or_else(|| anyhow!("jar size accounting overflow"))?;

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
                "jar extracted size exceeds cap {max_extracted_bytes} (entry {} overran)",
                path.display()
            );
        }
        total = total
            .checked_add(written)
            .ok_or_else(|| anyhow!("jar size accounting overflow"))?;
    }

    // Walk the extracted tree and apply rules.
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut main_class: Option<String> = None;
    let mut has_launcher_script = false;

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

        // The presence of an embedded build/launcher script is structurally
        // unusual for a jar — flag it regardless of whether it is text.
        if rules::is_embedded_build_script(&rel) {
            has_launcher_script = true;
            findings.push(
                finding(
                    "maven-embedded-build-script",
                    Severity::Medium,
                    format!("jar bundles an embedded build/launcher script `{rel}`"),
                )
                .at(rel.clone()),
            );
        }

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

        // MANIFEST.MF gives Main-Class + Implementation-Title/Version.
        if rel == "META-INF/MANIFEST.MF" || rel.ends_with("/META-INF/MANIFEST.MF") {
            let parsed = parse_jar_manifest(&content);
            if let Some(mc) = parsed.main_class {
                main_class = Some(mc);
            }
            if name.is_none() {
                name = parsed.implementation_title;
            }
            if version.is_none() {
                version = parsed.implementation_version;
            }
            continue;
        }

        // Ecosystem-agnostic content rules on every text resource.
        scan_text_file(
            &TextFile {
                rel: rel.clone(),
                content: content.clone(),
            },
            &mut findings,
        );
    }

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
