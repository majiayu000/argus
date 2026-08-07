//! Source distribution (`.tar.gz` with `setup.py`) extraction and scan.
//!
//! sdists are the dangerous PyPI artifact: `pip install` runs `setup.py`
//! as ordinary Python, with the user's full credentials and environment.
//! Most real PyPI supply-chain incidents in 2026 (LiteLLM, durabletask,
//! PyTorch Lightning, TrapDoor PyPI half) lived in `setup.py`.

use crate::{finding, rules, ArtifactScan};
use anyhow::{Context, Result};
use argus_archive::extract_tarball;
use argus_core::{Finding, Severity};
use argus_rules::{scan_text_file, scan_text_files_with_context, RuleSession};
use argus_syntax::{FactKind, ScriptLanguage};
use std::path::Path;

/// sdist paths whose contents the PyPI rules read.
fn is_sdist_security_relevant(rel: &str) -> bool {
    let base = std::path::Path::new(rel)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    rel.ends_with(".py")
        || rel.ends_with(".pyi")
        || matches!(base, "pyproject.toml" | "setup.cfg" | "PKG-INFO")
}

/// Maximum size we attempt to read as text. Matches `argus-rules`.
const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Extract a sdist tarball into `dest_root` and scan everything we get.
pub fn scan_sdist_dir(
    tarball_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<ArtifactScan> {
    let rules = RuleSession::builtin()?;
    scan_sdist_dir_with_rules(tarball_bytes, dest_root, max_extracted_bytes, &rules)
}

pub fn scan_sdist_dir_with_rules(
    tarball_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
) -> Result<ArtifactScan> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_sdist_dir_with_rules_and_context(
        tarball_bytes,
        dest_root,
        max_extracted_bytes,
        rules,
        &execution,
    )
}

pub fn scan_sdist_dir_with_rules_and_context(
    tarball_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<ArtifactScan> {
    let mut budget = argus_rules::ExternalScanBudget::default();
    scan_sdist_dir_with_rules_budget_and_context(
        tarball_bytes,
        dest_root,
        max_extracted_bytes,
        rules,
        execution,
        &mut budget,
    )
}

pub(crate) fn scan_sdist_dir_with_rules_budget_and_context(
    tarball_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
    external_budget: &mut argus_rules::ExternalScanBudget,
) -> Result<ArtifactScan> {
    let pkg_dir = extract_tarball(tarball_bytes, dest_root, max_extracted_bytes)
        .context("safe-extract PyPI sdist")?;
    let builtin = RuleSession::builtin()?;
    let mut scan = scan_extracted_sdist_with_rules_and_context(&pkg_dir, &builtin, execution)?;
    rules
        .scan_directory_with_budget_and_context(
            dest_root,
            &mut scan.findings,
            execution,
            external_budget,
        )
        .context("run configured rules on extracted PyPI sdist archive")?;
    rules.validate_external_limits(&scan.findings)?;
    rules.normalize_findings(&mut scan.findings);
    Ok(scan)
}

/// Walk an already-extracted sdist directory and apply both PyPI-specific
/// rules and the ecosystem-agnostic content rules from `argus-rules`.
pub fn scan_extracted_sdist(pkg_dir: &Path) -> Result<ArtifactScan> {
    let rules = RuleSession::builtin()?;
    scan_extracted_sdist_with_rules(pkg_dir, &rules)
}

pub fn scan_extracted_sdist_with_rules(
    pkg_dir: &Path,
    rules: &RuleSession,
) -> Result<ArtifactScan> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_extracted_sdist_with_rules_and_context(pkg_dir, rules, &execution)
}

pub fn scan_extracted_sdist_with_rules_and_context(
    pkg_dir: &Path,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<ArtifactScan> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    let mut setup_py_seen = false;
    let mut pyproject_seen = false;

    let (file_results, skipped) =
        scan_text_files_with_context(pkg_dir, TEXT_MAX_BYTES, execution, |file| {
            let mut per_file = Vec::new();
            scan_text_file(file, &mut per_file);
            let mut metadata = None;
            let mut saw_setup = false;
            let mut saw_pyproject = false;
            let base = std::path::Path::new(&file.rel)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if base == "setup.py" {
                saw_setup = true;
                scan_setup_py(&file.content, &file.rel, &mut per_file)?;
            } else if base == "pyproject.toml" {
                saw_pyproject = true;
                metadata = parse_pyproject_name_version(&file.content);
            } else if base == "setup.cfg" {
                metadata = parse_setupcfg_name_version(&file.content);
            } else if base == "PKG-INFO" {
                metadata = parse_pkginfo_name_version(&file.content);
            } else if (file.rel.ends_with(".py") || file.rel.ends_with(".pyi"))
                && rules::import_time_hook_regex().is_match(&file.content)
            {
                per_file.push(finding(
                    "import-time-hook",
                    Severity::Critical,
                    format!(
                        "Python file `{}` rewrites sys.modules or __builtins__ at module load",
                        file.rel
                    ),
                ));
            }
            Ok((per_file, metadata, saw_setup, saw_pyproject))
        })?;
    skipped.require_scanned("PyPI sdist", is_sdist_security_relevant)?;
    for (mut per_file, metadata, saw_setup, saw_pyproject) in file_results {
        setup_py_seen |= saw_setup;
        pyproject_seen |= saw_pyproject;
        if let Some((found_name, found_version)) = metadata {
            name = name.take().or(Some(found_name));
            version = version.take().or(Some(found_version));
        }
        findings.append(&mut per_file);
    }

    // sdist with no manifest at all is suspicious in its own right; flag it
    // as info so reviewers see something rather than blank findings.
    if !setup_py_seen && !pyproject_seen {
        findings.push(finding(
            "pypi-sdist-no-manifest",
            Severity::Info,
            "sdist contains neither setup.py nor pyproject.toml",
        ));
    }

    rules
        .scan_directory_with_context(pkg_dir, &mut findings, execution)
        .context("run configured rules on extracted PyPI sdist")?;
    rules.validate_external_limits(&findings)?;
    rules.normalize_findings(&mut findings);

    Ok(ArtifactScan {
        findings,
        name,
        version,
    })
}

fn scan_setup_py(content: &str, rel: &str, findings: &mut Vec<Finding>) -> Result<()> {
    let facts = argus_syntax::analyze_with_language(rel, content, ScriptLanguage::Python)
        .with_context(|| format!("parse PyPI setup source `{rel}`"))?;
    let mut subprocess = false;
    let mut remote_download = false;
    let mut eval = false;
    for fact in facts.iter().filter(|fact| fact.kind == FactKind::Call) {
        let Some(callee) = fact.callee.as_deref() else {
            continue;
        };
        let callee = callee.to_ascii_lowercase();
        subprocess |= is_setup_subprocess(&callee);
        remote_download |= is_setup_remote_download(&callee);
        eval |= is_setup_eval(&callee) && !fact.arguments.is_empty();
    }

    if subprocess {
        findings.push(finding(
            "setup-subprocess",
            Severity::Critical,
            format!("`{rel}` invokes subprocess/os.system/os.popen at install time"),
        ));
    }
    if remote_download {
        findings.push(finding(
            "setup-remote-download",
            Severity::Critical,
            format!("`{rel}` fetches a remote URL via urllib/requests/httpx at install time"),
        ));
    }
    if eval {
        findings.push(finding(
            "setup-eval",
            Severity::Critical,
            format!("`{rel}` calls exec() or eval() on a runtime value — classic payload decryption pattern"),
        ));
    }
    if subprocess || remote_download || eval {
        findings.push(finding(
            "setup-py-execution",
            Severity::High,
            format!("`{rel}` runs imperative code at `pip install` time; argus refuses to run setup.py to verify"),
        ));
    }
    Ok(())
}

fn is_setup_subprocess(callee: &str) -> bool {
    matches!(
        callee,
        "subprocess.run"
            | "subprocess.call"
            | "subprocess.popen"
            | "subprocess.check_output"
            | "subprocess.check_call"
            | "os.system"
            | "os.popen"
            | "commands.getoutput"
            | "pty.spawn"
            | "shutil.run"
            | "shutil.call"
    )
}

fn is_setup_remote_download(callee: &str) -> bool {
    matches!(
        callee,
        "urllib.request.urlopen"
            | "urllib.request.urlretrieve"
            | "urllib2.urlopen"
            | "requests.get"
            | "requests.post"
            | "requests.put"
            | "requests.patch"
            | "requests.delete"
            | "requests.request"
            | "requests.head"
            | "httpx.get"
            | "httpx.post"
            | "httpx.put"
            | "httpx.patch"
            | "httpx.delete"
            | "httpx.request"
            | "socket.create_connection"
            | "socket.socket"
    )
}

fn is_setup_eval(callee: &str) -> bool {
    matches!(callee, "exec" | "eval" | "builtins.exec" | "builtins.eval")
}

/// Very small TOML scraper for `[project] name = "..."` + `version = "..."`.
/// Avoids pulling the full `toml` crate for two fields.
fn parse_pyproject_name_version(s: &str) -> Option<(String, String)> {
    let project_section = s.find("[project]")?;
    let body = &s[project_section..];
    let name = scrape_string_field(body, "name")?;
    let version = scrape_string_field(body, "version")?;
    Some((name, version))
}

fn parse_setupcfg_name_version(s: &str) -> Option<(String, String)> {
    let mut name = None;
    let mut version = None;
    for line in s.lines() {
        let trimmed = line.trim();
        if let Some(v) = trimmed.strip_prefix("name") {
            if let Some(rest) = v.split_once('=') {
                name = Some(rest.1.trim().to_string());
            }
        } else if let Some(v) = trimmed.strip_prefix("version") {
            if let Some(rest) = v.split_once('=') {
                version = Some(rest.1.trim().to_string());
            }
        }
    }
    Some((name?, version?))
}

fn parse_pkginfo_name_version(s: &str) -> Option<(String, String)> {
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
    fn parse_pyproject_basic() {
        let toml = r#"
[project]
name = "demo"
version = "1.2.3"
description = "x"
"#;
        let (n, v) = parse_pyproject_name_version(toml).unwrap();
        assert_eq!(n, "demo");
        assert_eq!(v, "1.2.3");
    }

    #[test]
    fn parse_pkginfo_basic() {
        let pkginfo = "Metadata-Version: 2.1\nName: demo\nVersion: 1.2.3\n";
        let (n, v) = parse_pkginfo_name_version(pkginfo).unwrap();
        assert_eq!(n, "demo");
        assert_eq!(v, "1.2.3");
    }

    #[test]
    fn setup_ast_preserves_supported_api_families() {
        let cases = [
            ("subprocess.run(['true'])", "setup-subprocess"),
            ("subprocess.call(['true'])", "setup-subprocess"),
            ("subprocess.Popen(['true'])", "setup-subprocess"),
            ("subprocess.check_output(['true'])", "setup-subprocess"),
            ("subprocess.check_call(['true'])", "setup-subprocess"),
            ("os.system('true')", "setup-subprocess"),
            ("os.popen('true')", "setup-subprocess"),
            ("commands.getoutput('true')", "setup-subprocess"),
            ("pty.spawn('sh')", "setup-subprocess"),
            ("shutil.run(['true'])", "setup-subprocess"),
            ("shutil.call(['true'])", "setup-subprocess"),
            (
                "urllib.request.urlopen('https://x')",
                "setup-remote-download",
            ),
            (
                "urllib.request.urlretrieve('https://x')",
                "setup-remote-download",
            ),
            ("urllib2.urlopen('https://x')", "setup-remote-download"),
            ("requests.get('https://x')", "setup-remote-download"),
            ("requests.post('https://x')", "setup-remote-download"),
            ("requests.put('https://x')", "setup-remote-download"),
            ("requests.patch('https://x')", "setup-remote-download"),
            ("requests.delete('https://x')", "setup-remote-download"),
            (
                "requests.request('GET', 'https://x')",
                "setup-remote-download",
            ),
            ("requests.head('https://x')", "setup-remote-download"),
            ("httpx.get('https://x')", "setup-remote-download"),
            ("httpx.post('https://x')", "setup-remote-download"),
            ("httpx.put('https://x')", "setup-remote-download"),
            ("httpx.patch('https://x')", "setup-remote-download"),
            ("httpx.delete('https://x')", "setup-remote-download"),
            ("httpx.request('GET', 'https://x')", "setup-remote-download"),
            (
                "socket.create_connection(('x', 443))",
                "setup-remote-download",
            ),
            ("socket.socket()", "setup-remote-download"),
            ("exec(payload)", "setup-eval"),
            ("eval(payload)", "setup-eval"),
        ];
        for (source, expected) in cases {
            let mut findings = Vec::new();
            scan_setup_py(source, "setup.py", &mut findings).unwrap();
            assert!(
                findings.iter().any(|finding| finding.rule_id == expected),
                "{source}: {findings:?}"
            );
            assert_eq!(
                findings
                    .iter()
                    .filter(|finding| finding.rule_id == expected)
                    .count(),
                1,
                "{source}: {findings:?}"
            );
        }
    }

    #[test]
    fn oversized_python_source_fails_closed() {
        let directory = tempfile::tempdir().expect("test directory");
        std::fs::write(
            directory.path().join("setup.py"),
            vec![b'#'; (TEXT_MAX_BYTES + 1) as usize],
        )
        .expect("oversized setup.py");
        let error = match scan_extracted_sdist(directory.path()) {
            Ok(_) => panic!("oversized setup.py was accepted"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("exceeds text scan limit"));
    }
}
