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
use argus_rules::{looks_binary, scan_text_file, TextFile};
use argus_syntax::{FactKind, ScriptLanguage};
use std::path::Path;

/// Maximum size we attempt to read as text. Matches `argus-rules`.
const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Extract a sdist tarball into `dest_root` and scan everything we get.
pub fn scan_sdist_dir(
    tarball_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<ArtifactScan> {
    let pkg_dir = extract_tarball(tarball_bytes, dest_root, max_extracted_bytes)
        .context("safe-extract PyPI sdist")?;
    scan_extracted_sdist(&pkg_dir)
}

/// Walk an already-extracted sdist directory and apply both PyPI-specific
/// rules and the ecosystem-agnostic content rules from `argus-rules`.
pub fn scan_extracted_sdist(pkg_dir: &Path) -> Result<ArtifactScan> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    let mut setup_py_seen = false;
    let mut pyproject_seen = false;

    for entry in walkdir::WalkDir::new(pkg_dir).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let abs = entry.path();
        let rel = abs
            .strip_prefix(pkg_dir)
            .unwrap_or(abs)
            .to_string_lossy()
            .replace('\\', "/");
        let meta = entry.metadata()?;
        if meta.len() > TEXT_MAX_BYTES {
            continue; // not text, skip
        }
        let bytes = match std::fs::read(abs) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if looks_binary(&bytes) {
            continue;
        }
        let content = String::from_utf8_lossy(&bytes).into_owned();
        let text = TextFile {
            rel: rel.clone(),
            content: content.clone(),
        };

        // Ecosystem-agnostic content rules first: credential-access,
        // network-exfiltration, runtime-hook, ai-context-poisoning, …
        scan_text_file(&text, &mut findings);

        // Per-file PyPI-specific checks.
        let base = std::path::Path::new(&rel)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if base == "setup.py" {
            setup_py_seen = true;
            scan_setup_py(&content, &rel, &mut findings)?;
        } else if base == "pyproject.toml" {
            pyproject_seen = true;
            if let Some((n, v)) = parse_pyproject_name_version(&content) {
                name = name.or(Some(n));
                version = version.or(Some(v));
            }
        } else if base == "setup.cfg" {
            if let Some((n, v)) = parse_setupcfg_name_version(&content) {
                name = name.or(Some(n));
                version = version.or(Some(v));
            }
        } else if base == "PKG-INFO" {
            if let Some((n, v)) = parse_pkginfo_name_version(&content) {
                name = name.or(Some(n));
                version = version.or(Some(v));
            }
        } else if rel.ends_with(".py") || rel.ends_with(".pyi") {
            // Apply `import-time-hook` to any Python source, not just setup.py
            // — the wheel pattern can leak into sdists too.
            if rules::import_time_hook_regex().is_match(&content) {
                findings.push(finding(
                    "import-time-hook",
                    Severity::Critical,
                    format!(
                        "Python file `{rel}` rewrites sys.modules or __builtins__ at module load"
                    ),
                ));
            }
        }
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
}
