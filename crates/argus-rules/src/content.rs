//! Content-pattern rules. Run lexical/regex sweeps over the script and source
//! files of a package.
//!
//! Each rule below is intentionally narrow. False positives are paid for in
//! review time, so a rule fires only when its real-attack pattern is present.

use crate::TextFile;
use anyhow::{Context, Result};
use argus_core::{Finding, Severity};
use argus_syntax::{Fact, FactKind, ScriptLanguage};
use regex::Regex;
use std::sync::OnceLock;

pub(crate) fn scan_npm_text_file(file: &TextFile) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let language = ScriptLanguage::from_source(&file.rel, &file.content);
    if matches!(
        language,
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript | ScriptLanguage::Python
    ) {
        let facts = argus_syntax::analyze(&file.rel, &file.content)
            .with_context(|| format!("parse npm source `{}`", file.rel))?;
        let encoded = argus_syntax::analyze_encoded_dynamic_execution(&file.rel, &file.content)
            .with_context(|| format!("analyze npm source `{}`", file.rel))?;
        scan_file(file, &mut findings, NetworkScan::Syntax(&facts), encoded);
    } else {
        scan_file(file, &mut findings, NetworkScan::Disabled, false);
    }
    Ok(findings)
}

/// Apply the ecosystem-agnostic content rules (credential-access,
/// network-exfiltration, runtime-hook, wallet-interception,
/// ai-context-poisoning, binary-execution, github-write-api, npm-publish,
/// token-harvest) to a single text file.
///
/// This is the same scan that `run` performs on every file in an npm
/// package directory. argus-pypi and argus-crates call it for each Python
/// or Rust file they extract — none of these rules are npm-specific in
/// behaviour, only in the regex literals they look for (e.g. `.npmrc`).
pub fn scan_text_file(file: &TextFile, findings: &mut Vec<Finding>) {
    scan_file(file, findings, NetworkScan::Legacy, false);
}

/// Checked variant for package extractors whose source language is known.
/// Python files are parsed before content rules run so malformed syntax cannot
/// silently bypass encoded dynamic execution detection.
pub fn scan_text_file_checked(file: &TextFile, findings: &mut Vec<Finding>) -> Result<()> {
    let language = ScriptLanguage::from_source(&file.rel, &file.content);
    let encoded = if language == ScriptLanguage::Python {
        argus_syntax::analyze_encoded_dynamic_execution(&file.rel, &file.content)
            .with_context(|| format!("parse source `{}`", file.rel))?
    } else {
        false
    };
    scan_file(file, findings, NetworkScan::Legacy, encoded);
    Ok(())
}

enum NetworkScan<'a> {
    Syntax(&'a [Fact]),
    Legacy,
    Disabled,
}

/// Documentation extensions whose prose is not an executable surface.
const PROSE_EXTENSIONS: &[&str] = &[
    ".md",
    ".markdown",
    ".mdx",
    ".rst",
    ".txt",
    ".adoc",
    ".asciidoc",
];

/// Filenames an AI agent loads as instructions. These are `.md` by
/// convention but are executed by the agent that reads them, so they are
/// payload surfaces, not prose.
const AGENT_INSTRUCTION_FILES: &[&str] = &[
    "claude.md",
    "agents.md",
    ".cursorrules",
    ".continuerules",
    ".codexrules",
    ".windsurfrules",
    ".aider.conf.yml",
];

/// Whether a path's contents can meaningfully *read* host credentials.
///
/// Returns false only for prose documentation. Everything else — source,
/// config, unknown extensions, extensionless scripts — stays in scope, so a
/// payload cannot escape by choosing an unusual filename.
fn is_credential_scan_surface(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    if AGENT_INSTRUCTION_FILES.contains(&basename)
        || lower.contains("/.claude/")
        || lower.starts_with(".claude/")
    {
        return true;
    }
    !PROSE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

fn scan_file(
    file: &TextFile,
    findings: &mut Vec<Finding>,
    network_scan: NetworkScan<'_>,
    encoded_dynamic_execution: bool,
) {
    let body = &file.content;

    // credential-access: targets host secret files by literal path.
    //
    // Prose is excluded: a README that documents `~/.npmrc` setup is not a
    // package reading it, and that shape dominated the false positives the
    // skill census measured (GH-184). Agent instruction files stay in scope —
    // a shipped `CLAUDE.md` naming a credential path is read by the user's
    // agent, so there it is a payload rather than documentation.
    if is_credential_scan_surface(&file.rel) && cred_paths_regex().is_match(body) {
        findings.push(
            Finding::new(
                "credential-access",
                Severity::High,
                "references host secret files (.npmrc/.env/.ssh/.aws)",
            )
            .at(&file.rel),
        );
    }

    // github-write-api: api.github.com with mutating method.
    let has_github_write = github_write_regex().is_match(body);
    if has_github_write {
        findings.push(
            Finding::new(
                "github-write-api",
                Severity::High,
                "writes through api.github.com (PUT/POST/PATCH/DELETE)",
            )
            .at(&file.rel),
        );
    }

    // npm-publish: any npm publish invocation from JS or shell.
    let has_npm_publish = npm_publish_regex().is_match(body);
    if has_npm_publish {
        findings.push(
            Finding::new(
                "npm-publish",
                Severity::High,
                "invokes `npm publish` from within the package",
            )
            .at(&file.rel),
        );
    }

    // token-harvest: differentiate from credential-access. Fire only when
    // the script reads `~/.npmrc` directly, or pairs an NPM/GH token env var
    // with a self-republish/exfil-to-github path. Bulk credential-dump
    // scripts that happen to mention `process.env.NPM_TOKEN` are already
    // covered by credential-access + network-exfiltration.
    let has_npmrc_read = npmrc_read_regex().is_match(body);
    let has_env_token = token_env_regex().is_match(body);
    let token_harvest = has_npmrc_read || (has_env_token && (has_github_write || has_npm_publish));
    if token_harvest {
        findings.push(
            Finding::new(
                "token-harvest",
                Severity::High,
                "collects npm/github tokens for self-republish or exfil-to-github",
            )
            .at(&file.rel),
        );
    }

    // binary-execution: spawn/exec/execFile of a native artifact path.
    if binary_exec_regex().is_match(body) {
        findings.push(
            Finding::new(
                "binary-execution",
                Severity::High,
                "executes a bundled native binary at install time",
            )
            .at(&file.rel),
        );
    }

    // runtime-hook: monkey-patches a global at module load.
    if runtime_hook_regex().is_match(body) {
        findings.push(
            Finding::new(
                "runtime-hook",
                Severity::High,
                "overrides a global (globalThis/window/global) at module load",
            )
            .at(&file.rel),
        );
    }

    // wallet-interception: crypto wallet object access or ethSendTransaction.
    if wallet_regex().is_match(body) {
        findings.push(
            Finding::new(
                "wallet-interception",
                Severity::Critical,
                "accesses browser crypto wallet (ethereum/eth_sendTransaction)",
            )
            .at(&file.rel),
        );
    }

    // network-exfiltration: fetch/POST to external host, excluding api.github.com.
    let external_host = match &network_scan {
        NetworkScan::Syntax(facts) => syntax_external_fetch(facts),
        NetworkScan::Legacy => external_fetch(body),
        NetworkScan::Disabled => None,
    };
    if let Some(host) = external_host {
        findings.push(
            Finding::new(
                "network-exfiltration",
                Severity::High,
                format!("sends data to external host `{host}` at install/load time"),
            )
            .at(&file.rel),
        );
    }

    // ai-context-poisoning: writes to local AI-agent context files.
    // Pioneered at scale by TrapDoor (Socket.dev 2026-05-24), this attack
    // class plants instructions in `.cursorrules`, `CLAUDE.md`, and similar
    // files that later get loaded by Cursor / Claude Code / aider /
    // Continue.dev / Codex as authoritative agent context — meaning the
    // attacker's prompt can override the user's intent on every future
    // session. Distinct from credential theft because the value is
    // persistent, silent, and operates against the developer's AI tools
    // rather than their cloud creds.
    if let Some(target) = ai_context_write(body) {
        findings.push(
            Finding::new(
                "ai-context-poisoning",
                Severity::Critical,
                format!(
                    "writes to AI-agent context file `{target}` — pretends to be a maintainer-authored instruction, persists across sessions"
                ),
            )
            .at(&file.rel),
        );
    }

    // obfuscated-source: structural signatures a bundler cannot produce.
    // Statistical shape (entropy, minification, line length) rides along as
    // evidence only — see `crate::obfuscation` for why.
    if let Some(finding) = crate::obfuscation::scan_source(file) {
        findings.push(finding);
    }

    // encoded-dynamic-execution: only the direct decode -> eval/exec chain.
    // This intentionally does not score standalone decoders, long/minified
    // lines, or entropy: the chain itself is the high-confidence signal.
    if encoded_dynamic_execution {
        findings.push(
            Finding::new(
                "encoded-dynamic-execution",
                Severity::Medium,
                "decodes an encoded payload directly into dynamic execution",
            )
            .at(&file.rel),
        );
    }
}

// ---------- regex helpers (compiled once via OnceLock; scans touch every file) ----------

/// Quoted string that mentions a host credential path anywhere inside.
///
/// The earlier strict shape `["']<path>["']` required the path to be the
/// entire quoted content. That misses real attack code that builds the
/// path with `format!("{}/.aws/credentials", home)` — the literal sits
/// inside a string with extra characters on either side.
///
/// The intra-string scan stops at the next quote OR newline. Without the
/// newline bound, the regex would happily match an opening `"` on one
/// statement, eat through whitespace and unrelated code across multiple
/// lines, and close on a far-away `"` that happens to be on the right
/// side of a `.npmrc` token. JavaScript template literals (backticks)
/// are not in the class, so paths inside template literals fall through
/// to the npmrc-read regex instead.
fn cred_paths_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"[\"'][^\"'\n]*(\.npmrc|\.env|\.ssh/[^\"'\n]+|\.aws/credentials)[^\"'\n]*[\"']"#,
        )
        .unwrap()
    })
}

/// AI-agent context files. A package that writes here is impersonating a
/// maintainer-authored instruction file and will be loaded by the user's
/// agent on every future session. Match a write call (`writeFileSync`,
/// `appendFileSync`, `writeFile`, `outputFileSync`, etc.) targeting one
/// of the well-known path names — quoted, in a template literal, or as a
/// `path.join(..., 'CLAUDE.md')` final argument.
fn ai_context_paths_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Match a write call whose first 400 characters of arguments mention
        // one of the well-known AI-agent context filenames. Recognises both
        // JS-flavour writes (`writeFileSync`, `appendFileSync`, `writeFile`,
        // `outputFileSync`, etc.) and Python-flavour writes (pathlib's
        // `write_text` / `write_bytes`). The Python sdist TrapDoor variant
        // poisons `~/.cursorrules` via `Path(...).write_text(...)`.
        //
        // We deliberately do NOT require quote/template delimiters around the
        // filename: real attacks construct the path via interpolation
        // (``${homedir}/.cursorrules`` in JS, `Path.home() / ".cursorrules"`
        // in Python) where the only character immediately before the
        // filename is the `/` that follows the interpolation. Rust regex has
        // no lookbehind, so we just match the filename anywhere inside the
        // call argument list.
        //
        // Capture group 1 returns the matched filename for the finding detail.
        Regex::new(
            r#"(?x)
            (?:
                (?:write|append|outputFile|writeFile)[A-Za-z]*Sync? \s* \(           |  # JS
                write_text \s* \(                                                     |  # Python pathlib
                write_bytes \s* \(                                                    |  # Python pathlib
                format \s* ! \s* \(                                                      # Rust path-builder macro
            )
            [^)]{0,400}?
            ( \.cursorrules
            | CLAUDE\.md
            | \.claude/[^\"'`)\s]+
            | AGENTS\.md
            | \.aider\.conf\.yml
            | \.continuerules
            | \.codexrules
            | \.windsurfrules
            )
            "#,
        )
        .unwrap()
    })
}

/// Pathlib-style reverse shape: filename literal first, then a chained
/// `.write_text(` / `.write_bytes(` call within ~200 chars. Catches
/// `(home / ".cursorrules").write_text(...)` which the forward regex
/// misses because the filename sits OUTSIDE the parenthesized arg list.
fn ai_context_paths_regex_reverse() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            [\"'`/]
            ( \.cursorrules
            | CLAUDE\.md
            | \.claude/[^\"'`)\s]+
            | AGENTS\.md
            | \.aider\.conf\.yml
            | \.continuerules
            | \.codexrules
            | \.windsurfrules
            )
            [\"'`)]?
            [^\n]{0,200}?
            \.\s*
            (?: write_text | write_bytes | write )
            \s* \(
            "#,
        )
        .unwrap()
    })
}

fn ai_context_write(body: &str) -> Option<String> {
    if let Some(c) = ai_context_paths_regex().captures(body) {
        return c.get(1).map(|m| m.as_str().to_string());
    }
    ai_context_paths_regex_reverse()
        .captures(body)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn token_env_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"process\.env\.(NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN)\b"#,
        )
        .unwrap()
    })
}

fn npmrc_read_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"readFile\w*\s*\(\s*[^)]*\.npmrc"#).unwrap())
}

fn github_write_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?xs)
            api\.github\.com [^\"']* .{0,300}? method\s*:\s*[\"'](PUT|POST|PATCH|DELETE)[\"']
            "#,
        )
        .unwrap()
    })
}

fn npm_publish_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\bnpm\s+publish\b"#).unwrap())
}

fn binary_exec_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            \b(exec|execFile|execFileSync|execSync|spawn|spawnSync)\s*\(\s*
            [\"'] (?:
                [^\"']*\.(?:so|dll|dylib|exe|node) \b |
                rundll32(?:\.exe)? |
                powershell(?:\.exe)? |
                cmd\.exe
            )
            "#,
        )
        .unwrap()
    })
}

fn runtime_hook_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // No lookarounds: forbid `==` / `===` by requiring a non-`=` byte after the
        // assignment operator.
        Regex::new(
            r#"(?x)
            (?:globalThis|window|global)
            \s*\.\s* [A-Za-z_$][A-Za-z0-9_$]*
            (?:\s*\.\s* [A-Za-z_$][A-Za-z0-9_$]* )?
            \s*=\s* [^=]
            "#,
        )
        .unwrap()
    })
}

fn wallet_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            (?:globalThis|window) \. ethereum |
            \beth_sendTransaction\b |
            \bwallet_(?:requestPermissions|switchEthereumChain)\b
            "#,
        )
        .unwrap()
    })
}

/// Find a JS fetch/axios call to a non-local, non-github host. Returns the
/// host portion so the finding detail can name it.
///
/// The match is case-insensitive so wrapped references like
/// `originalFetch(...)` (a stored copy of `globalThis.fetch`) still fire.
///
/// Note: this rule is intentionally JS-only. Python additions
/// (`urllib.request.urlopen`, `requests.get`, `httpx.get`) were trialled
/// and reverted: real Python libraries embed `requests.get('https://...')`
/// inside docstring examples, which produces unmanageable false-positive
/// rates. PyPI install-time network calls are caught by argus-pypi's
/// `setup-remote-download` rule instead.
fn external_fetch(body: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:fetch|axios\.(?:post|put|patch|request))\s*\(\s*[\"']https?://([^\"'/]+)"#,
        )
        .unwrap()
    });
    for cap in re.captures_iter(body) {
        let host = cap.get(1).unwrap().as_str().to_ascii_lowercase();
        if is_local_host(&host) {
            continue;
        }
        if host_name(&host) == "api.github.com" {
            // covered by github-write-api
            continue;
        }
        return Some(host);
    }
    None
}

fn syntax_external_fetch(facts: &[Fact]) -> Option<String> {
    facts.iter().find_map(|fact| {
        if fact.kind != FactKind::Call || !is_network_callee(fact.callee.as_deref()?) {
            return None;
        }
        fact.arguments.first().and_then(|argument| {
            [argument.resolved.as_deref(), Some(argument.raw.as_str())]
                .into_iter()
                .flatten()
                .find_map(external_url_host)
        })
    })
}

fn is_network_callee(callee: &str) -> bool {
    let callee = callee.to_ascii_lowercase();
    callee.ends_with("fetch")
        || matches!(
            callee.as_str(),
            "axios.post" | "axios.put" | "axios.patch" | "axios.request"
        )
}

fn external_url_host(value: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(?i)https?://([^\"'/\s]+)"#).unwrap());
    for captures in re.captures_iter(value) {
        let host = captures.get(1)?.as_str().to_ascii_lowercase();
        if !is_local_host(&host) && host_name(&host) != "api.github.com" {
            return Some(host);
        }
    }
    None
}

fn is_local_host(host: &str) -> bool {
    let host = host_name(host);
    matches!(host, "localhost" | "127.0.0.1" | "::1") || host.starts_with("127.")
}

fn host_name(host: &str) -> &str {
    if let Some(bracketed) = host.strip_prefix('[') {
        return bracketed
            .split_once(']')
            .map_or(bracketed, |(name, _)| name);
    }
    host.split_once(':').map_or(host, |(name, _)| name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::{Decision, Finding};

    fn npm_ids(source: &str) -> Vec<String> {
        scan_npm_text_file(&TextFile {
            rel: "index.js".into(),
            content: source.into(),
        })
        .expect("scan JavaScript")
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
    }

    fn python_findings(source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        scan_text_file_checked(
            &TextFile {
                rel: "module.py".into(),
                content: source.into(),
            },
            &mut findings,
        )
        .expect("scan Python");
        findings
    }

    #[test]
    fn javascript_direct_decode_execution_fires() {
        let ids =
            npm_ids("eval(atob('Y29uc29sZS5sb2coMSk=')); new Function( atob(\"cHJpbnQoMSk=\") );");
        assert_eq!(
            ids.iter()
                .filter(|id| *id == "encoded-dynamic-execution")
                .count(),
            1,
            "one finding per file"
        );
    }

    #[test]
    fn javascript_function_constructor_decode_execution_fires() {
        let ids = npm_ids("new Function(atob('Y29uc29sZS5sb2coMSk='));");
        assert!(ids.iter().any(|id| id == "encoded-dynamic-execution"));
    }

    #[test]
    fn imported_decoders_do_not_fire() {
        let ids = npm_ids("import {atob} from './safe.js'; eval(atob('x'));");
        assert!(!ids.iter().any(|id| id == "encoded-dynamic-execution"));
        for source in [
            "import{atob}from './safe.js'; eval(atob('x'));",
            "import atob from'./safe.js'; eval(atob('x'));",
            "import * as atob from './safe.js'; eval(atob('x'));",
        ] {
            let ids = npm_ids(source);
            assert!(!ids.iter().any(|id| id == "encoded-dynamic-execution"));
        }
        let findings = python_findings("import local as base64\nexec(base64.b64decode('x'))");
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "encoded-dynamic-execution"));
    }

    #[test]
    fn javascript_parentheses_comments_and_context_boundaries_are_safe() {
        for source in [
            "eval((atob('Y29uc29sZS5sb2coMSk=')));",
            "eval(/* gap */ atob('Y29uc29sZS5sb2coMSk='));",
            "new Function(/* gap */ (atob('Y29uc29sZS5sb2coMSk=')));",
            "new Function(`return ${atob('Y29uc29sZS5sb2coMSk=')}`);",
        ] {
            assert!(
                npm_ids(source)
                    .iter()
                    .any(|id| id == "encoded-dynamic-execution"),
                "expected direct chain: {source}"
            );
        }
        for source in [
            "/eval(atob('fake'))/;",
            "safe.eval(atob('fake'));",
            "const eval = safe; eval(atob('fake'));",
            "function run(eval) { eval(atob('fake')); }",
            "new Function(atob('fake'), 'body');",
        ] {
            assert!(
                !npm_ids(source)
                    .iter()
                    .any(|id| id == "encoded-dynamic-execution"),
                "unexpected finding: {source}"
            );
        }
    }

    #[test]
    fn javascript_decode_only_and_inert_text_do_not_fire() {
        let ids = npm_ids(concat!(
            "const value = atob('Y29uc29sZS5sb2coMSk=');\n",
            "// eval(atob('fake'))\nconst docs = \"eval(atob('fake'))\";",
        ));
        assert!(!ids.iter().any(|id| id == "encoded-dynamic-execution"));
    }

    #[test]
    fn python_direct_decode_execution_fires_and_is_approval_only() {
        let findings = python_findings("exec(base64.b64decode('Y29uc29sZS5sb2coMSk='))");
        let encoded = findings
            .iter()
            .find(|finding| finding.rule_id == "encoded-dynamic-execution")
            .expect("encoded dynamic execution finding");
        assert_eq!(encoded.severity, Severity::Medium);
        assert_eq!(
            crate::decision::derive_from_findings(&findings),
            Decision::AllowWithApproval
        );
    }

    #[test]
    fn python_decode_only_comments_and_strings_do_not_fire() {
        let findings = python_findings(concat!(
            "value = base64.b64decode('Y29uc29sZS5sb2coMSk=')\n",
            "# eval(base64.b64decode('fake'))\n",
            "docs = \"exec(base64.b64decode('fake'))\"",
            "\ndocstring = \"\"\"eval(base64.b64decode('fake'))\"\"\"",
        ));
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "encoded-dynamic-execution"));
    }

    #[test]
    fn python_parentheses_comments_fstrings_and_context_boundaries_are_safe() {
        for source in [
            "exec((base64.b64decode('Y29uc29sZS5sb2coMSk=')))",
            "exec(\n # gap\n base64.b64decode('Y29uc29sZS5sb2coMSk='))",
            "exec(f\"{eval(base64.b64decode('Y29uc29sZS5sb2coMSk='))}\")",
        ] {
            assert!(
                python_findings(source)
                    .iter()
                    .any(|finding| finding.rule_id == "encoded-dynamic-execution"),
                "expected direct chain: {source}"
            );
        }
        for source in [
            "runner.exec(base64.b64decode('fake'))",
            "eval = safe\neval(base64.b64decode('fake'))",
            "def run(eval):\n    eval(base64.b64decode('fake'))",
            "exec(f\"{base64.b64decode('fake')}\")",
            "exec(r\"{eval(base64.b64decode('fake'))}\")",
        ] {
            assert!(
                !python_findings(source)
                    .iter()
                    .any(|finding| finding.rule_id == "encoded-dynamic-execution"),
                "unexpected finding: {source}"
            );
        }
        assert!(
            python_findings("eval = safe\nexec(base64.b64decode('YQ=='))")
                .iter()
                .any(|finding| finding.rule_id == "encoded-dynamic-execution")
        );
    }
}

#[cfg(test)]
mod surface_tests {
    use super::*;

    #[test]
    fn prose_documentation_is_not_a_credential_surface() {
        for rel in [
            "README.md",
            "docs/publishing.md",
            "CHANGELOG.markdown",
            "guide.rst",
            "NOTES.txt",
            "manual.adoc",
        ] {
            assert!(!is_credential_scan_surface(rel), "{rel}");
        }
    }

    #[test]
    fn agent_instruction_files_stay_in_scope() {
        // A shipped CLAUDE.md naming a credential path is read by the user's
        // agent. There the path is a payload, not documentation.
        for rel in [
            "CLAUDE.md",
            "sub/CLAUDE.md",
            "AGENTS.md",
            ".cursorrules",
            ".windsurfrules",
            ".claude/commands/deploy.md",
            "pkg/.claude/skills/x.md",
        ] {
            assert!(is_credential_scan_surface(rel), "{rel}");
        }
    }

    #[test]
    fn executable_and_unknown_surfaces_stay_in_scope() {
        // Nothing escapes by choosing an unusual name: only prose is excluded.
        for rel in [
            "index.js",
            "setup.py",
            "build.rs",
            "install.sh",
            "hooks/pre-commit",
            "config.json",
            "data.yaml",
            "weird.qqq",
        ] {
            assert!(is_credential_scan_surface(rel), "{rel}");
        }
    }

    #[test]
    fn documented_credential_path_no_longer_fires_but_source_still_does() {
        let quoted = r#"It mounts "~/.ssh/id_ed25519" too."#;

        let mut docs = Vec::new();
        scan_text_file(
            &TextFile {
                rel: "README.md".to_string(),
                content: quoted.to_string(),
            },
            &mut docs,
        );
        assert!(
            !docs.iter().any(|f| f.rule_id == "credential-access"),
            "documentation must not fire: {docs:?}"
        );

        let mut source = Vec::new();
        scan_text_file(
            &TextFile {
                rel: "index.js".to_string(),
                content: quoted.to_string(),
            },
            &mut source,
        );
        assert!(
            source.iter().any(|f| f.rule_id == "credential-access"),
            "source must still fire: {source:?}"
        );

        let mut agent = Vec::new();
        scan_text_file(
            &TextFile {
                rel: "CLAUDE.md".to_string(),
                content: quoted.to_string(),
            },
            &mut agent,
        );
        assert!(
            agent.iter().any(|f| f.rule_id == "credential-access"),
            "agent instruction file must still fire: {agent:?}"
        );
    }
}
