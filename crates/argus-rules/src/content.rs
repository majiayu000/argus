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
    let language = ScriptLanguage::from_path(&file.rel);
    if matches!(
        language,
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript | ScriptLanguage::Python
    ) {
        let facts = argus_syntax::analyze(&file.rel, &file.content)
            .with_context(|| format!("parse npm source `{}`", file.rel))?;
        scan_file(file, &mut findings, NetworkScan::Syntax(&facts));
    } else {
        scan_file(file, &mut findings, NetworkScan::Disabled);
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
    scan_file(file, findings, NetworkScan::Legacy);
}

enum NetworkScan<'a> {
    Syntax(&'a [Fact]),
    Legacy,
    Disabled,
}

fn scan_file(file: &TextFile, findings: &mut Vec<Finding>, network_scan: NetworkScan<'_>) {
    let body = &file.content;

    // credential-access: targets host secret files by literal path.
    if cred_paths_regex().is_match(body) {
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

    // encoded-dynamic-execution: only the direct decode -> eval/exec chain.
    // This intentionally does not score standalone decoders, long/minified
    // lines, or entropy: the chain itself is the high-confidence signal.
    let encoded_dynamic_execution = match &network_scan {
        NetworkScan::Syntax(facts) => syntax_encoded_dynamic_execution(facts),
        NetworkScan::Legacy => source_encoded_dynamic_execution(body, language_for_file(&file.rel)),
        // npm's syntax-backed network rule is JavaScript-only, but Python
        // source files shipped in a package still use the shared scanner.
        NetworkScan::Disabled => {
            source_encoded_dynamic_execution(body, language_for_file(&file.rel))
        }
    };
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

fn language_for_file(path: &str) -> ScriptLanguage {
    ScriptLanguage::from_path(path)
}

fn syntax_encoded_dynamic_execution(facts: &[Fact]) -> bool {
    facts
        .iter()
        .any(|fact| fact.kind == FactKind::EncodedDynamicExecution)
}

/// Scan Python and non-JavaScript shared surfaces without treating comments or
/// string literals as code. The grammar is deliberately limited to the exact
/// `exec/eval(base64.b64decode(...))` shape; aliases and intermediate values
/// are left for a future syntax-backed rule.
fn source_encoded_dynamic_execution(body: &str, language: ScriptLanguage) -> bool {
    if !matches!(language, ScriptLanguage::Python) {
        return false;
    }
    let eval_shadowed = python_shadowed_binding(body, "eval");
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'#' {
            skip_line_comment(bytes, &mut index);
            continue;
        }
        if is_quote(bytes[index]) {
            skip_string(bytes, &mut index);
            continue;
        }
        let Some((identifier, end)) = identifier_at(bytes, index) else {
            index += 1;
            continue;
        };
        if !matches!(identifier, "exec" | "eval")
            || (identifier == "eval" && eval_shadowed)
            || previous_member(bytes, index)
        {
            index = end;
            continue;
        }
        let mut cursor = skip_space(bytes, end);
        if bytes.get(cursor) != Some(&b'(') {
            index = end;
            continue;
        }
        cursor = skip_python_trivia(bytes, cursor + 1);
        if python_direct_decoder(bytes, cursor) || python_fstring_decoder(bytes, cursor) {
            return true;
        }
        index = end;
    }
    false
}

fn previous_member(bytes: &[u8], index: usize) -> bool {
    let mut cursor = index;
    while cursor > 0
        && bytes[cursor - 1].is_ascii_whitespace()
        && bytes[cursor - 1] != b'\n'
        && bytes[cursor - 1] != b'\r'
    {
        cursor -= 1;
    }
    cursor > 0 && (bytes[cursor - 1] == b'.' || bytes[cursor - 1] == b'?')
}

fn python_shadowed_binding(body: &str, name: &str) -> bool {
    if python_function_parameter_shadowed(body, name) {
        return true;
    }
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'#' {
            skip_line_comment(bytes, &mut index);
            continue;
        }
        if is_quote(bytes[index]) {
            skip_string(bytes, &mut index);
            continue;
        }
        let Some((identifier, end)) = identifier_at(bytes, index) else {
            index += 1;
            continue;
        };
        if identifier == name {
            let before = body[..index].trim_end();
            let declaration = before.ends_with("def")
                || before.ends_with("class")
                || before.ends_with("as")
                || bytes.get(skip_python_trivia(bytes, end)) == Some(&b'=');
            if declaration {
                return true;
            }
        }
        index = end;
    }
    false
}

fn python_function_parameter_shadowed(body: &str, name: &str) -> bool {
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'#' {
            skip_line_comment(bytes, &mut index);
            continue;
        }
        if is_quote(bytes[index]) {
            skip_string(bytes, &mut index);
            continue;
        }
        let Some((identifier, end)) = identifier_at(bytes, index) else {
            index += 1;
            continue;
        };
        if identifier != "def" {
            index = end;
            continue;
        }
        let mut cursor = skip_python_trivia(bytes, end);
        if let Some((_, function_end)) = identifier_at(bytes, cursor) {
            cursor = skip_python_trivia(bytes, function_end);
        }
        if bytes.get(cursor) != Some(&b'(') {
            index = end;
            continue;
        }
        let mut depth = 1;
        cursor += 1;
        while cursor < bytes.len() && depth > 0 {
            if let Some((parameter, parameter_end)) = identifier_at(bytes, cursor) {
                if parameter == name {
                    return true;
                }
                cursor = parameter_end;
                continue;
            }
            match bytes[cursor] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            cursor += 1;
        }
        index = end;
    }
    false
}

fn skip_python_trivia(bytes: &[u8], mut index: usize) -> usize {
    loop {
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if bytes.get(index) == Some(&b'#') {
            skip_line_comment(bytes, &mut index);
            continue;
        }
        break;
    }
    index
}

fn python_direct_decoder(bytes: &[u8], mut index: usize) -> bool {
    loop {
        index = skip_python_trivia(bytes, index);
        if bytes.get(index) != Some(&b'(') {
            break;
        }
        index += 1;
    }
    let Some((module, end)) = identifier_at(bytes, index) else {
        return false;
    };
    if module != "base64" {
        return false;
    }
    index = skip_python_trivia(bytes, end);
    if bytes.get(index) != Some(&b'.') {
        return false;
    }
    let Some((decoder, end)) = identifier_at(bytes, skip_python_trivia(bytes, index + 1)) else {
        return false;
    };
    decoder == "b64decode" && bytes.get(skip_python_trivia(bytes, end)) == Some(&b'(')
}

fn python_fstring_decoder(bytes: &[u8], index: usize) -> bool {
    let quote_index = if matches!(bytes.get(index), Some(b'f' | b'F'))
        && bytes.get(index + 1).is_some_and(|byte| is_quote(*byte))
    {
        index + 1
    } else if (matches!(bytes.get(index), Some(b'r' | b'R'))
        && bytes
            .get(index + 1)
            .is_some_and(|byte| matches!(byte, b'f' | b'F'))
        || matches!(bytes.get(index), Some(b'f' | b'F'))
            && bytes
                .get(index + 1)
                .is_some_and(|byte| matches!(byte, b'r' | b'R')))
        && bytes.get(index + 2).is_some_and(|byte| is_quote(*byte))
    {
        index + 2
    } else {
        return false;
    };
    let quote = bytes[quote_index];
    let triple = bytes
        .get(quote_index..quote_index + 3)
        .is_some_and(|window| window == [quote, quote, quote]);
    let mut cursor = quote_index + if triple { 3 } else { 1 };
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor = (cursor + 2).min(bytes.len());
            continue;
        }
        if triple && bytes.get(cursor..cursor + 3) == Some(&[quote, quote, quote]) {
            return false;
        }
        if !triple && bytes[cursor] == quote {
            return false;
        }
        if bytes[cursor] == b'{' && bytes.get(cursor + 1) != Some(&b'{') {
            let expression_start = cursor + 1;
            let mut depth = 1;
            cursor = expression_start;
            while cursor < bytes.len() && depth > 0 {
                if bytes[cursor] == b'{' {
                    depth += 1;
                } else if bytes[cursor] == b'}' {
                    depth -= 1;
                }
                cursor += 1;
            }
            let expression_end = cursor.saturating_sub(1);
            if depth == 0
                && python_fstring_expression_dynamic_decoder(
                    bytes,
                    expression_start.min(expression_end),
                )
            {
                return true;
            }
            continue;
        }
        cursor += 1;
    }
    false
}

fn python_fstring_expression_dynamic_decoder(bytes: &[u8], mut index: usize) -> bool {
    index = skip_python_trivia(bytes, index);
    let Some((callee, end)) = identifier_at(bytes, index) else {
        return false;
    };
    if !matches!(callee, "eval" | "exec") {
        return false;
    }
    index = skip_python_trivia(bytes, end);
    bytes.get(index) == Some(&b'(')
        && python_direct_decoder(bytes, skip_python_trivia(bytes, index + 1))
}

fn is_quote(byte: u8) -> bool {
    matches!(byte, b'\'' | b'"')
}

fn skip_line_comment(bytes: &[u8], index: &mut usize) {
    while *index < bytes.len() && bytes[*index] != b'\n' {
        *index += 1;
    }
}

fn skip_string(bytes: &[u8], index: &mut usize) {
    let quote = bytes[*index];
    let triple = bytes
        .get(*index..*index + 3)
        .is_some_and(|window| window == [quote, quote, quote]);
    if triple {
        *index += 3;
        while *index + 2 < bytes.len() && bytes[*index..*index + 3] != [quote, quote, quote] {
            *index += 1;
        }
        *index = (*index + 3).min(bytes.len());
        return;
    }
    *index += 1;
    while *index < bytes.len() {
        if bytes[*index] == b'\\' {
            *index = (*index + 2).min(bytes.len());
        } else if bytes[*index] == quote {
            *index += 1;
            break;
        } else {
            *index += 1;
        }
    }
}

fn skip_space(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn identifier_at(bytes: &[u8], start: usize) -> Option<(&str, usize)> {
    let first = *bytes.get(start)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        end += 1;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(|identifier| (identifier, end))
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
        scan_text_file(
            &TextFile {
                rel: "module.py".into(),
                content: source.into(),
            },
            &mut findings,
        );
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
