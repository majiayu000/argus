//! Content-pattern rules. Run lexical/regex sweeps over the script and source
//! files of a package.
//!
//! Each rule below is intentionally narrow. False positives are paid for in
//! review time, so a rule fires only when its real-attack pattern is present.

use crate::{all_script_bodies, PackageContext, TextFile};
use argus_core::{Finding, Severity};
use regex::Regex;

pub fn run(ctx: &PackageContext, findings: &mut Vec<Finding>) {
    let script_blob = all_script_bodies(&ctx.package);

    // Iterate over each text file once and apply per-file rules.
    for file in &ctx.text_files {
        scan_file(file, findings);
    }

    // Script-body rules (curl|sh, npm-publish lives in scripts too).
    if let Some(matched) = curl_sh_pipe(&script_blob) {
        findings.push(
            Finding::new(
                "remote-download",
                Severity::High,
                format!("script downloads remote payload: {matched}"),
            )
            .at("package.json:scripts"),
        );
        findings.push(
            Finding::new(
                "shell-pipe-execution",
                Severity::High,
                "script pipes downloaded content into a shell",
            )
            .at("package.json:scripts"),
        );
    }
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
    scan_file(file, findings);
}

fn scan_file(file: &TextFile, findings: &mut Vec<Finding>) {
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
    if let Some(host) = external_fetch(body) {
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
}

// ---------- regex helpers (lazy-compiled per call; the corpus is tiny) ----------

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
fn cred_paths_regex() -> Regex {
    Regex::new(r#"[\"'][^\"'\n]*(\.npmrc|\.env|\.ssh/[^\"'\n]+|\.aws/credentials)[^\"'\n]*[\"']"#)
        .unwrap()
}

/// AI-agent context files. A package that writes here is impersonating a
/// maintainer-authored instruction file and will be loaded by the user's
/// agent on every future session. Match a write call (`writeFileSync`,
/// `appendFileSync`, `writeFile`, `outputFileSync`, etc.) targeting one
/// of the well-known path names — quoted, in a template literal, or as a
/// `path.join(..., 'CLAUDE.md')` final argument.
fn ai_context_paths_regex() -> Regex {
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
}

/// Pathlib-style reverse shape: filename literal first, then a chained
/// `.write_text(` / `.write_bytes(` call within ~200 chars. Catches
/// `(home / ".cursorrules").write_text(...)` which the forward regex
/// misses because the filename sits OUTSIDE the parenthesized arg list.
fn ai_context_paths_regex_reverse() -> Regex {
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
}

fn ai_context_write(body: &str) -> Option<String> {
    if let Some(c) = ai_context_paths_regex().captures(body) {
        return c.get(1).map(|m| m.as_str().to_string());
    }
    ai_context_paths_regex_reverse()
        .captures(body)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn token_env_regex() -> Regex {
    Regex::new(
        r#"process\.env\.(NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN)\b"#,
    )
    .unwrap()
}

fn npmrc_read_regex() -> Regex {
    Regex::new(r#"readFile\w*\s*\(\s*[^)]*\.npmrc"#).unwrap()
}

fn github_write_regex() -> Regex {
    Regex::new(
        r#"(?xs)
        api\.github\.com [^\"']* .{0,300}? method\s*:\s*[\"'](PUT|POST|PATCH|DELETE)[\"']
        "#,
    )
    .unwrap()
}

fn npm_publish_regex() -> Regex {
    Regex::new(r#"\bnpm\s+publish\b"#).unwrap()
}

fn binary_exec_regex() -> Regex {
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
}

fn runtime_hook_regex() -> Regex {
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
}

fn wallet_regex() -> Regex {
    Regex::new(
        r#"(?x)
        (?:globalThis|window) \. ethereum |
        \beth_sendTransaction\b |
        \bwallet_(?:requestPermissions|switchEthereumChain)\b
        "#,
    )
    .unwrap()
}

fn curl_sh_pipe(blob: &str) -> Option<String> {
    let re = Regex::new(r#"(?i)(curl|wget)\s+[^\n]*\|\s*(sh|bash|zsh)\b"#).unwrap();
    re.find(blob).map(|m| m.as_str().to_string())
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
    let re = Regex::new(
        r#"(?i)(?:fetch|axios\.(?:post|put|patch|request))\s*\(\s*[\"']https?://([^\"'/]+)"#,
    )
    .unwrap();
    for cap in re.captures_iter(body) {
        let host = cap.get(1).unwrap().as_str().to_ascii_lowercase();
        if is_local_host(&host) {
            continue;
        }
        if host == "api.github.com" {
            // covered by github-write-api
            continue;
        }
        return Some(host);
    }
    None
}

fn is_local_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1") || host.starts_with("127.")
}
