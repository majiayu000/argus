//! Content-pattern rules. Run lexical/regex sweeps over the script and source
//! files of a package.
//!
//! Each rule below is intentionally narrow. False positives are paid for in
//! review time, so a rule fires only when its real-attack pattern is present.

use crate::{all_script_bodies, PackageContext, TextFile};
use regex::Regex;
use safepm_core::{Finding, Severity};

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
}

// ---------- regex helpers (lazy-compiled per call; the corpus is tiny) ----------

fn cred_paths_regex() -> Regex {
    Regex::new(r#"[\"'](\.npmrc|\.env|\.ssh/[^\"']+|\.aws/credentials)[\"']"#).unwrap()
}

fn token_env_regex() -> Regex {
    Regex::new(r#"process\.env\.(NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN)\b"#)
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

/// Find a fetch/axios POST to a non-local, non-github host. Returns the host
/// portion so the finding detail can name it.
///
/// The fetch-name match is case-insensitive so wrapped references like
/// `originalFetch(...)` (a stored copy of `globalThis.fetch`) still fire.
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
