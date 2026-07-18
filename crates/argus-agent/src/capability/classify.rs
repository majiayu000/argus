use super::syntax::{is_shell_wrapper, shell_wrapper_command, Fact, FactKind, StaticValue};
use super::{agent_config_write_re, resolve_host, sensitive_read_re};
use regex::Regex;

pub(super) fn is_network_fact(fact: &Fact) -> bool {
    if !matches!(fact.kind, FactKind::Command | FactKind::Call) {
        return false;
    }
    let callee = lower_callee(fact);
    let direct = matches!(
        callee.as_str(),
        "curl"
            | "wget"
            | "iwr"
            | "invoke-webrequest"
            | "nc"
            | "fetch"
            | "node-fetch"
            | "requests.get"
            | "requests.post"
            | "requests.put"
            | "requests.patch"
            | "urllib.request.urlopen"
            | "urllib.request.urlretrieve"
            | "httpx.get"
            | "httpx.post"
            | "httpx.put"
            | "axios"
            | "axios.get"
            | "axios.post"
            | "axios.put"
            | "http.get"
            | "http.request"
            | "https.get"
            | "https.request"
            | "xmlhttprequest.open"
            | "xmlhttprequest.send"
    );
    direct || wrapper_network_client(fact, &callee).is_some()
}

pub(super) fn is_incomplete_fact(fact: &Fact) -> bool {
    if !matches!(fact.kind, FactKind::Command | FactKind::Call) {
        return false;
    }
    let callee = fact.callee.as_deref().unwrap_or_default();
    if callee.starts_with('$') {
        return true;
    }
    let dynamic_loader = matches!(
        callee.to_ascii_lowercase().as_str(),
        "require" | "import" | "__import__" | "importlib.import_module"
    );
    dynamic_loader
        && match fact.arguments.first() {
            Some(argument) => argument.resolved.is_none(),
            None => true,
        }
}

pub(super) fn resolve_fact_host(fact: &Fact) -> Option<String> {
    fact.arguments.iter().find_map(|argument| {
        argument
            .resolved
            .as_deref()
            .and_then(resolve_host)
            .or_else(|| resolve_host(&argument.raw))
    })
}

pub(super) fn sensitive_read(fact: &Fact) -> Option<String> {
    let callee = lower_callee(fact);
    let network_fact = is_network_fact(fact);
    let eligible = match fact.kind {
        FactKind::Access => true,
        FactKind::Command => {
            matches!(
                callee.as_str(),
                "cat" | "source" | "." | "grep" | "head" | "tail" | "cp" | "echo" | "printf"
            ) || network_fact
        }
        FactKind::Call => {
            network_fact
                || callee == "open"
                || callee.ends_with(".open")
                || callee.ends_with(".read_text")
                || callee.ends_with(".readfile")
                || callee.ends_with(".readfilesync")
                || callee.ends_with(".getenv")
        }
        FactKind::Assignment => true,
        _ => false,
    };
    if !eligible {
        return None;
    }
    let provenance_only = network_fact
        || fact.kind == FactKind::Assignment
        || (fact.kind == FactKind::Command && matches!(callee.as_str(), "echo" | "printf"));
    fact.arguments
        .iter()
        .flat_map(|argument| {
            if provenance_only {
                [argument.executable_reference.as_deref().unwrap_or(""), ""]
            } else {
                [
                    argument.raw.as_str(),
                    argument.resolved.as_deref().unwrap_or(""),
                ]
            }
        })
        .chain((fact.kind == FactKind::Access).then_some(fact.text.as_str()))
        .flat_map(|candidate| sensitive_read_re().find_iter(candidate))
        .max_by_key(|matched| sensitive_match_rank(matched.as_str()))
        .map(|matched| matched.as_str().to_string())
}

pub(super) fn writes_agent_config(fact: &Fact) -> bool {
    if fact.redirect.iter().any(static_value_is_agent_config) {
        return true;
    }
    write_target(fact).is_some_and(static_value_is_agent_config)
}

/// Map a fact to the static value naming its write destination. Targets are
/// derived from the operation's shape (receiver, first argument, last
/// argument) so every writer with the same shape shares one entry instead of
/// a per-callee early return.
fn write_target(fact: &Fact) -> Option<&StaticValue> {
    if !matches!(fact.kind, FactKind::Command | FactKind::Call) {
        return None;
    }
    let callee = lower_callee(fact);
    if matches!(callee.as_str(), "tee" | "cp" | "mv" | "install" | "sed") {
        return fact.arguments.last();
    }
    if callee.ends_with(".write_text") || callee.ends_with(".write_bytes") {
        return fact.receiver.as_ref();
    }
    if [
        ".writefile",
        ".writefilesync",
        ".appendfile",
        ".appendfilesync",
    ]
    .iter()
    .any(|suffix| callee.ends_with(suffix))
    {
        return fact.arguments.first();
    }
    if (callee == "open" || callee == "opensync" || callee.ends_with(".opensync"))
        && call_mode_is_write(fact)
    {
        return fact.arguments.first();
    }
    if callee == "createwritestream" || callee.ends_with(".createwritestream") {
        return fact.arguments.first();
    }
    None
}

fn static_value_is_agent_config(value: &StaticValue) -> bool {
    agent_config_write_re().is_match(&value.raw)
        || value
            .resolved
            .as_deref()
            .is_some_and(|resolved| agent_config_write_re().is_match(resolved))
}

pub(super) fn resolved_payload_matches(fact: &Fact, pattern: &Regex) -> bool {
    pattern.is_match(&fact.text)
        || fact.arguments.iter().any(|argument| {
            pattern.is_match(&argument.raw)
                || argument
                    .resolved
                    .as_deref()
                    .is_some_and(|value| pattern.is_match(value))
        })
}

fn call_mode_is_write(fact: &Fact) -> bool {
    fact.arguments.get(1).is_some_and(|mode| {
        let value = mode.resolved.as_deref().unwrap_or(mode.raw.as_str());
        value.contains('w') || value.contains('a') || value.contains('x')
    })
}

pub(super) fn is_obfuscation_fact(fact: &Fact) -> bool {
    if !matches!(fact.kind, FactKind::Command | FactKind::Call) {
        return false;
    }
    let callee = lower_callee(fact);
    (callee == "base64"
        && fact
            .arguments
            .iter()
            .any(|argument| matches!(argument.raw.as_str(), "-d" | "-D" | "--decode")))
        || (callee == "openssl" && fact.arguments.iter().any(|argument| argument.raw == "enc"))
        || matches!(
            callee.as_str(),
            "atob" | "string.fromcharcode" | "base64.b64decode"
        )
}

pub(super) fn is_exec_fact(fact: &Fact) -> bool {
    if fact.kind == FactKind::Pipeline {
        let lower = fact.text.to_ascii_lowercase();
        return ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "| iex"]
            .iter()
            .any(|marker| lower.contains(marker));
    }
    if !matches!(fact.kind, FactKind::Command | FactKind::Call) {
        return false;
    }
    let callee = lower_callee(fact);
    callee == "eval" || callee == "iex" || callee == "function" || is_exec_wrapper(&callee)
}

pub(super) fn is_remote_shell_pipeline_fact(fact: &Fact) -> bool {
    match fact.kind {
        FactKind::Pipeline => {
            let source = fact
                .callee
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let sink = fact
                .arguments
                .first()
                .and_then(|value| value.resolved.as_deref())
                .unwrap_or_default()
                .to_ascii_lowercase();
            is_network_client_token(&source) && is_shell_sink(&sink)
        }
        FactKind::Command | FactKind::Call => {
            if !is_exec_wrapper(&lower_callee(fact)) {
                return false;
            }
            fact.arguments.first().is_some_and(|argument| {
                let command = argument
                    .resolved
                    .clone()
                    .unwrap_or_else(|| argument.raw.trim_matches(['\'', '"', '`']).to_string());
                remote_shell_command_string(&command)
            })
        }
        _ => false,
    }
}

/// Bounded one-level parse of a shell command string handed to an exec
/// wrapper: split the pipeline once and check whether a network client is
/// piped into a shell interpreter. No recursion into nested command strings.
fn remote_shell_command_string(command: &str) -> bool {
    let segments: Vec<&str> = command.split('|').collect();
    if segments.len() < 2 || segments.iter().any(|segment| segment.trim().is_empty()) {
        return false;
    }
    let source = effective_command_token(segments[0]);
    let sink = effective_command_token(segments[segments.len() - 1]);
    source.is_some_and(|token| is_network_client_token(&token))
        && sink.is_some_and(|token| is_shell_sink(&token))
}

/// First token of a pipeline segment after stripping quotes, flags,
/// `VAR=value` prefixes, and shell wrappers (`sudo`, `env`), normalized to a
/// lowercase basename.
fn effective_command_token(segment: &str) -> Option<String> {
    segment
        .split_whitespace()
        .map(|token| token.trim_matches(['\'', '"', '`']))
        .find(|token| {
            !token.is_empty()
                && !token.starts_with('-')
                && !token.contains('=')
                && !is_shell_wrapper(token)
        })
        .map(|token| {
            token
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(token)
                .to_ascii_lowercase()
        })
}

fn is_shell_sink(token: &str) -> bool {
    matches!(token, "sh" | "bash" | "zsh" | "iex")
}

pub(super) fn is_destructive_fact(fact: &Fact) -> bool {
    fact.kind == FactKind::Command
        && fact.callee.as_deref() == Some("rm")
        && fact.arguments.iter().any(|argument| {
            let raw = argument.raw.as_str();
            raw == "-rf" || raw == "-fr" || raw.contains("--recursive")
        })
}

fn lower_callee(fact: &Fact) -> String {
    let lower = fact
        .callee
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lower = lower.strip_prefix("node:").unwrap_or(&lower);
    let lower = lower.strip_prefix("globalthis.").unwrap_or(lower);
    let lower = lower.strip_prefix("window.").unwrap_or(lower);
    lower.to_string()
}

fn is_exec_wrapper(callee: &str) -> bool {
    matches!(
        callee,
        "exec"
            | "os.system"
            | "subprocess.run"
            | "subprocess.call"
            | "subprocess.popen"
            | "child_process.exec"
            | "child_process.execsync"
            | "child_process.spawn"
            | "child_process.spawnsync"
    )
}

fn wrapper_network_client<'a>(fact: &'a Fact, callee: &str) -> Option<&'a str> {
    if is_exec_wrapper(callee) {
        return fact
            .arguments
            .first()
            .and_then(|argument| first_executed_token(&argument.raw))
            .filter(|token| is_network_client_token(token));
    }
    if !is_shell_wrapper(callee) {
        return None;
    }
    shell_wrapper_command(&fact.arguments, callee).filter(|token| is_network_client_token(token))
}

fn first_executed_token(raw: &str) -> Option<&str> {
    let mut value = raw.trim();
    if let Some((name, assigned)) = value.split_once('=') {
        if name.trim() == "args" {
            value = assigned.trim();
        }
    }
    value = value.trim_start_matches(['[', '(']).trim_start();
    let token = value.split(',').next()?.split_whitespace().next()?;
    Some(token.trim_matches(['\'', '"']))
}

fn is_network_client_token(value: &str) -> bool {
    let executable = value.rsplit(['/', '\\']).next().unwrap_or(value);
    matches!(
        executable.to_ascii_lowercase().as_str(),
        "curl" | "wget" | "iwr" | "invoke-webrequest" | "nc"
    )
}

fn sensitive_match_rank(value: &str) -> u8 {
    let lower = value.to_ascii_lowercase();
    if [
        ".aws/credentials",
        ".npmrc",
        "id_rsa",
        ".ssh/",
        "keychain",
        "anthropic_api_key",
        "openai_api_key",
        "aws_secret_access_key",
        "github_token",
        "claude_code_oauth_token",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || (lower.contains(".env")
            && !lower.contains("process.env")
            && !lower.contains("import.meta.env"))
    {
        2
    } else {
        1
    }
}
