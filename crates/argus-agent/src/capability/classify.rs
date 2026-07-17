use super::syntax::{Fact, FactKind};
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
    let callee = lower_callee(fact);
    let is_writer = fact.redirect.is_some()
        || matches!(callee.as_str(), "tee" | "cp" | "mv" | "install" | "sed")
        || callee == "open" && call_mode_is_write(fact)
        || callee.ends_with(".write_text")
        || callee.ends_with(".writefile")
        || callee.ends_with(".writefilesync")
        || callee.ends_with(".appendfile")
        || callee.ends_with(".appendfilesync");
    if !is_writer {
        return false;
    }
    if fact.redirect.iter().any(static_value_is_agent_config) {
        return true;
    }
    if callee.ends_with(".write_text") {
        return fact
            .receiver
            .as_ref()
            .is_some_and(static_value_is_agent_config);
    }
    let target = if callee == "open"
        || callee.ends_with(".writefile")
        || callee.ends_with(".writefilesync")
        || callee.ends_with(".appendfile")
        || callee.ends_with(".appendfilesync")
    {
        fact.arguments.first()
    } else if matches!(callee.as_str(), "tee" | "cp" | "mv" | "install" | "sed") {
        fact.arguments.last()
    } else {
        None
    };
    target.is_some_and(static_value_is_agent_config)
}

fn static_value_is_agent_config(value: &super::syntax::StaticValue) -> bool {
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
    matches!(
        lower_callee(fact).as_str(),
        "eval"
            | "exec"
            | "iex"
            | "os.system"
            | "subprocess.run"
            | "subprocess.call"
            | "subprocess.popen"
            | "child_process.exec"
            | "child_process.execsync"
            | "child_process.spawn"
            | "child_process.spawnsync"
            | "function"
    )
}

pub(super) fn is_remote_shell_pipeline_fact(fact: &Fact) -> bool {
    if fact.kind != FactKind::Pipeline {
        return false;
    }
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
    matches!(
        source.as_str(),
        "curl" | "wget" | "iwr" | "invoke-webrequest"
    ) && matches!(sink.as_str(), "sh" | "bash" | "zsh" | "iex")
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
    lower.strip_prefix("node:").unwrap_or(&lower).to_string()
}

fn is_exec_wrapper(callee: &str) -> bool {
    matches!(
        callee,
        "subprocess.run"
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
    if !matches!(callee, "sudo" | "env") {
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

fn shell_wrapper_command<'a>(
    arguments: &'a [super::syntax::StaticValue],
    wrapper: &str,
) -> Option<&'a str> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let value = argument.resolved.as_deref().unwrap_or(&argument.raw);
        if wrapper == "env" && value.contains('=') && !value.starts_with('-') {
            index += 1;
            continue;
        }
        if value.starts_with('-') {
            let takes_value = matches!(
                value,
                "-u" | "--user"
                    | "-g"
                    | "--group"
                    | "-h"
                    | "--host"
                    | "-C"
                    | "--chdir"
                    | "-R"
                    | "--chroot"
                    | "-D"
                    | "--close-from"
                    | "--unset"
            );
            index += if takes_value { 2 } else { 1 };
            continue;
        }
        return Some(value.trim_matches(['\'', '"']));
    }
    None
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
