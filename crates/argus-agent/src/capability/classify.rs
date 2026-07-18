use super::syntax::{
    is_shell_wrapper, shell_wrapper_command, Fact, FactKind, ScriptLanguage, StaticValue,
};
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

pub(super) fn sensitive_read(fact: &Fact) -> Option<(String, bool)> {
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
        FactKind::Pipeline => pipeline_sink_is_network(fact),
        _ => false,
    };
    if !eligible {
        return None;
    }
    let sensitive = if network_fact {
        network_sensitive_match(fact)
    } else if fact.kind == FactKind::Pipeline {
        pipeline_sensitive_match(fact)
    } else {
        let provenance_only = fact.kind == FactKind::Assignment
            || (fact.kind == FactKind::Command && matches!(callee.as_str(), "echo" | "printf"));
        let candidates = fact.arguments.iter().flat_map(|argument| {
            if provenance_only {
                [argument.executable_reference.as_deref().unwrap_or(""), ""]
            } else {
                [
                    argument.raw.as_str(),
                    argument.resolved.as_deref().unwrap_or(""),
                ]
            }
        });
        best_sensitive_match(
            candidates.chain((fact.kind == FactKind::Access).then_some(fact.text.as_str())),
        )
    };
    let network_correlatable = network_fact
        || fact.kind == FactKind::Pipeline
        || !matches!(fact.kind, FactKind::Assignment)
            && !(fact.kind == FactKind::Command && matches!(callee.as_str(), "echo" | "printf"));
    sensitive.map(|matched| (matched, network_correlatable))
}

fn pipeline_sink_is_network(fact: &Fact) -> bool {
    let Some(sink) = fact
        .arguments
        .first()
        .and_then(|sink| sink.resolved.as_deref())
    else {
        return false;
    };
    if !is_network_client_token(sink) {
        return false;
    }
    match executable_basename(sink).as_str() {
        "nc" => !nc_zero_io(&fact.pipeline_sink_arguments),
        "curl" => fact
            .pipeline_sink_arguments
            .iter()
            .enumerate()
            .any(|(index, argument)| {
                curl_argument_reads_stdin(&fact.pipeline_sink_arguments, index, argument)
            }),
        _ => false,
    }
}

fn network_sensitive_match(fact: &Fact) -> Option<String> {
    let mut matches = Vec::new();
    for (index, argument) in fact.arguments.iter().enumerate() {
        let reads_file = network_argument_reads_file(fact, index, argument);
        let candidates = [
            argument.executable_reference.as_deref().unwrap_or(""),
            if reads_file {
                argument.raw.as_str()
            } else {
                ""
            },
            reads_file
                .then_some(argument.resolved.as_deref())
                .flatten()
                .unwrap_or(""),
        ];
        for candidate in candidates {
            for matched in sensitive_read_re().find_iter(candidate) {
                if !is_sensitive_path(matched.as_str()) || reads_file {
                    matches.push(matched.as_str().to_string());
                }
            }
        }
    }
    matches
        .into_iter()
        .max_by_key(|matched| sensitive_match_rank(matched))
}

fn pipeline_sensitive_match(fact: &Fact) -> Option<String> {
    let mut matches = Vec::new();
    for (callee, arguments) in &fact.pipeline_sources {
        for (index, argument) in arguments.iter().enumerate() {
            let reads_file =
                executable_basename(callee) == "cat" && argument_is_positional(arguments, index);
            let candidates = [
                argument.executable_reference.as_deref().unwrap_or(""),
                if reads_file {
                    argument.raw.as_str()
                } else {
                    ""
                },
                reads_file
                    .then_some(argument.resolved.as_deref())
                    .flatten()
                    .unwrap_or(""),
            ];
            for candidate in candidates {
                for matched in sensitive_read_re().find_iter(candidate) {
                    if pipeline_stage_emits_sensitive(callee, arguments, index, matched.as_str()) {
                        matches.push(matched.as_str().to_string());
                    }
                }
            }
        }
    }
    matches
        .into_iter()
        .max_by_key(|matched| sensitive_match_rank(matched))
}

fn best_sensitive_match<'a>(candidates: impl IntoIterator<Item = &'a str>) -> Option<String> {
    candidates
        .into_iter()
        .flat_map(|candidate| {
            sensitive_read_re()
                .find_iter(candidate)
                .map(|matched| matched.as_str().to_string())
        })
        .max_by_key(|matched| sensitive_match_rank(matched))
}

fn network_argument_reads_file(fact: &Fact, index: usize, argument: &StaticValue) -> bool {
    let candidate = argument.executable_reference.as_deref().unwrap_or("");
    if candidate.contains("open(") {
        return true;
    }
    effective_network_client(fact).as_deref() == Some("curl")
        && curl_argument_reads_file(&fact.arguments, index, argument)
}

fn previous_argument(arguments: &[StaticValue], index: usize) -> Option<&str> {
    let previous = index
        .checked_sub(1)
        .and_then(|offset| arguments.get(offset))?;
    Some(
        previous
            .resolved
            .as_deref()
            .unwrap_or(previous.raw.as_str())
            .trim_matches(['\'', '"']),
    )
}

fn curl_argument_reads_file(
    arguments: &[StaticValue],
    index: usize,
    argument: &StaticValue,
) -> bool {
    let raw = argument.raw.trim_matches(['\'', '"']);
    let previous = previous_argument(arguments, index);
    raw.starts_with("--upload-file=")
        || (raw.starts_with("-T") && raw.len() > 2)
        || ((raw.starts_with("--data=")
            || raw.starts_with("--data-binary=")
            || raw.starts_with("--form="))
            && raw.contains("=@"))
        || (raw.starts_with('@')
            && previous.is_some_and(|option| {
                matches!(option, "-d" | "--data" | "--data-binary" | "-F" | "--form")
            }))
        || (raw.contains("=@") && previous.is_some_and(|option| matches!(option, "-F" | "--form")))
        || previous.is_some_and(|option| matches!(option, "-T" | "--upload-file"))
}

fn curl_argument_reads_stdin(
    arguments: &[StaticValue],
    index: usize,
    argument: &StaticValue,
) -> bool {
    let value = argument
        .resolved
        .as_deref()
        .unwrap_or(argument.raw.as_str())
        .trim_matches(['\'', '"']);
    value == "--upload-file=-"
        || value == "-T-"
        || ((value.starts_with("--data=")
            || value.starts_with("--data-binary=")
            || value.starts_with("--form="))
            && value.ends_with("=@-"))
        || (value == "@-"
            && previous_argument(arguments, index).is_some_and(|option| {
                matches!(option, "-d" | "--data" | "--data-binary" | "-F" | "--form")
            }))
        || (value.ends_with("=@-")
            && previous_argument(arguments, index)
                .is_some_and(|option| matches!(option, "-F" | "--form")))
        || (value == "-"
            && previous_argument(arguments, index)
                .is_some_and(|option| matches!(option, "-T" | "--upload-file")))
}

fn pipeline_stage_emits_sensitive(
    callee: &str,
    arguments: &[StaticValue],
    index: usize,
    matched: &str,
) -> bool {
    match executable_basename(callee).as_str() {
        "echo" | "printf" => !is_sensitive_path(matched),
        "cat" => is_sensitive_path(matched) && argument_is_positional(arguments, index),
        _ => false,
    }
}

fn argument_is_positional(arguments: &[StaticValue], index: usize) -> bool {
    arguments.get(index).is_some_and(|argument| {
        !argument
            .resolved
            .as_deref()
            .unwrap_or(argument.raw.as_str())
            .starts_with('-')
    })
}

fn effective_network_client(fact: &Fact) -> Option<String> {
    let callee = lower_callee(fact);
    if is_network_client_token(&callee) {
        return Some(executable_basename(&callee));
    }
    wrapper_network_client(fact, &callee).map(executable_basename)
}

fn nc_zero_io(arguments: &[StaticValue]) -> bool {
    arguments.iter().any(|argument| {
        let value = argument
            .resolved
            .as_deref()
            .unwrap_or(argument.raw.as_str());
        value == "--zero"
            || value
                .strip_prefix('-')
                .is_some_and(|flags| !flags.starts_with('-') && flags.contains('z'))
    })
}

fn is_sensitive_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let dotenv = lower.trim_matches(|character: char| {
        character.is_whitespace() || ",;:\"'()[]{}".contains(character)
    }) == ".env";
    dotenv
        || [".aws/credentials", ".npmrc", "id_rsa", ".ssh/", "keychain"]
            .iter()
            .any(|marker| lower.contains(marker))
}

pub(super) fn writes_agent_config(fact: &Fact) -> bool {
    if fact.redirect.iter().any(static_value_is_agent_config) {
        return true;
    }
    write_targets(fact)
        .into_iter()
        .any(static_value_is_agent_config)
}

/// Map a fact to the static values naming configuration-sensitive endpoints.
/// Targets are derived from the operation's shape (receiver, positional
/// operands, first argument, last argument) so every writer with the same
/// shape shares one entry instead of a per-callee early return.
fn write_targets(fact: &Fact) -> Vec<&StaticValue> {
    if !matches!(fact.kind, FactKind::Command | FactKind::Call) {
        return Vec::new();
    }
    let callee = lower_callee(fact);
    if matches!(callee.as_str(), "cp" | "mv") {
        return positional_file_operands(&fact.arguments);
    }
    if matches!(callee.as_str(), "tee" | "install" | "sed") {
        return fact.arguments.last().into_iter().collect();
    }
    if callee.ends_with(".write_text") || callee.ends_with(".write_bytes") {
        return fact.receiver.iter().collect();
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
        return fact.arguments.first().into_iter().collect();
    }
    if (callee == "open" || callee == "opensync" || callee.ends_with(".opensync"))
        && call_mode_is_write(fact)
    {
        return fact.arguments.first().into_iter().collect();
    }
    if callee == "createwritestream" || callee.ends_with(".createwritestream") {
        return fact.arguments.first().into_iter().collect();
    }
    Vec::new()
}

fn positional_file_operands(arguments: &[StaticValue]) -> Vec<&StaticValue> {
    let mut operands = Vec::new();
    let mut target_directory = None;
    let mut options = true;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let value = argument
            .resolved
            .as_deref()
            .unwrap_or(argument.raw.as_str());
        if options && value == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && matches!(value, "-S" | "--suffix") {
            index += 2;
            continue;
        }
        if options && matches!(value, "-t" | "--target-directory") {
            if let Some(target) = arguments.get(index + 1) {
                target_directory = Some(target);
            }
            index += 2;
            continue;
        }
        if options
            && (value.starts_with("--target-directory=")
                || value
                    .strip_prefix("-t")
                    .is_some_and(|path| !path.is_empty()))
        {
            target_directory = Some(argument);
            index += 1;
            continue;
        }
        if options && value.starts_with('-') {
            index += 1;
            continue;
        }
        operands.push(argument);
        index += 1;
    }
    match target_directory {
        Some(target) if !operands.is_empty() => {
            operands.push(target);
            operands
        }
        None if operands.len() >= 2 => operands,
        _ => Vec::new(),
    }
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
            let callee = lower_callee(fact);
            if !is_string_executor(fact, &callee) {
                return false;
            }
            string_executor_command(fact, &callee)
                .as_deref()
                .is_some_and(remote_shell_command_string)
        }
        _ => false,
    }
}

fn is_string_executor(fact: &Fact, callee: &str) -> bool {
    is_exec_wrapper(callee)
        || (fact.language == ScriptLanguage::Bash && matches!(callee, "eval" | "iex"))
}

fn string_executor_command(fact: &Fact, callee: &str) -> Option<String> {
    if fact.language == ScriptLanguage::Bash && matches!(callee, "eval" | "iex") {
        let arguments: Option<Vec<&str>> = fact
            .arguments
            .iter()
            .map(|argument| argument.resolved.as_deref())
            .collect();
        return arguments
            .filter(|values| !values.is_empty())
            .map(|values| values.join(" "));
    }
    fact.arguments.first()?.resolved.clone()
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
    matches!(
        executable_basename(value).as_str(),
        "curl" | "wget" | "iwr" | "invoke-webrequest" | "nc"
    )
}

fn executable_basename(value: &str) -> String {
    value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase()
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
