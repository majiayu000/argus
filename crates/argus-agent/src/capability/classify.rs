use super::syntax::{Fact, FactKind};
use super::{agent_config_write_re, resolve_host, sensitive_read_re};

pub(super) fn is_network_fact(fact: &Fact) -> bool {
    if !matches!(fact.kind, FactKind::Command | FactKind::Call) {
        return false;
    }
    let callee = lower_callee(fact);
    matches!(
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
    )
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
                "cat" | "source" | "." | "grep" | "head" | "tail" | "cp"
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
        _ => false,
    };
    if !eligible {
        return None;
    }
    fact.arguments
        .iter()
        .flat_map(|argument| {
            if network_fact {
                [argument.executable_reference.as_deref().unwrap_or(""), ""]
            } else {
                [
                    argument.raw.as_str(),
                    argument.resolved.as_deref().unwrap_or(""),
                ]
            }
        })
        .chain((fact.kind == FactKind::Access).then_some(fact.text.as_str()))
        .find_map(|candidate| {
            sensitive_read_re()
                .find(candidate)
                .map(|matched| matched.as_str().to_string())
        })
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
    fact.redirect
        .iter()
        .flat_map(|target| {
            [
                target.raw.as_str(),
                target.resolved.as_deref().unwrap_or(""),
            ]
        })
        .chain(fact.arguments.iter().flat_map(|argument| {
            [
                argument.raw.as_str(),
                argument.resolved.as_deref().unwrap_or(""),
            ]
        }))
        .any(|value| agent_config_write_re().is_match(value))
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
    fact.callee
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase()
}
