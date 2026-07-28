//! Lifecycle-script and pre-scan marker rules.

use crate::PackageContext;
use anyhow::{Context, Result};
use argus_core::{Finding, Severity};
use argus_syntax::{
    bounded_shell_pipeline, effective_command_token, is_exec_wrapper, Fact, FactKind,
    ScriptLanguage, StaticValue,
};
use regex::Regex;
use std::sync::OnceLock;

const LIFECYCLE_SCRIPT_NAMES: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "preuninstall",
    "uninstall",
    "postuninstall",
];

/// Pattern used by the `blocked-marker` fixture and similar real attacks:
/// writing to a host-controlled path during a lifecycle script.
fn marker_write_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            fs\s*\.\s*(write|append|create)[A-Za-z]*Sync\s*\(\s*[\"']
            (
                /tmp/ |
                /var/tmp/ |
                ~/ |
                \$HOME/ |
                /etc/ |
                /usr/local/
            )
            "#,
        )
        .unwrap()
    })
}

pub fn run(ctx: &PackageContext, findings: &mut Vec<Finding>) -> Result<()> {
    let mut remote_shell = None;
    let mut legacy_script_blob = String::new();

    // Lifecycle bodies are executable shell surfaces even though package.json
    // has no file extension. Analyze them explicitly as Bash. Non-lifecycle
    // script keys keep their previous lexical coverage, but are selected
    // before scanning so one body never has two owners for these rule IDs.
    for name in LIFECYCLE_SCRIPT_NAMES {
        if let Some(body) = ctx
            .package
            .scripts
            .get(*name)
            .filter(|body| !body.trim().is_empty())
        {
            let path = format!("package.json:scripts/{name}");
            let facts = argus_syntax::analyze_with_language(&path, body, ScriptLanguage::Bash)
                .with_context(|| format!("parse npm lifecycle script `{name}` as Bash"))?;
            if remote_shell.is_none() {
                remote_shell = facts
                    .iter()
                    .find(|fact| remote_shell_fact(fact))
                    .map(|fact| fact.text.clone());
            }
            findings.push(
                Finding::new(
                    "lifecycle-script",
                    Severity::High,
                    format!("package.json declares `{name}` script: {body}"),
                )
                .at("package.json"),
            );
        }
    }
    for (name, body) in &ctx.package.scripts {
        if !LIFECYCLE_SCRIPT_NAMES.contains(&name.as_str()) && !body.trim().is_empty() {
            legacy_script_blob.push_str(body);
            legacy_script_blob.push('\n');
        }
    }

    if remote_shell.is_none() {
        remote_shell = legacy_curl_sh_pipe(&legacy_script_blob);
    }
    if let Some(matched) = remote_shell {
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

    for file in &ctx.text_files {
        scan_text_file(file, findings);
    }

    Ok(())
}

pub(crate) fn scan_text_file(file: &crate::TextFile, findings: &mut Vec<Finding>) {
    if is_script_file(&file.rel) && marker_write_regex().is_match(&file.content) {
        findings.push(
            Finding::new(
                "pre-scan-execution-marker",
                Severity::High,
                "lifecycle script writes a host-controlled marker path",
            )
            .at(&file.rel),
        );
    }
}

fn remote_shell_fact(fact: &Fact) -> bool {
    match fact.kind {
        FactKind::Pipeline => remote_shell_pipeline(fact),
        FactKind::Command => {
            command_string(fact).is_some_and(|command| remote_shell_command_string(&command))
        }
        _ => false,
    }
}

fn remote_shell_pipeline(fact: &Fact) -> bool {
    let Some(scan_text) = fact.pipeline_scan_text.as_deref() else {
        return false;
    };
    let Some((segments, edges)) = bounded_shell_pipeline(scan_text) else {
        return false;
    };
    let mut commands = fact
        .pipeline_sources
        .iter()
        .map(|(callee, _)| callee.clone())
        .collect::<Vec<_>>();
    if let Some(sink) = fact.arguments.first().and_then(static_text) {
        commands.push(sink.to_string());
    }
    if commands.len() != segments.len() {
        return false;
    }
    for source_index in 0..commands.len().saturating_sub(1) {
        if !is_download_client(&commands[source_index]) {
            continue;
        }
        for sink_index in source_index + 1..commands.len() {
            if edges[source_index..sink_index]
                .iter()
                .all(|connected| *connected)
                && is_shell_sink(&commands[sink_index])
            {
                return true;
            }
        }
    }
    false
}

fn command_string(fact: &Fact) -> Option<String> {
    let callee = fact.callee.as_deref()?.to_ascii_lowercase();
    if callee == "eval" {
        return fact
            .arguments
            .iter()
            .map(|argument| argument.resolved.as_deref())
            .collect::<Option<Vec<_>>>()
            .filter(|arguments| !arguments.is_empty())
            .map(|arguments| arguments.join(" "));
    }
    if is_exec_wrapper(&callee) {
        return fact.arguments.first()?.resolved.clone();
    }
    if matches!(executable_basename(&callee), "sh" | "bash" | "zsh") {
        let command_index = fact
            .arguments
            .iter()
            .position(|argument| static_text(argument) == Some("-c"))?
            + 1;
        return fact.arguments.get(command_index)?.resolved.clone();
    }
    None
}

fn remote_shell_command_string(command: &str) -> bool {
    let Some((segments, edges)) = bounded_shell_pipeline(command) else {
        return false;
    };
    let commands = segments
        .iter()
        .map(|segment| effective_command_token(segment))
        .collect::<Vec<_>>();
    for source_index in 0..commands.len().saturating_sub(1) {
        if !commands[source_index]
            .as_deref()
            .is_some_and(is_download_client)
        {
            continue;
        }
        for sink_index in source_index + 1..commands.len() {
            if edges[source_index..sink_index]
                .iter()
                .all(|connected| *connected)
                && commands[sink_index].as_deref().is_some_and(is_shell_sink)
            {
                return true;
            }
        }
    }
    false
}

fn static_text(value: &StaticValue) -> Option<&str> {
    value.resolved.as_deref().or(Some(value.raw.as_str()))
}

fn executable_basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

fn is_download_client(value: &str) -> bool {
    matches!(
        executable_basename(value).to_ascii_lowercase().as_str(),
        "curl" | "wget"
    )
}

fn is_shell_sink(value: &str) -> bool {
    matches!(
        executable_basename(value).to_ascii_lowercase().as_str(),
        "sh" | "bash" | "zsh"
    )
}

fn legacy_curl_sh_pipe(blob: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re =
        RE.get_or_init(|| Regex::new(r#"(?i)(curl|wget)\s+[^\n]*\|\s*(sh|bash|zsh)\b"#).unwrap());
    re.find(blob).map(|matched| matched.as_str().to_string())
}

fn is_script_file(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    lower.ends_with(".js")
        || lower.ends_with(".cjs")
        || lower.ends_with(".mjs")
        || lower.ends_with(".ts")
        || lower.ends_with(".sh")
}
