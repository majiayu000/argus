//! AGT-05 — high-risk agent configuration flags (VibeGuard SEC-12/SEC-13),
//! checked structurally via serde_json (no regex on config bodies):
//!
//! - `mcpServers.<name>.alwaysLoad: true` — permanent full trust, bypasses
//!   deferred-load description review.
//! - `enableAllProjectMcpServers: true` — blanket project MCP trust.
//! - `enabledMcpjsonServers` non-empty — pre-approved MCP server list.
//! - `PostToolUse` hook whose command (inline or referenced script) contains
//!   `updatedToolOutput` with a non-MCP matcher — tool-output rewriting MITM.
//!
//! Unparseable config files produce an info finding instead of a hard error
//! (product edge case 3).

use crate::{SurfaceFile, SurfaceKind};
use argus_core::fs::read_bounded_utf8_regular_file;
use argus_core::{Finding, Severity};
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

const RULE_ALWAYS_LOAD: &str = "AGT-05-mcp-always-load";
const RULE_ENABLE_ALL: &str = "AGT-05-enable-all-project-mcp";
const RULE_ENABLED_LIST: &str = "AGT-05-enabled-mcpjson-servers";
const RULE_OUTPUT_REWRITE: &str = "AGT-05-posttooluse-output-rewrite";
const RULE_HOOK_UNASSESSED: &str = "AGT-05-hook-unassessed";
const RULE_UNPARSEABLE: &str = "AGT-05-config-unparseable";
const HOOK_SCRIPT_MAX_BYTES: usize = 1024 * 1024;
const COMMAND_MAX_BYTES: usize = 8192;

pub fn run(root: &Path, files: &[SurfaceFile], findings: &mut Vec<Finding>) {
    for file in files {
        if file.kind != SurfaceKind::McpConfig {
            continue;
        }
        let value: Value = match serde_json::from_str(&file.content) {
            Ok(v) => v,
            Err(e) => {
                findings.push(
                    Finding::new(
                        RULE_UNPARSEABLE,
                        Severity::Info,
                        format!("agent config is not valid JSON: {e}"),
                    )
                    .at(&file.rel),
                );
                continue;
            }
        };
        check_always_load(&value, &file.rel, findings);
        check_enable_all(&value, &file.rel, findings);
        check_enabled_list(&value, &file.rel, findings);
        check_posttooluse_rewrite(root, &value, &file.rel, findings);
    }
}

fn check_always_load(value: &Value, rel: &str, findings: &mut Vec<Finding>) {
    let Some(servers) = value.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (name, server) in servers {
        if server.get("alwaysLoad").and_then(Value::as_bool) == Some(true) {
            findings.push(
                Finding::new(
                    RULE_ALWAYS_LOAD,
                    Severity::Medium,
                    format!("MCP server `{name}` sets alwaysLoad: true (permanent full trust, skips deferred-load description review)"),
                )
                .at(rel),
            );
        }
    }
}

fn check_enable_all(value: &Value, rel: &str, findings: &mut Vec<Finding>) {
    if value
        .get("enableAllProjectMcpServers")
        .and_then(Value::as_bool)
        == Some(true)
    {
        findings.push(
            Finding::new(
                RULE_ENABLE_ALL,
                Severity::Medium,
                "enableAllProjectMcpServers: true grants blanket trust to every project MCP server",
            )
            .at(rel),
        );
    }
}

fn check_enabled_list(value: &Value, rel: &str, findings: &mut Vec<Finding>) {
    if let Some(list) = value.get("enabledMcpjsonServers").and_then(Value::as_array) {
        if !list.is_empty() {
            findings.push(
                Finding::new(
                    RULE_ENABLED_LIST,
                    Severity::Medium,
                    format!(
                        "enabledMcpjsonServers pre-approves {} MCP server(s)",
                        list.len()
                    ),
                )
                .at(rel),
            );
        }
    }
}

fn check_posttooluse_rewrite(root: &Path, value: &Value, rel: &str, findings: &mut Vec<Finding>) {
    let Some(entries) = value
        .get("hooks")
        .and_then(|h| h.get("PostToolUse"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for entry in entries {
        let matcher = entry.get("matcher").and_then(Value::as_str).unwrap_or("*");
        if matcher.starts_with("mcp__") {
            continue; // MCP-output rewriting is the documented legitimate case
        }
        let commands = entry
            .get("hooks")
            .and_then(Value::as_array)
            .map(|hooks| {
                hooks
                    .iter()
                    .filter_map(|h| h.get("command").and_then(Value::as_str))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for command in commands {
            match inspect_output_rewrite(root, command) {
                HookInspection::Rewrites => findings.push(
                    Finding::new(
                        RULE_OUTPUT_REWRITE,
                        Severity::Medium,
                        format!(
                            "PostToolUse hook (matcher `{matcher}`) rewrites tool output via updatedToolOutput"
                        ),
                    )
                    .at(rel),
                ),
                HookInspection::Unassessed(reason) => findings.push(
                    Finding::new(
                        RULE_HOOK_UNASSESSED,
                        Severity::Medium,
                        format!(
                            "PostToolUse hook (matcher `{matcher}`) could not be safely assessed: {reason}"
                        ),
                    )
                    .at(rel),
                ),
                HookInspection::Clean => {}
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum HookInspection {
    Clean,
    Rewrites,
    Unassessed(String),
}

/// Inspect inline command text and conservatively resolved script operands.
/// Referenced files must stay below the canonical scan root and are read via
/// the shared no-follow, non-blocking, bounded regular-file primitive.
fn inspect_output_rewrite(root: &Path, command: &str) -> HookInspection {
    if command.contains("updatedToolOutput") {
        return HookInspection::Rewrites;
    }
    let candidates = match script_candidates(command) {
        Ok(candidates) => candidates,
        Err(reason) => return HookInspection::Unassessed(reason),
    };
    for candidate in candidates {
        let Some(path) = (match contained_existing_path(root, &candidate) {
            Ok(path) => path,
            Err(reason) => return HookInspection::Unassessed(reason),
        }) else {
            continue;
        };
        match read_bounded_utf8_regular_file(&path, HOOK_SCRIPT_MAX_BYTES) {
            Ok(body) if body.contains("updatedToolOutput") => return HookInspection::Rewrites,
            Ok(_) => {}
            Err(error) => {
                return HookInspection::Unassessed(format!(
                    "referenced script is not a bounded UTF-8 regular file ({error})"
                ))
            }
        }
    }
    HookInspection::Clean
}

fn script_candidates(command: &str) -> std::result::Result<Vec<PathBuf>, String> {
    if [";", "&&", "||", "|", "`", "$("]
        .iter()
        .any(|operator| command.contains(operator))
    {
        return Err(
            "command contains shell composition that cannot be safely resolved".to_string(),
        );
    }
    let tokens = tokenize_command(command)?;
    let Some(first) = tokens.first() else {
        return Ok(Vec::new());
    };
    let executable = Path::new(first)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(first)
        .to_ascii_lowercase();
    let interpreter = matches!(
        executable.as_str(),
        "bash"
            | "sh"
            | "zsh"
            | "python"
            | "python3"
            | "node"
            | "ruby"
            | "pwsh"
            | "powershell"
            | "powershell.exe"
    );
    let operands = if interpreter {
        if tokens[1..].iter().any(|token| {
            matches!(
                token.to_ascii_lowercase().as_str(),
                "-c" | "--command" | "-command" | "-encodedcommand"
            )
        }) {
            return Err("interpreter uses an opaque inline command mode".to_string());
        }
        &tokens[1..]
    } else {
        &tokens[..1]
    };
    Ok(operands
        .iter()
        .filter(|token| !token.starts_with('-') && looks_like_script_path(token))
        .map(PathBuf::from)
        .collect())
}

fn looks_like_script_path(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    token.contains('/')
        || token.contains('\\')
        || [
            ".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".mjs", ".rb", ".ps1", ".psm1",
        ]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn contained_existing_path(
    root: &Path,
    candidate: &Path,
) -> std::result::Result<Option<PathBuf>, String> {
    if candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err("referenced script escapes the scan root".to_string());
    }
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|error| format!("scan root cannot be canonicalized ({error})"))?;
    let joined = canonical_root.join(candidate);
    let canonical = match std::fs::canonicalize(&joined) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("referenced script cannot be resolved ({error})")),
    };
    if !canonical.starts_with(&canonical_root) {
        return Err("referenced script resolves outside the scan root".to_string());
    }
    Ok(Some(canonical))
}

fn tokenize_command(command: &str) -> std::result::Result<Vec<String>, String> {
    if command.len() > COMMAND_MAX_BYTES {
        return Err(format!("command exceeds {COMMAND_MAX_BYTES} byte limit"));
    }
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in command.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err("command has incomplete quoting or escaping".to_string());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(content: &str) -> SurfaceFile {
        SurfaceFile {
            rel: ".claude/settings.json".into(),
            content: content.into(),
            kind: SurfaceKind::McpConfig,
        }
    }

    fn run_on(content: &str) -> Vec<Finding> {
        let mut f = Vec::new();
        run(Path::new("/nonexistent"), &[cfg(content)], &mut f);
        f
    }

    #[test]
    fn fires_on_always_load() {
        let f = run_on(r#"{"mcpServers":{"x":{"alwaysLoad":true}}}"#);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, RULE_ALWAYS_LOAD);
    }

    #[test]
    fn fires_on_enable_all_and_enabled_list() {
        let f = run_on(r#"{"enableAllProjectMcpServers":true,"enabledMcpjsonServers":["a"]}"#);
        let ids: Vec<_> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(
            ids.contains(&RULE_ENABLE_ALL) && ids.contains(&RULE_ENABLED_LIST),
            "{ids:?}"
        );
    }

    #[test]
    fn fires_on_inline_output_rewrite_for_non_mcp_matcher() {
        let f = run_on(
            r#"{"hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"command":"jq '.hookSpecificOutput.updatedToolOutput=\"ok\"'"}]}]}}"#,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, RULE_OUTPUT_REWRITE);
    }

    #[test]
    fn mcp_matcher_rewrite_is_exempt() {
        let f = run_on(
            r#"{"hooks":{"PostToolUse":[{"matcher":"mcp__redactor","hooks":[{"command":"redact updatedToolOutput"}]}]}}"#,
        );
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn unparseable_config_reports_info() {
        let f = run_on("{not json");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, RULE_UNPARSEABLE);
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn benign_config_is_clean() {
        let f = run_on(r#"{"mcpServers":{"x":{"command":"node","args":["server.js"]}}}"#);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn interpreter_wrapped_script_is_inspected() {
        let root = tempfile::tempdir().expect("test root");
        std::fs::create_dir(root.path().join("hooks")).expect("hooks directory");
        std::fs::write(
            root.path().join("hooks/rewrite.py"),
            "print('updatedToolOutput')\n",
        )
        .expect("hook script");
        assert_eq!(
            inspect_output_rewrite(root.path(), "python3 'hooks/rewrite.py'"),
            HookInspection::Rewrites
        );
    }

    #[test]
    fn traversal_and_absolute_script_references_are_not_read() {
        let root = tempfile::tempdir().expect("test root");
        assert!(matches!(
            inspect_output_rewrite(root.path(), "python ../outside.py"),
            HookInspection::Unassessed(_)
        ));
        assert!(matches!(
            inspect_output_rewrite(root.path(), "python /dev/zero"),
            HookInspection::Unassessed(_)
        ));
    }

    #[test]
    fn oversized_and_non_utf8_hook_scripts_are_unassessed() {
        let root = tempfile::tempdir().expect("test root");
        let large = root.path().join("large.py");
        std::fs::write(&large, vec![b'x'; HOOK_SCRIPT_MAX_BYTES + 1]).expect("large hook");
        assert!(matches!(
            inspect_output_rewrite(root.path(), "python large.py"),
            HookInspection::Unassessed(_)
        ));
        let binary = root.path().join("binary.py");
        std::fs::write(&binary, [0xff, 0xfe]).expect("binary hook");
        assert!(matches!(
            inspect_output_rewrite(root.path(), "python binary.py"),
            HookInspection::Unassessed(_)
        ));
    }

    #[test]
    fn shell_composition_and_inline_interpreter_commands_are_unassessed() {
        let root = tempfile::tempdir().expect("test root");
        for command in [
            "bash hooks/check.sh | tee result",
            "bash -c 'source hooks/check.sh'",
            "powershell -Command hooks/check.ps1",
        ] {
            assert!(matches!(
                inspect_output_rewrite(root.path(), command),
                HookInspection::Unassessed(_)
            ));
        }
    }
}
