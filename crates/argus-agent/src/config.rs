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
use argus_core::{Finding, Severity};
use serde_json::Value;
use std::path::Path;

const RULE_ALWAYS_LOAD: &str = "AGT-05-mcp-always-load";
const RULE_ENABLE_ALL: &str = "AGT-05-enable-all-project-mcp";
const RULE_ENABLED_LIST: &str = "AGT-05-enabled-mcpjson-servers";
const RULE_OUTPUT_REWRITE: &str = "AGT-05-posttooluse-output-rewrite";
const RULE_UNPARSEABLE: &str = "AGT-05-config-unparseable";

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
            if command_rewrites_output(root, command) {
                findings.push(
                    Finding::new(
                        RULE_OUTPUT_REWRITE,
                        Severity::Medium,
                        format!(
                            "PostToolUse hook (matcher `{matcher}`) rewrites tool output via updatedToolOutput: `{command}`"
                        ),
                    )
                    .at(rel),
                );
            }
        }
    }
}

/// True when the inline command text, or the script file it points at,
/// contains `updatedToolOutput`. The referenced script is read as text only.
fn command_rewrites_output(root: &Path, command: &str) -> bool {
    if command.contains("updatedToolOutput") {
        return true;
    }
    let Some(first) = command.split_whitespace().next() else {
        return false;
    };
    let candidate = Path::new(first);
    let path = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    match std::fs::read_to_string(&path) {
        Ok(body) => body.contains("updatedToolOutput"),
        Err(_) => false,
    }
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
}
