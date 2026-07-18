//! Capability extraction and intent/capability misfit checks for skill scripts.
//!
//! The first layer is declarative: extract what the script can do and surface
//! it as machine-readable manifest fields. The second layer decides only clear
//! high-risk mismatches, keeping benign capability use at approval level.

use crate::{SurfaceFile, SurfaceKind};
use anyhow::Result;
use argus_core::{Finding, Severity};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

mod classify;
mod syntax;

use classify::{
    is_destructive_fact, is_exec_fact, is_incomplete_fact, is_network_fact, is_obfuscation_fact,
    is_remote_shell_pipeline_fact, resolve_fact_host, resolved_payload_matches, sensitive_read,
    writes_agent_config,
};
use syntax::FactKind;

const RULE_REMOTE_EXEC: &str = "AGT-03-remote-exec";
const RULE_SECRET_EXFIL: &str = "AGT-03-secret-exfil";
const RULE_AGENT_CONFIG_WRITE: &str = "agent-config-write";
const RULE_HOOK_PERSISTENCE: &str = "hook-persistence";
const RULE_CAPABILITY_MISFIT: &str = "capability-misfit";
const RULE_OBFUSCATION: &str = "obfuscation";
const RULE_SHELL_PIPE: &str = "shell-pipe-execution";
const RULE_REMOTE_DOWNLOAD: &str = "remote-download";
const RULE_CREDENTIAL_ACCESS: &str = "credential-access";
const RULE_NETWORK_EXFILTRATION: &str = "network-exfiltration";
const RULE_CAPABILITY_MANIFEST: &str = "capability-manifest";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Intent {
    AgentConfigTool,
    NetworkTool,
    Installer,
    FormatterOrDocs,
    Stats,
    Other,
}

impl Intent {
    fn from_files(files: &[SurfaceFile]) -> Self {
        let mut text = String::new();
        for file in files {
            if file.kind == SurfaceKind::Instruction {
                text.push_str(&file.content.to_ascii_lowercase());
                text.push('\n');
            }
        }

        if contains_any(
            &text,
            &[
                "agent config",
                "agent configuration",
                ".claude",
                "settings.json",
                "settings.local.json",
                "hook",
                "mcp",
            ],
        ) {
            Intent::AgentConfigTool
        } else if contains_any(
            &text,
            &[
                "weather", "api", "http", "https", "network", "fetch", "query", "service",
                "endpoint",
            ],
        ) {
            Intent::NetworkTool
        } else if contains_any(
            &text,
            &["install", "installer", "setup", "scaffold", "init"],
        ) {
            Intent::Installer
        } else if contains_any(
            &text,
            &[
                "markdown",
                "format",
                "formatter",
                "beautif",
                "document",
                "docs",
            ],
        ) {
            Intent::FormatterOrDocs
        } else if contains_any(&text, &["stats", "statistics", "contributors", "commit"]) {
            Intent::Stats
        } else {
            Intent::Other
        }
    }

    fn allows_agent_config_write(self) -> bool {
        matches!(self, Intent::AgentConfigTool)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapabilityHit {
    capability: &'static str,
    rel: String,
    line: usize,
    detail: String,
    resolved_host: Option<String>,
}

impl CapabilityHit {
    fn evidence(&self) -> Vec<String> {
        vec![format!("{}:{}", self.rel, self.line)]
    }

    fn finding(&self, rule_id: &str, severity: Severity, detail: impl Into<String>) -> Finding {
        Finding::new(rule_id, severity, detail)
            .at(&self.rel)
            .with_capability(self.capability, self.evidence(), self.resolved_host.clone())
    }
}

fn url_host_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"https?://([A-Za-z0-9.-]+)(?::\d+)?"#).expect("URL host pattern compiles")
    })
}

fn sensitive_read_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(\$HOME/\.aws/credentials|~/\.aws/credentials|\.aws/credentials|\.npmrc|id_rsa|\.ssh/|keychain|(^|[^\w.])\.env\b|ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|CLAUDE_CODE_OAUTH_TOKEN|[A-Z][A-Z0-9_]*API_KEY|process\.env\.[A-Z][A-Z0-9_]*|os\.environ|getenv\()"#,
        )
        .expect("sensitive read pattern compiles")
    })
}

fn agent_config_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(\.claude/(settings(\.local)?\.json|hooks)|\$HOME/\.claude/(settings(\.local)?\.json|hooks)|~/\.claude/(settings(\.local)?\.json|hooks))"#)
            .expect("agent config write pattern compiles")
    })
}

fn hook_persistence_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(PreToolUse|PostToolUse|decision["']?\s*:\s*["']approve["']|auto-?approv)"#,
        )
        .expect("hook persistence pattern compiles")
    })
}

pub fn run(files: &[SurfaceFile], findings: &mut Vec<Finding>) -> Result<()> {
    let intent = Intent::from_files(files);
    for file in files {
        if file.kind != SurfaceKind::Script {
            continue;
        }
        let hits = extract_capabilities(file)?;
        emit_findings(intent, &hits, findings);
    }
    Ok(())
}

fn extract_capabilities(file: &SurfaceFile) -> Result<Vec<CapabilityHit>> {
    let mut hits = Vec::new();
    let mut seen = BTreeSet::new();
    for fact in syntax::analyze(file)? {
        if fact.kind == FactKind::Unsupported {
            push_hit(
                &mut hits,
                &mut seen,
                "analysis_incomplete",
                file,
                fact.line,
                fact.text,
                None,
            );
            continue;
        }

        if is_incomplete_fact(&fact) {
            push_hit(
                &mut hits,
                &mut seen,
                "analysis_incomplete",
                file,
                fact.line,
                "dynamic import, require, or command dispatch could not be statically resolved",
                None,
            );
        }

        if is_network_fact(&fact) {
            if let Some(host) = resolve_fact_host(&fact) {
                push_hit(
                    &mut hits,
                    &mut seen,
                    "net_egress",
                    file,
                    fact.line,
                    format!("network egress to {host}"),
                    Some(host),
                );
            } else {
                push_hit(
                    &mut hits,
                    &mut seen,
                    "unresolved_host",
                    file,
                    fact.line,
                    "network egress host could not be statically resolved",
                    None,
                );
            }
        }

        if is_remote_shell_pipeline_fact(&fact) {
            push_hit(
                &mut hits,
                &mut seen,
                "remote_shell_pipeline",
                file,
                fact.line,
                "remote download is piped directly to a shell",
                None,
            );
        }

        if let Some(sensitive) = sensitive_read(&fact) {
            push_hit(
                &mut hits,
                &mut seen,
                "sensitive_read",
                file,
                fact.line,
                format!(
                    "reads sensitive token or credential `{}`",
                    snippet(&sensitive)
                ),
                None,
            );
        }

        if writes_agent_config(&fact) {
            push_hit(
                &mut hits,
                &mut seen,
                "agent_config_write",
                file,
                fact.line,
                "writes agent configuration or hook path",
                None,
            );
        }

        if writes_agent_config(&fact) && resolved_payload_matches(&fact, hook_persistence_re()) {
            push_hit(
                &mut hits,
                &mut seen,
                "persistence",
                file,
                fact.line,
                "persists or auto-approves an agent hook",
                None,
            );
        }

        if is_obfuscation_fact(&fact) {
            push_hit(
                &mut hits,
                &mut seen,
                "obfuscation",
                file,
                fact.line,
                "decodes or evaluates obfuscated content",
                None,
            );
        }

        if is_exec_fact(&fact) {
            push_hit(
                &mut hits,
                &mut seen,
                "exec_eval",
                file,
                fact.line,
                "executes code, a subprocess, or a shell pipeline",
                None,
            );
        }

        if is_destructive_fact(&fact) {
            push_hit(
                &mut hits,
                &mut seen,
                "destructive",
                file,
                fact.line,
                "performs recursive or forced deletion",
                None,
            );
        }
    }

    Ok(hits)
}

fn emit_findings(intent: Intent, hits: &[CapabilityHit], findings: &mut Vec<Finding>) {
    let net = hits_for(hits, "net_egress");
    let unresolved = hits_for(hits, "unresolved_host");
    let sensitive = hits_for(hits, "sensitive_read");
    let high_sensitive: Vec<&CapabilityHit> = sensitive
        .iter()
        .copied()
        .filter(|hit| is_high_sensitivity(&hit.detail))
        .collect();
    let agent_config = hits_for(hits, "agent_config_write");
    let persistence = hits_for(hits, "persistence");
    let obfuscation = hits_for(hits, "obfuscation");
    let exec_eval = hits_for(hits, "exec_eval");
    let destructive = hits_for(hits, "destructive");
    let incomplete = hits_for(hits, "analysis_incomplete");

    let mut emitted_high = false;

    if has_remote_shell_pipeline(hits) {
        emitted_high = true;
        if let Some(hit) = exec_eval.first() {
            findings.push(hit.finding(
                RULE_REMOTE_EXEC,
                Severity::High,
                format!("remote download piped to shell: {}", hit.detail),
            ));
        }
        for hit in net.iter().chain(unresolved.iter()) {
            findings.push(hit.finding(RULE_REMOTE_DOWNLOAD, Severity::High, &hit.detail));
        }
        for hit in &exec_eval {
            findings.push(hit.finding(RULE_SHELL_PIPE, Severity::High, &hit.detail));
        }
    }

    if !obfuscation.is_empty() && !exec_eval.is_empty() {
        emitted_high = true;
        for hit in &obfuscation {
            findings.push(hit.finding(RULE_OBFUSCATION, Severity::High, &hit.detail));
        }
        for hit in net.iter().chain(unresolved.iter()) {
            findings.push(hit.finding(RULE_REMOTE_DOWNLOAD, Severity::High, &hit.detail));
        }
        for hit in &exec_eval {
            findings.push(hit.finding(RULE_SHELL_PIPE, Severity::High, &hit.detail));
        }
    }

    if !high_sensitive.is_empty() && (!net.is_empty() || !unresolved.is_empty()) {
        emitted_high = true;
        let detail = "sensitive credential reads combined with network egress";
        if let Some(hit) = high_sensitive.first() {
            findings.push(hit.finding(RULE_SECRET_EXFIL, Severity::High, detail));
        }
        for hit in &high_sensitive {
            findings.push(hit.finding(RULE_CREDENTIAL_ACCESS, Severity::High, &hit.detail));
        }
        for hit in net.iter().chain(unresolved.iter()) {
            findings.push(hit.finding(RULE_NETWORK_EXFILTRATION, Severity::High, &hit.detail));
        }
        push_plain_once(
            findings,
            RULE_CAPABILITY_MISFIT,
            Severity::High,
            "declared skill intent does not justify credential access plus network egress",
            high_sensitive[0].rel.as_str(),
        );
    }

    if !agent_config.is_empty() {
        if intent.allows_agent_config_write() {
            // Capability is consistent with the declared intent (an
            // agent-config tool that writes agent config). Per the GH-59
            // manifest model, a capability that matches declared intent is a
            // stated fact, not a misfit: surface it at manifest severity
            // (allow-with-approval) instead of escalating the verdict to block.
            for hit in &agent_config {
                findings.push(hit.finding(RULE_AGENT_CONFIG_WRITE, Severity::Medium, &hit.detail));
            }
        } else {
            emitted_high = true;
            for hit in &agent_config {
                findings.push(hit.finding(RULE_AGENT_CONFIG_WRITE, Severity::High, &hit.detail));
            }
            push_plain_once(
                findings,
                RULE_CAPABILITY_MISFIT,
                Severity::High,
                "declared skill intent does not justify agent config or hook writes",
                agent_config[0].rel.as_str(),
            );
        }
    }

    if !persistence.is_empty() {
        emitted_high = true;
        for hit in &persistence {
            findings.push(hit.finding(RULE_HOOK_PERSISTENCE, Severity::High, &hit.detail));
        }
    }

    if !emitted_high {
        for hit in net
            .iter()
            .chain(unresolved.iter())
            .chain(sensitive.iter())
            .chain(exec_eval.iter())
            .chain(obfuscation.iter())
            .chain(destructive.iter())
            .chain(incomplete.iter())
        {
            findings.push(hit.finding(RULE_CAPABILITY_MANIFEST, Severity::Medium, &hit.detail));
        }
    }
}

fn push_hit(
    hits: &mut Vec<CapabilityHit>,
    seen: &mut BTreeSet<(String, usize, &'static str, String, Option<String>)>,
    capability: &'static str,
    file: &SurfaceFile,
    line: usize,
    detail: impl Into<String>,
    resolved_host: Option<String>,
) {
    let detail = detail.into();
    let key = (
        file.rel.clone(),
        line,
        capability,
        detail.clone(),
        resolved_host.clone(),
    );
    if !seen.insert(key) {
        return;
    }
    hits.push(CapabilityHit {
        capability,
        rel: file.rel.clone(),
        line,
        detail,
        resolved_host,
    });
}

fn hits_for<'a>(hits: &'a [CapabilityHit], capability: &str) -> Vec<&'a CapabilityHit> {
    hits.iter()
        .filter(|hit| hit.capability == capability)
        .collect()
}

fn has_remote_shell_pipeline(hits: &[CapabilityHit]) -> bool {
    hits.iter()
        .any(|hit| hit.capability == "remote_shell_pipeline")
}

fn is_high_sensitivity(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    let dotenv_file = lower.contains(".env")
        && !lower.contains("process.env")
        && !lower.contains("import.meta.env");
    dotenv_file
        || contains_any(
            &lower,
            &[
                ".aws/credentials",
                ".npmrc",
                "anthropic_api_key",
                "openai_api_key",
                "aws_secret_access_key",
                "github_token",
                "claude_code_oauth_token",
                "id_rsa",
                ".ssh/",
                "keychain",
            ],
        )
}

fn resolve_host(line: &str) -> Option<String> {
    url_host_re()
        .captures(line)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_ascii_lowercase())
}

fn push_plain_once(
    findings: &mut Vec<Finding>,
    rule_id: &str,
    severity: Severity,
    detail: impl Into<String>,
    rel: &str,
) {
    if findings
        .iter()
        .any(|f| f.rule_id == rule_id && f.location.as_deref() == Some(rel))
    {
        return;
    }
    findings.push(Finding::new(rule_id, severity, detail).at(rel));
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn snippet(s: &str) -> String {
    let mut out: String = s.chars().take(80).collect();
    if out.len() < s.len() {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
#[path = "capability/tests.rs"]
mod tests;
