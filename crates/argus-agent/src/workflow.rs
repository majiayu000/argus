//! AGT-06 — GitHub Actions workflow and local composite Action checks.
//!
//! Workflows and Action metadata are parsed as YAML and inspected statically.
//! Parse failures are operational errors: an invalid or unassessed protected
//! surface must never collapse into a clean decision.

use crate::{SurfaceFile, SurfaceKind};
use anyhow::{bail, Context, Result};
use argus_core::{Finding, Severity};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use yaml_rust2::{yaml::Hash, Yaml, YamlLoader};

const RULE_MUTABLE_ACTION: &str = "AGT-06-workflow-mutable-action";
const RULE_CONTEXT_INJECTION: &str = "AGT-06-workflow-context-injection";
const RULE_UNTRUSTED_CHECKOUT: &str = "AGT-06-workflow-untrusted-checkout";
const RULE_WRITE_ALL: &str = "AGT-06-workflow-write-all";
const RULE_PRIVILEGED_WRITE: &str = "AGT-06-workflow-privileged-write";

#[derive(Clone, Copy)]
struct TaintScope<'a> {
    envs: &'a HashSet<String>,
    inputs: &'a HashSet<String>,
}

pub(super) fn run(files: &[SurfaceFile], findings: &mut Vec<Finding>) -> Result<()> {
    let actions: HashMap<&str, &SurfaceFile> = files
        .iter()
        .filter(|file| file.kind == SurfaceKind::ActionMetadata)
        .map(|file| (file.rel.as_str(), file))
        .collect();
    for file in files {
        match file.kind {
            SurfaceKind::Workflow => {
                let mut visiting = HashSet::new();
                scan_workflow(file, &actions, &mut visiting, findings)
                    .with_context(|| format!("assess GitHub Actions workflow `{}`", file.rel))?;
            }
            SurfaceKind::ActionMetadata => {
                let mut visiting = HashSet::new();
                let empty = HashSet::new();
                scan_action_metadata(
                    file,
                    TaintScope {
                        envs: &empty,
                        inputs: &empty,
                    },
                    &actions,
                    &mut visiting,
                    findings,
                )
                .with_context(|| format!("assess GitHub Action metadata `{}`", file.rel))?;
            }
            _ => {}
        }
    }
    dedup_findings(findings);
    Ok(())
}

/// Local composites are scanned both as standalone ActionMetadata and again
/// through each local `uses:` caller. Caller-independent findings therefore
/// repeat at the same path; keep the first occurrence of each identity.
fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|finding| {
        seen.insert((
            finding.rule_id.clone(),
            finding.severity as u8,
            finding.detail.clone(),
            finding.location.clone(),
            finding.capability.clone(),
            finding.evidence.clone(),
            finding.resolved_host.clone(),
        ))
    });
}

fn scan_workflow(
    file: &SurfaceFile,
    actions: &HashMap<&str, &SurfaceFile>,
    visiting: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let documents = YamlLoader::load_from_str(&file.content)
        .with_context(|| format!("parse `{}` as YAML", file.rel))?;
    if documents.len() != 1 {
        bail!(
            "workflow `{}` must contain exactly one YAML document",
            file.rel
        );
    }
    let root = documents[0]
        .as_hash()
        .with_context(|| format!("workflow `{}` root must be a mapping", file.rel))?;
    let privileged_trigger =
        has_trigger(root, "pull_request_target") || has_trigger(root, "workflow_run");
    check_permissions(root, "workflow", privileged_trigger, &file.rel, findings);

    let mut workflow_tainted_envs = HashSet::new();
    let no_inputs = HashSet::new();
    if let Some(env) = get(root, "env").and_then(Yaml::as_hash) {
        apply_env_taints(&mut workflow_tainted_envs, env, &no_inputs, &file.rel)?;
    }

    let Some(jobs) = get(root, "jobs").and_then(Yaml::as_hash) else {
        return Ok(());
    };
    for job in jobs.values().filter_map(Yaml::as_hash) {
        check_permissions(job, "job", privileged_trigger, &file.rel, findings);
        if let Some(action) = get_string(job, "uses") {
            check_action_ref(action, &file.rel, findings);
        }
        let mut job_tainted_envs = workflow_tainted_envs.clone();
        if let Some(env) = get(job, "env").and_then(Yaml::as_hash) {
            apply_env_taints(&mut job_tainted_envs, env, &no_inputs, &file.rel)?;
        }
        let Some(steps) = get(job, "steps").and_then(Yaml::as_vec) else {
            continue;
        };
        for step in steps.iter().filter_map(Yaml::as_hash) {
            let mut step_tainted_envs = job_tainted_envs.clone();
            if let Some(env) = get(step, "env").and_then(Yaml::as_hash) {
                apply_env_taints(&mut step_tainted_envs, env, &no_inputs, &file.rel)?;
            }
            scan_step(
                step,
                &file.rel,
                privileged_trigger,
                TaintScope {
                    envs: &step_tainted_envs,
                    inputs: &no_inputs,
                },
                actions,
                visiting,
                findings,
            )?;
        }
    }
    Ok(())
}

fn scan_action_metadata(
    file: &SurfaceFile,
    caller_taint: TaintScope<'_>,
    actions: &HashMap<&str, &SurfaceFile>,
    visiting: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    if !visiting.insert(file.rel.clone()) {
        return Ok(());
    }
    let documents = YamlLoader::load_from_str(&file.content)
        .with_context(|| format!("parse `{}` as YAML", file.rel))?;
    if documents.len() != 1 {
        bail!(
            "Action metadata `{}` must contain exactly one YAML document",
            file.rel
        );
    }
    let root = documents[0]
        .as_hash()
        .with_context(|| format!("Action metadata `{}` root must be a mapping", file.rel))?;
    let Some(runs) = get(root, "runs").and_then(Yaml::as_hash) else {
        visiting.remove(&file.rel);
        return Ok(());
    };
    if !get_string(runs, "using").is_some_and(|using| using.eq_ignore_ascii_case("composite")) {
        visiting.remove(&file.rel);
        return Ok(());
    }
    let Some(steps) = get(runs, "steps").and_then(Yaml::as_vec) else {
        visiting.remove(&file.rel);
        return Ok(());
    };
    for step in steps.iter().filter_map(Yaml::as_hash) {
        // Caller env remains visible inside local composite steps at runtime.
        let mut step_tainted_envs = caller_taint.envs.clone();
        if let Some(env) = get(step, "env").and_then(Yaml::as_hash) {
            apply_env_taints(&mut step_tainted_envs, env, caller_taint.inputs, &file.rel)?;
        }
        scan_step(
            step,
            &file.rel,
            false,
            TaintScope {
                envs: &step_tainted_envs,
                inputs: caller_taint.inputs,
            },
            actions,
            visiting,
            findings,
        )?;
    }
    visiting.remove(&file.rel);
    Ok(())
}

fn scan_step(
    step: &Hash,
    rel: &str,
    privileged_trigger: bool,
    taint: TaintScope<'_>,
    actions: &HashMap<&str, &SurfaceFile>,
    visiting: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    if let Some(action) = get_string(step, "uses") {
        check_action_ref(action, rel, findings);
        if privileged_trigger && is_checkout(action) && has_untrusted_checkout_ref(step) {
            findings.push(
                Finding::new(
                    RULE_UNTRUSTED_CHECKOUT,
                    Severity::Critical,
                    "privileged workflow trigger checks out an attacker-controlled pull request ref",
                )
                .at(rel),
            );
        }
        if let Some(local) = action.strip_prefix("./") {
            if let Some(action_file) = resolve_local_action(local, actions) {
                let step_tainted_inputs = collect_tainted_with_inputs(step, taint, rel)?;
                scan_action_metadata(
                    action_file,
                    TaintScope {
                        envs: taint.envs,
                        inputs: &step_tainted_inputs,
                    },
                    actions,
                    visiting,
                    findings,
                )?;
            }
        }
    }
    if let Some(script) = get_string(step, "run") {
        check_inline_script(script, rel, taint, findings)?;
    }
    Ok(())
}

fn resolve_local_action<'a>(
    local_ref: &str,
    actions: &HashMap<&str, &'a SurfaceFile>,
) -> Option<&'a SurfaceFile> {
    let path = local_ref.trim_end_matches('/');
    // `uses: ./` resolves to the repository-root action metadata. An empty path
    // must look up `action.yml` directly; joining would invent `/action.yml`.
    if path.is_empty() {
        for name in ["action.yml", "action.yaml"] {
            if let Some(file) = actions.get(name) {
                return Some(*file);
            }
        }
        return None;
    }
    if let Some(file) = actions.get(path) {
        return Some(*file);
    }
    for name in ["action.yml", "action.yaml"] {
        let candidate = format!("{path}/{name}");
        if let Some(file) = actions.get(candidate.as_str()) {
            return Some(*file);
        }
    }
    None
}

fn collect_tainted_with_inputs(
    step: &Hash,
    taint: TaintScope<'_>,
    rel: &str,
) -> Result<HashSet<String>> {
    let mut tainted = HashSet::new();
    let Some(with_map) = get(step, "with").and_then(Yaml::as_hash) else {
        return Ok(tainted);
    };
    for (key, value) in with_map {
        let Some(name) = key.as_str() else {
            continue;
        };
        let Some(value) = value.as_str() else {
            continue;
        };
        // Caller `with:` bindings are evaluated before the composite runs, so a
        // tainted env, tainted input forwarded from a parent composite, or a
        // direct untrusted context becomes a tainted input for the callee.
        if value_contains_untrusted_context(value, rel)?
            || value_references_tainted_env(value, taint.envs, rel)?
            || value_references_tainted_input(value, taint.inputs, rel)?
        {
            tainted.insert(name.to_string());
        }
    }
    Ok(tainted)
}

fn apply_env_taints(
    tainted: &mut HashSet<String>,
    env: &Hash,
    tainted_inputs: &HashSet<String>,
    rel: &str,
) -> Result<()> {
    // GitHub Actions resolves each map entry against the parent scope, not
    // sibling keys in the same map. Snapshot the inherited set before applying
    // overrides so an earlier TITLE: fixed cannot clear taint for a later
    // ALIAS: ${{ env.TITLE }} that still reads the parent value.
    let inherited = tainted.clone();
    let mut updates = Vec::new();
    for (key, value) in env {
        let Some(name) = key.as_str() else {
            continue;
        };
        match value {
            Yaml::String(value) => {
                // Inherit taint from direct untrusted contexts, tainted env
                // aliases, and composite `inputs.*` when those are in scope.
                let is_tainted = value_contains_untrusted_context(value, rel)?
                    || value_references_tainted_env(value, &inherited, rel)?
                    || value_references_tainted_input(value, tainted_inputs, rel)?;
                updates.push((name.to_string(), is_tainted));
            }
            // Non-string YAML scalars are constant overrides and clear taint.
            Yaml::Integer(_) | Yaml::Real(_) | Yaml::Boolean(_) | Yaml::Null => {
                updates.push((name.to_string(), false));
            }
            // Mapping/sequence env values are not valid Actions scalars; leave
            // inherited taint rather than inventing a clean allow path.
            _ => {}
        }
    }
    for (name, is_tainted) in updates {
        if is_tainted {
            tainted.insert(name);
        } else {
            // A same-scope redeclaration without untrusted contexts clears prior taint.
            tainted.remove(&name);
        }
    }
    Ok(())
}

fn value_contains_untrusted_context(value: &str, rel: &str) -> Result<bool> {
    for_each_expression(value, rel, |expression| {
        Ok(is_untrusted_context(expression))
    })
}

fn value_references_tainted_env(value: &str, tainted: &HashSet<String>, rel: &str) -> Result<bool> {
    for_each_expression(value, rel, |expression| {
        Ok(expression_uses_tainted_env(expression, tainted))
    })
}

fn value_references_tainted_input(
    value: &str,
    tainted: &HashSet<String>,
    rel: &str,
) -> Result<bool> {
    for_each_expression(value, rel, |expression| {
        Ok(expression_uses_tainted_input(expression, tainted))
    })
}

fn for_each_expression(
    value: &str,
    rel: &str,
    mut predicate: impl FnMut(&str) -> Result<bool>,
) -> Result<bool> {
    let mut remaining = value;
    let mut matched = false;
    while let Some(start) = remaining.find("${{") {
        let after_start = &remaining[start + 3..];
        let Some(end) = find_expression_close(after_start) else {
            bail!("GitHub Actions surface `{rel}` contains an unterminated expression in `env`");
        };
        let expression = after_start[..end].trim();
        // Keep scanning after a positive hit so an unterminated trailing `${{`
        // still surfaces as an incomplete-scan error instead of a clean allow.
        if predicate(expression)? {
            matched = true;
        }
        remaining = &after_start[end + 2..];
    }
    Ok(matched)
}

/// Locate the closing `}}` while treating `}}` inside single-quoted literals as
/// data. GitHub Actions expressions use `''` to escape a literal quote.
fn find_expression_close(after_start: &str) -> Option<usize> {
    let mut quoted = false;
    let mut chars = after_start.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if character == '\'' {
            if quoted && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                chars.next();
                continue;
            }
            quoted = !quoted;
            continue;
        }
        if !quoted && character == '}' && chars.peek().is_some_and(|(_, next)| *next == '}') {
            return Some(index);
        }
    }
    None
}

fn check_permissions(
    owner: &Hash,
    scope: &str,
    privileged_trigger: bool,
    rel: &str,
    findings: &mut Vec<Finding>,
) {
    match get(owner, "permissions") {
        Some(Yaml::String(value)) if value == "write-all" => findings.push(
            Finding::new(
                RULE_WRITE_ALL,
                Severity::High,
                format!("{scope} grants write access to every GITHUB_TOKEN permission"),
            )
            .at(rel),
        ),
        Some(Yaml::Hash(permissions)) if privileged_trigger => {
            for (name, access) in permissions {
                let (Some(name), Some("write")) = (name.as_str(), access.as_str()) else {
                    continue;
                };
                findings.push(
                    Finding::new(
                        RULE_PRIVILEGED_WRITE,
                        Severity::Medium,
                        format!(
                            "{scope} grants `{}` write access under a privileged workflow trigger",
                            bounded(name)
                        ),
                    )
                    .at(rel),
                );
            }
        }
        _ => {}
    }
}

fn check_action_ref(action: &str, rel: &str, findings: &mut Vec<Finding>) {
    if is_immutable_action_ref(action) {
        return;
    }
    findings.push(
        Finding::new(
            RULE_MUTABLE_ACTION,
            Severity::Medium,
            format!(
                "GitHub Actions dependency `{}` is not pinned to an immutable digest",
                bounded(action)
            ),
        )
        .at(rel),
    );
}

fn is_immutable_action_ref(action: &str) -> bool {
    if action.starts_with("./") {
        return true;
    }
    if let Some(image) = action.strip_prefix("docker://") {
        return image
            .rsplit_once("@sha256:")
            .is_some_and(|(_, digest)| digest.len() == 64 && digest.bytes().all(is_hex));
    }
    action
        .rsplit_once('@')
        .is_some_and(|(_, revision)| revision.len() == 40 && revision.bytes().all(is_hex))
}

fn check_inline_script(
    script: &str,
    rel: &str,
    taint: TaintScope<'_>,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let mut remaining = script;
    while let Some(start) = remaining.find("${{") {
        let after_start = &remaining[start + 3..];
        let Some(end) = find_expression_close(after_start) else {
            bail!("GitHub Actions surface `{rel}` contains an unterminated expression in `run`");
        };
        let expression = after_start[..end].trim();
        if is_untrusted_context(expression)
            || expression_uses_tainted_env(expression, taint.envs)
            || expression_uses_tainted_input(expression, taint.inputs)
        {
            findings.push(
                Finding::new(
                    RULE_CONTEXT_INJECTION,
                    Severity::Critical,
                    format!(
                        "attacker-controlled context `{}` is interpolated directly into an inline script",
                        bounded(expression)
                    ),
                )
                .at(rel),
            );
        }
        remaining = &after_start[end + 2..];
    }
    Ok(())
}

/// Detect `${{ env.NAME }}` / `${{ env['NAME'] }}` / `${{ env["NAME"] }}` when
/// `NAME` was assigned an untrusted GitHub context in an in-scope `env` map.
///
/// Whole-context reads such as `toJSON(env)` or bare `env` are treated as
/// tainted whenever any in-scope env is tainted. Computed indexes such as
/// `env[matrix.key]` are likewise conservative. Nested property paths like
/// `fromJSON(...).env.TITLE` are ignored so only the root `env` context counts.
fn expression_uses_tainted_env(expression: &str, tainted_envs: &HashSet<String>) -> bool {
    if tainted_envs.is_empty() {
        return false;
    }
    if expression_reads_whole_context(expression, "env") {
        return true;
    }
    expression_uses_tainted_context_property(expression, "env", tainted_envs)
}

/// Detect `${{ inputs.NAME }}` (and index forms) when a local composite caller
/// bound that input to an untrusted value via `with:`.
fn expression_uses_tainted_input(expression: &str, tainted_inputs: &HashSet<String>) -> bool {
    if tainted_inputs.is_empty() {
        return false;
    }
    if expression_reads_whole_context(expression, "inputs") {
        return true;
    }
    expression_uses_tainted_context_property(expression, "inputs", tainted_inputs)
}

fn expression_reads_whole_context(expression: &str, context: &str) -> bool {
    let without_literals = remove_expression_string_literals(expression);
    let compact: String = without_literals
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    let context = context.to_ascii_lowercase();
    if compact == context {
        return true;
    }
    // Match `toJSON(env)` / `toJSON(inputs)` but not `toJSON(env.TITLE)`.
    let needle = format!("tojson({context})");
    let mut rest = compact.as_str();
    while let Some(index) = rest.find(&needle) {
        let after = index + needle.len();
        let next = rest.as_bytes().get(after).copied();
        if next.is_none_or(|byte| {
            !matches!(
                byte,
                b'.' | b'[' | b'_' | b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            )
        }) {
            return true;
        }
        rest = &rest[index + 1..];
    }
    false
}

fn expression_uses_tainted_context_property(
    expression: &str,
    context: &str,
    tainted_names: &HashSet<String>,
) -> bool {
    static ENV_REF: OnceLock<Regex> = OnceLock::new();
    static INPUTS_REF: OnceLock<Regex> = OnceLock::new();
    let pattern = match context {
        "env" => ENV_REF.get_or_init(|| {
            Regex::new(
                r#"(?i)\benv\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])"#,
            )
            .expect("tainted env reference pattern compiles")
        }),
        "inputs" => INPUTS_REF.get_or_init(|| {
            Regex::new(
                r#"(?i)\binputs\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])"#,
            )
            .expect("tainted inputs reference pattern compiles")
        }),
        _ => return false,
    };
    // Ignore context-looking text inside single-quoted expression literals
    // without stripping quotes used by `env['TITLE']` / `inputs['title']`.
    pattern.captures_iter(expression).any(|capture| {
        let Some(matched) = capture.get(0) else {
            return false;
        };
        // Reject nested properties such as `obj.env.TITLE` or spaced
        // `obj . env.TITLE` (`.` is a word boundary, so `\benv` alone is not
        // enough; ignore whitespace between the property dot and the context).
        if matched.start() > 0 && expression[..matched.start()].trim_end().ends_with('.') {
            return false;
        }
        if offset_inside_single_quoted_literal(expression, matched.start()) {
            return false;
        }
        if capture.get(3).is_some() {
            // Computed index: cannot resolve the name statically.
            return true;
        }
        let name = capture
            .get(1)
            .or_else(|| capture.get(2))
            .map(|matched| matched.as_str());
        name.is_some_and(|name| tainted_names.contains(name))
    })
}

fn offset_inside_single_quoted_literal(expression: &str, index: usize) -> bool {
    let mut quoted = false;
    let mut chars = expression[..index].chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\'' {
            continue;
        }
        if quoted && chars.peek() == Some(&'\'') {
            chars.next();
            continue;
        }
        quoted = !quoted;
    }
    quoted
}

fn is_untrusted_context(expression: &str) -> bool {
    let without_literals = remove_expression_string_literals(expression);
    let compact: String = without_literals
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    if compact.contains("github.head_ref")
        || compact.contains("tojson(github)")
        || compact.contains("tojson(github.event)")
    {
        return true;
    }
    if !compact.contains("github.event.") {
        return false;
    }
    const UNTRUSTED_FIELDS: &[&str] = &[
        "issue.title",
        "issue.body",
        "pull_request.title",
        "pull_request.body",
        "discussion.title",
        "discussion.body",
        "comment.body",
        "review.body",
        "review_comment.body",
        "page_name",
        "head_commit.message",
        "head_commit.author.email",
        "head_commit.author.name",
        "blocked_user.name",
        "blocked_user.email",
        "pull_request.head.ref",
        "pull_request.head.label",
        "pull_request.head.repo.default_branch",
    ];
    UNTRUSTED_FIELDS.iter().any(|field| compact.contains(field))
        || (compact.contains("commits")
            && (compact.contains(".message")
                || compact.contains(".author.email")
                || compact.contains(".author.name")))
}

fn remove_expression_string_literals(expression: &str) -> String {
    let mut output = String::with_capacity(expression.len());
    let mut chars = expression.chars().peekable();
    let mut quoted = false;
    while let Some(character) = chars.next() {
        if character != '\'' {
            if !quoted {
                output.push(character);
            }
            continue;
        }
        if quoted && chars.peek() == Some(&'\'') {
            chars.next();
            continue;
        }
        quoted = !quoted;
    }
    output
}

fn has_trigger(root: &Hash, trigger: &str) -> bool {
    match get(root, "on") {
        Some(Yaml::String(value)) => value == trigger,
        Some(Yaml::Array(values)) => values.iter().any(|value| value.as_str() == Some(trigger)),
        Some(Yaml::Hash(values)) => values.contains_key(&Yaml::String(trigger.to_string())),
        _ => false,
    }
}

fn has_untrusted_checkout_ref(step: &Hash) -> bool {
    get(step, "with")
        .and_then(Yaml::as_hash)
        .and_then(|with| get_string(with, "ref"))
        .is_some_and(|revision| {
            revision.contains("github.event.pull_request.head.")
                || revision.contains("github.event.pull_request.merge_commit_sha")
                || revision.contains("github.event.workflow_run.head_sha")
                || revision.contains("github.event.workflow_run.head_branch")
        })
}

fn is_checkout(action: &str) -> bool {
    action
        .split_once('@')
        .map_or(action, |(name, _)| name)
        .eq_ignore_ascii_case("actions/checkout")
}

fn get<'a>(hash: &'a Hash, key: &str) -> Option<&'a Yaml> {
    hash.get(&Yaml::String(key.to_string()))
}

fn get_string<'a>(hash: &'a Hash, key: &str) -> Option<&'a str> {
    get(hash, key).and_then(Yaml::as_str)
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn bounded(value: &str) -> String {
    const MAX_CHARS: usize = 160;
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(MAX_CHARS).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::Decision;

    fn findings_for(content: &str) -> Vec<Finding> {
        let file = SurfaceFile {
            rel: ".github/workflows/test.yml".to_string(),
            content: content.to_string(),
            kind: SurfaceKind::Workflow,
        };
        let mut findings = Vec::new();
        let actions = HashMap::new();
        let mut visiting = HashSet::new();
        scan_workflow(&file, &actions, &mut visiting, &mut findings)
            .expect("scan workflow fixture");
        findings
    }

    fn findings_for_files(files: &[SurfaceFile]) -> Vec<Finding> {
        let mut findings = Vec::new();
        run(files, &mut findings).expect("scan workflow surfaces");
        findings
    }

    #[test]
    fn write_all_blocks_at_workflow_and_job_scope() {
        let findings = findings_for(
            r#"
name: Release
on: push
permissions: write-all
jobs:
  publish:
    permissions: write-all
    runs-on: ubuntu-latest
    steps: []
"#,
        );

        let matches: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == "AGT-06-workflow-write-all")
            .collect();
        assert_eq!(matches.len(), 2);
        assert!(matches
            .iter()
            .all(|finding| finding.severity == Severity::High));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn privileged_trigger_with_explicit_write_requires_approval() {
        let findings = findings_for(
            r#"
name: Triage
on: pull_request_target
permissions:
  issues: write
jobs:
  label:
    permissions:
      pull-requests: write
    runs-on: ubuntu-latest
    steps: []
"#,
        );

        let matches: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == "AGT-06-workflow-privileged-write")
            .collect();
        assert_eq!(matches.len(), 2);
        assert!(matches
            .iter()
            .all(|finding| finding.severity == Severity::Medium));
        assert_eq!(
            crate::decision::derive(&findings),
            Decision::AllowWithApproval
        );

        let workflow_run_findings = findings_for(
            r#"
name: Publish follow-up
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  publish:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps: []
"#,
        );
        assert!(workflow_run_findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-privileged-write"
                && finding.severity == Severity::Medium
        }));
        assert_eq!(
            crate::decision::derive(&workflow_run_findings),
            Decision::AllowWithApproval
        );
    }

    #[test]
    fn scoped_write_on_trusted_trigger_and_privileged_read_only_are_allowed() {
        let trusted_findings = findings_for(
            r#"
name: Release
on: push
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps: []
"#,
        );
        let privileged_findings = findings_for(
            r#"
name: Inspect
on: workflow_run
permissions: read-all
jobs:
  inspect:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps: []
"#,
        );

        assert!(trusted_findings.is_empty());
        assert!(privileged_findings.is_empty());
    }

    #[test]
    fn env_indirection_same_step_blocks_context_injection() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "${{ env.TITLE }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env.TITLE")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn env_indirection_job_env_and_bracket_access_block() {
        let dotted = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo "${{ env.TITLE }}"
"#,
        );
        let bracketed = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "${{ env['TITLE'] }}"
"#,
        );

        assert!(dotted.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.detail.contains("env.TITLE")
        }));
        assert!(bracketed.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.detail.contains("env['TITLE']")
        }));
        assert_eq!(crate::decision::derive(&dotted), Decision::Block);
        assert_eq!(crate::decision::derive(&bracketed), Decision::Block);
    }

    #[test]
    fn env_shell_expansion_without_expression_interpolation_is_allowed() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
"#,
        );

        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != "AGT-06-workflow-context-injection"));
        assert_eq!(crate::decision::derive(&findings), Decision::Allow);
    }

    #[test]
    fn env_alias_from_job_env_blocks_context_injection() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - env:
          ALIAS: ${{ env.TITLE }}
        run: echo "${{ env.ALIAS }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env.ALIAS")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn env_alias_reads_parent_scope_despite_sibling_override() {
        // Step env cannot reference sibling keys: TITLE: fixed clears the local
        // binding, but ALIAS: ${{ env.TITLE }} still resolves the tainted job value.
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - env:
          TITLE: fixed
          ALIAS: ${{ env.TITLE }}
        run: echo "${{ env.ALIAS }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env.ALIAS")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn tainted_env_value_with_trailing_unterminated_expression_errors() {
        let file = SurfaceFile {
            rel: ".github/workflows/test.yml".to_string(),
            content: r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }} ${{
        run: echo "safe"
"#
            .to_string(),
            kind: SurfaceKind::Workflow,
        };
        let mut findings = Vec::new();
        let actions = HashMap::new();
        let mut visiting = HashSet::new();
        let error = scan_workflow(&file, &actions, &mut visiting, &mut findings)
            .expect_err("unterminated env expression");
        assert!(
            error
                .to_string()
                .contains("unterminated expression in `env`"),
            "unexpected error: {error:#}"
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn env_name_inside_expression_string_literal_is_not_tainted_read() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo "${{ 'env.TITLE' }}"
"#,
        );

        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != "AGT-06-workflow-context-injection"));
        assert_eq!(crate::decision::derive(&findings), Decision::Allow);
    }

    #[test]
    fn computed_env_index_blocks_when_any_tainted_env_in_scope() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo "${{ env[format('TI{0}', 'TLE')] }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env[format('TI{0}', 'TLE')]")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn nested_env_property_is_not_treated_as_actions_env_context() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo "${{ fromJSON('{\"env\":{\"TITLE\":\"fixed\"}}').env.TITLE }}"
"#,
        );

        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != "AGT-06-workflow-context-injection"));
        assert_eq!(crate::decision::derive(&findings), Decision::Allow);
    }

    #[test]
    fn spaced_nested_env_property_is_not_treated_as_actions_env_context() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo "${{ fromJSON('{\"env\":{\"TITLE\":\"fixed\"}}') . env.TITLE }}"
"#,
        );

        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != "AGT-06-workflow-context-injection"));
        assert_eq!(crate::decision::derive(&findings), Decision::Allow);
    }

    #[test]
    fn quoted_braces_inside_env_expression_still_detect_taint() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ format('}}{0}', github.event.issue.title) }}
        run: echo "${{ env.TITLE }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env.TITLE")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn local_composite_inherits_caller_env_taint() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/echo.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - uses: ./.github/actions/echo
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/echo/action.yml".to_string(),
                content: r#"
name: Echo title
description: Echo inherited env
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "${{ env.TITLE }}"
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env.TITLE")
                && finding
                    .location
                    .as_deref()
                    .is_some_and(|path| path.contains("action.yml"))
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn tojson_whole_env_context_blocks_when_tainted_env_in_scope() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo '${{ toJSON(env) }}'
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("toJSON(env)")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn composite_with_input_carries_caller_env_taint() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/echo.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - uses: ./.github/actions/echo
        with:
          title: ${{ env.TITLE }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/echo/action.yml".to_string(),
                content: r#"
name: Echo title
description: Echo input
inputs:
  title:
    required: true
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "${{ inputs.title }}"
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("inputs.title")
                && finding
                    .location
                    .as_deref()
                    .is_some_and(|path| path.contains("action.yml"))
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn nested_composite_forwards_input_taint() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/echo.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - uses: ./.github/actions/outer
        with:
          title: ${{ env.TITLE }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/outer/action.yml".to_string(),
                content: r#"
name: Outer
description: Forward input
inputs:
  title:
    required: true
runs:
  using: composite
  steps:
    - uses: ./.github/actions/inner
      with:
        title: ${{ inputs.title }}
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
            SurfaceFile {
                rel: ".github/actions/inner/action.yml".to_string(),
                content: r#"
name: Inner
description: Echo input
inputs:
  title:
    required: true
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "${{ inputs.title }}"
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("inputs.title")
                && finding.location.as_deref() == Some(".github/actions/inner/action.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn local_action_findings_are_deduplicated_across_callers() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/one.yml".to_string(),
                content: r#"
name: One
on: push
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/echo
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/workflows/two.yml".to_string(),
                content: r#"
name: Two
on: push
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/echo
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/echo/action.yml".to_string(),
                content: r#"
name: Echo
description: Mutable remote action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ];
        let findings = findings_for_files(&files);
        let mutable = findings
            .iter()
            .filter(|finding| {
                finding.rule_id == "AGT-06-workflow-mutable-action"
                    && finding.location.as_deref() == Some(".github/actions/echo/action.yml")
            })
            .count();
        assert_eq!(mutable, 1);
    }

    #[test]
    fn root_local_action_ref_inherits_caller_env_taint() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/echo.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - uses: ./
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: "action.yml".to_string(),
                content: r#"
name: Echo title
description: Root composite
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "${{ env.TITLE }}"
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env.TITLE")
                && finding.location.as_deref() == Some("action.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn non_string_scalar_env_override_clears_inherited_taint() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - env:
          TITLE: 123
        run: echo "${{ env.TITLE }}"
"#,
        );

        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != "AGT-06-workflow-context-injection"));
        assert_eq!(crate::decision::derive(&findings), Decision::Allow);
    }
}
