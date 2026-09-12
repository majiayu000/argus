//! AGT-06 — GitHub Actions workflow and local composite Action checks.
//!
//! Workflows and Action metadata are parsed as YAML and inspected statically.
//! Parse failures are operational errors: an invalid or unassessed protected
//! surface must never collapse into a clean decision.
//!
//! When a workflow step `uses` a same-repo composite (`./...`), that composite
//! is expanded with the caller's privileged-trigger flag and `with` input
//! bindings (merged over Action metadata `inputs.*.default`) so wrapping an
//! untrusted checkout — including via `ref: ${{ inputs.ref }}`, bracket forms
//! such as `ref: ${{ inputs['ref'] }}`, compound forms such as
//! `ref: ${{ inputs.ref || github.sha }}`, case-variant forms such as
//! `ref: ${{ inputs.Ref }}`, or an omitted `with` that relies on an untrusted
//! input default — cannot bypass Critical→block.
//! Standalone Action metadata scans still use `privileged_trigger=false` so
//! composites alone do not invent a privileged trigger. Local expansion is
//! depth-bounded and fail-closed; source findings on composite bodies are left
//! to the ActionMetadata pass so expansion does not duplicate them.

use crate::{SurfaceFile, SurfaceKind};
use anyhow::{bail, Context, Result};
use argus_core::{Finding, Severity};
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use yaml_rust2::{yaml::Hash, Yaml, YamlLoader};

/// Resolved caller `with` bindings for the current local-composite expansion.
type InputBindings = BTreeMap<String, String>;

struct StepScanCtx<'a> {
    privileged_trigger: bool,
    actions: &'a ActionIndex<'a>,
    depth: u32,
    expand_local: bool,
    input_bindings: &'a InputBindings,
}

const RULE_MUTABLE_ACTION: &str = "AGT-06-workflow-mutable-action";
const RULE_CONTEXT_INJECTION: &str = "AGT-06-workflow-context-injection";
const RULE_UNTRUSTED_CHECKOUT: &str = "AGT-06-workflow-untrusted-checkout";
const RULE_WRITE_ALL: &str = "AGT-06-workflow-write-all";
const RULE_PRIVILEGED_WRITE: &str = "AGT-06-workflow-privileged-write";
/// Workflow → local composite is one hop; one nested local composite is allowed.
const MAX_LOCAL_COMPOSITE_DEPTH: u32 = 2;

type ActionIndex<'a> = BTreeMap<&'a str, &'a SurfaceFile>;

pub(super) fn run(files: &[SurfaceFile], findings: &mut Vec<Finding>) -> Result<()> {
    let actions = index_action_metadata(files);
    for file in files {
        match file.kind {
            SurfaceKind::Workflow => scan_workflow(file, &actions, findings)
                .with_context(|| format!("assess GitHub Actions workflow `{}`", file.rel))?,
            SurfaceKind::ActionMetadata => scan_action_metadata(file, findings)
                .with_context(|| format!("assess GitHub Action metadata `{}`", file.rel))?,
            _ => {}
        }
    }
    Ok(())
}

fn index_action_metadata(files: &[SurfaceFile]) -> ActionIndex<'_> {
    let mut actions = ActionIndex::new();
    for file in files
        .iter()
        .filter(|file| file.kind == SurfaceKind::ActionMetadata)
    {
        actions.insert(file.rel.as_str(), file);
    }
    actions
}

fn scan_workflow(
    file: &SurfaceFile,
    actions: &ActionIndex<'_>,
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

    let Some(jobs) = get(root, "jobs").and_then(Yaml::as_hash) else {
        return Ok(());
    };
    let empty_bindings = InputBindings::new();
    for job in jobs.values().filter_map(Yaml::as_hash) {
        check_permissions(job, "job", privileged_trigger, &file.rel, findings);
        if let Some(action) = get_string(job, "uses") {
            check_action_ref(action, &file.rel, findings);
        }
        let Some(steps) = get(job, "steps").and_then(Yaml::as_vec) else {
            continue;
        };
        for step in steps.iter().filter_map(Yaml::as_hash) {
            scan_step(
                step,
                &file.rel,
                &StepScanCtx {
                    privileged_trigger,
                    actions,
                    depth: 0,
                    expand_local: true,
                    input_bindings: &empty_bindings,
                },
                findings,
            )?;
        }
    }
    Ok(())
}

fn scan_action_metadata(file: &SurfaceFile, findings: &mut Vec<Finding>) -> Result<()> {
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
    let empty = ActionIndex::new();
    let empty_bindings = InputBindings::new();
    // Standalone metadata keeps privileged_trigger=false and does not expand
    // nested local uses; workflow scans own that expansion with caller context.
    scan_composite_steps(
        root,
        &file.rel,
        &StepScanCtx {
            privileged_trigger: false,
            actions: &empty,
            depth: 0,
            expand_local: false,
            input_bindings: &empty_bindings,
        },
        findings,
    )
}

fn scan_composite_steps(
    root: &Hash,
    rel: &str,
    ctx: &StepScanCtx<'_>,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let Some(runs) = get(root, "runs").and_then(Yaml::as_hash) else {
        return Ok(());
    };
    if !get_string(runs, "using").is_some_and(|using| using.eq_ignore_ascii_case("composite")) {
        return Ok(());
    }
    let Some(steps) = get(runs, "steps").and_then(Yaml::as_vec) else {
        return Ok(());
    };
    for step in steps.iter().filter_map(Yaml::as_hash) {
        scan_step(step, rel, ctx, findings)?;
    }
    Ok(())
}

fn scan_step(
    step: &Hash,
    rel: &str,
    ctx: &StepScanCtx<'_>,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    // Expansion (depth > 0) only adds privileged-context findings. Mutable-action
    // and inline-script findings for composite bodies are emitted once by the
    // ActionMetadata pass so call-site count does not inflate source findings.
    let emit_source_findings = ctx.depth == 0;
    if let Some(action) = get_string(step, "uses") {
        if emit_source_findings {
            check_action_ref(action, rel, findings);
        }
        if ctx.privileged_trigger
            && is_checkout(action)
            && has_untrusted_checkout_ref(step, ctx.input_bindings)
        {
            findings.push(
                Finding::new(
                    RULE_UNTRUSTED_CHECKOUT,
                    Severity::Critical,
                    "privileged workflow trigger checks out an attacker-controlled pull request ref",
                )
                .at(rel),
            );
        }
        if ctx.expand_local && is_local_action_ref(action) {
            let nested_bindings = resolve_step_input_bindings(step, ctx.input_bindings);
            expand_local_composite(
                action,
                rel,
                &StepScanCtx {
                    privileged_trigger: ctx.privileged_trigger,
                    actions: ctx.actions,
                    depth: ctx.depth,
                    expand_local: true,
                    input_bindings: &nested_bindings,
                },
                findings,
            )?;
        }
    }
    if emit_source_findings {
        if let Some(script) = get_string(step, "run") {
            check_inline_script(script, rel, findings)?;
        }
    }
    Ok(())
}

fn expand_local_composite(
    action: &str,
    caller_rel: &str,
    ctx: &StepScanCtx<'_>,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    if ctx.depth >= MAX_LOCAL_COMPOSITE_DEPTH {
        bail!(
            "local composite expansion depth exceeded while resolving `{action}` from `{caller_rel}`"
        );
    }
    let Some(meta) = resolve_local_action(action, ctx.actions) else {
        bail!(
            "local Action metadata for `{action}` referenced from `{caller_rel}` is missing or unreadable"
        );
    };
    let documents = YamlLoader::load_from_str(&meta.content)
        .with_context(|| format!("parse `{}` as YAML", meta.rel))?;
    if documents.len() != 1 {
        bail!(
            "Action metadata `{}` must contain exactly one YAML document",
            meta.rel
        );
    }
    let root = documents[0]
        .as_hash()
        .with_context(|| format!("Action metadata `{}` root must be a mapping", meta.rel))?;
    // GitHub applies Action input defaults when the caller omits `with` keys;
    // merge those defaults under caller bindings before scanning steps.
    let merged_bindings = merge_composite_input_defaults(root, ctx.input_bindings);
    scan_composite_steps(
        root,
        &meta.rel,
        &StepScanCtx {
            privileged_trigger: ctx.privileged_trigger,
            actions: ctx.actions,
            depth: ctx.depth + 1,
            expand_local: true,
            input_bindings: &merged_bindings,
        },
        findings,
    )
}

/// Fill omitted composite inputs from Action metadata `inputs.*.default`.
///
/// Caller-supplied `with` bindings always win. Defaults are taken as literal
/// strings (the same form GitHub evaluates when the caller omits the input).
/// Input names are stored ASCII-lowercased to match GitHub's case-insensitive
/// `inputs` context.
fn merge_composite_input_defaults(root: &Hash, caller_bindings: &InputBindings) -> InputBindings {
    let mut bindings = InputBindings::new();
    if let Some(inputs) = get(root, "inputs").and_then(Yaml::as_hash) {
        for (key, value) in inputs {
            let Some(name) = key.as_str() else {
                continue;
            };
            let Some(spec) = value.as_hash() else {
                continue;
            };
            if let Some(default) = get_string(spec, "default") {
                bindings.insert(normalize_input_name(name), default.to_string());
            }
        }
    }
    for (name, value) in caller_bindings {
        bindings.insert(normalize_input_name(name), value.clone());
    }
    bindings
}

/// Build nested composite bindings from a step's `with:` map, resolving any
/// `${{ inputs.* }}` references against the caller's already-resolved bindings.
fn resolve_step_input_bindings(step: &Hash, parent_bindings: &InputBindings) -> InputBindings {
    let mut bindings = InputBindings::new();
    let Some(with) = get(step, "with").and_then(Yaml::as_hash) else {
        return bindings;
    };
    for (key, value) in with {
        let Some(name) = key.as_str() else {
            continue;
        };
        let Some(raw) = value.as_str() else {
            continue;
        };
        bindings.insert(
            normalize_input_name(name),
            resolve_input_expressions(raw, parent_bindings),
        );
    }
    bindings
}

/// Substitute composite `inputs.name` references with caller binding values.
///
/// Replaces identifier occurrences inside compound expressions
/// (`${{ inputs.ref || github.sha }}`) as well as whole-expression forms
/// (`${{ inputs.ref }}` / `${{ inputs['ref'] }}` / `${{ inputs.Ref }}`).
/// Bracket property access is normalized to dotted form first. Matching is
/// ASCII case-insensitive, matching GitHub's `inputs` context. Longer input
/// names are applied first so a binding named `ref` cannot partially match
/// `referral`.
fn resolve_input_expressions(value: &str, bindings: &InputBindings) -> String {
    if bindings.is_empty() {
        return value.to_string();
    }
    let mut names: Vec<&String> = bindings.keys().collect();
    names.sort_by(|left, right| right.len().cmp(&left.len()).then(left.cmp(right)));
    let mut resolved = normalize_bracket_property_access(value);
    for name in names {
        let Some(bound) = bindings.get(name) else {
            continue;
        };
        resolved = replace_input_identifier(&resolved, name, bound);
    }
    resolved
}

/// Rewrite `['id']` / `["id"]` (with optional whitespace) to `.id` so bracket
/// and mixed property access share the dotted-token input replacer.
fn normalize_bracket_property_access(expression: &str) -> String {
    static BRACKET_PROPERTY: OnceLock<Regex> = OnceLock::new();
    let pattern = BRACKET_PROPERTY.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r#"\[\s*['"]([A-Za-z_][A-Za-z0-9_-]*)['"]\s*\]"#)
            .expect("bracket property access pattern compiles")
    });
    pattern.replace_all(expression, ".$1").into_owned()
}

/// GitHub Action input names are case-insensitive; store one canonical key.
fn normalize_input_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// Replace bare `inputs.{name}` tokens that are not part of a longer property
/// path (for example skip `github.event.inputs.ref`). Matching is ASCII
/// case-insensitive so `${{ inputs.Ref }}` resolves against a `ref` binding.
fn replace_input_identifier(value: &str, name: &str, replacement: &str) -> String {
    let needle = format!("inputs.{}", name.to_ascii_lowercase());
    let lower = value.to_ascii_lowercase();
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(rel) = lower[cursor..].find(&needle) {
        let offset = cursor + rel;
        let end = offset + needle.len();
        let precedes_ok = offset == 0
            || value[..offset]
                .chars()
                .next_back()
                .is_some_and(|character| !is_expression_ident_char(character) && character != '.');
        let follows_ok = value[end..]
            .chars()
            .next()
            .is_none_or(|character| !is_expression_ident_char(character));
        if precedes_ok && follows_ok {
            output.push_str(&value[cursor..offset]);
            output.push_str(replacement);
            cursor = end;
            continue;
        }
        output.push_str(&value[cursor..end]);
        cursor = end;
    }
    output.push_str(&value[cursor..]);
    output
}

fn is_expression_ident_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_' || character == '-'
}

fn is_local_action_ref(action: &str) -> bool {
    action.starts_with("./") || action.starts_with(".github/")
}

fn resolve_local_action<'a>(action: &str, actions: &ActionIndex<'a>) -> Option<&'a SurfaceFile> {
    let normalized = action
        .strip_prefix("./")
        .unwrap_or(action)
        .trim_end_matches('/');
    let candidates = [
        format!("{normalized}/action.yml"),
        format!("{normalized}/action.yaml"),
        normalized.to_string(),
    ];
    candidates
        .iter()
        .find_map(|candidate| actions.get(candidate.as_str()).copied())
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
    if is_local_action_ref(action) {
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

fn check_inline_script(script: &str, rel: &str, findings: &mut Vec<Finding>) -> Result<()> {
    let mut remaining = script;
    while let Some(start) = remaining.find("${{") {
        let after_start = &remaining[start + 3..];
        let Some(end) = after_start.find("}}") else {
            bail!("GitHub Actions surface `{rel}` contains an unterminated expression in `run`");
        };
        let expression = after_start[..end].trim();
        if is_untrusted_context(expression) {
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

fn has_untrusted_checkout_ref(step: &Hash, input_bindings: &InputBindings) -> bool {
    get(step, "with")
        .and_then(Yaml::as_hash)
        .and_then(|with| get_string(with, "ref"))
        .is_some_and(|revision| {
            let resolved = resolve_input_expressions(revision, input_bindings);
            is_untrusted_ref_expression(&resolved)
        })
}

fn is_untrusted_ref_expression(revision: &str) -> bool {
    revision.contains("github.event.pull_request.head.")
        || revision.contains("github.event.pull_request.merge_commit_sha")
        || revision.contains("github.event.workflow_run.head_sha")
        || revision.contains("github.event.workflow_run.head_branch")
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
        findings_for_files(&[SurfaceFile {
            rel: ".github/workflows/test.yml".to_string(),
            content: content.to_string(),
            kind: SurfaceKind::Workflow,
        }])
    }

    fn findings_for_files(files: &[SurfaceFile]) -> Vec<Finding> {
        let mut findings = Vec::new();
        run(files, &mut findings).expect("scan workflow fixture");
        findings
    }

    fn try_scan(files: &[SurfaceFile]) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        run(files, &mut findings)?;
        Ok(findings)
    }

    const COMPOSITE_UNTRUSTED_CHECKOUT: &str = r#"
name: checkout-pr
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      with:
        ref: ${{ github.event.pull_request.head.sha }}
"#;

    #[test]
    fn privileged_local_composite_untrusted_checkout_blocks() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/checkout-pr/action.yml".to_string(),
                content: COMPOSITE_UNTRUSTED_CHECKOUT.to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == RULE_UNTRUSTED_CHECKOUT && finding.severity == Severity::Critical
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn non_privileged_local_composite_untrusted_checkout_skips_untrusted_rule() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/ci.yml".to_string(),
                content: r#"
name: CI
on: pull_request
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/checkout-pr/action.yml".to_string(),
                content: COMPOSITE_UNTRUSTED_CHECKOUT.to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != RULE_UNTRUSTED_CHECKOUT));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == RULE_MUTABLE_ACTION));
    }

    #[test]
    fn privileged_local_composite_input_taint_untrusted_checkout_blocks() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/checkout-pr/action.yml".to_string(),
                content: r#"
name: checkout-pr
inputs:
  ref:
    required: true
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      with:
        ref: ${{ inputs.ref }}
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == RULE_UNTRUSTED_CHECKOUT && finding.severity == Severity::Critical
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn privileged_local_composite_compound_input_taint_untrusted_checkout_blocks() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/checkout-pr/action.yml".to_string(),
                content: r#"
name: checkout-pr
inputs:
  ref:
    required: false
runs:
  using: composite
  steps:
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ inputs.ref || github.sha }}
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == RULE_UNTRUSTED_CHECKOUT && finding.severity == Severity::Critical
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn privileged_local_composite_bracket_input_taint_untrusted_checkout_blocks() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/checkout-pr/action.yml".to_string(),
                content: r#"
name: checkout-pr
inputs:
  ref:
    required: true
runs:
  using: composite
  steps:
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ inputs['ref'] }}
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == RULE_UNTRUSTED_CHECKOUT && finding.severity == Severity::Critical
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn privileged_local_composite_default_input_taint_untrusted_checkout_blocks() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/checkout-pr/action.yml".to_string(),
                content: r#"
name: checkout-pr
inputs:
  ref:
    required: false
    default: ${{ github.event.pull_request.head.sha }}
runs:
  using: composite
  steps:
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ inputs.ref }}
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == RULE_UNTRUSTED_CHECKOUT && finding.severity == Severity::Critical
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn privileged_local_composite_case_variant_input_taint_untrusted_checkout_blocks() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/checkout-pr/action.yml".to_string(),
                content: r#"
name: checkout-pr
inputs:
  Ref:
    required: true
runs:
  using: composite
  steps:
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ inputs.Ref }}
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == RULE_UNTRUSTED_CHECKOUT && finding.severity == Severity::Critical
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn local_composite_source_findings_are_not_duplicated_by_expansion() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
      - uses: ./.github/actions/checkout-pr
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/checkout-pr/action.yml".to_string(),
                content: COMPOSITE_UNTRUSTED_CHECKOUT.to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        let mutable_at_action = findings
            .iter()
            .filter(|finding| {
                finding.rule_id == RULE_MUTABLE_ACTION
                    && finding.location.as_deref() == Some(".github/actions/checkout-pr/action.yml")
            })
            .count();
        assert_eq!(
            mutable_at_action, 1,
            "mutable-action findings must not multiply with each workflow invocation"
        );
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RULE_UNTRUSTED_CHECKOUT && finding.severity == Severity::Critical
        }));
    }

    #[test]
    fn resolve_input_expressions_substitutes_inside_compound_forms() {
        let mut bindings = InputBindings::new();
        bindings.insert(
            "ref".to_string(),
            "${{ github.event.pull_request.head.sha }}".to_string(),
        );
        let resolved = resolve_input_expressions("${{ inputs.ref || github.sha }}", &bindings);
        assert!(resolved.contains("github.event.pull_request.head.sha"));
        assert!(!resolved.contains("inputs.ref"));
        assert!(is_untrusted_ref_expression(&resolved));
    }

    #[test]
    fn resolve_input_expressions_substitutes_bracket_forms() {
        let mut bindings = InputBindings::new();
        bindings.insert(
            "ref".to_string(),
            "${{ github.event.pull_request.head.sha }}".to_string(),
        );
        for expression in [
            "${{ inputs['ref'] }}",
            r#"${{ inputs["ref"] }}"#,
            "${{ inputs[ 'ref' ] || github.sha }}",
        ] {
            let resolved = resolve_input_expressions(expression, &bindings);
            assert!(
                resolved.contains("github.event.pull_request.head.sha"),
                "failed to substitute in {expression}: {resolved}"
            );
            assert!(
                !resolved.contains("inputs['ref']") && !resolved.contains(r#"inputs["ref"]"#),
                "bracket token remained in {expression}: {resolved}"
            );
            assert!(
                is_untrusted_ref_expression(&resolved),
                "resolved expression was not untrusted: {resolved}"
            );
        }
    }

    #[test]
    fn resolve_input_expressions_substitutes_case_variants() {
        let mut bindings = InputBindings::new();
        bindings.insert(
            normalize_input_name("Ref"),
            "${{ github.event.pull_request.head.sha }}".to_string(),
        );
        for expression in [
            "${{ inputs.Ref }}",
            "${{ inputs.REF || github.sha }}",
            "${{ inputs['Ref'] }}",
        ] {
            let resolved = resolve_input_expressions(expression, &bindings);
            assert!(
                resolved.contains("github.event.pull_request.head.sha"),
                "failed to substitute in {expression}: {resolved}"
            );
            assert!(
                is_untrusted_ref_expression(&resolved),
                "resolved expression was not untrusted: {resolved}"
            );
        }
    }

    #[test]
    fn missing_local_composite_fails_closed() {
        let error = try_scan(&[SurfaceFile {
            rel: ".github/workflows/triage.yml".to_string(),
            content: r#"
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/missing-action
"#
            .to_string(),
            kind: SurfaceKind::Workflow,
        }])
        .expect_err("missing local composite must fail closed");
        let message = format!("{error:#}");
        assert!(
            message.contains("missing or unreadable"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn standalone_composite_does_not_invent_privileged_trigger() {
        let findings = findings_for_files(&[SurfaceFile {
            rel: ".github/actions/checkout-pr/action.yml".to_string(),
            content: COMPOSITE_UNTRUSTED_CHECKOUT.to_string(),
            kind: SurfaceKind::ActionMetadata,
        }]);

        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != RULE_UNTRUSTED_CHECKOUT));
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
}
