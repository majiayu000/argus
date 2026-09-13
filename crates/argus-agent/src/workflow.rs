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
//! such as `ref: ${{ inputs['ref'] }}` or
//! `ref: ${{ github['event']['pull_request']['head']['sha'] }}`, compound forms
//! such as `ref: ${{ inputs.ref || github.sha }}`, case-variant forms such as
//! `ref: ${{ inputs.Ref }}`, env aliases such as
//! `with: ref: ${{ env.PR_REF }}` after `env.PR_REF` was set to an untrusted
//! github context, a step-local env alias such as
//! `env: { TARGET: ${{ inputs.ref }} }` with `with: { ref: ${{ env.TARGET }} }`,
//! a step-output indirection such as writing `${{ inputs.ref }}` to
//! `$GITHUB_OUTPUT` then checking out `${{ steps.resolve.outputs.ref }}`,
//! including when a later untracked `$GITHUB_OUTPUT` overwrite (with optional
//! trailing shell comments / operators after the redirect) or backtick
//! command substitution would otherwise leave a stale safe binding,
//! a `$GITHUB_ENV` write such as `echo "TARGET=${{ inputs.ref }}" >> "$GITHUB_ENV"`
//! followed by `ref: ${{ env.TARGET }}`,
//! including when an untracked `$GITHUB_ENV` write (`echo "TARGET=$VAR"`,
//! `echo -e`, or `printf`) leaves `${{ env.TARGET }}` unresolved,
//! including when a later non-`echo` `$GITHUB_OUTPUT`/`$GITHUB_ENV` redirect
//! (for example `printf 'ref=%s\n' "$TARGET"`) would otherwise leave a stale
//! safe binding,
//! including non-redirect environment-file writes such as
//! `printf 'ref=%s\n' "$TARGET" | tee -a "$GITHUB_OUTPUT"` that must be treated
//! as opaque rather than ignored,
//! computed input access such as `ref: ${{ fromJSON(toJSON(inputs)).ref }}`,
//! computed env access such as `ref: ${{ fromJSON(toJSON(env)).TARGET }}`,
//! computed GitHub event access such as
//! `ref: ${{ fromJSON(toJSON(github.event.pull_request)).head.sha }}`,
//! parent serialization
//! `ref: ${{ fromJSON(toJSON(github.event)).pull_request.head.sha }}`, or
//! whole-context serialization
//! `ref: ${{ fromJSON(toJSON(github)).event.pull_request.head.sha }}`,
//! branch-dependent `$GITHUB_OUTPUT` writes under `if`/`else`/`&&`/`||` that
//! cannot be proven sequential, multi-redirect command lists on one line,
//! opaque `$GITHUB_ENV` redirects that cannot name the overwritten key,
//! including PowerShell `$env:GITHUB_ENV` / `$env:GITHUB_OUTPUT` writers,
//! or an omitted `with` that relies on an untrusted input default — cannot
//! bypass Critical→block. `$GITHUB_ENV` writes inside an expanded local
//! composite propagate to later caller steps (GitHub job-wide env file),
//! including when the composite writes a value equal to the invoking step's
//! transient `env:` override,
//! steps with a statically false `if:` do not apply env/output side effects,
//! non-literal/`if` conditions treat env writes as uncertain (invalidate),
//! braced parameter expansions such as `${GITHUB_ENV:?missing}` are recognized
//! as environment-file targets,
//! `&&`/`||` multi-redirect lists are fully parsed, and unresolved
//! `needs.*.outputs.*` checkout refs fail closed. Unresolved
//! `steps.*.outputs.*`, unresolved `env` access, and unresolved `inputs`
//! access in checkout refs fail closed under a privileged trigger. Quoted
//! expression literals such as `${{ 'inputs.ref' }}` are not treated as input
//! references; `}}` inside those quotes does not terminate the expression
//! region. Single-quoted
//! shell payloads such as `echo 'ref=$TARGET' >> "$GITHUB_OUTPUT"` keep their
//! literal value (no shell expansion) and are not marked untracked.
//! Standalone Action metadata scans still use `privileged_trigger=false` so
//! composites alone do not invent a privileged trigger. Local expansion is
//! depth-bounded and fail-closed; source findings on composite bodies are left
//! to the ActionMetadata pass so expansion does not duplicate them.

use crate::{SurfaceFile, SurfaceKind};
use anyhow::{bail, Context, Result};
use argus_core::{Finding, Severity};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use yaml_rust2::{yaml::Hash, Yaml, YamlLoader};

/// Resolved caller `with` bindings for the current local-composite expansion.
type InputBindings = BTreeMap<String, String>;
/// Workflow / job / step `env` map used to resolve `${{ env.NAME }}` aliases.
type EnvBindings = BTreeMap<String, String>;
/// Prior-step `$GITHUB_OUTPUT` writes keyed as `{step_id}.{output_name}`.
type StepOutputBindings = BTreeMap<String, String>;

/// `$GITHUB_ENV` side effects from an expanded local composite.
///
/// `env` is the full map after scanning (inherited bindings plus writes).
/// `written_keys` names keys assigned or cleared via `$GITHUB_ENV` (including
/// nested composites). `cleared` is set when an opaque write wiped the map.
/// Propagation uses `written_keys` rather than value diffs against the
/// composite entry map so a write equal to the invoking step's transient
/// `env:` still persists to later caller steps.
struct CompositeEnvEffects {
    env: EnvBindings,
    written_keys: BTreeSet<String>,
    cleared: bool,
}

struct StepScanCtx<'a> {
    privileged_trigger: bool,
    actions: &'a ActionIndex<'a>,
    depth: u32,
    expand_local: bool,
    input_bindings: &'a InputBindings,
    env_bindings: &'a EnvBindings,
    step_outputs: &'a StepOutputBindings,
}

const RULE_MUTABLE_ACTION: &str = "AGT-06-workflow-mutable-action";
const RULE_CONTEXT_INJECTION: &str = "AGT-06-workflow-context-injection";
const RULE_UNTRUSTED_CHECKOUT: &str = "AGT-06-workflow-untrusted-checkout";
const RULE_WRITE_ALL: &str = "AGT-06-workflow-write-all";
const RULE_PRIVILEGED_WRITE: &str = "AGT-06-workflow-privileged-write";
/// Workflow → local composite is one hop; one nested local composite is allowed.
const MAX_LOCAL_COMPOSITE_DEPTH: u32 = 2;
/// Cap transitive input/env alias rewriting (env → inputs → env …).
const MAX_CONTEXT_RESOLVE_DEPTH: u32 = 8;

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
    let workflow_env = collect_env_bindings(root);
    for job in jobs.values().filter_map(Yaml::as_hash) {
        check_permissions(job, "job", privileged_trigger, &file.rel, findings);
        if let Some(action) = get_string(job, "uses") {
            check_action_ref(action, &file.rel, findings);
        }
        let Some(steps) = get(job, "steps").and_then(Yaml::as_vec) else {
            continue;
        };
        let job_env = merge_env_bindings(&workflow_env, &collect_env_bindings(job));
        let mut step_outputs = StepOutputBindings::new();
        // `$GITHUB_ENV` writes from earlier steps become env bindings for later ones.
        let mut env_bindings = job_env;
        for step in steps.iter().filter_map(Yaml::as_hash) {
            let step_env = merge_env_bindings(&env_bindings, &collect_env_bindings(step));
            let composite_env = scan_step(
                step,
                &file.rel,
                &StepScanCtx {
                    privileged_trigger,
                    actions,
                    depth: 0,
                    expand_local: true,
                    input_bindings: &empty_bindings,
                    env_bindings: &env_bindings,
                    step_outputs: &step_outputs,
                },
                findings,
            )?;
            // Statically skipped steps do not run, so their `$GITHUB_ENV` /
            // `$GITHUB_OUTPUT` writes and nested composite env side effects
            // must not update later-step bindings.
            if step_condition_is_always_false(step) {
                continue;
            }
            // Runtime-dependent or non-literal conditions may or may not run;
            // apply concrete values only when execution is definite. Otherwise
            // invalidate keys the step would touch so stale safe bindings
            // cannot mask attacker-controlled values.
            if !step_condition_is_definitely_executed(step) {
                if let Some(effects) = composite_env {
                    invalidate_composite_env_effects(&effects, &mut env_bindings);
                }
                invalidate_github_env_writes(step, &mut env_bindings);
                continue;
            }
            if let Some(effects) = composite_env {
                apply_composite_env_effects(&effects, &mut env_bindings);
            }
            for (key, value) in
                collect_step_output_bindings(step, &empty_bindings, &step_env, &step_outputs)
            {
                step_outputs.insert(key, value);
            }
            let _ = apply_github_env_writes(
                step,
                &empty_bindings,
                &step_env,
                &step_outputs,
                &mut env_bindings,
            );
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
    let empty_env = EnvBindings::new();
    let empty_step_outputs = StepOutputBindings::new();
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
            env_bindings: &empty_env,
            step_outputs: &empty_step_outputs,
        },
        findings,
    )
    .map(|_| ())
}

fn scan_composite_steps(
    root: &Hash,
    rel: &str,
    ctx: &StepScanCtx<'_>,
    findings: &mut Vec<Finding>,
) -> Result<CompositeEnvEffects> {
    let empty_effects = || CompositeEnvEffects {
        env: ctx.env_bindings.clone(),
        written_keys: BTreeSet::new(),
        cleared: false,
    };
    let Some(runs) = get(root, "runs").and_then(Yaml::as_hash) else {
        return Ok(empty_effects());
    };
    if !get_string(runs, "using").is_some_and(|using| using.eq_ignore_ascii_case("composite")) {
        return Ok(empty_effects());
    }
    let Some(steps) = get(runs, "steps").and_then(Yaml::as_vec) else {
        return Ok(empty_effects());
    };
    let mut step_outputs = StepOutputBindings::new();
    // Accumulate `$GITHUB_ENV` writes so later composite steps see them via
    // `${{ env.NAME }}` the same way GitHub does. Written keys are tracked so
    // callers can propagate job-wide env-file writes across the composite
    // boundary even when the written value equals the invoking step's
    // transient `env:`.
    let mut env_bindings = ctx.env_bindings.clone();
    let mut written_keys = BTreeSet::new();
    let mut cleared = false;
    for step in steps.iter().filter_map(Yaml::as_hash) {
        let step_env = merge_env_bindings(&env_bindings, &collect_env_bindings(step));
        let nested_env = scan_step(
            step,
            rel,
            &StepScanCtx {
                privileged_trigger: ctx.privileged_trigger,
                actions: ctx.actions,
                depth: ctx.depth,
                expand_local: ctx.expand_local,
                input_bindings: ctx.input_bindings,
                env_bindings: &env_bindings,
                step_outputs: &step_outputs,
            },
            findings,
        )?;
        if step_condition_is_always_false(step) {
            continue;
        }
        if !step_condition_is_definitely_executed(step) {
            if let Some(effects) = nested_env {
                merge_invalidated_composite_env(
                    &effects,
                    &mut env_bindings,
                    &mut written_keys,
                    &mut cleared,
                );
            }
            let invalidated = invalidate_github_env_writes(step, &mut env_bindings);
            if cleared {
                written_keys.clear();
            } else {
                written_keys.extend(invalidated);
            }
            continue;
        }
        if let Some(effects) = nested_env {
            merge_composite_env_effects(
                &effects,
                &mut env_bindings,
                &mut written_keys,
                &mut cleared,
            );
        }
        for (key, value) in
            collect_step_output_bindings(step, ctx.input_bindings, &step_env, &step_outputs)
        {
            step_outputs.insert(key, value);
        }
        let (step_keys, step_cleared) = apply_github_env_writes(
            step,
            ctx.input_bindings,
            &step_env,
            &step_outputs,
            &mut env_bindings,
        );
        if step_cleared {
            cleared = true;
            written_keys.clear();
        } else if !cleared {
            written_keys.extend(step_keys);
        }
    }
    Ok(CompositeEnvEffects {
        env: env_bindings,
        written_keys,
        cleared,
    })
}

fn scan_step(
    step: &Hash,
    rel: &str,
    ctx: &StepScanCtx<'_>,
    findings: &mut Vec<Finding>,
) -> Result<Option<CompositeEnvEffects>> {
    // Expansion (depth > 0) only adds privileged-context findings. Mutable-action
    // and inline-script findings for composite bodies are emitted once by the
    // ActionMetadata pass so call-site count does not inflate source findings.
    let emit_source_findings = ctx.depth == 0;
    let step_env = merge_env_bindings(ctx.env_bindings, &collect_env_bindings(step));
    let mut composite_env = None;
    if let Some(action) = get_string(step, "uses") {
        if emit_source_findings {
            check_action_ref(action, rel, findings);
        }
        if ctx.privileged_trigger
            && is_checkout(action)
            && has_untrusted_checkout_ref(step, ctx.input_bindings, &step_env, ctx.step_outputs)
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
            let nested_bindings =
                resolve_step_input_bindings(step, ctx.input_bindings, &step_env, ctx.step_outputs);
            let empty_step_outputs = StepOutputBindings::new();
            composite_env = Some(expand_local_composite(
                action,
                rel,
                &StepScanCtx {
                    privileged_trigger: ctx.privileged_trigger,
                    actions: ctx.actions,
                    depth: ctx.depth,
                    expand_local: true,
                    input_bindings: &nested_bindings,
                    env_bindings: &step_env,
                    step_outputs: &empty_step_outputs,
                },
                findings,
            )?);
        }
    }
    if emit_source_findings {
        if let Some(script) = get_string(step, "run") {
            check_inline_script(script, rel, findings)?;
        }
    }
    Ok(composite_env)
}

fn expand_local_composite(
    action: &str,
    caller_rel: &str,
    ctx: &StepScanCtx<'_>,
    findings: &mut Vec<Finding>,
) -> Result<CompositeEnvEffects> {
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
    let empty_step_outputs = StepOutputBindings::new();
    scan_composite_steps(
        root,
        &meta.rel,
        &StepScanCtx {
            privileged_trigger: ctx.privileged_trigger,
            actions: ctx.actions,
            depth: ctx.depth + 1,
            expand_local: true,
            input_bindings: &merged_bindings,
            env_bindings: ctx.env_bindings,
            step_outputs: &empty_step_outputs,
        },
        findings,
    )
}

/// Apply tracked `$GITHUB_ENV` side effects from an expanded composite onto the
/// caller's accumulated env map without persisting the calling step's
/// transient `env:`.
fn apply_composite_env_effects(effects: &CompositeEnvEffects, persist: &mut EnvBindings) {
    if effects.cleared {
        persist.clear();
        return;
    }
    for key in &effects.written_keys {
        match effects.env.get(key) {
            Some(value) => {
                persist.insert(key.clone(), value.clone());
            }
            None => {
                persist.remove(key);
            }
        }
    }
}

/// Fail closed: drop keys a conditionally executed composite would write so a
/// skipped safe overwrite cannot leave a stale trusted binding.
fn invalidate_composite_env_effects(effects: &CompositeEnvEffects, persist: &mut EnvBindings) {
    if effects.cleared {
        persist.clear();
        return;
    }
    for key in &effects.written_keys {
        persist.remove(key);
    }
}

fn merge_composite_env_effects(
    effects: &CompositeEnvEffects,
    env_bindings: &mut EnvBindings,
    written_keys: &mut BTreeSet<String>,
    cleared: &mut bool,
) {
    if effects.cleared {
        env_bindings.clear();
        written_keys.clear();
        *cleared = true;
        return;
    }
    apply_composite_env_effects(effects, env_bindings);
    if !*cleared {
        written_keys.extend(effects.written_keys.iter().cloned());
    }
}

fn merge_invalidated_composite_env(
    effects: &CompositeEnvEffects,
    env_bindings: &mut EnvBindings,
    written_keys: &mut BTreeSet<String>,
    cleared: &mut bool,
) {
    if effects.cleared {
        env_bindings.clear();
        written_keys.clear();
        *cleared = true;
        return;
    }
    invalidate_composite_env_effects(effects, env_bindings);
    if !*cleared {
        written_keys.extend(effects.written_keys.iter().cloned());
    }
}

/// True when a step `if:` is statically false (`false` / `${{ false }}`), so
/// GitHub skips the step and its env/output side effects must be ignored.
fn step_condition_is_always_false(step: &Hash) -> bool {
    get_string(step, "if").is_some_and(is_always_false_condition)
}

/// True when a step has no `if:` or a statically true condition, so side
/// effects definitely run. Any other condition is treated as uncertain.
fn step_condition_is_definitely_executed(step: &Hash) -> bool {
    match get_string(step, "if") {
        None => true,
        Some(condition) => is_always_true_condition(condition),
    }
}

fn is_always_false_condition(condition: &str) -> bool {
    expression_condition_atom(condition).eq_ignore_ascii_case("false")
}

fn is_always_true_condition(condition: &str) -> bool {
    expression_condition_atom(condition).eq_ignore_ascii_case("true")
}

fn expression_condition_atom(condition: &str) -> &str {
    let trimmed = condition.trim();
    trimmed
        .strip_prefix("${{")
        .and_then(|value| value.strip_suffix("}}"))
        .map(str::trim)
        .unwrap_or(trimmed)
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
/// `${{ inputs.* }}`, `${{ env.* }}`, and `${{ steps.*.outputs.* }}` references
/// against the caller's already-resolved bindings, the effective
/// workflow/job/step env map, and prior-step output writes.
fn resolve_step_input_bindings(
    step: &Hash,
    parent_bindings: &InputBindings,
    env_bindings: &EnvBindings,
    step_outputs: &StepOutputBindings,
) -> InputBindings {
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
            resolve_context_expressions(raw, parent_bindings, env_bindings, step_outputs),
        );
    }
    bindings
}

/// Collect literal `env:` key/value pairs from a workflow, job, or step mapping.
fn collect_env_bindings(owner: &Hash) -> EnvBindings {
    let mut bindings = EnvBindings::new();
    let Some(env) = get(owner, "env").and_then(Yaml::as_hash) else {
        return bindings;
    };
    for (key, value) in env {
        let Some(name) = key.as_str() else {
            continue;
        };
        let Some(raw) = value.as_str() else {
            continue;
        };
        bindings.insert(name.to_string(), raw.to_string());
    }
    bindings
}

/// Child `env` keys override parent keys (workflow → job → step).
fn merge_env_bindings(parent: &EnvBindings, child: &EnvBindings) -> EnvBindings {
    let mut merged = parent.clone();
    for (name, value) in child {
        merged.insert(name.clone(), value.clone());
    }
    merged
}

/// Resolve composite input, env, and step-output aliases, normalizing bracket
/// property access.
///
/// Substitution is applied until a fixed point (or
/// [`MAX_CONTEXT_RESOLVE_DEPTH`]) so env aliases that expand to
/// `${{ inputs.* }}`, step outputs that expand to env/input expressions, and
/// the reverse are fully rewritten before the untrusted-ref detector runs.
fn resolve_context_expressions(
    value: &str,
    input_bindings: &InputBindings,
    env_bindings: &EnvBindings,
    step_outputs: &StepOutputBindings,
) -> String {
    let mut resolved = value.to_string();
    for _ in 0..MAX_CONTEXT_RESOLVE_DEPTH {
        let next = resolve_step_output_expressions(
            &resolve_env_expressions(
                &resolve_input_expressions(&resolved, input_bindings),
                env_bindings,
            ),
            step_outputs,
        );
        if next == resolved {
            return next;
        }
        resolved = next;
    }
    resolved
}

/// Substitute composite `inputs.name` references with caller binding values.
///
/// Replaces identifier occurrences inside `${{ ... }}` expression regions only,
/// including compound forms (`${{ inputs.ref || github.sha }}`) as well as
/// whole-expression forms (`${{ inputs.ref }}` / `${{ inputs['ref'] }}` /
/// `${{ inputs.Ref }}`). Bracket property access is normalized to dotted form
/// first so empty binding maps still convert
/// `github['event']['pull_request']['head']['sha']` into the dotted detector
/// shape. Matching is ASCII case-insensitive, matching GitHub's `inputs`
/// context. Longer input names are applied first so a binding named `ref`
/// cannot partially match `referral`.
fn resolve_input_expressions(value: &str, bindings: &InputBindings) -> String {
    let mut resolved = normalize_bracket_property_access(value);
    if bindings.is_empty() {
        return resolved;
    }
    let mut names: Vec<&String> = bindings.keys().collect();
    names.sort_by(|left, right| right.len().cmp(&left.len()).then(left.cmp(right)));
    for name in names {
        let Some(bound) = bindings.get(name) else {
            continue;
        };
        resolved = replace_context_identifier(&resolved, "inputs", name, bound, true);
    }
    resolved
}

/// Substitute `env.NAME` references using the effective workflow/job/step env.
///
/// Replacement is limited to `${{ ... }}` regions. Env names keep their
/// declared case (GitHub env is case-sensitive on Linux runners).
fn resolve_env_expressions(value: &str, bindings: &EnvBindings) -> String {
    if bindings.is_empty() {
        return value.to_string();
    }
    let mut names: Vec<&String> = bindings.keys().collect();
    names.sort_by(|left, right| right.len().cmp(&left.len()).then(left.cmp(right)));
    let mut resolved = value.to_string();
    for name in names {
        let Some(bound) = bindings.get(name) else {
            continue;
        };
        resolved = replace_context_identifier(&resolved, "env", name, bound, false);
    }
    resolved
}

/// Substitute `steps.<id>.outputs.<name>` using prior `$GITHUB_OUTPUT` writes.
///
/// Keys are stored as `{id}.{name}`. Bracket property access is normalized
/// first. Step ids and output names are case-sensitive.
fn resolve_step_output_expressions(value: &str, bindings: &StepOutputBindings) -> String {
    let mut resolved = normalize_bracket_property_access(value);
    if bindings.is_empty() {
        return resolved;
    }
    let mut keys: Vec<&String> = bindings.keys().collect();
    keys.sort_by(|left, right| right.len().cmp(&left.len()).then(left.cmp(right)));
    for key in keys {
        let Some((step_id, output_name)) = key.split_once('.') else {
            continue;
        };
        let Some(bound) = bindings.get(key) else {
            continue;
        };
        let context = format!("steps.{step_id}.outputs");
        resolved = replace_context_identifier(&resolved, &context, output_name, bound, false);
    }
    resolved
}

/// Collect `id` + `run` step writes of the form `echo "name=value" >> $GITHUB_OUTPUT`.
fn collect_step_output_bindings(
    step: &Hash,
    input_bindings: &InputBindings,
    env_bindings: &EnvBindings,
    step_outputs: &StepOutputBindings,
) -> StepOutputBindings {
    let mut collected = StepOutputBindings::new();
    let Some(step_id) = get_string(step, "id") else {
        return collected;
    };
    if !is_github_ident(step_id) {
        return collected;
    }
    let Some(script) = get_string(step, "run") else {
        return collected;
    };
    for (name, resolved) in resolve_github_file_write_bindings(
        script,
        "GITHUB_OUTPUT",
        input_bindings,
        env_bindings,
        step_outputs,
    ) {
        let key = format!("{step_id}.{name}");
        match resolved {
            Some(value) => {
                collected.insert(key, value);
            }
            None => {
                collected.remove(&key);
            }
        }
    }
    collected
}

/// Merge `$GITHUB_ENV` writes from a `run` step into `env_bindings` for later steps.
///
/// GitHub exposes these values to subsequent steps via `${{ env.NAME }}`. Untracked
/// shell expansions invalidate any earlier binding for the same name (last write
/// wins, and an untracked last write must not leave a stale safe value). Writes
/// under shell control flow that compete for the same name are left unresolved.
/// An opaque `$GITHUB_ENV` redirect that cannot recover an assignment name can
/// replace any key, so every inherited binding is dropped rather than retaining
/// a stale safe value.
fn apply_github_env_writes(
    step: &Hash,
    input_bindings: &InputBindings,
    step_env: &EnvBindings,
    step_outputs: &StepOutputBindings,
    env_bindings: &mut EnvBindings,
) -> (BTreeSet<String>, bool) {
    let Some(script) = get_string(step, "run") else {
        return (BTreeSet::new(), false);
    };
    let (_, opaque_redirect) = parse_github_file_writes(script, "GITHUB_ENV");
    if opaque_redirect {
        env_bindings.clear();
        return (BTreeSet::new(), true);
    }
    let mut written = BTreeSet::new();
    for (name, resolved) in resolve_github_file_write_bindings(
        script,
        "GITHUB_ENV",
        input_bindings,
        step_env,
        step_outputs,
    ) {
        written.insert(name.clone());
        match resolved {
            Some(value) => {
                env_bindings.insert(name, value);
            }
            None => {
                env_bindings.remove(&name);
            }
        }
    }
    (written, false)
}

/// Drop keys a `$GITHUB_ENV` writer would touch without applying resolved
/// values — used when the step's `if:` is not statically definite.
fn invalidate_github_env_writes(step: &Hash, env_bindings: &mut EnvBindings) -> BTreeSet<String> {
    let Some(script) = get_string(step, "run") else {
        return BTreeSet::new();
    };
    let (writes, opaque_redirect) = parse_github_file_writes(script, "GITHUB_ENV");
    if opaque_redirect {
        env_bindings.clear();
        return BTreeSet::new();
    }
    let mut written = BTreeSet::new();
    for (name, _, _) in writes {
        written.insert(name.clone());
        env_bindings.remove(&name);
    }
    written
}

/// Resolve `echo … >> $GITHUB_{OUTPUT,ENV}` writes into tracked values or
/// explicit unresolved markers (`None`).
///
/// Linear scripts keep last-write-wins, with untracked shell expansions clearing
/// any earlier safe binding. Scripts with shell control flow (`if`/`else`/…)
/// cannot prove which branch runs, so competing or untracked writes for the
/// same name stay unresolved instead of retaining a later textual binding.
fn resolve_github_file_write_bindings(
    script: &str,
    file_var: &str,
    input_bindings: &InputBindings,
    env_bindings: &EnvBindings,
    step_outputs: &StepOutputBindings,
) -> Vec<(String, Option<String>)> {
    let (writes, opaque_redirect) = parse_github_file_writes(script, file_var);
    if writes.is_empty() {
        return Vec::new();
    }
    if script_has_shell_control_flow(script) {
        let mut grouped: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
        for (name, raw_value, shell_expands) in writes {
            grouped
                .entry(name)
                .or_default()
                .push((raw_value, shell_expands));
        }
        return grouped
            .into_iter()
            .map(|(name, entries)| {
                if opaque_redirect || entries.len() != 1 {
                    return (name, None);
                }
                let Some((raw_value, shell_expands)) = entries.into_iter().next() else {
                    return (name, None);
                };
                // Single-quoted echo payloads are shell literals (`$` / backticks
                // do not expand), so they remain trackable.
                if shell_expands && value_contains_untracked_shell_expansion(&raw_value) {
                    return (name, None);
                }
                (
                    name,
                    Some(resolve_context_expressions(
                        &raw_value,
                        input_bindings,
                        env_bindings,
                        step_outputs,
                    )),
                )
            })
            .collect();
    }

    let mut collected: BTreeMap<String, Option<String>> = BTreeMap::new();
    for (name, raw_value, shell_expands) in writes {
        // Shell expansions outside `${{ }}` are not statically trackable; leave
        // the binding unresolved so privileged checkout fails closed.
        // GitHub keeps the last write for a given name, so an untracked
        // overwrite must also drop any earlier safe binding for that name.
        if shell_expands && value_contains_untracked_shell_expansion(&raw_value) {
            collected.insert(name, None);
            continue;
        }
        collected.insert(
            name,
            Some(resolve_context_expressions(
                &raw_value,
                input_bindings,
                env_bindings,
                step_outputs,
            )),
        );
    }
    if opaque_redirect {
        // A redirect we cannot parse (for example `cat file >> $GITHUB_OUTPUT`)
        // may overwrite any earlier key; drop every binding rather than keep a
        // stale safe value.
        return collected.into_keys().map(|name| (name, None)).collect();
    }
    collected.into_iter().collect()
}

/// True when `script` contains shell control-flow keywords or boolean lists that
/// make lexical last-write-wins unsafe for `$GITHUB_OUTPUT` / `$GITHUB_ENV`
/// tracking.
fn script_has_shell_control_flow(script: &str) -> bool {
    static CONTROL_FLOW: OnceLock<Regex> = OnceLock::new();
    let pattern = CONTROL_FLOW.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(
            r"(?m)(?:(?:^|[^A-Za-z0-9_])(?:if|elif|else|fi|case|esac|for|while|until|done|select)(?:$|[^A-Za-z0-9_])|&&|\|\|)",
        )
        .expect("shell control-flow pattern compiles")
    });
    // Blank `${{ }}` regions so expression operators such as
    // `${{ false && inputs.ref }}` are not treated as shell control flow.
    pattern.is_match(&blank_github_expression_regions(script))
}

/// True when `value` still has `$...` or backtick command substitution outside
/// GitHub expressions.
fn value_contains_untracked_shell_expansion(value: &str) -> bool {
    // Blank entire `${{ ... }}` regions, including the leading `$`, so expression
    // syntax is not mistaken for shell expansion.
    let without_expressions = blank_github_expression_regions(value);
    without_expressions.contains('$') || without_expressions.contains('`')
}

/// Replace each `${{ ... }}` span with a single space (unclosed tails blanked).
fn blank_github_expression_regions(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(rel_start) = value[cursor..].find("${{") {
        let start = cursor + rel_start;
        output.push_str(&value[cursor..start]);
        let after_open = start + 3;
        let Some(rel_end) = find_expression_close(&value[after_open..]) else {
            output.push(' ');
            return output;
        };
        output.push(' ');
        cursor = after_open + rel_end + 2;
    }
    output.push_str(&value[cursor..]);
    output
}

/// Parse `… >> $GITHUB_{OUTPUT,ENV}` lines into tracked echo writes.
///
/// Returns `(writes, opaque_redirect)` where `writes` entries are
/// `(name, value, shell_expands)` and `opaque_redirect` is set when a redirect
/// target is present but the command cannot be tied to a specific `name=`
/// assignment (for example `cat file >> "$GITHUB_OUTPUT"`), or when the segment
/// references `$GITHUB_OUTPUT` / `$GITHUB_ENV` without a recognized `>>`
/// redirect (for example `printf … | tee -a "$GITHUB_OUTPUT"`). Non-`echo`
/// writes such as `printf 'ref=%s\n' "$TARGET"` still contribute an untracked
/// write for the inferred name so earlier safe bindings are invalidated.
/// Semicolon-separated command lists on one line are split so each redirect is
/// processed.
fn parse_github_file_writes(script: &str, file_var: &str) -> (Vec<(String, String, bool)>, bool) {
    let mut writes = Vec::new();
    let mut opaque_redirect = false;
    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for segment in split_shell_list_segments(trimmed) {
            let segment = segment.trim();
            if segment.is_empty() || segment.starts_with('#') {
                continue;
            }
            let Some(command) = split_github_file_redirect(segment, file_var) else {
                // Pipes / `tee` / other non-`>>` writers still mutate the file at
                // runtime; ignoring them would retain a stale safe binding.
                if segment_references_github_file(segment, file_var) {
                    opaque_redirect = true;
                }
                continue;
            };
            let Some(payload) = extract_echo_payload(command) else {
                if let Some(name) = infer_github_file_assignment_name(command) {
                    // Force untracked invalidation for this name (last write wins).
                    writes.push((name, "$".to_string(), true));
                } else {
                    opaque_redirect = true;
                }
                continue;
            };
            let (payload, shell_expands) = unwrap_echo_payload(payload.trim());
            let Some((name, value)) = payload.split_once('=') else {
                opaque_redirect = true;
                continue;
            };
            let name = name.trim();
            if !is_github_ident(name) {
                opaque_redirect = true;
                continue;
            }
            writes.push((name.to_string(), value.trim().to_string(), shell_expands));
        }
    }
    (writes, opaque_redirect)
}

/// Split a shell line on unquoted `;`, `&&`, and `||` so multi-redirect command
/// lists are each inspected rather than keeping only the first `>>` write.
fn split_shell_list_segments(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut in_single = false;
    let mut in_double = false;
    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'\\' if in_double && index + 1 < bytes.len() => {
                index += 2;
                continue;
            }
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b';' if !in_single && !in_double => {
                segments.push(&line[start..index]);
                start = index + 1;
            }
            b'&' if !in_single
                && !in_double
                && index + 1 < bytes.len()
                && bytes[index + 1] == b'&' =>
            {
                segments.push(&line[start..index]);
                start = index + 2;
                index += 2;
                continue;
            }
            b'|' if !in_single
                && !in_double
                && index + 1 < bytes.len()
                && bytes[index + 1] == b'|' =>
            {
                segments.push(&line[start..index]);
                start = index + 2;
                index += 2;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    segments.push(&line[start..]);
    segments
}

/// Best-effort `name=` extraction for non-`echo` redirects such as
/// `printf 'ref=%s\n' "$TARGET"`.
fn infer_github_file_assignment_name(command: &str) -> Option<String> {
    let trimmed = command.trim();
    let rest = trimmed.strip_prefix("printf")?.trim_start();
    let format = first_shell_token(rest)?;
    let format = strip_wrapping_shell_quotes(format);
    let (name, _) = format.split_once('=')?;
    let name = name.trim();
    if is_github_ident(name) {
        Some(name.to_string())
    } else {
        None
    }
}

fn split_github_file_redirect<'a>(line: &'a str, file_var: &str) -> Option<&'a str> {
    let index = line.find(">>")?;
    let (before, after) = line.split_at(index);
    let after = after.trim_start_matches('>').trim();
    // Trailing `# ...` comments and operators after the redirect target are
    // valid Bash; exact-matching the whole suffix would drop the write and
    // retain an earlier safe binding (fail-open for AGT-06).
    let after = strip_trailing_shell_comment(after).trim();
    let target_token = first_shell_token(after)?;
    let target = strip_wrapping_shell_quotes(target_token).trim();
    if is_github_file_redirect_target(target, file_var) {
        Some(before.trim())
    } else {
        None
    }
}

/// True when `target` names a GitHub Actions environment file via Bash
/// `$VAR` / `${VAR}` / `${VAR:…}` parameter expansions or PowerShell
/// `$env:VAR` syntax.
fn is_github_file_redirect_target(target: &str, file_var: &str) -> bool {
    let dollar = format!("${file_var}");
    let pwsh = format!("$env:{file_var}");
    if target == dollar || target.eq_ignore_ascii_case(&pwsh) {
        return true;
    }
    is_braced_github_file_ref(target, file_var)
}

/// `${VAR}`, `${VAR:?msg}`, `${VAR:-word}`, and other bash parameter
/// expansions whose base name is a GitHub environment-file variable.
fn is_braced_github_file_ref(target: &str, file_var: &str) -> bool {
    let prefix = format!("${{{file_var}");
    let Some(rest) = target
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix('}'))
    else {
        return false;
    };
    rest.is_empty()
        || rest.starts_with(':')
        || rest.starts_with('#')
        || rest.starts_with('%')
        || rest.starts_with('/')
        || rest.starts_with('^')
        || rest.starts_with(',')
}

/// True when a shell segment mentions `$GITHUB_{OUTPUT,ENV}` / `${…}` /
/// `$env:GITHUB_{OUTPUT,ENV}` even without a recognized `>>` redirect
/// (pipes, `tee`, `cat`, …).
fn segment_references_github_file(segment: &str, file_var: &str) -> bool {
    let dollar = format!("${file_var}");
    let braced = format!("${{{file_var}}}");
    let pwsh = format!("$env:{file_var}");
    if segment.contains(&dollar) || segment.contains(&braced) {
        return true;
    }
    if contains_braced_github_file_ref(segment, file_var) {
        return true;
    }
    // PowerShell provider names are case-insensitive (`$Env:GITHUB_ENV`).
    let lower = segment.to_ascii_lowercase();
    lower.contains(&pwsh.to_ascii_lowercase())
}

fn contains_braced_github_file_ref(segment: &str, file_var: &str) -> bool {
    let prefix = format!("${{{file_var}");
    let mut search = segment;
    while let Some(rel) = search.find(&prefix) {
        let after_prefix = &search[rel + prefix.len()..];
        if let Some(end) = after_prefix.find('}') {
            let rest = &after_prefix[..end];
            if rest.is_empty()
                || rest.starts_with(':')
                || rest.starts_with('#')
                || rest.starts_with('%')
                || rest.starts_with('/')
                || rest.starts_with('^')
                || rest.starts_with(',')
            {
                return true;
            }
        }
        search = &search[rel + 1..];
    }
    false
}

/// Drop an unquoted trailing `# ...` shell comment.
fn strip_trailing_shell_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    let mut index = 0;
    let mut in_single = false;
    let mut in_double = false;
    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'\\' if in_double && index + 1 < bytes.len() => {
                index += 2;
                continue;
            }
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double => return value[..index].trim_end(),
            _ => {}
        }
        index += 1;
    }
    value
}

/// First shell word: a quoted span or an unquoted run until whitespace.
fn first_shell_token(value: &str) -> Option<&str> {
    let trimmed = value.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let bytes = trimmed.as_bytes();
    match bytes[0] {
        b'"' | b'\'' => {
            let quote = bytes[0];
            let mut index = 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' && quote == b'"' && index + 1 < bytes.len() {
                    index += 2;
                    continue;
                }
                if bytes[index] == quote {
                    return Some(&trimmed[..=index]);
                }
                index += 1;
            }
            // Unclosed quote: treat the remainder as the token.
            Some(trimmed)
        }
        _ => {
            let end = trimmed
                .find(|character: char| character.is_ascii_whitespace())
                .unwrap_or(trimmed.len());
            Some(&trimmed[..end])
        }
    }
}

fn extract_echo_payload(command: &str) -> Option<&str> {
    let trimmed = command.trim();
    let rest = trimmed.strip_prefix("echo")?.trim_start();
    let rest = rest
        .strip_prefix("-n")
        .map(|value| value.trim_start())
        .unwrap_or(rest);
    if rest.is_empty() {
        None
    } else {
        Some(rest)
    }
}

/// Strip wrapping shell quotes and report whether the shell would expand the payload.
///
/// Single-quoted payloads are literals (`$` / backticks do not expand). Double-quoted
/// and unquoted payloads undergo shell expansion.
fn unwrap_echo_payload(value: &str) -> (&str, bool) {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if first == b'\'' && last == b'\'' {
            return (&value[1..value.len() - 1], false);
        }
        if first == b'"' && last == b'"' {
            return (&value[1..value.len() - 1], true);
        }
    }
    (value, true)
}

fn strip_wrapping_shell_quotes(value: &str) -> &str {
    unwrap_echo_payload(value).0
}

fn is_github_ident(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-')
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

/// Replace `context.name` tokens inside `${{ ... }}` regions only.
///
/// Literal YAML text such as `refs/heads/inputs.ref` is left untouched because
/// GitHub does not interpolate outside expression delimiters. Quoted expression
/// string literals such as `${{ 'inputs.ref' }}` are also left untouched —
/// GitHub treats those as literal branch names, not input references. When
/// `case_insensitive` is set, matching follows GitHub's `inputs` context;
/// otherwise the declared spelling must match (env).
fn replace_context_identifier(
    value: &str,
    context: &str,
    name: &str,
    replacement: &str,
    case_insensitive: bool,
) -> String {
    map_expression_regions(value, |inner| {
        replace_context_identifier_in_region(inner, context, name, replacement, case_insensitive)
    })
}

/// Apply `f` to each `${{ ... }}` inner region; copy surrounding text unchanged.
fn map_expression_regions(value: &str, mut transform: impl FnMut(&str) -> String) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(rel_start) = value[cursor..].find("${{") {
        let start = cursor + rel_start;
        output.push_str(&value[cursor..start]);
        let after_open = start + 3;
        let Some(rel_end) = find_expression_close(&value[after_open..]) else {
            output.push_str(&value[start..]);
            return output;
        };
        let end = after_open + rel_end;
        output.push_str("${{");
        output.push_str(&transform(&value[after_open..end]));
        output.push_str("}}");
        cursor = end + 2;
    }
    output.push_str(&value[cursor..]);
    output
}

/// Offset of the closing `}}` that terminates a `${{ ... }}` region, ignoring
/// `}}` that appear inside expression string literals (`'...'`, with `''`
/// escapes).
fn find_expression_close(after_open: &str) -> Option<usize> {
    let bytes = after_open.as_bytes();
    let mut index = 0;
    let mut quoted = false;
    while index + 1 < bytes.len() {
        let byte = bytes[index];
        if byte == b'\'' {
            if quoted && index + 1 < bytes.len() && bytes[index + 1] == b'\'' {
                index += 2;
                continue;
            }
            quoted = !quoted;
            index += 1;
            continue;
        }
        if !quoted && byte == b'}' && bytes[index + 1] == b'}' {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// Replace bare `{context}.{name}` tokens that are not part of a longer property
/// path (for example skip `github.event.inputs.ref`).
fn replace_context_identifier_in_region(
    value: &str,
    context: &str,
    name: &str,
    replacement: &str,
    case_insensitive: bool,
) -> String {
    let needle = if case_insensitive {
        format!(
            "{}.{}",
            context.to_ascii_lowercase(),
            name.to_ascii_lowercase()
        )
    } else {
        format!("{context}.{name}")
    };
    let haystack = if case_insensitive {
        value.to_ascii_lowercase()
    } else {
        value.to_string()
    };
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(rel) = haystack[cursor..].find(&needle) {
        let offset = cursor + rel;
        let end = offset + needle.len();
        if offset_inside_expression_string_literal(value, offset) {
            output.push_str(&value[cursor..end]);
            cursor = end;
            continue;
        }
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

/// True when `offset` falls inside a GitHub expression string literal (`'...'`).
///
/// Doubled quotes (`''`) are treated as an escaped literal quote, matching
/// GitHub's expression language and [`remove_expression_string_literals`].
fn offset_inside_expression_string_literal(value: &str, offset: usize) -> bool {
    let mut quoted = false;
    let mut index = 0;
    let bytes = value.as_bytes();
    while index < offset && index < bytes.len() {
        if bytes[index] != b'\'' {
            index += 1;
            continue;
        }
        if quoted && index + 1 < bytes.len() && bytes[index + 1] == b'\'' {
            index += 2;
            continue;
        }
        quoted = !quoted;
        index += 1;
    }
    quoted
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
        let Some(end) = find_expression_close(after_start) else {
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

fn has_untrusted_checkout_ref(
    step: &Hash,
    input_bindings: &InputBindings,
    env_bindings: &EnvBindings,
    step_outputs: &StepOutputBindings,
) -> bool {
    get(step, "with")
        .and_then(Yaml::as_hash)
        .and_then(|with| get_string(with, "ref"))
        .is_some_and(|revision| {
            let resolved =
                resolve_context_expressions(revision, input_bindings, env_bindings, step_outputs);
            is_untrusted_ref_expression(&resolved)
                || has_unresolved_step_output_ref(&resolved)
                || has_unresolved_needs_output_ref(&resolved)
                || has_unresolved_env_ref(&resolved)
                || has_unresolved_inputs_access(&resolved)
        })
}

fn is_untrusted_ref_expression(revision: &str) -> bool {
    let normalized = normalize_bracket_property_access(revision);
    contains_untrusted_github_ref_tokens(&normalized)
}

/// True when `revision` names an attacker-controlled GitHub event ref, including
/// computed forms such as `fromJSON(toJSON(github.event.pull_request)).head.sha`,
/// parent serialization
/// `fromJSON(toJSON(github.event)).pull_request.head.sha`, or whole-context
/// serialization `fromJSON(toJSON(github)).event.pull_request.head.sha` where
/// the classic contiguous dotted path is split by function calls.
fn contains_untrusted_github_ref_tokens(revision: &str) -> bool {
    let mut haystack = String::new();
    let _ = map_expression_regions(revision, |inner| {
        haystack.push_str(&remove_expression_string_literals(inner));
        haystack.push(' ');
        inner.to_string()
    });
    if haystack.chars().all(|character| character.is_whitespace()) {
        haystack = remove_expression_string_literals(revision);
    }
    // Contiguous dotted paths plus computed forms that reassemble
    // `github.event` → `pull_request` / `workflow_run` across `toJSON`/`fromJSON`,
    // including whole-context `toJSON(github)` followed by `.event…`.
    let has_github_event = haystack.contains("github.event")
        || (haystack.contains("toJSON(github)") && haystack.contains(".event"));
    let has_pr_head = haystack.contains(".head.sha")
        || haystack.contains(".head.ref")
        || haystack.contains(".head.repo")
        || haystack.contains(".merge_commit_sha");
    let has_workflow_run_head = haystack.contains(".head_sha")
        || haystack.contains(".head_branch")
        || haystack.contains(".head.sha")
        || haystack.contains(".head.ref");
    haystack.contains("github.event.pull_request.head.")
        || haystack.contains("github.event.pull_request.merge_commit_sha")
        || haystack.contains("github.event.workflow_run.head_sha")
        || haystack.contains("github.event.workflow_run.head_branch")
        || (has_github_event && haystack.contains("pull_request") && has_pr_head)
        || (has_github_event && haystack.contains("workflow_run") && has_workflow_run_head)
}

/// Fail closed when a checkout ref still names `steps.*.outputs.*` after
/// known `$GITHUB_OUTPUT` rewrites — incomplete step-output tracking must not
/// collapse into allow under a privileged trigger.
fn has_unresolved_step_output_ref(revision: &str) -> bool {
    static STEP_OUTPUT_REF: OnceLock<Regex> = OnceLock::new();
    let pattern = STEP_OUTPUT_REF.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"(?i)(?:^|[^A-Za-z0-9_.])steps\.[A-Za-z_][A-Za-z0-9_-]*\.outputs\.[A-Za-z_][A-Za-z0-9_-]*(?:$|[^A-Za-z0-9_-])")
            .expect("step output ref pattern compiles")
    });
    expression_matches_unresolved_context(revision, pattern)
}

/// Fail closed when a checkout ref still names `needs.*.outputs.*` after known
/// rewrites — cross-job outputs are not yet tracked into composite input
/// bindings and must not collapse into allow under a privileged trigger.
fn has_unresolved_needs_output_ref(revision: &str) -> bool {
    static NEEDS_OUTPUT_REF: OnceLock<Regex> = OnceLock::new();
    let pattern = NEEDS_OUTPUT_REF.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"(?i)(?:^|[^A-Za-z0-9_.])needs\.[A-Za-z_][A-Za-z0-9_-]*\.outputs\.[A-Za-z_][A-Za-z0-9_-]*(?:$|[^A-Za-z0-9_-])")
            .expect("needs output ref pattern compiles")
    });
    expression_matches_unresolved_context(revision, pattern)
}

/// Fail closed when a checkout ref still reaches the `env` context after known
/// env / `$GITHUB_ENV` rewrites — incomplete env tracking (`echo -e`, `printf`,
/// shell `$VAR` writes) and computed forms such as
/// `fromJSON(toJSON(env)).TARGET` must not collapse into allow under a
/// privileged trigger.
fn has_unresolved_env_ref(revision: &str) -> bool {
    static ENV_REF: OnceLock<Regex> = OnceLock::new();
    let pattern = ENV_REF.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"(?i)(?:^|[^A-Za-z0-9_.])env(?:$|[^A-Za-z0-9_-])")
            .expect("env ref pattern compiles")
    });
    expression_matches_unresolved_context(revision, pattern)
}

/// Fail closed when a checkout ref still reaches the composite `inputs` context
/// after known input rewrites — computed forms such as
/// `fromJSON(toJSON(inputs)).ref` are not rewritten by literal `inputs.<name>`
/// substitution and must not collapse into allow under a privileged trigger.
fn has_unresolved_inputs_access(revision: &str) -> bool {
    static INPUTS_ACCESS: OnceLock<Regex> = OnceLock::new();
    let pattern = INPUTS_ACCESS.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"(?i)(?:^|[^A-Za-z0-9_.])inputs(?:$|[^A-Za-z0-9_-])")
            .expect("inputs access pattern compiles")
    });
    expression_matches_unresolved_context(revision, pattern)
}

fn expression_matches_unresolved_context(revision: &str, pattern: &Regex) -> bool {
    let normalized = normalize_bracket_property_access(revision);
    let mut found = false;
    let _ = map_expression_regions(&normalized, |inner| {
        let cleaned = remove_expression_string_literals(inner);
        if pattern.is_match(&cleaned) {
            found = true;
        }
        inner.to_string()
    });
    found
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
    fn resolve_input_expressions_normalizes_bracket_github_paths_without_bindings() {
        let resolved = resolve_input_expressions(
            "${{ github['event']['pull_request']['head']['sha'] }}",
            &InputBindings::new(),
        );
        assert_eq!(resolved, "${{ github.event.pull_request.head.sha }}");
        assert!(is_untrusted_ref_expression(&resolved));
    }

    #[test]
    fn resolve_input_expressions_ignores_literal_inputs_outside_expressions() {
        let mut bindings = InputBindings::new();
        bindings.insert(
            "ref".to_string(),
            "${{ github.event.pull_request.head.sha }}".to_string(),
        );
        let resolved = resolve_input_expressions("refs/heads/inputs.ref", &bindings);
        assert_eq!(resolved, "refs/heads/inputs.ref");
        assert!(!is_untrusted_ref_expression(&resolved));
    }

    #[test]
    fn resolve_input_expressions_ignores_quoted_expression_literals() {
        let mut bindings = InputBindings::new();
        bindings.insert(
            "ref".to_string(),
            "${{ github.event.pull_request.head.sha }}".to_string(),
        );
        let resolved = resolve_input_expressions("${{ 'inputs.ref' }}", &bindings);
        assert_eq!(resolved, "${{ 'inputs.ref' }}");
        assert!(!is_untrusted_ref_expression(&resolved));
        let compound =
            resolve_input_expressions("${{ 'inputs.ref' || inputs.ref || github.sha }}", &bindings);
        assert!(
            compound.contains("'inputs.ref'"),
            "quoted literal must remain: {compound}"
        );
        assert!(
            compound.contains("github.event.pull_request.head.sha"),
            "unquoted inputs.ref must still resolve: {compound}"
        );
    }

    #[test]
    fn resolve_context_expressions_resolves_env_then_inputs_transitively() {
        let mut inputs = InputBindings::new();
        inputs.insert(
            "ref".to_string(),
            "${{ github.event.pull_request.head.sha }}".to_string(),
        );
        let mut env = EnvBindings::new();
        env.insert("TARGET".to_string(), "${{ inputs.ref }}".to_string());
        let resolved = resolve_context_expressions(
            "${{ env.TARGET }}",
            &inputs,
            &env,
            &StepOutputBindings::new(),
        );
        assert!(
            resolved.contains("github.event.pull_request.head.sha"),
            "env→inputs chain must resolve: {resolved}"
        );
        assert!(!resolved.contains("inputs.ref") && !resolved.contains("env.TARGET"));
        assert!(is_untrusted_ref_expression(&resolved));
    }

    #[test]
    fn resolve_context_expressions_resolves_step_output_from_github_output() {
        let mut inputs = InputBindings::new();
        inputs.insert(
            "ref".to_string(),
            "${{ github.event.pull_request.head.sha }}".to_string(),
        );
        let mut step_outputs = StepOutputBindings::new();
        step_outputs.insert("resolve.ref".to_string(), "${{ inputs.ref }}".to_string());
        let resolved = resolve_context_expressions(
            "${{ steps.resolve.outputs.ref }}",
            &inputs,
            &EnvBindings::new(),
            &step_outputs,
        );
        assert!(
            resolved.contains("github.event.pull_request.head.sha"),
            "step-output→inputs chain must resolve: {resolved}"
        );
        assert!(!resolved.contains("steps.resolve.outputs.ref"));
        assert!(is_untrusted_ref_expression(&resolved));
    }

    #[test]
    fn privileged_local_composite_step_output_taint_untrusted_checkout_blocks() {
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
    - id: resolve
      shell: bash
      run: echo "ref=${{ inputs.ref }}" >> "$GITHUB_OUTPUT"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn privileged_local_composite_unresolved_step_output_checkout_fails_closed() {
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
runs:
  using: composite
  steps:
    - id: resolve
      shell: bash
      run: |
        REF=$(git rev-parse HEAD)
        echo "ref=$REF" >> "$GITHUB_OUTPUT"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn value_contains_untracked_shell_expansion_detects_dollar_and_backtick() {
        assert!(value_contains_untracked_shell_expansion("$TARGET"));
        assert!(value_contains_untracked_shell_expansion(
            "`printenv TARGET`"
        ));
        assert!(value_contains_untracked_shell_expansion(
            "prefix`cmd`suffix"
        ));
        assert!(!value_contains_untracked_shell_expansion("main"));
        assert!(!value_contains_untracked_shell_expansion(
            "${{ inputs.ref }}"
        ));
    }

    #[test]
    fn collect_step_output_bindings_invalidates_untracked_overwrite() {
        let docs = YamlLoader::load_from_str(
            r#"
id: resolve
run: |
  echo "ref=main" >> "$GITHUB_OUTPUT"
  echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let collected = collect_step_output_bindings(
            step,
            &InputBindings::new(),
            &EnvBindings::new(),
            &StepOutputBindings::new(),
        );
        assert!(
            !collected.contains_key("resolve.ref"),
            "untracked overwrite must drop the earlier safe binding: {collected:?}"
        );
    }

    #[test]
    fn collect_step_output_bindings_treats_backtick_substitution_as_untracked() {
        let docs = YamlLoader::load_from_str(
            r#"
id: resolve
run: echo "ref=`printenv TARGET`" >> "$GITHUB_OUTPUT"
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let collected = collect_step_output_bindings(
            step,
            &InputBindings::new(),
            &EnvBindings::new(),
            &StepOutputBindings::new(),
        );
        assert!(
            !collected.contains_key("resolve.ref"),
            "backtick command substitution must leave the output unresolved: {collected:?}"
        );
    }

    #[test]
    fn collect_step_output_bindings_invalidates_untracked_overwrite_with_trailing_comment() {
        let docs = YamlLoader::load_from_str(
            r#"
id: resolve
run: |
  echo "ref=main" >> "$GITHUB_OUTPUT"
  echo "ref=$TARGET" >> "$GITHUB_OUTPUT" # final value
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let collected = collect_step_output_bindings(
            step,
            &InputBindings::new(),
            &EnvBindings::new(),
            &StepOutputBindings::new(),
        );
        assert!(
            !collected.contains_key("resolve.ref"),
            "trailing comment on redirect must not retain the earlier safe binding: {collected:?}"
        );
    }

    #[test]
    fn split_github_output_redirect_accepts_trailing_comment() {
        assert_eq!(
            split_github_file_redirect(
                r#"echo "ref=$TARGET" >> "$GITHUB_OUTPUT" # final value"#,
                "GITHUB_OUTPUT"
            ),
            Some(r#"echo "ref=$TARGET""#)
        );
        assert_eq!(
            split_github_file_redirect(
                r#"echo "ref=$TARGET" >> "$GITHUB_OUTPUT" && true"#,
                "GITHUB_OUTPUT"
            ),
            Some(r#"echo "ref=$TARGET""#)
        );
    }

    #[test]
    fn split_github_env_redirect_accepts_powershell_env_syntax() {
        assert_eq!(
            split_github_file_redirect(
                r#"echo "TARGET=$env:EVIL" >> $env:GITHUB_ENV"#,
                "GITHUB_ENV"
            ),
            Some(r#"echo "TARGET=$env:EVIL""#)
        );
        assert_eq!(
            split_github_file_redirect(r#""TARGET=$env:EVIL" >> $Env:GITHUB_ENV"#, "GITHUB_ENV"),
            Some(r#""TARGET=$env:EVIL""#)
        );
        assert!(segment_references_github_file(
            r#"Add-Content -Path $env:GITHUB_ENV -Value "TARGET=$env:EVIL""#,
            "GITHUB_ENV"
        ));
    }

    #[test]
    fn privileged_local_composite_step_output_untracked_overwrite_fails_closed() {
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
    - id: resolve
      shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: |
        echo "ref=main" >> "$GITHUB_OUTPUT"
        echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn privileged_local_composite_step_output_backtick_substitution_fails_closed() {
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
    - id: resolve
      shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: echo "ref=`printenv TARGET`" >> "$GITHUB_OUTPUT"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn privileged_local_composite_step_output_trailing_comment_overwrite_fails_closed() {
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
    - id: resolve
      shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: |
        echo "ref=main" >> "$GITHUB_OUTPUT"
        echo "ref=$TARGET" >> "$GITHUB_OUTPUT" # final value
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn collect_step_output_bindings_preserves_single_quoted_literal_payload() {
        let docs = YamlLoader::load_from_str(
            r#"
id: resolve
run: echo 'ref=$TARGET' >> "$GITHUB_OUTPUT"
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let collected = collect_step_output_bindings(
            step,
            &InputBindings::new(),
            &EnvBindings::new(),
            &StepOutputBindings::new(),
        );
        assert_eq!(
            collected.get("resolve.ref").map(String::as_str),
            Some("$TARGET"),
            "single-quoted payload must keep the literal value: {collected:?}"
        );
    }

    #[test]
    fn privileged_local_composite_single_quoted_github_output_is_not_untracked() {
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
    - id: resolve
      shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: echo 'ref=$TARGET' >> "$GITHUB_OUTPUT"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id != RULE_UNTRUSTED_CHECKOUT),
            "literal single-quoted `$TARGET` must not be over-classified as untracked: {findings:?}"
        );
    }

    #[test]
    fn apply_github_env_writes_tracks_input_taint() {
        let docs = YamlLoader::load_from_str(
            r#"
run: echo "TARGET=${{ inputs.ref }}" >> "$GITHUB_ENV"
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let mut inputs = InputBindings::new();
        inputs.insert(
            "ref".to_string(),
            "${{ github.event.pull_request.head.sha }}".to_string(),
        );
        let mut env_bindings = EnvBindings::new();
        let (written, cleared) = apply_github_env_writes(
            step,
            &inputs,
            &EnvBindings::new(),
            &StepOutputBindings::new(),
            &mut env_bindings,
        );
        assert!(!cleared);
        assert!(written.contains("TARGET"));
        assert!(
            env_bindings
                .get("TARGET")
                .is_some_and(|value| value.contains("github.event.pull_request.head.sha")),
            "GITHUB_ENV write must resolve input taint: {env_bindings:?}"
        );
    }

    #[test]
    fn privileged_local_composite_github_env_taint_untrusted_checkout_blocks() {
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
    - shell: bash
      run: echo "TARGET=${{ inputs.ref }}" >> "$GITHUB_ENV"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ env.TARGET }}
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
    fn privileged_local_composite_unresolved_github_env_shell_var_fails_closed() {
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
    - shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: echo "TARGET=$TARGET" >> "$GITHUB_ENV"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ env.TARGET }}
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
    fn privileged_local_composite_unresolved_github_env_echo_e_fails_closed() {
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
    - shell: bash
      run: echo -e "TARGET=${{ inputs.ref }}" >> "$GITHUB_ENV"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ env.TARGET }}
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
    fn privileged_local_composite_unresolved_github_env_printf_fails_closed() {
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
    - shell: bash
      run: printf 'TARGET=%s\n' "${{ inputs.ref }}" >> "$GITHUB_ENV"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ env.TARGET }}
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
    fn privileged_local_composite_computed_inputs_access_fails_closed() {
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
        ref: ${{ fromJSON(toJSON(inputs)).ref }}
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
    fn privileged_local_composite_computed_env_access_fails_closed() {
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
      env:
        TARGET: ${{ inputs.ref }}
      with:
        ref: ${{ fromJSON(toJSON(env)).TARGET }}
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
    fn privileged_local_composite_opaque_github_env_invalidates_inherited_binding() {
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
    - shell: bash
      run: echo "TARGET=main" >> "$GITHUB_ENV"
    - shell: bash
      env:
        EVIL: ${{ inputs.ref }}
      run: printf '%s=%s\n' TARGET "$EVIL" >> "$GITHUB_ENV"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ env.TARGET }}
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
    fn privileged_local_composite_powershell_env_overwrite_fails_closed() {
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
    - shell: bash
      run: echo "TARGET=main" >> "$GITHUB_ENV"
    - shell: pwsh
      env:
        EVIL: ${{ inputs.ref }}
      run: '"TARGET=$env:EVIL" >> $env:GITHUB_ENV'
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ env.TARGET }}
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
    fn collect_step_output_bindings_invalidates_boolean_control_flow_writes() {
        let docs = YamlLoader::load_from_str(
            r#"
id: resolve
run: |
  true && echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
  false && echo "ref=main" >> "$GITHUB_OUTPUT"
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let collected = collect_step_output_bindings(
            step,
            &InputBindings::new(),
            &EnvBindings::new(),
            &StepOutputBindings::new(),
        );
        assert!(
            !collected.contains_key("resolve.ref"),
            "boolean control-flow writes must leave the output unresolved: {collected:?}"
        );
    }

    #[test]
    fn privileged_local_composite_boolean_control_flow_step_output_fails_closed() {
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
    - id: resolve
      shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: |
        true && echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
        false && echo "ref=main" >> "$GITHUB_OUTPUT"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn collect_step_output_bindings_processes_semicolon_multi_redirect_line() {
        let docs = YamlLoader::load_from_str(
            r#"
id: resolve
run: echo "ref=main" >> "$GITHUB_OUTPUT"; echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let collected = collect_step_output_bindings(
            step,
            &InputBindings::new(),
            &EnvBindings::new(),
            &StepOutputBindings::new(),
        );
        assert!(
            !collected.contains_key("resolve.ref"),
            "semicolon multi-redirect must not retain the earlier safe binding: {collected:?}"
        );
    }

    #[test]
    fn privileged_local_composite_semicolon_multi_redirect_fails_closed() {
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
    - id: resolve
      shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: echo "ref=main" >> "$GITHUB_OUTPUT"; echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn collect_step_output_bindings_invalidates_branch_dependent_writes() {
        let docs = YamlLoader::load_from_str(
            r#"
id: resolve
run: |
  if true; then
    echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
  else
    echo "ref=main" >> "$GITHUB_OUTPUT"
  fi
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let collected = collect_step_output_bindings(
            step,
            &InputBindings::new(),
            &EnvBindings::new(),
            &StepOutputBindings::new(),
        );
        assert!(
            !collected.contains_key("resolve.ref"),
            "branch-dependent writes must leave the output unresolved: {collected:?}"
        );
    }

    #[test]
    fn privileged_local_composite_branch_dependent_step_output_fails_closed() {
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
    - id: resolve
      shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: |
        if true; then
          echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
        else
          echo "ref=main" >> "$GITHUB_OUTPUT"
        fi
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn collect_step_output_bindings_invalidates_unparsed_printf_overwrite() {
        let docs = YamlLoader::load_from_str(
            r#"
id: resolve
run: |
  echo "ref=main" >> "$GITHUB_OUTPUT"
  printf 'ref=%s\n' "$TARGET" >> "$GITHUB_OUTPUT"
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let collected = collect_step_output_bindings(
            step,
            &InputBindings::new(),
            &EnvBindings::new(),
            &StepOutputBindings::new(),
        );
        assert!(
            !collected.contains_key("resolve.ref"),
            "unparsed printf overwrite must drop the earlier safe binding: {collected:?}"
        );
    }

    #[test]
    fn collect_step_output_bindings_invalidates_tee_overwrite() {
        let docs = YamlLoader::load_from_str(
            r#"
id: resolve
run: |
  echo "ref=main" >> "$GITHUB_OUTPUT"
  printf 'ref=%s\n' "$TARGET" | tee -a "$GITHUB_OUTPUT"
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let collected = collect_step_output_bindings(
            step,
            &InputBindings::new(),
            &EnvBindings::new(),
            &StepOutputBindings::new(),
        );
        assert!(
            !collected.contains_key("resolve.ref"),
            "non-redirect tee overwrite must drop the earlier safe binding: {collected:?}"
        );
    }

    #[test]
    fn privileged_local_composite_tee_github_output_overwrite_fails_closed() {
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
    - id: resolve
      shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: |
        echo "ref=main" >> "$GITHUB_OUTPUT"
        printf 'ref=%s\n' "$TARGET" | tee -a "$GITHUB_OUTPUT"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn privileged_local_composite_unparsed_printf_output_overwrite_fails_closed() {
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
    - id: resolve
      shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: |
        echo "ref=main" >> "$GITHUB_OUTPUT"
        printf 'ref=%s\n' "$TARGET" >> "$GITHUB_OUTPUT"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn privileged_local_composite_computed_github_event_access_fails_closed() {
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
runs:
  using: composite
  steps:
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ fromJSON(toJSON(github.event.pull_request)).head.sha }}
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
    fn privileged_local_composite_computed_github_event_parent_serialization_fails_closed() {
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
runs:
  using: composite
  steps:
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ fromJSON(toJSON(github.event)).pull_request.head.sha }}
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
    fn privileged_local_composite_computed_github_whole_context_serialization_fails_closed() {
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
runs:
  using: composite
  steps:
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ fromJSON(toJSON(github)).event.pull_request.head.sha }}
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
    fn map_expression_regions_ignores_quoted_expression_terminators() {
        let rewritten = replace_context_identifier(
            "${{ false && '}}' || inputs.ref }}",
            "inputs",
            "ref",
            "github.event.pull_request.head.sha",
            true,
        );
        assert_eq!(
            rewritten, "${{ false && '}}' || github.event.pull_request.head.sha }}",
            "quoted braces must not truncate the expression region: {rewritten}"
        );
    }

    #[test]
    fn privileged_local_composite_quoted_expression_terminator_input_taint_blocks() {
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
        ref: ${{ false && '}}' || inputs.ref }}
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
    fn privileged_local_composite_bracket_github_context_untrusted_checkout_blocks() {
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
runs:
  using: composite
  steps:
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ github['event']['pull_request']['head']['sha'] }}
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
    fn privileged_local_composite_env_alias_taint_untrusted_checkout_blocks() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
env:
  PR_REF: ${{ github.event.pull_request.head.sha }}
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
        with:
          ref: ${{ env.PR_REF }}
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
    fn privileged_local_composite_literal_inputs_path_is_not_tainted() {
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
        ref: refs/heads/inputs.ref
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != RULE_UNTRUSTED_CHECKOUT));
    }

    #[test]
    fn privileged_local_composite_step_env_alias_of_input_untrusted_checkout_blocks() {
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
      env:
        TARGET: ${{ inputs.ref }}
      with:
        ref: ${{ env.TARGET }}
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
    fn privileged_local_composite_quoted_inputs_literal_is_not_tainted() {
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
        ref: ${{ 'inputs.ref' }}
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ]);

        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != RULE_UNTRUSTED_CHECKOUT));
    }

    #[test]
    fn privileged_workflow_composite_github_env_propagates_to_caller_checkout() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    env:
      TARGET: main
    steps:
      - uses: ./.github/actions/export-ref
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
        with:
          ref: ${{ env.TARGET }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/export-ref/action.yml".to_string(),
                content: r#"
name: export-ref
inputs:
  ref:
    required: true
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "TARGET=${{ inputs.ref }}" >> "$GITHUB_ENV"
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
    fn privileged_local_composite_skipped_step_env_write_is_ignored() {
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
    - shell: bash
      run: echo "TARGET=${{ inputs.ref }}" >> "$GITHUB_ENV"
    - if: ${{ false }}
      shell: bash
      run: echo "TARGET=main" >> "$GITHUB_ENV"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ env.TARGET }}
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
    fn privileged_workflow_composite_github_env_propagates_matching_step_env() {
        // Invoking step overrides TARGET with attacker-controlled taint; composite
        // persists that same value via `$GITHUB_ENV`. Propagation must not drop
        // the write just because it equals the transient step env.
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    env:
      TARGET: main
    steps:
      - uses: ./.github/actions/export-ref
        env:
          TARGET: ${{ github.event.pull_request.head.sha }}
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
        with:
          ref: ${{ env.TARGET }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/export-ref/action.yml".to_string(),
                content: r#"
name: export-ref
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "TARGET=${{ env.TARGET }}" >> "$GITHUB_ENV"
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
    fn privileged_local_composite_uncertain_false_condition_env_write_is_invalidated() {
        // `${{ false && true }}` is not the literal `false`, so the step must not
        // confidently overwrite attacker-controlled TARGET with `main`.
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
    - shell: bash
      run: echo "TARGET=${{ inputs.ref }}" >> "$GITHUB_ENV"
    - if: ${{ false && true }}
      shell: bash
      run: echo "TARGET=main" >> "$GITHUB_ENV"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ env.TARGET }}
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
    fn is_github_file_redirect_target_accepts_braced_parameter_expansions() {
        assert!(is_github_file_redirect_target(
            "${GITHUB_ENV:?missing}",
            "GITHUB_ENV"
        ));
        assert!(is_github_file_redirect_target(
            "${GITHUB_ENV:-$fallback}",
            "GITHUB_ENV"
        ));
        assert!(is_github_file_redirect_target(
            "${GITHUB_ENV}",
            "GITHUB_ENV"
        ));
        assert!(segment_references_github_file(
            r#"echo "TARGET=$EVIL" >> "${GITHUB_ENV:?missing}""#,
            "GITHUB_ENV"
        ));
        assert_eq!(
            split_github_file_redirect(
                r#"echo "TARGET=$EVIL" >> "${GITHUB_ENV:?missing}""#,
                "GITHUB_ENV"
            ),
            Some(r#"echo "TARGET=$EVIL""#)
        );
    }

    #[test]
    fn privileged_local_composite_braced_github_env_overwrite_fails_closed() {
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
    - shell: bash
      run: echo "TARGET=main" >> "$GITHUB_ENV"
    - shell: bash
      env:
        EVIL: ${{ inputs.ref }}
      run: echo "TARGET=$EVIL" >> "${GITHUB_ENV:?missing}"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ env.TARGET }}
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
    fn collect_step_output_bindings_processes_boolean_multi_redirect_line() {
        let docs = YamlLoader::load_from_str(
            r#"
id: resolve
run: echo "ref=main" >> "$GITHUB_OUTPUT" && echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
"#,
        )
        .expect("parse step");
        let step = docs[0].as_hash().expect("step mapping");
        let collected = collect_step_output_bindings(
            step,
            &InputBindings::new(),
            &EnvBindings::new(),
            &StepOutputBindings::new(),
        );
        assert!(
            !collected.contains_key("resolve.ref"),
            "boolean multi-redirect must not retain the earlier safe binding: {collected:?}"
        );
    }

    #[test]
    fn privileged_local_composite_boolean_multi_redirect_fails_closed() {
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
    - id: resolve
      shell: bash
      env:
        TARGET: ${{ inputs.ref }}
      run: echo "ref=main" >> "$GITHUB_OUTPUT" && echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ steps.resolve.outputs.ref }}
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
    fn privileged_local_composite_unresolved_needs_output_checkout_fails_closed() {
        let findings = findings_for_files(&[
            SurfaceFile {
                rel: ".github/workflows/triage.yml".to_string(),
                content: r#"
name: Triage
on: pull_request_target
jobs:
  prepare:
    runs-on: ubuntu-latest
    outputs:
      ref: ${{ steps.export.outputs.ref }}
    steps:
      - id: export
        env:
          TARGET: ${{ github.event.pull_request.head.sha }}
        run: echo "ref=$TARGET" >> "$GITHUB_OUTPUT"
  run:
    needs: prepare
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
        with:
          ref: ${{ needs.prepare.outputs.ref }}
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
