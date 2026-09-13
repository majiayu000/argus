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
    /// Named secrets bound by a reusable-workflow caller via `secrets:`.
    /// Composite actions have no `secrets` context, so this stays empty there.
    secrets: &'a HashSet<String>,
    /// Prior-step `$GITHUB_OUTPUT` writes keyed as `{step_id}.{output_name}`.
    step_outputs: &'a HashSet<String>,
    /// Peer-job `outputs:` values keyed as `{job_id}.{output_name}` for
    /// `needs.<job>.outputs.<name>` reads.
    job_outputs: &'a HashSet<String>,
}

pub(super) fn run(files: &[SurfaceFile], findings: &mut Vec<Finding>) -> Result<()> {
    let actions: HashMap<&str, &SurfaceFile> = files
        .iter()
        .filter(|file| file.kind == SurfaceKind::ActionMetadata)
        .map(|file| (file.rel.as_str(), file))
        .collect();
    let workflows: HashMap<&str, &SurfaceFile> = files
        .iter()
        .filter(|file| file.kind == SurfaceKind::Workflow)
        .map(|file| (file.rel.as_str(), file))
        .collect();
    let empty = HashSet::new();
    for file in files {
        match file.kind {
            SurfaceKind::Workflow => {
                let mut visiting = HashSet::new();
                scan_workflow(
                    file,
                    TaintScope {
                        envs: &empty,
                        inputs: &empty,
                        secrets: &empty,
                        step_outputs: &empty,
                        job_outputs: &empty,
                    },
                    &actions,
                    &workflows,
                    &mut visiting,
                    findings,
                )
                .with_context(|| format!("assess GitHub Actions workflow `{}`", file.rel))?;
            }
            SurfaceKind::ActionMetadata => {
                let mut visiting = HashSet::new();
                scan_action_metadata(
                    file,
                    TaintScope {
                        envs: &empty,
                        inputs: &empty,
                        secrets: &empty,
                        step_outputs: &empty,
                        job_outputs: &empty,
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
    caller_taint: TaintScope<'_>,
    actions: &HashMap<&str, &SurfaceFile>,
    workflows: &HashMap<&str, &SurfaceFile>,
    visiting: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    if !visiting.insert(file.rel.clone()) {
        return Ok(());
    }
    let result = scan_workflow_inner(file, caller_taint, actions, workflows, visiting, findings);
    visiting.remove(&file.rel);
    result
}

fn scan_workflow_inner(
    file: &SurfaceFile,
    caller_taint: TaintScope<'_>,
    actions: &HashMap<&str, &SurfaceFile>,
    workflows: &HashMap<&str, &SurfaceFile>,
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

    let empty_outputs = HashSet::new();
    let mut workflow_tainted_envs = HashSet::new();
    if let Some(env) = get(root, "env").and_then(Yaml::as_hash) {
        apply_env_taints(
            &mut workflow_tainted_envs,
            env,
            TaintScope {
                envs: &empty_outputs,
                inputs: caller_taint.inputs,
                secrets: caller_taint.secrets,
                step_outputs: &empty_outputs,
                job_outputs: &empty_outputs,
            },
            &file.rel,
        )?;
    }

    let Some(jobs) = get(root, "jobs").and_then(Yaml::as_hash) else {
        return Ok(());
    };

    // Collect job-output taint before scanning so `needs.*.outputs` is available
    // regardless of YAML job order.
    let mut tainted_job_outputs = HashSet::new();
    for (job_key, job_yaml) in jobs {
        let Some(job_id) = job_key.as_str() else {
            continue;
        };
        let Some(job) = job_yaml.as_hash() else {
            continue;
        };
        if get_string(job, "uses").is_some() {
            continue;
        }
        let Some(steps) = get(job, "steps").and_then(Yaml::as_vec) else {
            continue;
        };
        let mut job_tainted_envs = workflow_tainted_envs.clone();
        if let Some(env) = get(job, "env").and_then(Yaml::as_hash) {
            apply_env_taints(
                &mut job_tainted_envs,
                env,
                TaintScope {
                    envs: &empty_outputs,
                    inputs: caller_taint.inputs,
                    secrets: caller_taint.secrets,
                    step_outputs: &empty_outputs,
                    job_outputs: &tainted_job_outputs,
                },
                &file.rel,
            )?;
        }
        let mut tainted_step_outputs = HashSet::new();
        for step in steps.iter().filter_map(Yaml::as_hash) {
            let mut step_tainted_envs = job_tainted_envs.clone();
            if let Some(env) = get(step, "env").and_then(Yaml::as_hash) {
                apply_env_taints(
                    &mut step_tainted_envs,
                    env,
                    TaintScope {
                        envs: &empty_outputs,
                        inputs: caller_taint.inputs,
                        secrets: caller_taint.secrets,
                        step_outputs: &tainted_step_outputs,
                        job_outputs: &tainted_job_outputs,
                    },
                    &file.rel,
                )?;
            }
            let added = {
                let step_scope = TaintScope {
                    envs: &step_tainted_envs,
                    inputs: caller_taint.inputs,
                    secrets: caller_taint.secrets,
                    step_outputs: &tainted_step_outputs,
                    job_outputs: &tainted_job_outputs,
                };
                collect_tainted_github_outputs(step, step_scope, &file.rel)?
            };
            tainted_step_outputs.extend(added);
        }
        let added = {
            let job_scope = TaintScope {
                envs: &job_tainted_envs,
                inputs: caller_taint.inputs,
                secrets: caller_taint.secrets,
                step_outputs: &tainted_step_outputs,
                job_outputs: &tainted_job_outputs,
            };
            collect_tainted_job_outputs(job, job_id, job_scope, &file.rel)?
        };
        tainted_job_outputs.extend(added);
    }

    for job in jobs.values().filter_map(Yaml::as_hash) {
        check_permissions(job, "job", privileged_trigger, &file.rel, findings);
        let mut job_tainted_envs = workflow_tainted_envs.clone();
        if let Some(env) = get(job, "env").and_then(Yaml::as_hash) {
            apply_env_taints(
                &mut job_tainted_envs,
                env,
                TaintScope {
                    envs: &empty_outputs,
                    inputs: caller_taint.inputs,
                    secrets: caller_taint.secrets,
                    step_outputs: &empty_outputs,
                    job_outputs: &tainted_job_outputs,
                },
                &file.rel,
            )?;
        }
        if let Some(action) = get_string(job, "uses") {
            check_action_ref(action, &file.rel, findings);
            // Local reusable workflows receive caller `with:` as `inputs.*` and
            // caller `secrets:` as `secrets.*`. They do not inherit the caller's
            // environment across the workflow boundary.
            if let Some(local) = action.strip_prefix("./") {
                if let Some(workflow_file) = resolve_local_workflow(local, workflows) {
                    let job_scope = TaintScope {
                        envs: &job_tainted_envs,
                        inputs: caller_taint.inputs,
                        secrets: caller_taint.secrets,
                        step_outputs: &empty_outputs,
                        job_outputs: &tainted_job_outputs,
                    };
                    let job_tainted_inputs =
                        collect_tainted_with_inputs(job, job_scope, &file.rel)?;
                    let job_tainted_secrets = collect_tainted_secrets(job, job_scope, &file.rel)?;
                    let empty_envs = HashSet::new();
                    scan_workflow(
                        workflow_file,
                        TaintScope {
                            envs: &empty_envs,
                            inputs: &job_tainted_inputs,
                            secrets: &job_tainted_secrets,
                            step_outputs: &empty_outputs,
                            job_outputs: &empty_outputs,
                        },
                        actions,
                        workflows,
                        visiting,
                        findings,
                    )?;
                }
            }
        }
        let Some(steps) = get(job, "steps").and_then(Yaml::as_vec) else {
            continue;
        };
        let mut tainted_step_outputs = HashSet::new();
        for step in steps.iter().filter_map(Yaml::as_hash) {
            let mut step_tainted_envs = job_tainted_envs.clone();
            if let Some(env) = get(step, "env").and_then(Yaml::as_hash) {
                apply_env_taints(
                    &mut step_tainted_envs,
                    env,
                    TaintScope {
                        envs: &empty_outputs,
                        inputs: caller_taint.inputs,
                        secrets: caller_taint.secrets,
                        step_outputs: &tainted_step_outputs,
                        job_outputs: &tainted_job_outputs,
                    },
                    &file.rel,
                )?;
            }
            let added = {
                let step_scope = TaintScope {
                    envs: &step_tainted_envs,
                    inputs: caller_taint.inputs,
                    secrets: caller_taint.secrets,
                    step_outputs: &tainted_step_outputs,
                    job_outputs: &tainted_job_outputs,
                };
                scan_step(
                    step,
                    &file.rel,
                    privileged_trigger,
                    step_scope,
                    actions,
                    visiting,
                    findings,
                )?;
                collect_tainted_github_outputs(step, step_scope, &file.rel)?
            };
            tainted_step_outputs.extend(added);
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
    // Composite actions have no `secrets` context; only env + inputs apply.
    let empty_secrets = HashSet::new();
    let empty_outputs = HashSet::new();
    let mut tainted_step_outputs = HashSet::new();
    for step in steps.iter().filter_map(Yaml::as_hash) {
        // Caller env remains visible inside local composite steps at runtime.
        let mut step_tainted_envs = caller_taint.envs.clone();
        if let Some(env) = get(step, "env").and_then(Yaml::as_hash) {
            apply_env_taints(
                &mut step_tainted_envs,
                env,
                TaintScope {
                    envs: &empty_outputs,
                    inputs: caller_taint.inputs,
                    secrets: &empty_secrets,
                    step_outputs: &tainted_step_outputs,
                    job_outputs: &empty_outputs,
                },
                &file.rel,
            )?;
        }
        let added = {
            let step_scope = TaintScope {
                envs: &step_tainted_envs,
                inputs: caller_taint.inputs,
                secrets: &empty_secrets,
                step_outputs: &tainted_step_outputs,
                job_outputs: &empty_outputs,
            };
            scan_step(
                step, &file.rel, false, step_scope, actions, visiting, findings,
            )?;
            collect_tainted_github_outputs(step, step_scope, &file.rel)?
        };
        tainted_step_outputs.extend(added);
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
                let empty_secrets = HashSet::new();
                let empty_outputs = HashSet::new();
                scan_action_metadata(
                    action_file,
                    TaintScope {
                        envs: taint.envs,
                        inputs: &step_tainted_inputs,
                        // Composites cannot read the caller's `secrets` context.
                        secrets: &empty_secrets,
                        // Nested composites start with a fresh step-output scope.
                        step_outputs: &empty_outputs,
                        job_outputs: &empty_outputs,
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
    let path = normalize_local_ref(local_ref);
    // `uses: ./` and filesystem-equivalent forms such as `uses: ././` resolve to
    // the repository-root action metadata. An empty path must look up
    // `action.yml` directly; joining would invent `/action.yml`.
    if path.is_empty() {
        for name in ["action.yml", "action.yaml"] {
            if let Some(file) = actions.get(name) {
                return Some(*file);
            }
        }
        return None;
    }
    if let Some(file) = actions.get(path.as_str()) {
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

fn resolve_local_workflow<'a>(
    local_ref: &str,
    workflows: &HashMap<&str, &'a SurfaceFile>,
) -> Option<&'a SurfaceFile> {
    let path = normalize_local_ref(local_ref);
    if path.is_empty() {
        return None;
    }
    workflows.get(path.as_str()).copied()
}

/// Collapse `.` / `..` segments and trailing slashes so local `uses:` refs match
/// collected surface keys the way the filesystem would resolve them.
fn normalize_local_ref(local_ref: &str) -> String {
    let trimmed = local_ref.trim_end_matches('/');
    let mut parts: Vec<&str> = Vec::new();
    for component in trimmed.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                let _ = parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

fn collect_tainted_with_inputs(
    binding: &Hash,
    taint: TaintScope<'_>,
    rel: &str,
) -> Result<HashSet<String>> {
    let mut tainted = HashSet::new();
    let Some(with_map) = get(binding, "with").and_then(Yaml::as_hash) else {
        return Ok(tainted);
    };
    for (key, value) in with_map {
        let Some(name) = key.as_str() else {
            continue;
        };
        let Some(value) = value.as_str() else {
            continue;
        };
        // Caller `with:` bindings are evaluated before the composite or
        // reusable workflow runs, so a tainted env, tainted input forwarded
        // from a parent, tainted secret, tainted step/job output, or a direct
        // untrusted context becomes a tainted input for the callee.
        if value_carries_taint(value, taint, rel)? {
            tainted.insert(name.to_string());
        }
    }
    Ok(tainted)
}

/// Collect secrets bound by a reusable-workflow caller that carry untrusted
/// values. `secrets: inherit` forwards every already-tainted secret name.
fn collect_tainted_secrets(
    binding: &Hash,
    taint: TaintScope<'_>,
    rel: &str,
) -> Result<HashSet<String>> {
    let mut tainted = HashSet::new();
    let Some(secrets_node) = get(binding, "secrets") else {
        return Ok(tainted);
    };
    if secrets_node
        .as_str()
        .is_some_and(|value| value.eq_ignore_ascii_case("inherit"))
    {
        return Ok(taint.secrets.iter().cloned().collect());
    }
    let Some(secrets_map) = secrets_node.as_hash() else {
        return Ok(tainted);
    };
    for (key, value) in secrets_map {
        let Some(name) = key.as_str() else {
            continue;
        };
        let Some(value) = value.as_str() else {
            continue;
        };
        if value_carries_taint(value, taint, rel)? {
            tainted.insert(name.to_string());
        }
    }
    Ok(tainted)
}

fn apply_env_taints(
    tainted: &mut HashSet<String>,
    env: &Hash,
    parent: TaintScope<'_>,
    rel: &str,
) -> Result<()> {
    // GitHub Actions resolves each map entry against the parent scope, not
    // sibling keys in the same map. Snapshot the inherited set before applying
    // overrides so an earlier TITLE: fixed cannot clear taint for a later
    // ALIAS: ${{ env.TITLE }} that still reads the parent value.
    let inherited = tainted.clone();
    let scope = TaintScope {
        envs: &inherited,
        inputs: parent.inputs,
        secrets: parent.secrets,
        step_outputs: parent.step_outputs,
        job_outputs: parent.job_outputs,
    };
    let mut updates = Vec::new();
    for (key, value) in env {
        let Some(name) = key.as_str() else {
            continue;
        };
        match value {
            Yaml::String(value) => {
                // Inherit taint from direct untrusted contexts, tainted env
                // aliases, composite/reusable `inputs.*`, reusable `secrets.*`,
                // and step/job outputs when those are in scope.
                let is_tainted = value_carries_taint(value, scope, rel)?;
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

fn value_carries_taint(value: &str, taint: TaintScope<'_>, rel: &str) -> Result<bool> {
    Ok(value_contains_untrusted_context(value, rel)?
        || value_references_tainted_env(value, taint.envs, rel)?
        || value_references_tainted_input(value, taint.inputs, rel)?
        || value_references_tainted_secret(value, taint.secrets, rel)?
        || value_references_tainted_step_output(value, taint.step_outputs, rel)?
        || value_references_tainted_job_output(value, taint.job_outputs, rel)?)
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

fn value_references_tainted_secret(
    value: &str,
    tainted: &HashSet<String>,
    rel: &str,
) -> Result<bool> {
    for_each_expression(value, rel, |expression| {
        Ok(expression_uses_tainted_secret(expression, tainted))
    })
}

fn value_references_tainted_step_output(
    value: &str,
    tainted: &HashSet<String>,
    rel: &str,
) -> Result<bool> {
    for_each_expression(value, rel, |expression| {
        Ok(expression_uses_tainted_step_output(expression, tainted))
    })
}

fn value_references_tainted_job_output(
    value: &str,
    tainted: &HashSet<String>,
    rel: &str,
) -> Result<bool> {
    for_each_expression(value, rel, |expression| {
        Ok(expression_uses_tainted_job_output(expression, tainted))
    })
}

/// Collect tainted `{step_id}.{output}` keys written via `$GITHUB_OUTPUT`.
fn collect_tainted_github_outputs(
    step: &Hash,
    taint: TaintScope<'_>,
    rel: &str,
) -> Result<HashSet<String>> {
    let mut tainted = HashSet::new();
    let Some(step_id) = get_string(step, "id") else {
        return Ok(tainted);
    };
    if !is_github_ident(step_id) {
        return Ok(tainted);
    }
    let Some(script) = get_string(step, "run") else {
        return Ok(tainted);
    };
    for (name, raw_value) in parse_github_output_writes(script) {
        if github_output_value_is_tainted(&raw_value, taint, rel)? {
            tainted.insert(format!("{step_id}.{name}"));
        }
    }
    Ok(tainted)
}

fn github_output_value_is_tainted(value: &str, taint: TaintScope<'_>, rel: &str) -> Result<bool> {
    if value_carries_taint(value, taint, rel)? {
        return Ok(true);
    }
    // Safe remediation writes (`echo "title=$TITLE" >> $GITHUB_OUTPUT`) still
    // propagate attacker-controlled env values into step outputs.
    Ok(value_references_tainted_shell_env(value, taint.envs))
}

/// Collect tainted `{job_id}.{output}` keys from a job's `outputs:` map.
fn collect_tainted_job_outputs(
    job: &Hash,
    job_id: &str,
    taint: TaintScope<'_>,
    rel: &str,
) -> Result<HashSet<String>> {
    let mut tainted = HashSet::new();
    let Some(outputs) = get(job, "outputs").and_then(Yaml::as_hash) else {
        return Ok(tainted);
    };
    for (key, value) in outputs {
        let Some(name) = key.as_str() else {
            continue;
        };
        let Some(value) = value.as_str() else {
            continue;
        };
        if value_carries_taint(value, taint, rel)? {
            tainted.insert(format!("{job_id}.{name}"));
        }
    }
    Ok(tainted)
}

/// Parse simple `echo[ -n] "name=value" >> $GITHUB_OUTPUT` lines from a script.
fn parse_github_output_writes(script: &str) -> Vec<(String, String)> {
    let mut writes = Vec::new();
    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(command) = split_github_output_redirect(trimmed) else {
            continue;
        };
        let Some(payload) = extract_echo_payload(command) else {
            continue;
        };
        let payload = strip_wrapping_shell_quotes(payload.trim());
        let Some((name, value)) = payload.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !is_github_ident(name) {
            continue;
        }
        writes.push((name.to_string(), value.trim().to_string()));
    }
    writes
}

fn split_github_output_redirect(line: &str) -> Option<&str> {
    let index = line.find(">>")?;
    let (before, after) = line.split_at(index);
    let after = after.trim_start_matches('>').trim();
    let target = strip_wrapping_shell_quotes(after).trim();
    if target == "$GITHUB_OUTPUT" || target == "${GITHUB_OUTPUT}" {
        Some(before.trim())
    } else {
        None
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

fn strip_wrapping_shell_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' || first == b'\'') && first == last {
            return &value[1..value.len() - 1];
        }
    }
    value
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

/// Detect `$NAME` / `${NAME}` shell expansions that read a tainted env binding.
fn value_references_tainted_shell_env(value: &str, tainted_envs: &HashSet<String>) -> bool {
    if tainted_envs.is_empty() {
        return false;
    }
    let mut index = 0;
    let bytes = value.as_bytes();
    while index < bytes.len() {
        // Skip GitHub expression regions so `${{ env.TITLE }}` is handled by
        // expression taint, not shell-variable matching.
        if value[index..].starts_with("${{") {
            let after = &value[index + 3..];
            match find_expression_close(after) {
                Some(end) => {
                    index += 3 + end + 2;
                    continue;
                }
                None => return false,
            }
        }
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }
        let after_dollar = &value[index + 1..];
        let name = if let Some(rest) = after_dollar.strip_prefix('{') {
            let Some(end) = rest.find('}') else {
                break;
            };
            let name = rest[..end].trim();
            index += 2 + end + 1;
            name
        } else {
            let name_len = after_dollar
                .chars()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || *character == '_' || *character == '-'
                })
                .map(char::len_utf8)
                .sum::<usize>();
            if name_len == 0 {
                index += 1;
                continue;
            }
            let name = &after_dollar[..name_len];
            index += 1 + name_len;
            name
        };
        if is_github_ident(name) && tainted_envs.contains(name) {
            return true;
        }
    }
    false
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
            || expression_uses_tainted_secret(expression, taint.secrets)
            || expression_uses_tainted_step_output(expression, taint.step_outputs)
            || expression_uses_tainted_job_output(expression, taint.job_outputs)
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
/// Whole-context reads such as `toJSON(env)`, bare `env`, or object-filter
/// wildcards such as `env.*` are treated as tainted whenever any in-scope env
/// is tainted. Computed indexes such as `env[matrix.key]` are likewise
/// conservative. Nested property paths like `fromJSON(...).env.TITLE` are
/// ignored so only the root `env` context counts.
fn expression_uses_tainted_env(expression: &str, tainted_envs: &HashSet<String>) -> bool {
    if tainted_envs.is_empty() {
        return false;
    }
    if expression_reads_whole_context(expression, "env") {
        return true;
    }
    expression_uses_tainted_context_property(expression, "env", tainted_envs)
}

/// Detect `${{ inputs.NAME }}` (and index forms) when a local composite or
/// reusable-workflow caller bound that input to an untrusted value via `with:`.
fn expression_uses_tainted_input(expression: &str, tainted_inputs: &HashSet<String>) -> bool {
    if tainted_inputs.is_empty() {
        return false;
    }
    if expression_reads_whole_context(expression, "inputs") {
        return true;
    }
    expression_uses_tainted_context_property(expression, "inputs", tainted_inputs)
}

/// Detect `${{ secrets.NAME }}` when a reusable-workflow caller bound that
/// secret to an untrusted value via `secrets:`.
fn expression_uses_tainted_secret(expression: &str, tainted_secrets: &HashSet<String>) -> bool {
    if tainted_secrets.is_empty() {
        return false;
    }
    if expression_reads_whole_context(expression, "secrets") {
        return true;
    }
    expression_uses_tainted_context_property(expression, "secrets", tainted_secrets)
}

/// Detect `${{ steps.<id>.outputs.<name> }}` when a prior step wrote a tainted
/// value to `$GITHUB_OUTPUT`.
fn expression_uses_tainted_step_output(
    expression: &str,
    tainted_step_outputs: &HashSet<String>,
) -> bool {
    if tainted_step_outputs.is_empty() {
        return false;
    }
    expression_uses_tainted_nested_output(expression, "steps", tainted_step_outputs)
}

/// Detect `${{ needs.<job>.outputs.<name> }}` when a peer job exposed a tainted
/// output.
fn expression_uses_tainted_job_output(
    expression: &str,
    tainted_job_outputs: &HashSet<String>,
) -> bool {
    if tainted_job_outputs.is_empty() {
        return false;
    }
    expression_uses_tainted_nested_output(expression, "needs", tainted_job_outputs)
}

fn expression_uses_tainted_nested_output(
    expression: &str,
    root: &str,
    tainted_keys: &HashSet<String>,
) -> bool {
    static STEPS_REF: OnceLock<Regex> = OnceLock::new();
    static NEEDS_REF: OnceLock<Regex> = OnceLock::new();
    let pattern = match root {
        "steps" => STEPS_REF.get_or_init(|| {
            Regex::new(
                r#"(?i)\bsteps\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])\s*\.\s*outputs\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])?"#,
            )
            .expect("tainted steps output reference pattern compiles")
        }),
        "needs" => NEEDS_REF.get_or_init(|| {
            Regex::new(
                r#"(?i)\bneeds\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])\s*\.\s*outputs\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])?"#,
            )
            .expect("tainted needs output reference pattern compiles")
        }),
        _ => return false,
    };
    pattern.captures_iter(expression).any(|capture| {
        let Some(matched) = capture.get(0) else {
            return false;
        };
        if matched.start() > 0 && expression[..matched.start()].trim_end().ends_with('.') {
            return false;
        }
        if offset_inside_single_quoted_literal(expression, matched.start()) {
            return false;
        }
        // Computed job/step id: any tainted key is enough.
        if capture.get(3).is_some() {
            return true;
        }
        let Some(owner) = capture
            .get(1)
            .or_else(|| capture.get(2))
            .map(|matched| matched.as_str())
        else {
            return false;
        };
        // `steps.id.outputs` / `needs.job.outputs` without a property, or a
        // computed output index, exposes every output from that owner.
        if capture.get(6).is_some()
            || (capture.get(4).is_none() && capture.get(5).is_none() && capture.get(6).is_none())
        {
            let prefix = format!("{owner}.");
            return tainted_keys.iter().any(|key| key.starts_with(&prefix));
        }
        let Some(output) = capture
            .get(4)
            .or_else(|| capture.get(5))
            .map(|matched| matched.as_str())
        else {
            return false;
        };
        tainted_keys.contains(&format!("{owner}.{output}"))
    })
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
    // Match object-filter wildcards such as `env.*` / `inputs.*` (e.g. in
    // `join(env.*, ',')`) whenever any named binding in that context is tainted.
    let wildcard = format!("{context}.*");
    let mut rest = compact.as_str();
    while let Some(index) = rest.find(&wildcard) {
        let before_ok = index == 0
            || !matches!(
                rest.as_bytes()[index - 1],
                b'_' | b'.' | b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            );
        if before_ok {
            return true;
        }
        rest = &rest[index + 1..];
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
    static SECRETS_REF: OnceLock<Regex> = OnceLock::new();
    let pattern = match context {
        "env" => ENV_REF.get_or_init(|| {
            Regex::new(
                r#"(?i)\benv\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])"#,
            )
            .expect("tainted env reference pattern compiles")
        }),
        "inputs" => INPUTS_REF.get_or_init(|| {
            Regex::new(
                r#"(?i)\binputs\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])"#,
            )
            .expect("tainted inputs reference pattern compiles")
        }),
        "secrets" => SECRETS_REF.get_or_init(|| {
            Regex::new(
                r#"(?i)\bsecrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])"#,
            )
            .expect("tainted secrets reference pattern compiles")
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
        findings_for_files(&[file])
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
        let workflows = HashMap::new();
        let empty = HashSet::new();
        let mut visiting = HashSet::new();
        let error = scan_workflow(
            &file,
            TaintScope {
                envs: &empty,
                inputs: &empty,
                secrets: &empty,
                step_outputs: &empty,
                job_outputs: &empty,
            },
            &actions,
            &workflows,
            &mut visiting,
            &mut findings,
        )
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
    fn normalized_root_local_action_ref_inherits_caller_env_taint() {
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
      - uses: ././
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
    fn env_wildcard_filter_is_tainted_when_any_env_is_tainted() {
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
      - run: echo "${{ join(env.*, ',') }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env")
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

    #[test]
    fn hyphenated_env_property_reference_blocks() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      ISSUE-TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo "${{ env.ISSUE-TITLE }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env.ISSUE-TITLE")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn local_reusable_workflow_with_input_propagates_taint() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/caller.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  echo:
    uses: ./.github/workflows/reusable.yml
    with:
      title: ${{ github.event.issue.title }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/workflows/reusable.yml".to_string(),
                content: r#"
name: Reusable echo
on:
  workflow_call:
    inputs:
      title:
        type: string
        required: true
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.title }}"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("inputs.title")
                && finding.location.as_deref() == Some(".github/workflows/reusable.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn local_reusable_workflow_with_secret_propagates_taint() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/caller.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  echo:
    uses: ./.github/workflows/reusable.yml
    secrets:
      title: ${{ github.event.issue.title }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/workflows/reusable.yml".to_string(),
                content: r#"
name: Reusable echo
on:
  workflow_call:
    secrets:
      title:
        required: true
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.title }}"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("secrets.title")
                && finding.location.as_deref() == Some(".github/workflows/reusable.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn needs_job_output_into_reusable_workflow_with_propagates_taint() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/caller.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  producer:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    outputs:
      title: ${{ steps.set.outputs.title }}
    steps:
      - id: set
        run: echo "title=$TITLE" >> "$GITHUB_OUTPUT"
  consumer:
    needs: producer
    uses: ./.github/workflows/reusable.yml
    with:
      title: ${{ needs.producer.outputs.title }}
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/workflows/reusable.yml".to_string(),
                content: r#"
name: Reusable echo
on:
  workflow_call:
    inputs:
      title:
        type: string
        required: true
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.title }}"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("inputs.title")
                && finding.location.as_deref() == Some(".github/workflows/reusable.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn step_output_reinjection_into_later_run_blocks() {
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
      - id: set
        run: echo "title=$TITLE" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.set.outputs.title }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("steps.set.outputs.title")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }
}
