//! Env / job-output / reusable-workflow indirection for AGT-06 inline scripts.

use super::{
    apply_composite_env_effects, apply_github_env_writes, check_action_ref, check_inline_script,
    check_permissions, collect_env_bindings, collect_step_output_bindings, get, get_string,
    has_trigger, invalidate_composite_env_effects, invalidate_github_env_writes, is_github_ident,
    merge_env_bindings, replace_context_identifier, resolve_context_expressions,
    resolve_step_input_bindings, scan_step, step_can_run_after_failure,
    step_condition_is_always_false, step_condition_is_definitely_executed, ActionIndex,
    EnvBindings, InputBindings, JobOutputBindings, StepOutputBindings, StepScanCtx, SurfaceFile,
    WorkflowIndex, MAX_CONTEXT_RESOLVE_DEPTH,
};
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use yaml_rust2::yaml::Hash;
use yaml_rust2::{Yaml, YamlLoader};

pub(super) fn scan_workflow(
    file: &SurfaceFile,
    actions: &ActionIndex<'_>,
    workflows: &WorkflowIndex<'_>,
    input_bindings: &InputBindings,
    visiting: &mut std::collections::BTreeSet<String>,
    findings: &mut Vec<argus_core::Finding>,
) -> Result<JobOutputBindings> {
    if !visiting.insert(file.rel.clone()) {
        return Ok(JobOutputBindings::new());
    }
    let result = scan_workflow_inner(file, actions, workflows, input_bindings, visiting, findings);
    visiting.remove(&file.rel);
    result
}

fn scan_workflow_inner(
    file: &SurfaceFile,
    actions: &ActionIndex<'_>,
    workflows: &WorkflowIndex<'_>,
    input_bindings: &InputBindings,
    visiting: &mut std::collections::BTreeSet<String>,
    findings: &mut Vec<argus_core::Finding>,
) -> Result<JobOutputBindings> {
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
        return Ok(JobOutputBindings::new());
    };
    let workflow_env = collect_env_bindings(root);
    let mut job_outputs = JobOutputBindings::new();
    for _ in 0..=jobs.keys().count() {
        let mut discarded = Vec::new();
        let next = scan_workflow_jobs(
            file,
            jobs,
            actions,
            workflows,
            input_bindings,
            &workflow_env,
            privileged_trigger,
            &job_outputs,
            visiting,
            &mut discarded,
        )?;
        if next == job_outputs {
            break;
        }
        job_outputs = next;
    }
    let _ = scan_workflow_jobs(
        file,
        jobs,
        actions,
        workflows,
        input_bindings,
        &workflow_env,
        privileged_trigger,
        &job_outputs,
        visiting,
        findings,
    )?;
    Ok(collect_workflow_call_outputs(
        root,
        input_bindings,
        &job_outputs,
    ))
}

#[allow(clippy::too_many_arguments)]
fn scan_workflow_jobs(
    file: &SurfaceFile,
    jobs: &Hash,
    actions: &ActionIndex<'_>,
    workflows: &WorkflowIndex<'_>,
    input_bindings: &InputBindings,
    workflow_env: &EnvBindings,
    privileged_trigger: bool,
    job_outputs: &JobOutputBindings,
    visiting: &mut std::collections::BTreeSet<String>,
    findings: &mut Vec<argus_core::Finding>,
) -> Result<JobOutputBindings> {
    let mut next_job_outputs = JobOutputBindings::new();
    for (job_key, job_yaml) in jobs {
        let Some(job_id) = job_key.as_str() else {
            continue;
        };
        let Some(job) = job_yaml.as_hash() else {
            continue;
        };
        check_permissions(job, "job", privileged_trigger, &file.rel, findings);
        if step_condition_is_always_false(job) {
            continue;
        }
        let job_env = merge_env_bindings(workflow_env, &collect_env_bindings(job));
        if let Some(action) = get_string(job, "uses") {
            check_action_ref(action, &file.rel, findings);
            if let Some(workflow_file) = resolve_local_workflow(action, workflows) {
                let nested_inputs =
                    resolve_job_with_bindings(job, input_bindings, &job_env, job_outputs);
                let exported = scan_workflow(
                    workflow_file,
                    actions,
                    workflows,
                    &nested_inputs,
                    visiting,
                    findings,
                )?;
                if is_github_ident(job_id) {
                    for (name, value) in exported {
                        next_job_outputs.insert(format!("{job_id}.{name}"), value);
                    }
                }
            }
            continue;
        }
        let Some(steps) = get(job, "steps").and_then(Yaml::as_vec) else {
            continue;
        };
        let mut step_outputs = StepOutputBindings::new();
        let mut env_bindings = job_env;
        let step_hashes: Vec<&Hash> = steps.iter().filter_map(Yaml::as_hash).collect();
        for (index, step) in step_hashes.iter().enumerate() {
            let later_post_failure = step_hashes[index + 1..]
                .iter()
                .any(|later| step_can_run_after_failure(later));
            let step_env = merge_env_bindings(&env_bindings, &collect_env_bindings(step));
            let composite_env = scan_step(
                step,
                &file.rel,
                &StepScanCtx {
                    privileged_trigger,
                    actions,
                    depth: 0,
                    expand_local: true,
                    input_bindings,
                    env_bindings: &env_bindings,
                    step_outputs: &step_outputs,
                    job_outputs,
                },
                findings,
            )?;
            if step_condition_is_always_false(step) {
                continue;
            }
            if !step_condition_is_definitely_executed(step, later_post_failure) {
                if let Some(effects) = composite_env {
                    invalidate_composite_env_effects(&effects, &mut env_bindings);
                }
                invalidate_github_env_writes(step, &mut env_bindings);
                continue;
            }
            if let Some(effects) = composite_env {
                apply_composite_env_effects(&effects, &mut env_bindings);
                if let Some(step_id) = get_string(step, "id").filter(|id| is_github_ident(id)) {
                    for (name, value) in &effects.declared_outputs {
                        step_outputs.insert(format!("{step_id}.{name}"), value.clone());
                    }
                }
            }
            for (key, value) in
                collect_step_output_bindings(step, input_bindings, &step_env, &step_outputs)
            {
                step_outputs.insert(key, value);
            }
            let _ = apply_github_env_writes(
                step,
                input_bindings,
                &step_env,
                &step_outputs,
                &mut env_bindings,
            );
        }
        if is_github_ident(job_id) {
            for (name, value) in
                collect_job_output_bindings(job, input_bindings, &step_outputs, job_outputs)
            {
                next_job_outputs.insert(format!("{job_id}.{name}"), value);
            }
        }
    }
    Ok(next_job_outputs)
}

/// Scan inline `run:` and first-party `actions/github-script` `with.script`.
pub(super) fn scan_step_scripts(
    step: &Hash,
    rel: &str,
    ctx: &StepScanCtx<'_>,
    step_env: &EnvBindings,
    findings: &mut Vec<argus_core::Finding>,
) -> Result<()> {
    if let Some(script) = get_string(step, "run") {
        scan_run_script(script, rel, ctx, step_env, findings)?;
    }
    if let Some(action) = get_string(step, "uses") {
        if is_github_script(action) {
            if let Some(script) = get(step, "with")
                .and_then(Yaml::as_hash)
                .and_then(|with| get_string(with, "script"))
            {
                scan_run_script(script, rel, ctx, step_env, findings)?;
            }
        }
    }
    Ok(())
}

fn is_github_script(action: &str) -> bool {
    action
        .split_once('@')
        .map_or(action, |(name, _)| name)
        .eq_ignore_ascii_case("actions/github-script")
}

fn scan_run_script(
    script: &str,
    rel: &str,
    ctx: &StepScanCtx<'_>,
    step_env: &EnvBindings,
    findings: &mut Vec<argus_core::Finding>,
) -> Result<()> {
    if ctx.depth == 0 {
        check_inline_script(script, rel, findings)?;
    }
    let resolved = resolve_full(
        script,
        ctx.input_bindings,
        step_env,
        ctx.step_outputs,
        ctx.job_outputs,
    );
    if resolved != script {
        check_inline_script(&resolved, rel, findings)?;
    }
    Ok(())
}

pub(super) fn tracked_shell_env_value(
    raw_value: &str,
    env_bindings: &EnvBindings,
) -> Option<String> {
    let trimmed = raw_value.trim();
    let name = trimmed
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
        .map(str::trim)
        .or_else(|| trimmed.strip_prefix('$'))?;
    if !is_github_ident(name) {
        return None;
    }
    env_bindings.get(name).cloned()
}

pub(super) fn collect_declared_composite_outputs(
    root: &Hash,
    step_outputs: &StepOutputBindings,
) -> BTreeMap<String, String> {
    let mut outputs = BTreeMap::new();
    let Some(declared) = get(root, "outputs").and_then(Yaml::as_hash) else {
        return outputs;
    };
    for (key, value) in declared {
        let Some(name) = key.as_str() else {
            continue;
        };
        let Some(expr) = output_expression(value) else {
            continue;
        };
        outputs.insert(
            name.to_string(),
            resolve_full(
                &expr,
                &InputBindings::new(),
                &EnvBindings::new(),
                step_outputs,
                &JobOutputBindings::new(),
            ),
        );
    }
    outputs
}

fn resolve_job_with_bindings(
    job: &Hash,
    parent_bindings: &InputBindings,
    env_bindings: &EnvBindings,
    job_outputs: &JobOutputBindings,
) -> InputBindings {
    let mut bindings = resolve_step_input_bindings(
        job,
        parent_bindings,
        env_bindings,
        &StepOutputBindings::new(),
    );
    for value in bindings.values_mut() {
        *value = resolve_full(
            value,
            parent_bindings,
            env_bindings,
            &StepOutputBindings::new(),
            job_outputs,
        );
    }
    bindings
}

fn collect_job_output_bindings(
    job: &Hash,
    input_bindings: &InputBindings,
    step_outputs: &StepOutputBindings,
    job_outputs: &JobOutputBindings,
) -> BTreeMap<String, String> {
    let mut outputs = BTreeMap::new();
    let Some(declared) = get(job, "outputs").and_then(Yaml::as_hash) else {
        return outputs;
    };
    for (key, value) in declared {
        let Some(name) = key.as_str() else {
            continue;
        };
        let Some(expr) = output_expression(value) else {
            continue;
        };
        outputs.insert(
            name.to_string(),
            resolve_full(
                &expr,
                input_bindings,
                &EnvBindings::new(),
                step_outputs,
                job_outputs,
            ),
        );
    }
    outputs
}

fn collect_workflow_call_outputs(
    root: &Hash,
    input_bindings: &InputBindings,
    job_outputs: &JobOutputBindings,
) -> JobOutputBindings {
    let mut exported = JobOutputBindings::new();
    let Some(on) = get(root, "on").and_then(Yaml::as_hash) else {
        return exported;
    };
    let Some(workflow_call) = get(on, "workflow_call").and_then(Yaml::as_hash) else {
        return exported;
    };
    let Some(outputs) = get(workflow_call, "outputs").and_then(Yaml::as_hash) else {
        return exported;
    };
    for (key, value) in outputs {
        let Some(name) = key.as_str() else {
            continue;
        };
        let Some(expr) = output_expression(value) else {
            continue;
        };
        exported.insert(
            name.to_string(),
            resolve_full(
                &expr,
                input_bindings,
                &EnvBindings::new(),
                &StepOutputBindings::new(),
                job_outputs,
            ),
        );
    }
    exported
}

fn output_expression(value: &Yaml) -> Option<String> {
    if let Some(expr) = value.as_str() {
        return Some(expr.to_string());
    }
    get(value.as_hash()?, "value")?.as_str().map(str::to_string)
}

fn resolve_full(
    value: &str,
    input_bindings: &InputBindings,
    env_bindings: &EnvBindings,
    step_outputs: &StepOutputBindings,
    job_outputs: &JobOutputBindings,
) -> String {
    let mut resolved = value.to_string();
    for _ in 0..MAX_CONTEXT_RESOLVE_DEPTH {
        let next = resolve_needs_output_expressions(
            &resolve_context_expressions(&resolved, input_bindings, env_bindings, step_outputs),
            job_outputs,
        );
        if next == resolved {
            return next;
        }
        resolved = next;
    }
    resolved
}

fn resolve_needs_output_expressions(value: &str, bindings: &JobOutputBindings) -> String {
    let mut resolved = super::normalize_bracket_property_access(value);
    if bindings.is_empty() {
        return resolved;
    }
    let mut keys: Vec<&String> = bindings.keys().collect();
    keys.sort_by(|left, right| right.len().cmp(&left.len()).then(left.cmp(right)));
    for key in keys {
        let Some((job_id, output_name)) = key.split_once('.') else {
            continue;
        };
        let Some(bound) = bindings.get(key) else {
            continue;
        };
        let context = format!("needs.{job_id}.outputs");
        resolved = replace_context_identifier(&resolved, &context, output_name, bound, false);
    }
    resolved
}

fn resolve_local_workflow<'a>(
    action: &str,
    workflows: &WorkflowIndex<'a>,
) -> Option<&'a SurfaceFile> {
    let normalized = action
        .strip_prefix("./")
        .unwrap_or(action)
        .trim_end_matches('/');
    if !(normalized.ends_with(".yml") || normalized.ends_with(".yaml")) {
        return None;
    }
    workflows.get(normalized).copied()
}

#[cfg(test)]
mod tests {
    use super::super::run;
    use crate::{SurfaceFile, SurfaceKind};
    use argus_core::{Decision, Finding, Severity};

    const RULE_CONTEXT_INJECTION: &str = "AGT-06-workflow-context-injection";

    fn findings_for(content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        run(
            &[SurfaceFile {
                rel: ".github/workflows/test.yml".to_string(),
                content: content.to_string(),
                kind: SurfaceKind::Workflow,
            }],
            &mut findings,
        )
        .expect("scan workflow fixture");
        findings
    }

    fn github_script_workflow(script: &str) -> String {
        format!(
            r#"
name: Comment
on: issues
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            {script}
"#
        )
    }

    fn assert_context_injection_blocks(findings: &[Finding], case: &str) {
        assert!(
            findings.iter().any(|finding| {
                finding.rule_id == RULE_CONTEXT_INJECTION && finding.severity == Severity::Critical
            }),
            "expected context injection for {case}; findings={findings:?}"
        );
        assert_eq!(
            crate::decision::derive(findings),
            Decision::Block,
            "expected block for {case}"
        );
    }

    #[test]
    fn github_script_with_script_context_injection_blocks() {
        let scripts = [
            r#"console.log("${{ github.event.issue.title }}")"#,
            r#"console.log("${{ github.event['issue']['title'] }}")"#,
            r#"console.log("${{ github.event.issue['body'] }}")"#,
            r#"console.log("${{ github['head_ref'] }}")"#,
            r#"console.log("${{ toJSON(github['event']) }}")"#,
        ];
        for script in scripts {
            assert_context_injection_blocks(&findings_for(&github_script_workflow(script)), script);
        }
    }

    #[test]
    fn github_script_env_indirection_blocks() {
        assert_context_injection_blocks(
            &findings_for(
                r#"
name: Comment
on: issues
jobs:
  comment:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ env.TITLE }}")
"#,
            ),
            "github-script env indirection",
        );
    }

    #[test]
    fn github_script_env_passthrough_is_not_context_injection() {
        let findings = findings_for(
            r#"
name: Comment
on: issues
jobs:
  comment:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - uses: actions/github-script@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          script: |
            console.log(process.env.TITLE)
"#,
        );
        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != RULE_CONTEXT_INJECTION));
        assert_eq!(crate::decision::derive(&findings), Decision::Allow);
    }
}
