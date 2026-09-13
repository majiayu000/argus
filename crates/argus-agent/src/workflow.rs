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
    /// `strategy.matrix` properties that carry untrusted values for
    /// `${{ matrix.* }}` interpolations in this job (and nested composites).
    matrix: &'a HashSet<String>,
}

/// Outputs and post-scan env taint exported from a local composite action.
struct CompositeExport {
    outputs: HashSet<String>,
    /// `$GITHUB_ENV` writes from the composite (and nested composites).
    /// `true` = tainted, `false` = clean overwrite that clears prior taint.
    env_writes: HashMap<String, bool>,
}

/// Step scan side effects: produced outputs and optional composite env export.
struct StepScanEffects {
    outputs: HashSet<String>,
    /// `$GITHUB_ENV` writes when the step invoked a local composite.
    env_writes: Option<HashMap<String, bool>>,
}

fn apply_github_env_overlay(envs: &mut HashSet<String>, writes: &HashMap<String, bool>) {
    for (name, tainted) in writes {
        if *tainted {
            envs.insert(name.clone());
        } else {
            envs.remove(name);
        }
    }
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
                let _ = scan_workflow(
                    file,
                    TaintScope {
                        envs: &empty,
                        inputs: &empty,
                        secrets: &empty,
                        step_outputs: &empty,
                        job_outputs: &empty,
                        matrix: &empty,
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
                let _ = scan_action_metadata(
                    file,
                    TaintScope {
                        envs: &empty,
                        inputs: &empty,
                        secrets: &empty,
                        step_outputs: &empty,
                        job_outputs: &empty,
                        matrix: &empty,
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
) -> Result<HashSet<String>> {
    if !visiting.insert(file.rel.clone()) {
        return Ok(HashSet::new());
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
) -> Result<HashSet<String>> {
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
                matrix: &empty_outputs,
            },
            &file.rel,
        )?;
    }

    let Some(jobs) = get(root, "jobs").and_then(Yaml::as_hash) else {
        return collect_tainted_workflow_call_outputs(
            root,
            TaintScope {
                envs: &workflow_tainted_envs,
                inputs: caller_taint.inputs,
                secrets: caller_taint.secrets,
                step_outputs: &empty_outputs,
                job_outputs: &empty_outputs,
                matrix: &empty_outputs,
            },
            &file.rel,
        );
    };

    // Collect job-output taint before scanning so `needs.*.outputs` is available
    // regardless of YAML job order. Iterate to a fixed point: a relay job may be
    // declared before its producer and re-export `needs.producer.outputs.*`.
    let mut tainted_job_outputs = HashSet::new();
    let job_count = jobs.keys().count();
    for _ in 0..=job_count {
        let before = tainted_job_outputs.len();
        for (job_key, job_yaml) in jobs {
            let Some(job_id) = job_key.as_str() else {
                continue;
            };
            let Some(job) = job_yaml.as_hash() else {
                continue;
            };
            let mut job_tainted_envs = workflow_tainted_envs.clone();
            let job_tainted_matrix = collect_tainted_matrix(
                job,
                TaintScope {
                    envs: &job_tainted_envs,
                    inputs: caller_taint.inputs,
                    secrets: caller_taint.secrets,
                    step_outputs: &empty_outputs,
                    job_outputs: &tainted_job_outputs,
                    matrix: &empty_outputs,
                },
                &file.rel,
            )?;
            apply_job_level_env_taints(
                &mut job_tainted_envs,
                job,
                TaintScope {
                    envs: &empty_outputs,
                    inputs: caller_taint.inputs,
                    secrets: caller_taint.secrets,
                    step_outputs: &empty_outputs,
                    job_outputs: &tainted_job_outputs,
                    matrix: &job_tainted_matrix,
                },
                &file.rel,
            )?;
            if let Some(action) = get_string(job, "uses") {
                // Map reusable-workflow `on.workflow_call.outputs` back onto the
                // call job so later `needs.<call>.outputs.*` reads stay tainted.
                if let Some(local) = action.strip_prefix("./") {
                    if let Some(workflow_file) = resolve_local_workflow(local, workflows) {
                        let job_scope = TaintScope {
                            envs: &job_tainted_envs,
                            inputs: caller_taint.inputs,
                            secrets: caller_taint.secrets,
                            step_outputs: &empty_outputs,
                            job_outputs: &tainted_job_outputs,
                            matrix: &job_tainted_matrix,
                        };
                        let job_tainted_inputs =
                            collect_tainted_with_inputs(job, job_scope, &file.rel)?;
                        let job_tainted_secrets =
                            collect_tainted_secrets(job, job_scope, &file.rel)?;
                        let empty_envs = HashSet::new();
                        let mut discarded = Vec::new();
                        let exported = scan_workflow(
                            workflow_file,
                            TaintScope {
                                envs: &empty_envs,
                                inputs: &job_tainted_inputs,
                                secrets: &job_tainted_secrets,
                                step_outputs: &empty_outputs,
                                job_outputs: &empty_outputs,
                                matrix: &empty_outputs,
                            },
                            actions,
                            workflows,
                            visiting,
                            &mut discarded,
                        )?;
                        for name in exported {
                            if is_github_ident(&name) {
                                tainted_job_outputs.insert(format!("{job_id}.{name}"));
                            }
                        }
                    }
                }
                continue;
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
                            matrix: &job_tainted_matrix,
                        },
                        &file.rel,
                    )?;
                }
                let step_scope = TaintScope {
                    envs: &step_tainted_envs,
                    inputs: caller_taint.inputs,
                    secrets: caller_taint.secrets,
                    step_outputs: &tainted_step_outputs,
                    job_outputs: &tainted_job_outputs,
                    matrix: &job_tainted_matrix,
                };
                let mut discarded = Vec::new();
                let effects = collect_step_produced_output_taint(
                    step,
                    step_scope,
                    actions,
                    visiting,
                    &mut discarded,
                    &file.rel,
                )?;
                // `$GITHUB_ENV` writes become env bindings for later steps.
                apply_github_env_file_taints(&mut job_tainted_envs, step, step_scope, &file.rel)?;
                if let Some(ref env_writes) = effects.env_writes {
                    apply_github_env_overlay(&mut job_tainted_envs, env_writes);
                }
                tainted_step_outputs.extend(effects.outputs);
            }
            let added = {
                let job_scope = TaintScope {
                    envs: &job_tainted_envs,
                    inputs: caller_taint.inputs,
                    secrets: caller_taint.secrets,
                    step_outputs: &tainted_step_outputs,
                    job_outputs: &tainted_job_outputs,
                    matrix: &job_tainted_matrix,
                };
                collect_tainted_job_outputs(job, job_id, job_scope, &file.rel)?
            };
            tainted_job_outputs.extend(added);
        }
        if tainted_job_outputs.len() == before {
            break;
        }
    }

    for job in jobs.values().filter_map(Yaml::as_hash) {
        check_permissions(job, "job", privileged_trigger, &file.rel, findings);
        let mut job_tainted_envs = workflow_tainted_envs.clone();
        let job_tainted_matrix = collect_tainted_matrix(
            job,
            TaintScope {
                envs: &job_tainted_envs,
                inputs: caller_taint.inputs,
                secrets: caller_taint.secrets,
                step_outputs: &empty_outputs,
                job_outputs: &tainted_job_outputs,
                matrix: &empty_outputs,
            },
            &file.rel,
        )?;
        apply_job_level_env_taints(
            &mut job_tainted_envs,
            job,
            TaintScope {
                envs: &empty_outputs,
                inputs: caller_taint.inputs,
                secrets: caller_taint.secrets,
                step_outputs: &empty_outputs,
                job_outputs: &tainted_job_outputs,
                matrix: &job_tainted_matrix,
            },
            &file.rel,
        )?;
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
                        matrix: &job_tainted_matrix,
                    };
                    let job_tainted_inputs =
                        collect_tainted_with_inputs(job, job_scope, &file.rel)?;
                    let job_tainted_secrets = collect_tainted_secrets(job, job_scope, &file.rel)?;
                    let empty_envs = HashSet::new();
                    let _ = scan_workflow(
                        workflow_file,
                        TaintScope {
                            envs: &empty_envs,
                            inputs: &job_tainted_inputs,
                            secrets: &job_tainted_secrets,
                            step_outputs: &empty_outputs,
                            job_outputs: &empty_outputs,
                            matrix: &empty_outputs,
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
                        matrix: &job_tainted_matrix,
                    },
                    &file.rel,
                )?;
            }
            let step_scope = TaintScope {
                envs: &step_tainted_envs,
                inputs: caller_taint.inputs,
                secrets: caller_taint.secrets,
                step_outputs: &tainted_step_outputs,
                job_outputs: &tainted_job_outputs,
                matrix: &job_tainted_matrix,
            };
            let from_composite = scan_step(
                step,
                &file.rel,
                privileged_trigger,
                step_scope,
                actions,
                visiting,
                findings,
            )?;
            let from_run = collect_tainted_github_outputs(step, step_scope, &file.rel)?;
            // `$GITHUB_ENV` writes become env bindings for later steps.
            apply_github_env_file_taints(&mut job_tainted_envs, step, step_scope, &file.rel)?;
            if let Some(ref env_writes) = from_composite.env_writes {
                apply_github_env_overlay(&mut job_tainted_envs, env_writes);
            }
            tainted_step_outputs.extend(from_composite.outputs.into_iter().chain(from_run));
        }
    }
    let exported = collect_tainted_workflow_call_outputs(
        root,
        TaintScope {
            envs: &workflow_tainted_envs,
            inputs: caller_taint.inputs,
            secrets: caller_taint.secrets,
            step_outputs: &empty_outputs,
            job_outputs: &tainted_job_outputs,
            matrix: &empty_outputs,
        },
        &file.rel,
    )?;
    Ok(exported)
}

fn scan_action_metadata(
    file: &SurfaceFile,
    caller_taint: TaintScope<'_>,
    actions: &HashMap<&str, &SurfaceFile>,
    visiting: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
) -> Result<CompositeExport> {
    let unchanged = || CompositeExport {
        outputs: HashSet::new(),
        env_writes: HashMap::new(),
    };
    if !visiting.insert(file.rel.clone()) {
        return Ok(unchanged());
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
        return Ok(unchanged());
    };
    if !get_string(runs, "using").is_some_and(|using| using.eq_ignore_ascii_case("composite")) {
        visiting.remove(&file.rel);
        return Ok(unchanged());
    }
    let Some(steps) = get(runs, "steps").and_then(Yaml::as_vec) else {
        visiting.remove(&file.rel);
        return Ok(unchanged());
    };
    // Composite actions have no `secrets` context; only env + inputs apply.
    let empty_secrets = HashSet::new();
    let empty_outputs = HashSet::new();
    let mut tainted_step_outputs = HashSet::new();
    // Caller env remains visible; `$GITHUB_ENV` writes accumulate across steps.
    let mut cross_step_envs = caller_taint.envs.clone();
    let mut env_writes = HashMap::new();
    for step in steps.iter().filter_map(Yaml::as_hash) {
        let mut step_tainted_envs = cross_step_envs.clone();
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
                    matrix: caller_taint.matrix,
                },
                &file.rel,
            )?;
        }
        let step_scope = TaintScope {
            envs: &step_tainted_envs,
            inputs: caller_taint.inputs,
            secrets: &empty_secrets,
            step_outputs: &tainted_step_outputs,
            job_outputs: &empty_outputs,
            matrix: caller_taint.matrix,
        };
        let from_composite = scan_step(
            step, &file.rel, false, step_scope, actions, visiting, findings,
        )?;
        let from_run = collect_tainted_github_outputs(step, step_scope, &file.rel)?;
        let step_env_writes =
            apply_github_env_file_taints(&mut cross_step_envs, step, step_scope, &file.rel)?;
        env_writes.extend(step_env_writes);
        if let Some(nested_writes) = from_composite.env_writes {
            apply_github_env_overlay(&mut cross_step_envs, &nested_writes);
            env_writes.extend(nested_writes);
        }
        tainted_step_outputs.extend(from_composite.outputs.into_iter().chain(from_run));
    }
    // Declared outputs may reference env vars written earlier via `$GITHUB_ENV`
    // (for example `value: ${{ env.ALIAS }}`); evaluate against the final
    // cross-step environment, not only the original caller env.
    let exported = collect_tainted_declared_outputs(
        root,
        TaintScope {
            envs: &cross_step_envs,
            inputs: caller_taint.inputs,
            secrets: &empty_secrets,
            step_outputs: &tainted_step_outputs,
            job_outputs: &empty_outputs,
            matrix: caller_taint.matrix,
        },
        &file.rel,
    )?;
    visiting.remove(&file.rel);
    Ok(CompositeExport {
        outputs: exported,
        env_writes,
    })
}

fn scan_step(
    step: &Hash,
    rel: &str,
    privileged_trigger: bool,
    taint: TaintScope<'_>,
    actions: &HashMap<&str, &SurfaceFile>,
    visiting: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
) -> Result<StepScanEffects> {
    let mut produced = HashSet::new();
    let mut env_writes = None;
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
                let exported = scan_action_metadata(
                    action_file,
                    TaintScope {
                        envs: taint.envs,
                        inputs: &step_tainted_inputs,
                        // Composites cannot read the caller's `secrets` context.
                        secrets: &empty_secrets,
                        // Nested composites start with a fresh step-output scope.
                        step_outputs: &empty_outputs,
                        job_outputs: &empty_outputs,
                        matrix: taint.matrix,
                    },
                    actions,
                    visiting,
                    findings,
                )?;
                env_writes = Some(exported.env_writes);
                if let Some(step_id) = get_string(step, "id") {
                    if is_github_ident(step_id) {
                        for name in exported.outputs {
                            produced.insert(format!("{step_id}.{name}"));
                        }
                    }
                }
            }
        }
    }
    if let Some(script) = get_string(step, "run") {
        check_inline_script(script, rel, taint, findings)?;
    }
    Ok(StepScanEffects {
        outputs: produced,
        env_writes,
    })
}

/// Collect `$GITHUB_OUTPUT` writes and local composite exported outputs for a
/// step without requiring the caller to run the full `scan_step` finding pass.
fn collect_step_produced_output_taint(
    step: &Hash,
    taint: TaintScope<'_>,
    actions: &HashMap<&str, &SurfaceFile>,
    visiting: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
    rel: &str,
) -> Result<StepScanEffects> {
    let mut produced = collect_tainted_github_outputs(step, taint, rel)?;
    let Some(action) = get_string(step, "uses") else {
        return Ok(StepScanEffects {
            outputs: produced,
            env_writes: None,
        });
    };
    let Some(local) = action.strip_prefix("./") else {
        return Ok(StepScanEffects {
            outputs: produced,
            env_writes: None,
        });
    };
    let Some(action_file) = resolve_local_action(local, actions) else {
        return Ok(StepScanEffects {
            outputs: produced,
            env_writes: None,
        });
    };
    let step_tainted_inputs = collect_tainted_with_inputs(step, taint, rel)?;
    let empty_secrets = HashSet::new();
    let empty_outputs = HashSet::new();
    let exported = scan_action_metadata(
        action_file,
        TaintScope {
            envs: taint.envs,
            inputs: &step_tainted_inputs,
            secrets: &empty_secrets,
            step_outputs: &empty_outputs,
            job_outputs: &empty_outputs,
            matrix: taint.matrix,
        },
        actions,
        visiting,
        findings,
    )?;
    if let Some(step_id) = get_string(step, "id") {
        if is_github_ident(step_id) {
            for name in exported.outputs {
                produced.insert(format!("{step_id}.{name}"));
            }
        }
    }
    Ok(StepScanEffects {
        outputs: produced,
        env_writes: Some(exported.env_writes),
    })
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

/// Sentinel inserted when `strategy.matrix` is an expression (for example
/// `${{ fromJSON(inputs.payload) }}`) whose keys are unknown statically.
/// Any later `${{ matrix.* }}` read is treated as tainted while this is set.
const MATRIX_EXPRESSION_UNKNOWN_KEYS: &str = "__argus_matrix_expression__";

/// Collect `strategy.matrix` property names whose values carry untrusted data.
///
/// Covers dimension arrays (`title: ["${{ inputs.title }}"]`), scalar entries,
/// `include` row fields, and expression-valued matrices such as
/// `matrix: ${{ fromJSON(inputs.payload) }}`. `exclude` rows do not introduce
/// runtime matrix values for interpolation, so they are ignored.
fn collect_tainted_matrix(job: &Hash, taint: TaintScope<'_>, rel: &str) -> Result<HashSet<String>> {
    let mut tainted = HashSet::new();
    let Some(strategy) = get(job, "strategy").and_then(Yaml::as_hash) else {
        return Ok(tainted);
    };
    let Some(matrix_node) = get(strategy, "matrix") else {
        return Ok(tainted);
    };
    // Expression-valued matrices (common with `fromJSON`) have unknown keys;
    // conservatively taint every matrix property read when the expression
    // itself carries untrusted data.
    if let Some(expression) = matrix_node.as_str() {
        if value_carries_taint(expression, taint, rel)? {
            tainted.insert(MATRIX_EXPRESSION_UNKNOWN_KEYS.to_string());
        }
        return Ok(tainted);
    }
    let Some(matrix) = matrix_node.as_hash() else {
        return Ok(tainted);
    };
    for (key, value) in matrix {
        let Some(name) = key.as_str() else {
            continue;
        };
        if name == "include" {
            if let Some(rows) = value.as_vec() {
                for row in rows.iter().filter_map(Yaml::as_hash) {
                    for (row_key, row_value) in row {
                        let Some(row_name) = row_key.as_str() else {
                            continue;
                        };
                        if yaml_value_carries_taint(row_value, taint, rel)? {
                            tainted.insert(row_name.to_string());
                        }
                    }
                }
            } else if let Some(expression) = value.as_str() {
                // Expression-valued includes (e.g. `include: ${{ fromJSON(inputs.rows) }}`)
                // introduce unknown row properties; conservatively taint every
                // matrix property read when the expression carries untrusted data.
                if value_carries_taint(expression, taint, rel)? {
                    tainted.insert(MATRIX_EXPRESSION_UNKNOWN_KEYS.to_string());
                }
            }
            continue;
        }
        if name == "exclude" {
            continue;
        }
        if yaml_value_carries_taint(value, taint, rel)? {
            tainted.insert(name.to_string());
        }
    }
    Ok(tainted)
}

fn yaml_value_carries_taint(value: &Yaml, taint: TaintScope<'_>, rel: &str) -> Result<bool> {
    match value {
        Yaml::String(text) => value_carries_taint(text, taint, rel),
        Yaml::Array(items) => {
            for item in items {
                if yaml_value_carries_taint(item, taint, rel)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        // Object-valued matrix dimensions such as
        // `target: [{ title: "${{ inputs.title }}" }]` carry taint in nested
        // string leaves; recurse into mappings so `${{ matrix.target.title }}`
        // still sees the parent dimension as tainted.
        Yaml::Hash(map) => {
            for (_, item) in map {
                if yaml_value_carries_taint(item, taint, rel)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        // Non-string scalars are constants.
        _ => Ok(false),
    }
}

/// Apply job-level `env` and `container.env` taint. Container env vars are
/// injected into every step's shell on container jobs, so they must enter the
/// same job env taint set as `jobs.<id>.env`.
fn apply_job_level_env_taints(
    job_tainted_envs: &mut HashSet<String>,
    job: &Hash,
    parent: TaintScope<'_>,
    rel: &str,
) -> Result<()> {
    if let Some(env) = get(job, "env").and_then(Yaml::as_hash) {
        apply_env_taints(job_tainted_envs, env, parent, rel)?;
    }
    if let Some(container) = get(job, "container").and_then(Yaml::as_hash) {
        if let Some(env) = get(container, "env").and_then(Yaml::as_hash) {
            apply_env_taints(job_tainted_envs, env, parent, rel)?;
        }
    }
    Ok(())
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
        matrix: parent.matrix,
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
        // Actions env lookups are case-insensitive on Windows runners; store a
        // canonical key so `TITLE` taint still matches `${{ env.title }}`.
        let key = normalize_env_name(&name);
        if is_tainted {
            tainted.insert(key);
        } else {
            // A same-scope redeclaration without untrusted contexts clears prior taint.
            tainted.remove(&key);
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
        || value_references_tainted_job_output(value, taint.job_outputs, rel)?
        || value_references_tainted_matrix(value, taint.matrix, rel)?)
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

fn value_references_tainted_matrix(
    value: &str,
    tainted: &HashSet<String>,
    rel: &str,
) -> Result<bool> {
    for_each_expression(value, rel, |expression| {
        Ok(expression_uses_tainted_matrix(expression, tainted))
    })
}

/// Collect tainted `{step_id}.{output}` keys written via `$GITHUB_OUTPUT`.
///
/// Multiple writes to the same output name are processed in order; a later clean
/// overwrite clears prior taint for that name (matching Actions semantics).
/// When the script contains shell control flow (`if`/`&&`/…), a clean overwrite
/// is not guaranteed to run, so prior taint is retained.
///
/// Shell-local aliases are advanced in script order alongside command-file
/// writes, so `ALIAS=$TITLE` / write / `ALIAS=fixed` still taints the write.
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
    let retain_on_clean = script_has_shell_control_flow(script);
    let mut locals = HashSet::new();
    for effect in parse_github_file_effects(script, "GITHUB_OUTPUT", rel)? {
        match effect {
            ShellFileEffect::Assignment { name, rhs, expands } => {
                apply_shell_local_assignment(&mut locals, taint.envs, &name, &rhs, expands);
            }
            ShellFileEffect::Write {
                name,
                value,
                expands,
            } => {
                let mut shell_envs = taint.envs.clone();
                shell_envs.extend(locals.iter().cloned());
                let key = format!("{step_id}.{name}");
                if github_output_value_is_tainted(&value, taint, rel, expands, &shell_envs)? {
                    tainted.insert(key);
                } else if !retain_on_clean {
                    tainted.remove(&key);
                }
            }
        }
    }
    Ok(tainted)
}

fn github_output_value_is_tainted(
    value: &str,
    taint: TaintScope<'_>,
    rel: &str,
    shell_expands: bool,
    shell_envs: &HashSet<String>,
) -> Result<bool> {
    if value_carries_taint(value, taint, rel)? {
        return Ok(true);
    }
    // Safe remediation writes (`echo "title=$TITLE" >> $GITHUB_OUTPUT`) still
    // propagate attacker-controlled env values into step outputs. Single-quoted
    // payloads are literal shell text, so `$TITLE` must not count as taint.
    // `shell_envs` also includes shell-local aliases such as `ALIAS=$TITLE`.
    if !shell_expands {
        return Ok(false);
    }
    Ok(value_references_tainted_shell_env(value, shell_envs))
}

/// Apply one shell-local assignment against base Actions env taint.
fn apply_shell_local_assignment(
    locals: &mut HashSet<String>,
    base_envs: &HashSet<String>,
    name: &str,
    rhs: &str,
    expands: bool,
) {
    let key = normalize_env_name(name);
    let mut working = base_envs.clone();
    working.extend(locals.iter().cloned());
    if expands && value_references_tainted_shell_env(rhs, &working) {
        locals.insert(key);
    } else {
        // Clean reassignment clears a prior local alias; base env taint stays.
        locals.remove(&key);
    }
}

/// Parse `NAME=value` / `export NAME=value` shell assignments.
fn parse_shell_assignment(segment: &str) -> Option<(&str, &str)> {
    let segment = segment.trim();
    let segment = if let Some(rest) = segment.strip_prefix("export") {
        if rest.starts_with(char::is_whitespace) {
            rest.trim_start()
        } else {
            return None;
        }
    } else {
        segment
    };
    let eq = segment.find('=')?;
    let name = &segment[..eq];
    if !is_posix_shell_ident(name) {
        return None;
    }
    Some((name, &segment[eq + 1..]))
}

fn is_posix_shell_ident(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Merge `$GITHUB_ENV` writes from a `run` step into later-step env taint.
///
/// GitHub exposes these values to subsequent steps via `${{ env.NAME }}` (and
/// shell `$NAME`). A clean overwrite clears prior taint for that name unless the
/// script has shell control flow (conditional overwrites are not guaranteed).
/// Returns the ordered write overlay (`true` = tainted, `false` = clean).
fn apply_github_env_file_taints(
    env_taints: &mut HashSet<String>,
    step: &Hash,
    taint: TaintScope<'_>,
    rel: &str,
) -> Result<HashMap<String, bool>> {
    let mut writes = HashMap::new();
    let Some(script) = get_string(step, "run") else {
        return Ok(writes);
    };
    let retain_on_clean = script_has_shell_control_flow(script);
    let mut locals = HashSet::new();
    for effect in parse_github_file_effects(script, "GITHUB_ENV", rel)? {
        match effect {
            ShellFileEffect::Assignment { name, rhs, expands } => {
                apply_shell_local_assignment(&mut locals, taint.envs, &name, &rhs, expands);
            }
            ShellFileEffect::Write {
                name,
                value,
                expands,
            } => {
                let mut shell_envs = taint.envs.clone();
                shell_envs.extend(locals.iter().cloned());
                let key = normalize_env_name(&name);
                let tainted =
                    github_output_value_is_tainted(&value, taint, rel, expands, &shell_envs)?;
                if tainted {
                    env_taints.insert(key.clone());
                    writes.insert(key, true);
                } else if !retain_on_clean {
                    env_taints.remove(&key);
                    writes.insert(key, false);
                } else if env_taints.contains(&key) {
                    // Conditional clean overwrite: keep prior taint visible to later steps.
                    writes.insert(key, true);
                } else {
                    writes.insert(key, false);
                }
            }
        }
    }
    Ok(writes)
}

/// True when `script` contains shell control-flow keywords or boolean lists that
/// make lexical last-write-wins unsafe for `$GITHUB_OUTPUT` / `$GITHUB_ENV`
/// tracking.
fn script_has_shell_control_flow(script: &str) -> bool {
    static CONTROL_FLOW: OnceLock<Regex> = OnceLock::new();
    let pattern = CONTROL_FLOW.get_or_init(|| {
        Regex::new(
            r"(?m)(?:(?:^|[^A-Za-z0-9_])(?:if|elif|else|fi|case|esac|for|while|until|done|select)(?:$|[^A-Za-z0-9_])|&&|\|\|)",
        )
        .expect("shell control-flow pattern compiles")
    });
    // Blank `${{ }}` regions so expression operators such as
    // `${{ false && inputs.ref }}` are not treated as shell control flow.
    pattern.is_match(&blank_github_expression_regions(script))
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

/// Collect composite Action `outputs.<name>` entries whose `value` carries taint.
fn collect_tainted_declared_outputs(
    root: &Hash,
    taint: TaintScope<'_>,
    rel: &str,
) -> Result<HashSet<String>> {
    let mut tainted = HashSet::new();
    let Some(outputs) = get(root, "outputs").and_then(Yaml::as_hash) else {
        return Ok(tainted);
    };
    for (key, value) in outputs {
        let Some(name) = key.as_str() else {
            continue;
        };
        if !is_github_ident(name) {
            continue;
        }
        let Some(expr) = declared_output_value(value) else {
            continue;
        };
        if value_carries_taint(expr, taint, rel)? {
            tainted.insert(name.to_string());
        }
    }
    Ok(tainted)
}

/// Collect reusable-workflow `on.workflow_call.outputs` that forward tainted
/// `jobs.*.outputs.*` (or other in-scope taint) back to the caller.
fn collect_tainted_workflow_call_outputs(
    root: &Hash,
    taint: TaintScope<'_>,
    rel: &str,
) -> Result<HashSet<String>> {
    let mut tainted = HashSet::new();
    let Some(on) = get(root, "on").and_then(Yaml::as_hash) else {
        return Ok(tainted);
    };
    let Some(workflow_call) = get(on, "workflow_call").and_then(Yaml::as_hash) else {
        return Ok(tainted);
    };
    let Some(outputs) = get(workflow_call, "outputs").and_then(Yaml::as_hash) else {
        return Ok(tainted);
    };
    for (key, value) in outputs {
        let Some(name) = key.as_str() else {
            continue;
        };
        if !is_github_ident(name) {
            continue;
        }
        let Some(expr) = declared_output_value(value) else {
            continue;
        };
        if workflow_call_output_carries_taint(expr, taint, rel)? {
            tainted.insert(name.to_string());
        }
    }
    Ok(tainted)
}

fn workflow_call_output_carries_taint(
    value: &str,
    taint: TaintScope<'_>,
    rel: &str,
) -> Result<bool> {
    Ok(value_carries_taint(value, taint, rel)?
        || value_references_tainted_jobs_output(value, taint.job_outputs, rel)?)
}

fn value_references_tainted_jobs_output(
    value: &str,
    tainted: &HashSet<String>,
    rel: &str,
) -> Result<bool> {
    for_each_expression(value, rel, |expression| {
        Ok(expression_uses_tainted_nested_output(
            expression, "jobs", tainted,
        ))
    })
}

fn declared_output_value(value: &Yaml) -> Option<&str> {
    match value {
        Yaml::String(text) => Some(text.as_str()),
        Yaml::Hash(map) => get_string(map, "value"),
        _ => None,
    }
}

/// Ordered shell effects that affect Actions command-file / alias taint.
enum ShellFileEffect {
    Assignment {
        name: String,
        rhs: String,
        expands: bool,
    },
    Write {
        name: String,
        value: String,
        expands: bool,
    },
}

/// Parse shell assignments and `echo` / `printf` / `tee` writes to `$GITHUB_*`
/// in script order so alias state advances alongside each write.
fn parse_github_file_effects(
    script: &str,
    file_var: &str,
    rel: &str,
) -> Result<Vec<ShellFileEffect>> {
    let mut effects = Vec::new();
    let lines: Vec<&str> = script.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        index += 1;
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // `{ echo ...; echo ...; } >> $GITHUB_OUTPUT` (single- or multi-line).
        if let Some((body, next_index)) =
            extract_brace_group_redirect_body(&lines, index - 1, file_var)
        {
            index = next_index;
            push_redirect_free_github_file_effects(&mut effects, &body)?;
            continue;
        }
        if let Some(command) = split_github_file_tee_pipeline(trimmed, file_var) {
            push_producer_command_effects(&mut effects, command)?;
            continue;
        }
        let Some(command) = split_github_file_redirect(trimmed, file_var) else {
            if line_references_github_file_var(trimmed, file_var) {
                bail!(
                    "GitHub Actions surface `{rel}` contains an unsupported `${file_var}` producer that cannot be assessed statically"
                );
            }
            push_assignment_effects(&mut effects, trimmed);
            continue;
        };
        if let Some((name, delimiter)) = extract_echo_multiline_header(command) {
            push_assignment_effects_before_producer(&mut effects, command, |c| {
                extract_echo_multiline_header(c).is_some()
                    || extract_cat_heredoc_header(c).is_some()
                    || extract_echo_github_output(c).is_some()
                    || !extract_printf_github_output(c).is_empty()
                    || extract_bare_string_github_output(c).is_some()
            });
            let (value, shell_expands) =
                collect_multiline_github_file_body(&lines, &mut index, file_var, &delimiter);
            effects.push(ShellFileEffect::Write {
                name,
                value,
                expands: shell_expands,
            });
            continue;
        }
        if let Some((delimiter, shell_expands)) = extract_cat_heredoc_header(command) {
            push_assignment_effects_before_producer(&mut effects, command, |c| {
                extract_cat_heredoc_header(c).is_some()
            });
            for (name, value, expands) in collect_cat_heredoc_github_file_writes(
                &lines,
                &mut index,
                &delimiter,
                shell_expands,
            ) {
                effects.push(ShellFileEffect::Write {
                    name,
                    value,
                    expands,
                });
            }
            continue;
        }
        push_producer_command_effects(&mut effects, command)?;
    }
    Ok(effects)
}

/// Collect writes/assignments from brace-group bodies where only `}` is redirected.
fn push_redirect_free_github_file_effects(
    effects: &mut Vec<ShellFileEffect>,
    body: &str,
) -> Result<()> {
    let commands = split_shell_group_commands(body);
    let mut index = 0;
    while index < commands.len() {
        let command = commands[index].trim();
        index += 1;
        if command.is_empty() || command.starts_with('#') {
            continue;
        }
        if let Some((name, delimiter)) = extract_echo_multiline_header(command) {
            let (value, shell_expands) = collect_multiline_github_file_body_without_redirect(
                &commands, &mut index, &delimiter,
            );
            effects.push(ShellFileEffect::Write {
                name,
                value,
                expands: shell_expands,
            });
            continue;
        }
        if let Some((delimiter, shell_expands)) = extract_cat_heredoc_header(command) {
            let command_refs: Vec<&str> = commands.iter().map(String::as_str).collect();
            for (name, value, expands) in collect_cat_heredoc_github_file_writes(
                &command_refs,
                &mut index,
                &delimiter,
                shell_expands,
            ) {
                effects.push(ShellFileEffect::Write {
                    name,
                    value,
                    expands,
                });
            }
            continue;
        }
        push_producer_command_effects(effects, command)?;
    }
    Ok(())
}

/// Process `;`-separated assignments then a command-file producer.
fn push_producer_command_effects(effects: &mut Vec<ShellFileEffect>, command: &str) -> Result<()> {
    let segments = split_shell_group_commands(command);
    if segments.is_empty() {
        return Ok(());
    }
    let mut write_index = None;
    for (index, segment) in segments.iter().enumerate() {
        let trimmed = segment.trim();
        if extract_echo_github_output(trimmed).is_some()
            || !extract_printf_github_output(trimmed).is_empty()
            || extract_bare_string_github_output(trimmed).is_some()
        {
            write_index = Some(index);
        }
    }
    let Some(write_index) = write_index else {
        // Redirected command we cannot classify — fail closed.
        bail!("unsupported GitHub Actions command-file producer `{command}`");
    };
    for segment in &segments[..write_index] {
        push_assignment_effects(effects, segment);
    }
    let producer = segments[write_index].trim();
    if let Some((name, value, expands)) = extract_echo_github_output(producer) {
        effects.push(ShellFileEffect::Write {
            name,
            value,
            expands,
        });
        for segment in &segments[write_index + 1..] {
            push_assignment_effects(effects, segment);
        }
        return Ok(());
    }
    let printf_writes = extract_printf_github_output(producer);
    if !printf_writes.is_empty() {
        for (name, value, expands) in printf_writes {
            effects.push(ShellFileEffect::Write {
                name,
                value,
                expands,
            });
        }
        for segment in &segments[write_index + 1..] {
            push_assignment_effects(effects, segment);
        }
        return Ok(());
    }
    if let Some((name, value, expands)) = extract_bare_string_github_output(producer) {
        effects.push(ShellFileEffect::Write {
            name,
            value,
            expands,
        });
        for segment in &segments[write_index + 1..] {
            push_assignment_effects(effects, segment);
        }
        return Ok(());
    }
    bail!("unsupported GitHub Actions command-file producer `{command}`");
}

fn push_assignment_effects(effects: &mut Vec<ShellFileEffect>, command: &str) {
    for segment in split_shell_group_commands(command) {
        let Some((name, rhs)) = parse_shell_assignment(segment.trim()) else {
            continue;
        };
        let (rhs, expands) = match strip_wrapping_shell_quote_style(rhs.trim()) {
            Some((inner, b'\'')) => (inner, false),
            Some((inner, _)) => (inner, true),
            None => (rhs.trim(), true),
        };
        effects.push(ShellFileEffect::Assignment {
            name: name.to_string(),
            rhs: rhs.to_string(),
            expands,
        });
    }
}

/// Emit leading assignments when a compound command ends in a producer header.
fn push_assignment_effects_before_producer(
    effects: &mut Vec<ShellFileEffect>,
    command: &str,
    is_producer: impl Fn(&str) -> bool,
) {
    let segments = split_shell_group_commands(command);
    let Some(write_index) = segments
        .iter()
        .position(|segment| is_producer(segment.trim()))
    else {
        return;
    };
    for segment in &segments[..write_index] {
        push_assignment_effects(effects, segment);
    }
}

/// Recognize `producer | tee [-a] $GITHUB_*` append/overwrite pipelines.
fn split_github_file_tee_pipeline<'a>(line: &'a str, file_var: &str) -> Option<&'a str> {
    let mut index = 0;
    let bytes = line.as_bytes();
    let mut quote: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(open) = quote {
            if byte == open {
                quote = None;
            }
            index += 1;
            continue;
        }
        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
            index += 1;
            continue;
        }
        if byte == b'|' {
            let before = line[..index].trim();
            let after = line[index + 1..].trim_start();
            let Some(rest) = after.strip_prefix("tee") else {
                index += 1;
                continue;
            };
            let rest = rest.trim_start();
            let rest = if let Some(stripped) = rest.strip_prefix("-a") {
                if stripped.is_empty() || stripped.starts_with(char::is_whitespace) {
                    stripped.trim_start()
                } else {
                    index += 1;
                    continue;
                }
            } else {
                rest
            };
            let target = rest
                .split_whitespace()
                .next()
                .map(strip_wrapping_shell_quotes)
                .unwrap_or("");
            if matches_github_file_var_target(target, file_var)
                && rest.split_whitespace().count() == 1
            {
                return Some(before);
            }
        }
        index += 1;
    }
    None
}

/// True when a command line mentions an Actions command-file variable.
fn line_references_github_file_var(line: &str, file_var: &str) -> bool {
    let patterns = [
        format!("${file_var}"),
        format!("${{{file_var}}}"),
        format!("$env:{file_var}"),
        format!("%{file_var}%"),
    ];
    let lower = line.to_ascii_lowercase();
    patterns.iter().any(|pattern| {
        if pattern.starts_with("$env:") || pattern.starts_with('%') {
            lower.contains(&pattern.to_ascii_lowercase())
        } else {
            line.contains(pattern.as_str())
        }
    })
}

/// Split a `{ ... }` body on newlines and top-level `;` separators.
fn split_shell_group_commands(body: &str) -> Vec<String> {
    let mut commands = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut start = 0;
        let bytes = line.as_bytes();
        let mut index = 0;
        let mut quote: Option<u8> = None;
        while index < bytes.len() {
            let byte = bytes[index];
            if let Some(current) = quote {
                if byte == current {
                    quote = None;
                }
                index += 1;
                continue;
            }
            if byte == b'\'' || byte == b'"' {
                quote = Some(byte);
                index += 1;
                continue;
            }
            if byte == b';' {
                let piece = line[start..index].trim();
                if !piece.is_empty() {
                    commands.push(piece.to_string());
                }
                index += 1;
                start = index;
                continue;
            }
            index += 1;
        }
        let piece = line[start..].trim();
        if !piece.is_empty() {
            commands.push(piece.to_string());
        }
    }
    commands
}

/// Parse `{ ... } >> $GITHUB_*` spanning one or more lines. Returns the group
/// body and the index of the line after the closing redirect.
fn extract_brace_group_redirect_body(
    lines: &[&str],
    start_index: usize,
    file_var: &str,
) -> Option<(String, usize)> {
    let first = lines.get(start_index)?.trim();
    if !first.starts_with('{') {
        return None;
    }

    // Fast path: open brace and redirected close share one line.
    if let Some((inner, _)) = split_closing_brace_redirect(first[1..].trim_start(), file_var) {
        return Some((inner.to_string(), start_index + 1));
    }

    let mut body = String::new();
    // Remainder after `{` on the opening line.
    let after_open = first[1..].trim();
    if !after_open.is_empty() {
        body.push_str(after_open);
    }

    for (offset, line) in lines[start_index + 1..].iter().enumerate() {
        let trimmed = line.trim();
        if let Some((before, _)) = split_line_closing_brace_redirect(trimmed, file_var) {
            if !before.is_empty() {
                if !body.is_empty() {
                    body.push('\n');
                }
                body.push_str(before);
            }
            let body = body.trim().trim_end_matches(';').trim().to_string();
            return Some((body, start_index + 1 + offset + 1));
        }
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str(trimmed);
    }
    None
}

/// Split `inner } >> $GITHUB_*` when the open brace and redirect share a line.
fn split_closing_brace_redirect<'a>(
    after_open: &'a str,
    file_var: &str,
) -> Option<(&'a str, &'a str)> {
    split_line_closing_brace_redirect(after_open, file_var)
}

/// Find a top-level `} >> $GITHUB_*` on `line` and return the text before `}`.
fn split_line_closing_brace_redirect<'a>(
    line: &'a str,
    file_var: &str,
) -> Option<(&'a str, &'a str)> {
    let mut quote: Option<u8> = None;
    let bytes = line.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(current) = quote {
            if byte == current {
                quote = None;
            }
            index += 1;
            continue;
        }
        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
            index += 1;
            continue;
        }
        if byte == b'{' {
            depth += 1;
            index += 1;
            continue;
        }
        if byte == b'}' {
            if depth == 0 {
                let inner = line[..index].trim().trim_end_matches(';').trim();
                let rest = line[index + 1..].trim_start();
                if is_github_file_redirect_target(rest, file_var) {
                    return Some((inner, rest));
                }
                return None;
            }
            depth -= 1;
        }
        index += 1;
    }
    None
}

fn is_github_file_redirect_target(after_close: &str, file_var: &str) -> bool {
    let trimmed = after_close.trim_start();
    if !trimmed.starts_with(">>") {
        return false;
    }
    let after = trimmed.trim_start_matches('>').trim();
    let target = strip_wrapping_shell_quotes(after).trim();
    let target = target
        .split_whitespace()
        .next()
        .map(strip_wrapping_shell_quotes)
        .unwrap_or(target);
    matches_github_file_var_target(target, file_var)
}

/// Collect multiline body lines that are bare `echo` commands (no per-line redirect).
fn collect_multiline_github_file_body_without_redirect(
    commands: &[String],
    index: &mut usize,
    delimiter: &str,
) -> (String, bool) {
    let mut value = String::new();
    let mut shell_expands = false;
    while *index < commands.len() {
        let command = commands[*index].trim();
        *index += 1;
        if command.is_empty() || command.starts_with('#') {
            continue;
        }
        let Some(payload) = extract_echo_payload(command) else {
            break;
        };
        let (payload, expands) = match strip_wrapping_shell_quote_style(payload.trim()) {
            Some((inner, b'\'')) => (inner, false),
            Some((inner, _)) => (inner, true),
            None => (payload.trim(), true),
        };
        if payload == delimiter {
            break;
        }
        if !value.is_empty() {
            value.push('\n');
        }
        value.push_str(payload);
        shell_expands = shell_expands || expands;
    }
    (value, shell_expands)
}

/// Recognize `echo 'name<<EOF'` headers used by GitHub's multiline env-file form.
fn extract_echo_multiline_header(command: &str) -> Option<(String, String)> {
    let payload = extract_echo_payload(command)?;
    let (payload, _) = match strip_wrapping_shell_quote_style(payload.trim()) {
        Some((inner, _)) => (inner, true),
        None => (payload.trim(), true),
    };
    // Prefer `name=value` over `name<<delim` when both markers appear.
    if payload.contains('=') {
        return None;
    }
    let (name, delimiter) = payload.split_once("<<")?;
    let name = name.trim();
    let delimiter = delimiter.trim();
    if !is_github_ident(name) || delimiter.is_empty() || !is_multiline_delimiter(delimiter) {
        return None;
    }
    Some((name.to_string(), delimiter.to_string()))
}

fn is_multiline_delimiter(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Collect body lines after `name<<EOF` until a matching delimiter redirect.
fn collect_multiline_github_file_body(
    lines: &[&str],
    index: &mut usize,
    file_var: &str,
    delimiter: &str,
) -> (String, bool) {
    let mut value = String::new();
    let mut shell_expands = false;
    while *index < lines.len() {
        let trimmed = lines[*index].trim();
        *index += 1;
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(command) = split_github_file_redirect(trimmed, file_var) else {
            // Non-redirect lines are outside the common per-line multiline form.
            break;
        };
        let Some(payload) = extract_echo_payload(command) else {
            break;
        };
        let (payload, expands) = match strip_wrapping_shell_quote_style(payload.trim()) {
            Some((inner, b'\'')) => (inner, false),
            Some((inner, _)) => (inner, true),
            None => (payload.trim(), true),
        };
        if payload == delimiter {
            break;
        }
        if !value.is_empty() {
            value.push('\n');
        }
        value.push_str(payload);
        shell_expands = shell_expands || expands;
    }
    (value, shell_expands)
}

fn extract_echo_github_output(command: &str) -> Option<(String, String, bool)> {
    let payload = extract_echo_payload(command)?;
    let (payload, shell_expands) = match strip_wrapping_shell_quote_style(payload.trim()) {
        Some((inner, b'\'')) => (inner, false),
        Some((inner, _)) => (inner, true),
        None => (payload.trim(), true),
    };
    let (name, value) = payload.split_once('=')?;
    let name = name.trim();
    if !is_github_ident(name) {
        return None;
    }
    Some((name.to_string(), value.trim().to_string(), shell_expands))
}

/// Recognize PowerShell string redirects such as
/// `"title=$env:TITLE" >> $env:GITHUB_OUTPUT` (no `echo`/`printf`).
fn extract_bare_string_github_output(command: &str) -> Option<(String, String, bool)> {
    let (payload, shell_expands) = strip_wrapping_shell_quote_style(command.trim())?;
    let (name, value) = payload.split_once('=')?;
    let name = name.trim();
    if !is_github_ident(name) {
        return None;
    }
    let expands = shell_expands != b'\'';
    Some((name.to_string(), value.trim().to_string(), expands))
}

/// Recognize `printf 'name=%s\n' "$VALUE"` (and similar) redirects to
/// `$GITHUB_OUTPUT` / `$GITHUB_ENV`. Format strings without a leading `name=`
/// are ignored. Only arguments consumed by format conversions contribute to
/// the value (and taint), so `printf 'title=fixed\n' "$TITLE"` stays clean
/// while `printf 'title=prefix-%s\n' "$TITLE"` still propagates `$TITLE`.
///
/// Bash reuses the format to consume remaining arguments, so
/// `printf 'title=%s\n' fixed "$TITLE"` emits two writes (clean, then tainted).
/// Multi-record formats such as `printf 'first=%s\nsecond=%s\n' a "$TITLE"`
/// emit one write per `name=` record in each format cycle.
fn extract_printf_github_output(command: &str) -> Vec<(String, String, bool)> {
    let mut writes = Vec::new();
    let Some(rest) = command.trim().strip_prefix("printf").map(str::trim_start) else {
        return writes;
    };
    let Some((format, after_format, format_expands)) = next_shell_word(rest) else {
        return writes;
    };
    let records = split_printf_output_records(format);
    if records.is_empty() {
        return writes;
    }
    let mut args = Vec::new();
    let mut remaining = after_format;
    while let Some((arg, after, arg_expands)) = next_shell_word(remaining) {
        args.push((arg, arg_expands));
        remaining = after;
    }
    let conversion_counts: Vec<usize> = records
        .iter()
        .map(|(_, fmt_value)| count_printf_conversions(fmt_value))
        .collect();
    let total_conversions: usize = conversion_counts.iter().sum();
    if total_conversions == 0 || args.is_empty() {
        for (name, fmt_value) in records {
            writes.push((name, fmt_value, format_expands));
        }
        return writes;
    }
    // Reuse the whole multi-record format for each cycle of conversions.
    let mut arg_index = 0;
    while arg_index < args.len() {
        let cycle_start = arg_index;
        for ((name, fmt_value), conversion_count) in records.iter().zip(&conversion_counts) {
            let mut value = fmt_value.clone();
            let mut expands = format_expands;
            for _ in 0..*conversion_count {
                if arg_index >= args.len() {
                    break;
                }
                let (arg, arg_expands) = &args[arg_index];
                value.push(' ');
                value.push_str(arg);
                expands = expands || *arg_expands;
                arg_index += 1;
            }
            writes.push((name.clone(), value, expands));
        }
        if arg_index == cycle_start {
            break;
        }
    }
    writes
}

/// Split a printf format into `name=value` records on `\n` escapes / newlines.
fn split_printf_output_records(format: &str) -> Vec<(String, String)> {
    let mut records = Vec::new();
    for piece in split_printf_format_lines(format) {
        let Some((name, fmt_value)) = piece.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !is_github_ident(name) {
            continue;
        }
        records.push((name.to_string(), fmt_value.trim().to_string()));
    }
    records
}

fn split_printf_format_lines(format: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let bytes = format.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            lines.push(&format[start..index]);
            index += 1;
            start = index;
            continue;
        }
        if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'n') {
            lines.push(&format[start..index]);
            index += 2;
            start = index;
            continue;
        }
        index += 1;
    }
    if start < format.len() || lines.is_empty() {
        let tail = &format[start..];
        if !tail.is_empty() || lines.is_empty() {
            lines.push(tail);
        }
    }
    lines
        .into_iter()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

/// Recognize `cat <<EOF` / `cat <<'EOF'` / `cat <<-EOF` producers redirected to
/// Actions command files. Quoted delimiters disable shell expansion in the body.
fn extract_cat_heredoc_header(command: &str) -> Option<(String, bool)> {
    let rest = command.trim().strip_prefix("cat")?.trim_start();
    let rest = rest.strip_prefix("--").map(str::trim_start).unwrap_or(rest);
    let rest = rest.strip_prefix("<<")?;
    let rest = if let Some(stripped) = rest.strip_prefix('-') {
        stripped.trim_start()
    } else {
        rest.trim_start()
    };
    if rest.is_empty() {
        return None;
    }
    // Any quoting of the delimiter disables body expansion (bash heredoc rules).
    let (delimiter, shell_expands) = match strip_wrapping_shell_quote_style(rest.trim()) {
        Some((inner, _)) => (inner.to_string(), false),
        None => (rest.trim().to_string(), true),
    };
    if delimiter.is_empty() || delimiter.contains(char::is_whitespace) {
        return None;
    }
    Some((delimiter, shell_expands))
}

/// Collect `name=value` records from a `cat` heredoc body until the delimiter.
fn collect_cat_heredoc_github_file_writes(
    lines: &[&str],
    index: &mut usize,
    delimiter: &str,
    shell_expands: bool,
) -> Vec<(String, String, bool)> {
    let mut writes = Vec::new();
    while *index < lines.len() {
        let line = lines[*index];
        *index += 1;
        // `<<-` strips leading tabs from the delimiter line; accept either form.
        let trimmed = line.trim_end_matches('\r');
        if trimmed == delimiter || trimmed.trim_start_matches('\t') == delimiter {
            break;
        }
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !is_github_ident(name) {
            continue;
        }
        writes.push((name.to_string(), value.to_string(), shell_expands));
    }
    writes
}

/// Count `printf` conversion specifications in a format string (`%%` is literal).
fn count_printf_conversions(format: &str) -> usize {
    let mut count = 0;
    let mut chars = format.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '%' {
            continue;
        }
        match chars.peek().copied() {
            Some('%') => {
                chars.next();
            }
            Some(_) => {
                for next in chars.by_ref() {
                    if matches!(
                        next,
                        'd' | 'i'
                            | 'o'
                            | 'u'
                            | 'x'
                            | 'X'
                            | 'f'
                            | 'F'
                            | 'e'
                            | 'E'
                            | 'g'
                            | 'G'
                            | 'a'
                            | 'A'
                            | 'c'
                            | 's'
                            | 'p'
                            | 'n'
                    ) {
                        count += 1;
                        break;
                    }
                }
            }
            None => break,
        }
    }
    count
}

/// Split the next shell word, tracking whether it shell-expands.
fn next_shell_word(input: &str) -> Option<(&str, &str, bool)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    let bytes = input.as_bytes();
    if bytes[0] == b'\'' || bytes[0] == b'"' {
        let quote = bytes[0];
        let expands = quote == b'"';
        let rest = &input[1..];
        let end = rest.find(quote as char)?;
        let word = &rest[..end];
        let after = &rest[end + 1..];
        return Some((word, after, expands));
    }
    let end = input.find(char::is_whitespace).unwrap_or(input.len());
    Some((&input[..end], &input[end..], true))
}

fn split_github_file_redirect<'a>(line: &'a str, file_var: &str) -> Option<&'a str> {
    // Locate `>>` outside shell quotes so a payload such as
    // `echo "title=prefix >> $TITLE" >> "$GITHUB_OUTPUT"` keeps the content
    // `>>` and uses the real redirect target.
    let mut index = 0;
    let bytes = line.as_bytes();
    let mut quote: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(open) = quote {
            if byte == open {
                quote = None;
            }
            index += 1;
            continue;
        }
        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
            index += 1;
            continue;
        }
        if byte == b'>' && bytes.get(index + 1) == Some(&b'>') {
            let before = &line[..index];
            let after = line[index..].trim_start_matches('>').trim();
            let target = strip_wrapping_shell_quotes(after).trim();
            // Drop a trailing shell comment so `>> "$GITHUB_OUTPUT" # note` still matches.
            let target = target
                .split_whitespace()
                .next()
                .map(strip_wrapping_shell_quotes)
                .unwrap_or(target);
            if matches_github_file_var_target(target, file_var) {
                return Some(before.trim());
            }
            // Unquoted `>>` that is not the Actions file target: keep scanning.
            index += 2;
            continue;
        }
        index += 1;
    }
    None
}

/// True when `target` names a GitHub Actions environment file via Bash
/// `$VAR` / `${VAR}` / `${VAR:…}` parameter expansions, PowerShell
/// `$env:VAR`, or cmd.exe `%VAR%` syntax.
fn matches_github_file_var_target(target: &str, file_var: &str) -> bool {
    let dollar = format!("${file_var}");
    let braced = format!("${{{file_var}}}");
    let pwsh = format!("$env:{file_var}");
    let cmd = format!("%{file_var}%");
    if target == dollar
        || target == braced
        || target.eq_ignore_ascii_case(&pwsh)
        || target.eq_ignore_ascii_case(&cmd)
    {
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

fn extract_echo_payload(command: &str) -> Option<&str> {
    let trimmed = command.trim();
    let mut rest = trimmed.strip_prefix("echo")?.trim_start();
    // Bash `echo` accepts `-n`, `-e`, `-E`, and combinations such as `-ne`.
    // Strip every leading option token so `echo -e "name=value"` still parses.
    while let Some(token_end) = rest.find(|c: char| c.is_whitespace()) {
        let token = &rest[..token_end];
        if is_echo_option_token(token) {
            rest = rest[token_end..].trim_start();
            continue;
        }
        break;
    }
    if !rest.is_empty() && !rest.contains(char::is_whitespace) && is_echo_option_token(rest) {
        // `echo -n` with no payload
        return None;
    }
    if rest.is_empty() {
        None
    } else {
        Some(rest)
    }
}

fn is_echo_option_token(token: &str) -> bool {
    let mut chars = token.chars();
    if chars.next() != Some('-') {
        return false;
    }
    let rest: String = chars.collect();
    !rest.is_empty() && rest.chars().all(|c| matches!(c, 'n' | 'e' | 'E'))
}

fn strip_wrapping_shell_quotes(value: &str) -> &str {
    match strip_wrapping_shell_quote_style(value) {
        Some((inner, _)) => inner,
        None => value,
    }
}

fn strip_wrapping_shell_quote_style(value: &str) -> Option<(&str, u8)> {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' || first == b'\'') && first == last {
            return Some((&value[1..value.len() - 1], first));
        }
    }
    None
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

fn normalize_env_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// Detect `$NAME` / `${NAME}` / `${NAME:-…}` / `$env:NAME` / `%NAME%` expansions
/// that read a tainted env.
fn value_references_tainted_shell_env(value: &str, tainted_envs: &HashSet<String>) -> bool {
    if tainted_envs.is_empty() {
        return false;
    }
    if value_references_tainted_cmd_env(value, tainted_envs) {
        return true;
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
            // Advance by Unicode scalar so a non-ASCII byte (e.g. in `é`) never
            // leaves `index` mid-character before the next `value[index..]` slice.
            index += value[index..].chars().next().map_or(1, char::len_utf8);
            continue;
        }
        let after_dollar = &value[index + 1..];
        let name = if let Some(rest) = after_dollar.strip_prefix('{') {
            let Some(end) = rest.find('}') else {
                break;
            };
            let inner = rest[..end].trim();
            index += 2 + end + 1;
            // `${TITLE:-fallback}` expands TITLE; parse the ident before operators.
            braced_shell_param_name(inner)
        } else if let Some(rest) = strip_pwsh_env_prefix(after_dollar) {
            // PowerShell `$env:TITLE` (hyphens allowed in the env name).
            let name_len = rest
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
            let name = &rest[..name_len];
            // `$` + `env:` + name
            index += 1 + 4 + name_len;
            name
        } else {
            // POSIX unbraced names stop before `-` so `$TITLE-suffix` reads TITLE.
            let name_len = after_dollar
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
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
        if is_github_ident(name) && tainted_envs.contains(&normalize_env_name(name)) {
            return true;
        }
    }
    false
}

/// Extract the parameter name from a braced expansion body such as
/// `TITLE:-fallback`, `TITLE:?err`, or `#TITLE` (length).
fn braced_shell_param_name(inner: &str) -> &str {
    let inner = inner.strip_prefix('#').unwrap_or(inner);
    let end = inner
        .find([':', '#', '%', '/', '^', ',', '['])
        .unwrap_or(inner.len());
    inner[..end].trim()
}

/// Detect cmd.exe `%NAME%` expansions that read a tainted env.
fn value_references_tainted_cmd_env(value: &str, tainted_envs: &HashSet<String>) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let name_start = index + 1;
        let Some(rel_end) = value[name_start..].find('%') else {
            return false;
        };
        let name = &value[name_start..name_start + rel_end];
        if is_github_ident(name) && tainted_envs.contains(&normalize_env_name(name)) {
            return true;
        }
        index = name_start + rel_end + 1;
    }
    false
}

fn strip_pwsh_env_prefix(after_dollar: &str) -> Option<&str> {
    // Use `get` so a multi-byte scalar straddling offset 4 (e.g. `$é€`) returns
    // None instead of panicking on a non-char boundary.
    let prefix = after_dollar.get(..4)?;
    if prefix.eq_ignore_ascii_case("env:") {
        Some(&after_dollar[4..])
    } else {
        None
    }
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
            || expression_uses_tainted_matrix(expression, taint.matrix)
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

/// Detect `${{ matrix.NAME }}` when `strategy.matrix` bound that property to an
/// untrusted value (direct context, tainted input/env/secret/output, etc.).
fn expression_uses_tainted_matrix(expression: &str, tainted_matrix: &HashSet<String>) -> bool {
    if tainted_matrix.is_empty() {
        return false;
    }
    if expression_reads_whole_context(expression, "matrix") {
        return true;
    }
    // Expression-valued matrices expose unknown keys; any matrix property /
    // index / wildcard read is treated as tainted.
    if tainted_matrix.contains(MATRIX_EXPRESSION_UNKNOWN_KEYS) {
        return expression_references_any_matrix_property(expression);
    }
    expression_uses_tainted_context_property(expression, "matrix", tainted_matrix)
}

/// True when `expression` references any `matrix` property or index, including
/// named keys that are unknown for expression-valued matrices.
fn expression_references_any_matrix_property(expression: &str) -> bool {
    static MATRIX_ANY: OnceLock<Regex> = OnceLock::new();
    let pattern = MATRIX_ANY.get_or_init(|| {
        Regex::new(
            r#"(?i)\bmatrix\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])"#,
        )
        .expect("any matrix reference pattern compiles")
    });
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
        true
    })
}

/// Detect `${{ steps.<id>.outputs.<name> }}` when a prior step wrote a tainted
/// value to `$GITHUB_OUTPUT`. Whole-context / wildcard reads such as
/// `toJSON(steps)`, bare `steps`, or `steps.*.outputs.title` are tainted when
/// any step output in scope is tainted.
fn expression_uses_tainted_step_output(
    expression: &str,
    tainted_step_outputs: &HashSet<String>,
) -> bool {
    if tainted_step_outputs.is_empty() {
        return false;
    }
    if expression_reads_whole_context(expression, "steps") {
        return true;
    }
    expression_uses_tainted_nested_output(expression, "steps", tainted_step_outputs)
}

/// Detect `${{ needs.<job>.outputs.<name> }}` when a peer job exposed a tainted
/// output. Whole-context / wildcard reads such as `toJSON(needs)` or
/// `needs.*.outputs.title` are tainted whenever any job output is tainted.
fn expression_uses_tainted_job_output(
    expression: &str,
    tainted_job_outputs: &HashSet<String>,
) -> bool {
    if tainted_job_outputs.is_empty() {
        return false;
    }
    if expression_reads_whole_context(expression, "needs") {
        return true;
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
    static JOBS_REF: OnceLock<Regex> = OnceLock::new();
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
        "jobs" => JOBS_REF.get_or_init(|| {
            Regex::new(
                r#"(?i)\bjobs\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])\s*\.\s*outputs\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])?"#,
            )
            .expect("tainted jobs output reference pattern compiles")
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
    static MATRIX_REF: OnceLock<Regex> = OnceLock::new();
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
        "matrix" => MATRIX_REF.get_or_init(|| {
            Regex::new(
                r#"(?i)\bmatrix\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?:['"]([^'"]+)['"]|([^\]]+?))\s*\])"#,
            )
            .expect("tainted matrix reference pattern compiles")
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
        name.is_some_and(|name| {
            if context == "env" {
                tainted_names.contains(&normalize_env_name(name))
            } else {
                tainted_names.contains(name)
            }
        })
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
                matrix: &empty,
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

    #[test]
    fn needs_relay_job_output_fixed_point_propagates_taint() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/caller.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  relay:
    needs: producer
    runs-on: ubuntu-latest
    outputs:
      title: ${{ needs.producer.outputs.title }}
    steps:
      - run: echo relay
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
    needs: relay
    uses: ./.github/workflows/reusable.yml
    with:
      title: ${{ needs.relay.outputs.title }}
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
    fn composite_declared_output_propagates_to_caller_step_outputs() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/caller.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - id: action
        uses: ./.github/actions/echo
        with:
          title: ${{ github.event.issue.title }}
      - run: echo "${{ steps.action.outputs.title }}"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/echo/action.yml".to_string(),
                content: r#"
name: Echo title
description: Export tainted input
inputs:
  title:
    required: true
outputs:
  title:
    value: ${{ steps.set.outputs.title }}
runs:
  using: composite
  steps:
    - id: set
      shell: bash
      run: echo "title=${{ inputs.title }}" >> "$GITHUB_OUTPUT"
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("steps.action.outputs.title")
                && finding.location.as_deref() == Some(".github/workflows/caller.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn single_quoted_github_output_write_keeps_literal_shell_text() {
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
        run: echo 'title=$TITLE' >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.set.outputs.title }}"
"#,
        );

        assert!(findings.iter().all(|finding| {
            finding.rule_id != "AGT-06-workflow-context-injection"
                || !finding.detail.contains("steps.set.outputs.title")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Allow);
    }

    #[test]
    fn github_output_shell_scan_advances_past_utf8_without_panic() {
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
        run: echo "title=é $TITLE" >> "$GITHUB_OUTPUT"
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

    #[test]
    fn printf_github_output_write_propagates_shell_env_taint() {
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
        run: printf 'title=%s\n' "$TITLE" >> "$GITHUB_OUTPUT"
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

    #[test]
    fn env_context_taint_lookup_is_case_insensitive() {
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
      - run: echo "${{ env.title }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env.title")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn reusable_workflow_call_outputs_propagate_to_caller_needs() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/caller.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    with:
      title: ${{ github.event.issue.title }}
  consume:
    needs: call
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ needs.call.outputs.title }}"
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
    outputs:
      title:
        value: ${{ jobs.echo.outputs.title }}
jobs:
  echo:
    runs-on: ubuntu-latest
    outputs:
      title: ${{ steps.set.outputs.title }}
    steps:
      - id: set
        run: echo "title=${{ inputs.title }}" >> "$GITHUB_OUTPUT"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("needs.call.outputs.title")
                && finding.location.as_deref() == Some(".github/workflows/caller.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn github_env_file_write_taints_later_step_env_interpolation() {
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
      - run: echo "ALIAS=$TITLE" >> "$GITHUB_ENV"
      - run: echo "${{ env.ALIAS }}"
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
    fn steps_whole_context_and_wildcard_output_reads_are_tainted() {
        let to_json = findings_for(
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
      - run: echo '${{ toJSON(steps) }}'
"#,
        );
        let wildcard = findings_for(
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
      - run: echo "${{ steps.*.outputs.title }}"
"#,
        );

        assert!(to_json.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("toJSON(steps)")
        }));
        assert!(wildcard.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("steps.*.outputs.title")
        }));
        assert_eq!(crate::decision::derive(&to_json), Decision::Block);
        assert_eq!(crate::decision::derive(&wildcard), Decision::Block);
    }

    #[test]
    fn printf_github_output_prefix_format_propagates_shell_env_taint() {
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
        run: printf 'title=prefix-%s\n' "$TITLE" >> "$GITHUB_OUTPUT"
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

    #[test]
    fn composite_github_env_write_taints_caller_later_step() {
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
      - uses: ./.github/actions/export
      - run: echo "${{ env.ALIAS }}"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/export/action.yml".to_string(),
                content: r#"
name: Export alias
description: Write tainted env for the caller
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "ALIAS=$TITLE" >> "$GITHUB_ENV"
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("env.ALIAS")
                && finding.location.as_deref() == Some(".github/workflows/echo.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn later_clean_github_output_overwrite_clears_prior_taint() {
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
        run: |
          echo "title=$TITLE" >> "$GITHUB_OUTPUT"
          echo "title=fixed" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.set.outputs.title }}"
"#,
        );

        assert!(findings.iter().all(|finding| {
            finding.rule_id != "AGT-06-workflow-context-injection"
                || !finding.detail.contains("steps.set.outputs.title")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Allow);
    }

    #[test]
    fn multiline_github_output_record_propagates_shell_env_taint() {
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
        run: |
          echo 'title<<EOF' >> "$GITHUB_OUTPUT"
          echo "$TITLE" >> "$GITHUB_OUTPUT"
          echo 'EOF' >> "$GITHUB_OUTPUT"
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

    #[test]
    fn unbraced_shell_var_stops_before_hyphen_suffix() {
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
        run: echo "out=$TITLE-suffix" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.set.outputs.out }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("steps.set.outputs.out")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn pwsh_env_github_output_redirect_propagates_shell_env_taint() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: windows-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - id: set
        shell: pwsh
        run: echo "title=$env:TITLE" >> $env:GITHUB_OUTPUT
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

    #[test]
    fn pwsh_prefix_scan_tolerates_utf8_before_env_marker() {
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
        run: echo "title=$é€$TITLE" >> "$GITHUB_OUTPUT"
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

    #[test]
    fn grouped_multiline_github_output_redirect_propagates_shell_env_taint() {
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
        run: |
          { echo 'title<<EOF'
            echo "$TITLE"
            echo EOF
          } >> "$GITHUB_OUTPUT"
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

    #[test]
    fn grouped_oneline_multiline_github_output_redirect_propagates_taint() {
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
        run: "{ echo 'title<<EOF'; echo \"$TITLE\"; echo EOF; } >> \"$GITHUB_OUTPUT\""
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

    #[test]
    fn bare_pwsh_string_github_output_redirect_propagates_shell_env_taint() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: windows-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - id: set
        shell: pwsh
        run: '"title=$env:TITLE" >> $env:GITHUB_OUTPUT'
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

    #[test]
    fn conditional_clean_github_output_overwrite_retains_prior_taint() {
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
        run: |
          echo "title=$TITLE" >> "$GITHUB_OUTPUT"
          if false; then
            echo "title=fixed" >> "$GITHUB_OUTPUT"
          fi
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

    #[test]
    fn braced_shell_param_default_propagates_taint_to_github_output() {
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
        run: echo "title=${TITLE:-fallback}" >> "$GITHUB_OUTPUT"
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

    #[test]
    fn cmd_percent_github_output_redirect_propagates_shell_env_taint() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: windows-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - id: set
        shell: cmd
        run: echo title=%TITLE%>>%GITHUB_OUTPUT%
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

    #[test]
    fn echo_dash_e_github_output_write_propagates_shell_env_taint() {
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
        run: echo -e "title=$TITLE" >> "$GITHUB_OUTPUT"
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

    #[test]
    fn strategy_matrix_input_taint_propagates_into_inline_script() {
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
    strategy:
      matrix:
        title: ["${{ inputs.title }}"]
    steps:
      - run: echo "${{ matrix.title }}"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("matrix.title")
                && finding.location.as_deref() == Some(".github/workflows/reusable.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn expression_valued_strategy_matrix_fromjson_propagates_taint() {
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
      payload: ${{ toJSON(github.event) }}
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
      payload:
        type: string
        required: true
jobs:
  echo:
    runs-on: ubuntu-latest
    strategy:
      matrix: ${{ fromJSON(inputs.payload) }}
    steps:
      - run: echo "${{ matrix.title }}"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("matrix.title")
                && finding.location.as_deref() == Some(".github/workflows/reusable.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn quoted_redirect_payload_with_inner_arrows_propagates_shell_env_taint() {
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
        run: echo "title=prefix >> $TITLE" >> "$GITHUB_OUTPUT"
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

    #[test]
    fn printf_unused_argument_does_not_taint_github_output() {
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
        run: printf 'title=fixed\n' "$TITLE" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.set.outputs.title }}"
"#,
        );

        assert!(!findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.detail.contains("steps.set.outputs.title")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Allow);
    }

    #[test]
    fn shell_local_alias_propagates_taint_to_github_output() {
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
        run: |
          ALIAS=$TITLE
          echo "out=$ALIAS" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.set.outputs.out }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("steps.set.outputs.out")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn cat_heredoc_github_output_propagates_shell_env_taint() {
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
        run: |
          cat <<EOF >> "$GITHUB_OUTPUT"
          title=$TITLE
          EOF
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

    #[test]
    fn printf_format_reuse_propagates_later_tainted_argument() {
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
        run: printf 'title=%s\n' fixed "$TITLE" >> "$GITHUB_OUTPUT"
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

    #[test]
    fn container_env_taint_propagates_into_github_output() {
        let findings = findings_for(
            r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    container:
      image: node:20
      env:
        TITLE: ${{ github.event.issue.title }}
    steps:
      - id: set
        run: echo "out=$TITLE" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.set.outputs.out }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("steps.set.outputs.out")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn composite_github_env_declared_output_propagates_to_caller() {
        let files = [
            SurfaceFile {
                rel: ".github/workflows/caller.yml".to_string(),
                content: r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - id: action
        uses: ./.github/actions/echo
        with:
          title: ${{ github.event.issue.title }}
      - run: echo "${{ steps.action.outputs.title }}"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
            SurfaceFile {
                rel: ".github/actions/echo/action.yml".to_string(),
                content: r#"
name: Echo title
description: Export env written via GITHUB_ENV
inputs:
  title:
    required: true
outputs:
  title:
    value: ${{ env.ALIAS }}
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "ALIAS=${{ inputs.title }}" >> "$GITHUB_ENV"
"#
                .to_string(),
                kind: SurfaceKind::ActionMetadata,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("steps.action.outputs.title")
                && finding.location.as_deref() == Some(".github/workflows/caller.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn expression_valued_matrix_include_fromjson_propagates_taint() {
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
      rows: ${{ toJSON(github.event) }}
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
      rows:
        type: string
        required: true
jobs:
  echo:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include: ${{ fromJSON(inputs.rows) }}
    steps:
      - run: echo "${{ matrix.title }}"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("matrix.title")
                && finding.location.as_deref() == Some(".github/workflows/reusable.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn object_valued_matrix_dimension_propagates_nested_taint() {
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
    strategy:
      matrix:
        target:
          - title: "${{ inputs.title }}"
    steps:
      - run: echo "${{ matrix.target.title }}"
"#
                .to_string(),
                kind: SurfaceKind::Workflow,
            },
        ];
        let findings = findings_for_files(&files);

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("matrix.target")
                && finding.location.as_deref() == Some(".github/workflows/reusable.yml")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn shell_local_alias_clean_overwrite_clears_prior_taint() {
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
        run: |
          ALIAS=$TITLE
          ALIAS=fixed
          echo "out=$ALIAS" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.set.outputs.out }}"
"#,
        );

        assert!(findings.iter().all(|finding| {
            finding.rule_id != "AGT-06-workflow-context-injection"
                || !finding.detail.contains("steps.set.outputs.out")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Allow);
    }

    #[test]
    fn shell_local_alias_taint_at_write_survives_later_clean_reassignment() {
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
        run: |
          ALIAS=$TITLE
          echo "out=$ALIAS" >> "$GITHUB_OUTPUT"
          ALIAS=fixed
      - run: echo "${{ steps.set.outputs.out }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("steps.set.outputs.out")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn printf_multi_record_format_tracks_each_named_output() {
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
        run: printf 'first=%s\nsecond=%s\n' fixed "$TITLE" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.set.outputs.second }}"
"#,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "AGT-06-workflow-context-injection"
                && finding.severity == Severity::Critical
                && finding.detail.contains("steps.set.outputs.second")
        }));
        assert!(findings.iter().all(|finding| {
            finding.rule_id != "AGT-06-workflow-context-injection"
                || !finding.detail.contains("steps.set.outputs.first")
        }));
        assert_eq!(crate::decision::derive(&findings), Decision::Block);
    }

    #[test]
    fn tee_pipeline_github_output_propagates_shell_env_taint() {
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
        run: printf 'title=%s\n' "$TITLE" | tee -a "$GITHUB_OUTPUT"
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

    #[test]
    fn unsupported_github_output_producer_is_incomplete_scan_error() {
        let file = SurfaceFile {
            rel: ".github/workflows/test.yml".to_string(),
            content: r#"
name: Echo issue
on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - id: set
        run: custom_writer "$TITLE" > "$GITHUB_OUTPUT"
      - run: echo "${{ steps.set.outputs.title }}"
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
                matrix: &empty,
            },
            &actions,
            &workflows,
            &mut visiting,
            &mut findings,
        )
        .expect_err("unsupported GITHUB_OUTPUT producer");
        assert!(
            error
                .to_string()
                .contains("unsupported `$GITHUB_OUTPUT` producer"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn split_github_file_redirect_accepts_cmd_percent_syntax() {
        assert_eq!(
            split_github_file_redirect(r#"echo title=%TITLE%>>%GITHUB_OUTPUT%"#, "GITHUB_OUTPUT"),
            Some(r#"echo title=%TITLE%"#)
        );
        assert_eq!(
            split_github_file_redirect(
                r#"echo "title=prefix >> $TITLE" >> "$GITHUB_OUTPUT""#,
                "GITHUB_OUTPUT"
            ),
            Some(r#"echo "title=prefix >> $TITLE""#)
        );
        assert!(matches_github_file_var_target(
            "%GITHUB_OUTPUT%",
            "GITHUB_OUTPUT"
        ));
        assert!(is_braced_github_file_ref(
            "${GITHUB_OUTPUT:-fallback}",
            "GITHUB_OUTPUT"
        ));
        assert_eq!(
            extract_echo_payload(r#"echo -e "title=$TITLE""#),
            Some(r#""title=$TITLE""#)
        );
        assert_eq!(
            extract_echo_payload(r#"echo -ne "title=$TITLE""#),
            Some(r#""title=$TITLE""#)
        );
        assert_eq!(count_printf_conversions(r#"title=fixed\n"#), 0);
        assert_eq!(count_printf_conversions(r#"title=%s\n"#), 1);
        assert_eq!(count_printf_conversions(r#"title=%%s\n"#), 0);
    }
}
