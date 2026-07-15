//! Regression-corpus execution and explicitly scoped evaluation metrics.

use crate::{corpus_path, Format};
use anyhow::{bail, ensure, Context, Result};
use argus_agent::scan_agent_surface;
use argus_core::ScanReport;
use argus_rules::{scan_lockfile, scan_package_dir};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const SYNTHETIC_DATASET_TYPE: &str = "synthetic-fixtures";

#[derive(Debug, Deserialize)]
struct CorpusIndex {
    #[serde(default)]
    surface: Option<String>,
    #[serde(default)]
    evaluation: Option<EvaluationContract>,
    cases: Vec<CorpusCase>,
}

#[derive(Debug, Deserialize)]
struct CorpusCase {
    id: String,
    kind: String,
    path: String,
    #[serde(rename = "expectedDecision")]
    expected_decision: String,
    rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvaluationContract {
    schema_version: u8,
    dataset_type: String,
    label_source: String,
    positive_decision: String,
    frozen: bool,
}

#[derive(Debug, Serialize, PartialEq)]
struct EvaluationReport {
    schema_version: u8,
    dataset_type: String,
    label_source: String,
    positive_decision: String,
    sample_count: usize,
    true_positives: usize,
    false_positives: usize,
    false_negatives: usize,
    true_negatives: usize,
    precision: f64,
    recall: f64,
}

pub(crate) fn cmd_test(corpus_root: &Path) -> Result<ExitCode> {
    let mut passed = 0usize;
    let mut total = 0usize;
    let mut failed: Vec<String> = Vec::new();

    for index_path in corpus_index_paths(corpus_root)? {
        let index = load_index(&index_path)?;
        let index_root = index_path
            .parent()
            .with_context(|| format!("resolve corpus index parent {}", index_path.display()))?;
        println!("index: {}", index_path.display());

        for case in &index.cases {
            total += 1;
            let report = match scan_case(index_root, &index, case) {
                Ok(report) => report,
                Err(error) => {
                    failed.push(format!("{} — {error:#}", case.id));
                    continue;
                }
            };
            let actual_decision = report.decision.as_str().to_string();
            let actual_rules = corpus_rule_ids(&report, index.surface.as_deref());
            let expected_rules: BTreeSet<String> = case.rules.iter().cloned().collect();

            let mut deltas: Vec<String> = Vec::new();
            if actual_decision != case.expected_decision {
                deltas.push(format!(
                    "decision expected `{}` got `{actual_decision}`",
                    case.expected_decision
                ));
            }
            let missing: Vec<&String> = expected_rules.difference(&actual_rules).collect();
            let extra: Vec<&String> = actual_rules.difference(&expected_rules).collect();
            if !missing.is_empty() {
                deltas.push(format!("missing rules: {missing:?}"));
            }
            if !extra.is_empty() {
                deltas.push(format!("extra rules: {extra:?}"));
            }

            if deltas.is_empty() {
                passed += 1;
                println!(
                    "  PASS  {:<32}  {}  [{}]",
                    case.id,
                    actual_decision,
                    join_sorted(&actual_rules)
                );
            } else {
                failed.push(format!("{} — {}", case.id, deltas.join("; ")));
                println!(
                    "  FAIL  {:<32}  {}  [{}]",
                    case.id,
                    actual_decision,
                    join_sorted(&actual_rules)
                );
                for delta in &deltas {
                    println!("        > {delta}");
                }
            }
        }
    }

    println!();
    println!("argus corpus test: {passed}/{total} passed");
    if !failed.is_empty() {
        println!("failures:");
        for failure in &failed {
            println!("  - {failure}");
        }
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::from(0))
}

pub(crate) fn cmd_eval(corpus_root: &Path, format: Format) -> Result<ExitCode> {
    let mut reports = Vec::new();
    for index_path in corpus_index_paths(corpus_root)? {
        let index = load_index(&index_path)?;
        let Some(contract) = &index.evaluation else {
            continue;
        };
        validate_evaluation_contract(contract, &index_path)?;
        let index_root = index_path
            .parent()
            .with_context(|| format!("resolve corpus index parent {}", index_path.display()))?;
        let mut labels_and_predictions = Vec::with_capacity(index.cases.len());
        for case in &index.cases {
            validate_decision(&case.expected_decision, &case.id)?;
            let report = scan_case(index_root, &index, case)
                .with_context(|| format!("evaluate corpus case {}", case.id))?;
            labels_and_predictions.push((
                case.expected_decision == contract.positive_decision,
                report.decision.as_str() == contract.positive_decision,
            ));
        }
        reports.push(compute_evaluation_report(
            contract,
            &labels_and_predictions,
        )?);
    }
    if reports.is_empty() {
        bail!(
            "no corpus evaluation contract found under {}",
            corpus_root.display()
        );
    }

    match format {
        Format::Json if reports.len() == 1 => {
            println!("{}", serde_json::to_string_pretty(&reports[0])?)
        }
        Format::Json => println!("{}", serde_json::to_string_pretty(&reports)?),
        Format::Text => {
            for report in &reports {
                println!("dataset_type: {}", report.dataset_type);
                println!("label_source: {}", report.label_source);
                println!("positive_decision: {}", report.positive_decision);
                println!("sample_count: {}", report.sample_count);
                println!(
                    "confusion_matrix: TP={} FP={} FN={} TN={}",
                    report.true_positives,
                    report.false_positives,
                    report.false_negatives,
                    report.true_negatives
                );
                println!("precision: {:.4}", report.precision);
                println!("recall: {:.4}", report.recall);
            }
        }
    }
    Ok(ExitCode::from(0))
}

fn compute_evaluation_report(
    contract: &EvaluationContract,
    labels_and_predictions: &[(bool, bool)],
) -> Result<EvaluationReport> {
    let mut tp = 0;
    let mut fp = 0;
    let mut fn_count = 0;
    let mut tn = 0;
    for &(label, prediction) in labels_and_predictions {
        match (label, prediction) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (true, false) => fn_count += 1,
            (false, false) => tn += 1,
        }
    }
    let predicted_positives = tp + fp;
    let actual_positives = tp + fn_count;
    ensure!(
        predicted_positives > 0,
        "precision is undefined because the evaluated detector predicted no positives"
    );
    ensure!(
        actual_positives > 0,
        "recall is undefined because the evaluation set has no positive labels"
    );
    Ok(EvaluationReport {
        schema_version: 1,
        dataset_type: contract.dataset_type.clone(),
        label_source: contract.label_source.clone(),
        positive_decision: contract.positive_decision.clone(),
        sample_count: labels_and_predictions.len(),
        true_positives: tp,
        false_positives: fp,
        false_negatives: fn_count,
        true_negatives: tn,
        precision: tp as f64 / predicted_positives as f64,
        recall: tp as f64 / actual_positives as f64,
    })
}

fn validate_evaluation_contract(contract: &EvaluationContract, path: &Path) -> Result<()> {
    ensure!(
        contract.schema_version == 1,
        "{}: unsupported evaluation schemaVersion {}",
        path.display(),
        contract.schema_version
    );
    ensure!(
        contract.frozen,
        "{}: evaluation contract must declare frozen=true",
        path.display()
    );
    ensure!(
        contract.dataset_type == SYNTHETIC_DATASET_TYPE,
        "{}: datasetType must be `{SYNTHETIC_DATASET_TYPE}`",
        path.display()
    );
    ensure!(
        !contract.label_source.trim().is_empty(),
        "{}: labelSource must not be empty",
        path.display()
    );
    ensure!(
        contract.positive_decision == "block",
        "{}: positiveDecision must be `block`",
        path.display()
    );
    Ok(())
}

fn validate_decision(decision: &str, case_id: &str) -> Result<()> {
    ensure!(
        matches!(decision, "allow" | "allow-with-approval" | "block"),
        "{case_id}: unsupported expectedDecision `{decision}`"
    );
    Ok(())
}

fn load_index(path: &Path) -> Result<CorpusIndex> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read corpus index {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse corpus index {}", path.display()))
}

fn scan_case(index_root: &Path, index: &CorpusIndex, case: &CorpusCase) -> Result<ScanReport> {
    let kind = match case.kind.as_str() {
        "fixture" => corpus_path::CaseKind::Fixture,
        "lockfile" => corpus_path::CaseKind::Lockfile,
        unknown => bail!("unknown kind `{unknown}`"),
    };
    let case_path = corpus_path::resolve_case_path(index_root, Path::new(&case.path), kind)?;
    if matches!(kind, corpus_path::CaseKind::Fixture) {
        if index.surface.as_deref() == Some("agent-skill") {
            scan_agent_surface(&case_path)
        } else {
            scan_package_dir(&case_path)
        }
    } else {
        scan_lockfile(&case_path)
    }
    .context("scan corpus case")
}

fn corpus_index_paths(corpus_root: &Path) -> Result<Vec<PathBuf>> {
    let root_index = corpus_root.join("index.json");
    let mut paths = Vec::new();
    if root_index.exists() {
        paths.push(root_index);
    }
    for entry in std::fs::read_dir(corpus_root)
        .with_context(|| format!("read corpus directory {}", corpus_root.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let nested = entry.path().join("index.json");
            if nested.exists() {
                paths.push(nested);
            }
        }
    }
    paths.sort();
    if paths.is_empty() {
        bail!(
            "no corpus index found under {} (expected index.json)",
            corpus_root.display()
        );
    }
    Ok(paths)
}

fn corpus_rule_ids(report: &ScanReport, surface: Option<&str>) -> BTreeSet<String> {
    if surface != Some("agent-skill") {
        return report.rule_ids().into_iter().collect();
    }
    let mut rules = BTreeSet::new();
    for finding in &report.findings {
        match finding.rule_id.as_str() {
            "AGT-01-injection-language" => {
                rules.insert(if is_concealment_pattern(&finding.detail) {
                    "concealment".to_string()
                } else {
                    "injection-override".to_string()
                });
            }
            "AGT-03-secret-exfil" => {
                rules.insert("credential-access".to_string());
                rules.insert("network-exfiltration".to_string());
            }
            "AGT-03-remote-exec" => {
                rules.insert("remote-download".to_string());
                rules.insert("shell-pipe-execution".to_string());
            }
            id if !id.starts_with("AGT-") => {
                rules.insert(id.to_string());
            }
            _ => {}
        }
    }
    rules
}

fn is_concealment_pattern(detail: &str) -> bool {
    detail.contains("do\\s+not")
        || detail.contains("hide")
        || detail.contains("静默执行")
        || detail.contains("不要提及")
}

fn join_sorted(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_corpus() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/agent")
    }

    fn contract() -> EvaluationContract {
        EvaluationContract {
            schema_version: 1,
            dataset_type: SYNTHETIC_DATASET_TYPE.to_string(),
            label_source: "maintainer labels".to_string(),
            positive_decision: "block".to_string(),
            frozen: true,
        }
    }

    #[test]
    fn metrics_cover_all_confusion_matrix_cells() {
        let report = compute_evaluation_report(
            &contract(),
            &[(true, true), (false, true), (true, false), (false, false)],
        )
        .unwrap();
        assert_eq!(report.true_positives, 1);
        assert_eq!(report.false_positives, 1);
        assert_eq!(report.false_negatives, 1);
        assert_eq!(report.true_negatives, 1);
        assert_eq!(report.precision, 0.5);
        assert_eq!(report.recall, 0.5);
    }

    #[test]
    fn metrics_reject_undefined_denominators() {
        assert!(compute_evaluation_report(&contract(), &[(false, false)]).is_err());
        assert!(compute_evaluation_report(&contract(), &[(true, false)]).is_err());
    }

    #[test]
    fn corpus_commands_execute_the_frozen_agent_dataset() {
        cmd_test(&agent_corpus()).expect("corpus test command");
        cmd_eval(&agent_corpus(), Format::Json).expect("JSON corpus eval command");
        cmd_eval(&agent_corpus(), Format::Text).expect("text corpus eval command");
    }

    #[test]
    fn evaluation_contract_validation_fails_closed() {
        let path = Path::new("index.json");
        let mut invalid = contract();
        invalid.frozen = false;
        assert!(validate_evaluation_contract(&invalid, path).is_err());

        invalid = contract();
        invalid.dataset_type = "real-world".to_string();
        assert!(validate_evaluation_contract(&invalid, path).is_err());

        assert!(validate_decision("review", "case-1").is_err());
    }
}
