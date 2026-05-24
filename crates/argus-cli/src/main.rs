//! argus CLI binary.
//!
//! Two subcommands at Milestone 0:
//! - `argus scan <path>`         — scan one package directory or lockfile.
//! - `argus corpus test ...`     — run the regression corpus and diff against
//!                                 each case's `expectedDecision` + `rules`.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use argus_core::{Decision, ScanReport};
use argus_rules::{scan_lockfile, scan_package_dir};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "argus", version, about = "Supply-chain install guard for npm/JS")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Scan a package directory or an npm lockfile.
    Scan {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Regression-corpus operations.
    Corpus {
        #[command(subcommand)]
        op: CorpusOp,
    },
}

#[derive(Subcommand, Debug)]
enum CorpusOp {
    /// Run every case in the corpus and verify expected decision and rules.
    Test {
        /// Path to the corpus directory (must contain `index.json`).
        #[arg(long, default_value = "../safepm-test-corpus")]
        corpus: PathBuf,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum Format {
    Text,
    Json,
}

#[derive(Debug, Deserialize)]
struct CorpusIndex {
    cases: Vec<CorpusCase>,
}

#[derive(Debug, Deserialize)]
struct CorpusCase {
    id: String,
    kind: String, // "fixture" or "lockfile"
    path: String,
    #[serde(rename = "expectedDecision")]
    expected_decision: String,
    rules: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("argus: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Scan { path, format } => cmd_scan(&path, format),
        Cmd::Corpus { op: CorpusOp::Test { corpus } } => cmd_corpus_test(&corpus),
    }
}

fn cmd_scan(path: &Path, format: Format) -> Result<ExitCode> {
    let report = scan_path(path)?;
    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Format::Text => print_report_text(&report),
    }
    let code = match report.decision {
        Decision::Allow => 0,
        Decision::AllowWithApproval => 0,
        Decision::Block => 1,
    };
    Ok(ExitCode::from(code))
}

fn scan_path(path: &Path) -> Result<ScanReport> {
    if path.is_dir() {
        scan_package_dir(path).with_context(|| format!("scan dir {}", path.display()))
    } else if path.is_file() {
        scan_lockfile(path).with_context(|| format!("scan lockfile {}", path.display()))
    } else {
        bail!("path is neither a directory nor a file: {}", path.display());
    }
}

fn print_report_text(report: &ScanReport) {
    println!(
        "decision: {}  package: {}",
        report.decision.as_str(),
        report
            .package_name
            .as_deref()
            .unwrap_or("<unnamed>"),
    );
    println!("path: {}", report.path.display());
    if report.findings.is_empty() {
        println!("findings: none");
        return;
    }
    println!("findings:");
    for f in &report.findings {
        let loc = f.location.as_deref().unwrap_or("");
        println!("  - [{}] {} — {} ({})", severity_tag(f), f.rule_id, f.detail, loc);
    }
}

fn severity_tag(f: &argus_core::Finding) -> &'static str {
    match f.severity {
        argus_core::Severity::Critical => "CRIT",
        argus_core::Severity::High => "HIGH",
        argus_core::Severity::Medium => "MED ",
        argus_core::Severity::Low => "LOW ",
        argus_core::Severity::Info => "INFO",
    }
}

fn cmd_corpus_test(corpus_root: &Path) -> Result<ExitCode> {
    let index_path = corpus_root.join("index.json");
    let raw = std::fs::read_to_string(&index_path)
        .with_context(|| format!("read corpus index {}", index_path.display()))?;
    let index: CorpusIndex = serde_json::from_str(&raw)
        .with_context(|| format!("parse corpus index {}", index_path.display()))?;

    let mut passed = 0usize;
    let mut failed: Vec<String> = Vec::new();

    for case in &index.cases {
        let case_path = corpus_root.join(&case.path);
        let report = match case.kind.as_str() {
            "fixture" => scan_package_dir(&case_path),
            "lockfile" => scan_lockfile(&case_path),
            other => {
                failed.push(format!("{} — unknown kind `{}`", case.id, other));
                continue;
            }
        };
        let report = match report {
            Ok(r) => r,
            Err(e) => {
                failed.push(format!("{} — scan error: {e:#}", case.id));
                continue;
            }
        };

        let actual_decision = report.decision.as_str().to_string();
        let actual_rules: BTreeSet<String> = report.rule_ids().into_iter().collect();
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
            for d in &deltas {
                println!("        > {d}");
            }
        }
    }

    let total = index.cases.len();
    println!();
    println!("argus corpus test: {passed}/{total} passed");
    if !failed.is_empty() {
        println!("failures:");
        for f in &failed {
            println!("  - {f}");
        }
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::from(0))
}

fn join_sorted(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(",")
}
