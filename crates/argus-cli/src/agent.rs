//! `argus agent scan` command handling, including AGT-02 baseline modes.

use crate::{print_report_text, Format};
use anyhow::{bail, Context, Result};
use argus_agent::{scan_agent_surface_with_baseline, BaselineMode};
use argus_core::Decision;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Scan each path as an agent surface. The exit code is the worst decision
/// across all paths (block > allow-with-approval > allow), so a CI gate over
/// several directories fails if any one of them is bad.
///
/// AGT-02 baseline modes (`--baseline` / `--update-baseline` are mutually
/// exclusive, enforced by clap):
/// - `--update-baseline <file>`: (re)write the baseline from the scanned
///   surface, print `baseline written: N entries` to stderr, exit 0.
/// - `--baseline <file>`: compare against the approved baseline; drift is a
///   medium AGT-02 finding → allow-with-approval (does not force exit non-zero
///   on its own).
pub fn cmd_agent_scan(
    paths: &[PathBuf],
    format: Format,
    baseline: Option<&Path>,
    update_baseline: Option<&Path>,
) -> Result<ExitCode> {
    let mut reports = Vec::with_capacity(paths.len());
    for path in paths {
        if !path.exists() {
            bail!("path does not exist: {}", path.display());
        }
        let mode = match (baseline, update_baseline) {
            (Some(b), _) => BaselineMode::Check(b),
            (_, Some(u)) => BaselineMode::Update(u),
            _ => BaselineMode::None,
        };
        let report = scan_agent_surface_with_baseline(path, mode)
            .with_context(|| format!("agent scan {}", path.display()))?;
        reports.push(report);
    }

    match format {
        Format::Json => {
            if reports.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&reports[0])?);
            } else {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            }
        }
        Format::Text => {
            for report in &reports {
                print_report_text(report);
            }
        }
    }

    // Update mode is a trust action, not a gate: report the entry count and
    // exit 0 regardless of the other rules' decision.
    if let Some(target) = update_baseline {
        let count = baseline_entry_count(target)
            .with_context(|| format!("count baseline entries {}", target.display()))?;
        eprintln!("baseline written: {count} entries");
        return Ok(ExitCode::from(0));
    }

    let worst = reports
        .iter()
        .map(|r| match r.decision {
            Decision::Allow => 0u8,
            Decision::AllowWithApproval => 2,
            Decision::Block => 1,
        })
        .max_by_key(|c| match c {
            1 => 2, // block outranks approval
            2 => 1,
            _ => 0,
        })
        .unwrap_or(0);
    Ok(ExitCode::from(worst))
}

/// Count the entries of a freshly written baseline file (shape:
/// `{ "version": 1, "entries": { ... } }`).
fn baseline_entry_count(path: &Path) -> Result<usize> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read baseline {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse baseline {}", path.display()))?;
    Ok(value
        .get("entries")
        .and_then(serde_json::Value::as_object)
        .map(|o| o.len())
        .unwrap_or(0))
}
