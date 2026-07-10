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
    // A baseline is a single approved surface tree. Running update/check once
    // per path against one shared file would let each path overwrite the
    // previous one (update) or report the other paths' entries as missing
    // (check) — silent loss of protection. Reject multiple paths in baseline
    // modes rather than degrade quietly.
    if (baseline.is_some() || update_baseline.is_some()) && paths.len() > 1 {
        bail!(
            "baseline modes (--baseline / --update-baseline) operate on a single \
             surface tree; pass exactly one path (got {})",
            paths.len()
        );
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    // The multi-path guard must fire before any filesystem access, so
    // non-existent paths still trigger it deterministically.
    fn two_paths() -> Vec<PathBuf> {
        vec![PathBuf::from("/nonexistent/a"), PathBuf::from("/nonexistent/b")]
    }

    #[test]
    fn update_baseline_rejects_multiple_paths() {
        let err = cmd_agent_scan(
            &two_paths(),
            Format::Text,
            None,
            Some(Path::new("/tmp/b.json")),
        )
        .unwrap_err();
        assert!(err.to_string().contains("single"), "{err}");
    }

    #[test]
    fn check_baseline_rejects_multiple_paths() {
        let err = cmd_agent_scan(
            &two_paths(),
            Format::Text,
            Some(Path::new("/tmp/b.json")),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("single"), "{err}");
    }

    #[test]
    fn no_baseline_allows_multiple_paths_past_the_guard() {
        // Without a baseline flag the guard must NOT fire; the call proceeds to
        // the existence check and fails there instead (proving the guard is
        // scoped to baseline modes only).
        let err = cmd_agent_scan(&two_paths(), Format::Text, None, None).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }
}
