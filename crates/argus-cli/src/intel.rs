use anyhow::{Context, Result};
use argus_core::{IntelMatchStatus, IntelSnapshotStatus, ScanReport};
use argus_intel::{
    import_snapshot, AtomicCleanupState, AtomicWriteOutcome, HttpArchiveTransport, ImportLimits,
    ImportOutcome, ImportRequest, IntelDatabase, MatchResult, SnapshotEnvelope,
};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Args, Debug)]
pub(crate) struct ScanIntelArgs {
    /// Match the resolved package coordinate against this verified local snapshot.
    #[arg(long, value_name = "PATH")]
    pub(crate) malicious_db: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum IntelOp {
    /// Import a pinned OpenSSF malicious-packages revision into a local snapshot.
    Import {
        #[arg(long)]
        source: String,
        #[arg(long)]
        revision: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate and describe a local malicious-package snapshot.
    Status {
        #[arg(long)]
        db: PathBuf,
    },
}

pub(crate) fn cmd_intel(op: IntelOp) -> Result<ExitCode> {
    match op {
        IntelOp::Import {
            source,
            revision,
            output,
        } => {
            let request = ImportRequest {
                source: &source,
                revision: &revision,
                output: &output,
                imported_at: Utc::now(),
                limits: ImportLimits::default(),
            };
            let outcome = import_snapshot(&request, &HttpArchiveTransport::new())
                .context("import malicious-package snapshot")?;
            write_import_outcome(
                &outcome,
                &output,
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            )
            .context("write malicious-package import outcome")?;
        }
        IntelOp::Status { db } => {
            let database = IntelDatabase::load(&db)
                .with_context(|| format!("load malicious-package database {}", db.display()))?;
            print_snapshot_status(database.snapshot(), Some(&db));
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn write_import_outcome(
    outcome: &ImportOutcome,
    path: &Path,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    stdout.write_all(render_snapshot_status(&outcome.snapshot, Some(path)).as_bytes())?;
    if let Some(warning) = render_import_cleanup_warning(&outcome.atomic_outcome) {
        stderr.write_all(warning.as_bytes())?;
        stderr.write_all(b"\n")?;
    }
    Ok(())
}

pub(crate) fn render_import_cleanup_warning(outcome: &AtomicWriteOutcome) -> Option<String> {
    let AtomicWriteOutcome::CommittedWithCleanupWarning {
        backup_name,
        state,
        cause,
    } = outcome
    else {
        return None;
    };
    Some(match state {
        AtomicCleanupState::Pending => format!(
            "warning: malicious intelligence snapshot committed, but backup cleanup is pending; \
             retained_backup={backup_name:?}; cause={cause:?}"
        ),
        AtomicCleanupState::DurabilityUncertain => format!(
            "warning: malicious intelligence snapshot committed, but backup cleanup durability is \
             uncertain; backup_identifier={backup_name:?}; cause={cause:?}"
        ),
    })
}

pub(crate) fn apply_malicious_snapshot(
    report: &mut ScanReport,
    database_path: Option<&Path>,
    scan_started_at: DateTime<Utc>,
) -> Result<()> {
    let Some(database_path) = database_path else {
        return Ok(());
    };
    let coordinate = report.coordinate.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "--malicious-db requires a trusted resolved package coordinate; this scan produced none"
        )
    })?;
    let database = IntelDatabase::load(database_path).with_context(|| {
        format!(
            "load malicious-package database {}",
            database_path.display()
        )
    })?;
    let MatchResult {
        mut findings,
        status,
    } = database
        .match_coordinate(coordinate)
        .with_context(|| format!("match malicious-package coordinate {}", coordinate.purl))?;
    let intelligence = database
        .status(scan_started_at, status)
        .context("derive malicious-package snapshot status")?;

    report.findings.append(&mut findings);
    report.intelligence = Some(intelligence);
    report.decision = argus_rules::derive_decision_from_findings(&report.findings);
    Ok(())
}

pub(crate) fn render_status_text(status: &IntelSnapshotStatus) -> String {
    let mut output = String::new();
    writeln!(output, "malicious intelligence:")
        .expect("writing an intelligence status to String cannot fail");
    writeln!(output, "  source: {}", status.source)
        .expect("writing an intelligence status to String cannot fail");
    writeln!(output, "  revision: {}", status.revision)
        .expect("writing an intelligence status to String cannot fail");
    writeln!(output, "  imported_at: {}", status.imported_at.to_rfc3339())
        .expect("writing an intelligence status to String cannot fail");
    writeln!(output, "  age_seconds: {}", status.age_seconds)
        .expect("writing an intelligence status to String cannot fail");
    writeln!(output, "  archive_sha256: {}", status.archive_sha256)
        .expect("writing an intelligence status to String cannot fail");
    writeln!(output, "  records_sha256: {}", status.records_sha256)
        .expect("writing an intelligence status to String cannot fail");
    writeln!(output, "  snapshot_sha256: {}", status.snapshot_sha256)
        .expect("writing an intelligence status to String cannot fail");
    writeln!(output, "  status: {}", match_status_name(status.status))
        .expect("writing an intelligence status to String cannot fail");
    output
}

fn match_status_name(status: IntelMatchStatus) -> &'static str {
    match status {
        IntelMatchStatus::Matched => "matched",
        IntelMatchStatus::NoMatch => "no_match",
    }
}

fn print_snapshot_status(snapshot: &SnapshotEnvelope, path: Option<&Path>) {
    print!("{}", render_snapshot_status(snapshot, path));
}

pub(crate) fn render_snapshot_status(snapshot: &SnapshotEnvelope, path: Option<&Path>) -> String {
    let counts = snapshot.record_counts();
    let path = path
        .map(|path| format!("  path: {}\n", path.display()))
        .unwrap_or_default();
    format!(
        "malicious intelligence snapshot:\n\
         {path}  source: {}\n\
           revision: {}\n\
           imported_at: {}\n\
           archive_sha256: {}\n\
           records_sha256: {}\n\
           snapshot_sha256: {}\n\
           active_records: {}\n\
           withdrawn_records: {}\n",
        snapshot.source,
        snapshot.revision,
        snapshot.imported_at.to_rfc3339(),
        snapshot.archive_sha256,
        snapshot.records_sha256,
        snapshot.snapshot_sha256,
        counts.active_records,
        counts.withdrawn_records,
    )
}
