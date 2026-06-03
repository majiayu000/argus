//! argus CLI binary.
//!
//! Subcommands:
//! - `argus scan <path>` — scan one package directory or lockfile.
//! - `argus fetch <pkg>[@version]` — download from npm, verify integrity,
//!   extract, scan.
//! - `argus corpus test ...` — run the regression corpus and diff against
//!   each case's `expectedDecision` + `rules`.

use anyhow::{bail, Context, Result};
use argus_core::{Decision, ScanReport};
use argus_crates::{
    fetch_and_scan_crate, CrateRef, CratesFetchOptions, HttpTransport as CratesHttpTransport,
};
use argus_fetch::{fetch_and_scan, FetchOptions, HttpTransport, PackageRef};
use argus_go::{fetch_and_scan_go, GoFetchOptions, GoModuleRef, HttpTransport as GoHttpTransport};
use argus_pypi::{
    fetch_and_scan_pypi, HttpTransport as PypiHttpTransport,
    PreferredFormat as PypiPreferredFormat, PypiFetchOptions, PypiPackageRef,
};
use argus_rules::{scan_lockfile, scan_package_dir};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "argus",
    version,
    about = "Supply-chain install guard for npm/JS"
)]
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
    /// Fetch a package from an npm registry, verify integrity, extract, and scan.
    Fetch {
        /// Package spec: `<name>` or `<name>@<version>` or `<name>@<dist-tag>`.
        /// Scoped names like `@types/node@20.10.0` are supported.
        pkg: String,
        /// Registry base URL.
        #[arg(long, default_value = "https://registry.npmjs.org")]
        registry: String,
        /// Persistent scratch parent for tarballs and extraction. When
        /// omitted, each fetch uses a fresh private system temp dir
        /// (mode 0700 on Unix) to avoid multi-user races in shared `/tmp`.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        /// Additional host name that the tarball URL is allowed to resolve
        /// to (the registry host is always accepted). Pass multiple times
        /// for multiple hosts. Use this for custom registries that delegate
        /// tarball storage to a separate CDN or object store.
        #[arg(long = "allow-tarball-host", value_name = "HOST")]
        allow_tarball_host: Vec<String>,
        /// Layer full Sigstore signature verification (Fulcio chain +
        /// Rekor inclusion + DSSE + OIDC identity allowlist) on top of
        /// the always-on subject-digest check. Requires argus-fetch
        /// built with `--features sigstore`; without that feature the
        /// flag is parsed but only emits an informational finding.
        #[arg(long = "verify-sigstore")]
        verify_sigstore: bool,
        /// OIDC issuer the leaf cert must carry when `--verify-sigstore`
        /// is on. Defaults to GitHub Actions.
        #[arg(
            long = "sigstore-issuer",
            default_value = "https://token.actions.githubusercontent.com",
            value_name = "URL"
        )]
        sigstore_issuer: String,
        /// Regex pattern allowlist for the leaf cert SAN URI when
        /// `--verify-sigstore` is on. Pass multiple times for OR.
        /// Anchored patterns (`^…$`) are recommended.
        #[arg(long = "sigstore-identity", value_name = "REGEX")]
        sigstore_identity: Vec<String>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Fetch a package from PyPI, verify SHA-256, safe-extract sdist/wheel, scan.
    PypiFetch {
        /// Package spec: `<name>` or `<name>@<version>`.
        pkg: String,
        /// PyPI registry base URL.
        #[arg(long, default_value = "https://pypi.org")]
        registry: String,
        /// Persistent scratch parent. Omitted → private system temp dir.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        /// Which artifact format(s) to scan.
        #[arg(long, value_enum, default_value_t = PypiFormat::Both)]
        prefer: PypiFormat,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Fetch a crate from crates.io, verify SHA-256, safe-extract, scan build.rs + Rust sources.
    CratesFetch {
        /// Crate spec: `<name>` or `<name>@<version>`.
        pkg: String,
        /// crates.io registry base URL.
        #[arg(long, default_value = "https://crates.io")]
        registry: String,
        /// Persistent scratch parent. Omitted → private system temp dir.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Fetch a Go module from a GOPROXY, verify the dirhash h1 checksum, safe-extract the zip, scan init/exec/network surfaces.
    GoFetch {
        /// Module spec: `<module-path>` or `<module-path>@<version>`.
        pkg: String,
        /// GOPROXY registry base URL.
        #[arg(long, default_value = "https://proxy.golang.org")]
        registry: String,
        /// Persistent scratch parent. Omitted → private system temp dir.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Regression-corpus operations.
    Corpus {
        #[command(subcommand)]
        op: CorpusOp,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum PypiFormat {
    Sdist,
    Wheel,
    Both,
}

impl From<PypiFormat> for PypiPreferredFormat {
    fn from(f: PypiFormat) -> Self {
        match f {
            PypiFormat::Sdist => PypiPreferredFormat::Sdist,
            PypiFormat::Wheel => PypiPreferredFormat::Wheel,
            PypiFormat::Both => PypiPreferredFormat::Both,
        }
    }
}

#[derive(Subcommand, Debug)]
enum CorpusOp {
    /// Run every case in the corpus and verify expected decision and rules.
    Test {
        /// Path to the corpus directory (must contain `index.json`).
        #[arg(long, default_value = "corpus")]
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
        Cmd::Fetch {
            pkg,
            registry,
            cache_dir,
            allow_tarball_host,
            verify_sigstore,
            sigstore_issuer,
            sigstore_identity,
            format,
        } => cmd_fetch(
            &pkg,
            registry,
            cache_dir,
            allow_tarball_host,
            verify_sigstore,
            sigstore_issuer,
            sigstore_identity,
            format,
        ),
        Cmd::PypiFetch {
            pkg,
            registry,
            cache_dir,
            prefer,
            format,
        } => cmd_pypi_fetch(&pkg, registry, cache_dir, prefer.into(), format),
        Cmd::CratesFetch {
            pkg,
            registry,
            cache_dir,
            format,
        } => cmd_crates_fetch(&pkg, registry, cache_dir, format),
        Cmd::GoFetch {
            pkg,
            registry,
            cache_dir,
            format,
        } => cmd_go_fetch(&pkg, registry, cache_dir, format),
        Cmd::Corpus {
            op: CorpusOp::Test { corpus },
        } => cmd_corpus_test(&corpus),
    }
}

fn cmd_scan(path: &Path, format: Format) -> Result<ExitCode> {
    let report = scan_path(path)?;
    emit_report(&report, format)
}

fn cmd_crates_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
) -> Result<ExitCode> {
    let pkg_ref = CrateRef::parse(pkg).with_context(|| format!("parse crates.io spec `{pkg}`"))?;
    let opts = CratesFetchOptions {
        registry,
        cache_dir,
        ..CratesFetchOptions::default()
    };
    let transport = CratesHttpTransport::new();
    let report = fetch_and_scan_crate(&pkg_ref, &opts, &transport)
        .with_context(|| format!("crates-fetch + scan {pkg}"))?;
    emit_report(&report, format)
}

fn cmd_go_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
) -> Result<ExitCode> {
    let pkg_ref =
        GoModuleRef::parse(pkg).with_context(|| format!("parse Go module spec `{pkg}`"))?;
    let opts = GoFetchOptions {
        registry,
        cache_dir,
        ..GoFetchOptions::default()
    };
    let transport = GoHttpTransport::new();
    let report = fetch_and_scan_go(&pkg_ref, &opts, &transport)
        .with_context(|| format!("go-fetch + scan {pkg}"))?;
    emit_report(&report, format)
}

fn cmd_pypi_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    prefer: PypiPreferredFormat,
    format: Format,
) -> Result<ExitCode> {
    let pkg_ref =
        PypiPackageRef::parse(pkg).with_context(|| format!("parse PyPI package spec `{pkg}`"))?;
    let opts = PypiFetchOptions {
        registry,
        cache_dir,
        prefer,
        ..PypiFetchOptions::default()
    };
    let transport = PypiHttpTransport::new();
    let report = fetch_and_scan_pypi(&pkg_ref, &opts, &transport)
        .with_context(|| format!("pypi-fetch + scan {pkg}"))?;
    emit_report(&report, format)
}

#[allow(clippy::too_many_arguments)]
fn cmd_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    allow_tarball_host: Vec<String>,
    verify_sigstore: bool,
    sigstore_issuer: String,
    sigstore_identity: Vec<String>,
    format: Format,
) -> Result<ExitCode> {
    let pkg_ref = PackageRef::parse(pkg).with_context(|| format!("parse package spec `{pkg}`"))?;
    if cfg!(feature = "sigstore") && verify_sigstore && sigstore_identity.is_empty() {
        anyhow::bail!(
            "--verify-sigstore requires at least one --sigstore-identity regex (an empty allowlist silently rejects every signed bundle)"
        );
    }
    let opts = FetchOptions {
        registry,
        cache_dir,
        tarball_host_allowlist: allow_tarball_host,
        verify_sigstore,
        sigstore_issuer,
        sigstore_identity_patterns: sigstore_identity,
        ..FetchOptions::default()
    };
    let transport = HttpTransport::new();
    let report = fetch_and_scan(&pkg_ref, &opts, &transport)
        .with_context(|| format!("fetch + scan {pkg}"))?;
    emit_report(&report, format)
}

/// Exit codes are part of the CLI contract.
///
/// - `0` — `allow` (clean)
/// - `1` — `block` (a rule fired and the package must not be installed)
/// - `2` — `allow-with-approval` (only a recognised native-build pattern
///   fired; a human reviewer must sign off before install). Distinct from
///   `allow` so CI gates can require explicit approval rather than silently
///   passing.
fn emit_report(report: &ScanReport, format: Format) -> Result<ExitCode> {
    match format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        Format::Text => print_report_text(report),
    }
    let code = match report.decision {
        Decision::Allow => 0,
        Decision::Block => 1,
        Decision::AllowWithApproval => 2,
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
        report.package_name.as_deref().unwrap_or("<unnamed>"),
    );
    println!("path: {}", report.path.display());
    if report.findings.is_empty() {
        println!("findings: none");
        return;
    }
    println!("findings:");
    for f in &report.findings {
        let loc = f.location.as_deref().unwrap_or("");
        println!(
            "  - [{}] {} — {} ({})",
            severity_tag(f),
            f.rule_id,
            f.detail,
            loc
        );
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
