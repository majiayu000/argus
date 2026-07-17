//! argus CLI binary.
//!
//! Subcommands:
//! - `argus scan <path>` — scan one package directory or lockfile.
//! - `argus fetch <pkg>[@version]` — download from npm, verify integrity,
//!   extract, scan.
//! - `argus corpus test ...` — run the regression corpus and diff against
//!   each case's `expectedDecision` + `rules`.

mod agent;
mod corpus;
mod corpus_path;
mod sarif;

use anyhow::{bail, Context, Result};
use argus_composer::{
    fetch_and_scan_composer, ComposerFetchOptions, ComposerRef,
    HttpTransport as ComposerHttpTransport,
};
use argus_core::{Decision, ScanReport};
use argus_crates::{
    fetch_and_scan_crate, CrateRef, CratesFetchOptions, HttpTransport as CratesHttpTransport,
};
use argus_fetch::{fetch_and_scan, FetchOptions, HttpTransport, PackageRef};
use argus_go::{fetch_and_scan_go, GoFetchOptions, GoModuleRef, HttpTransport as GoHttpTransport};
use argus_maven::{
    fetch_and_scan_maven, HttpTransport as MavenHttpTransport, MavenFetchOptions, MavenRef,
};
use argus_nuget::{
    fetch_and_scan_nuget, HttpTransport as NugetHttpTransport, NugetFetchOptions, NugetRef,
};
use argus_pypi::{
    fetch_and_scan_pypi, HttpTransport as PypiHttpTransport,
    PreferredFormat as PypiPreferredFormat, PypiFetchOptions, PypiPackageRef,
};
use argus_rubygems::{
    fetch_and_scan_gems, GemFetchOptions, GemRef, HttpTransport as GemsHttpTransport,
};
use argus_rules::{scan_lockfile, scan_package_dir};
use clap::{Parser, Subcommand};
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
    /// Agent supply-chain surface commands (MCP configs, skills, hooks, AGENTS.md).
    Agent {
        #[command(subcommand)]
        op: AgentOp,
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
    /// Fetch a package from NuGet, verify catalog SHA-512, safe-extract .nupkg, scan.
    NugetFetch {
        /// Package spec: `<id>` or `<id>@<version>`.
        pkg: String,
        /// NuGet registry base URL.
        #[arg(long, default_value = "https://api.nuget.org")]
        registry: String,
        /// Persistent scratch parent. Omitted → private system temp dir.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Fetch a jar from Maven Central, verify checksum, safe-extract, scan pom.xml + resources.
    MavenFetch {
        /// Maven coordinate: `groupId:artifactId` or `groupId:artifactId:version`.
        pkg: String,
        /// Maven registry base URL.
        #[arg(long, default_value = "https://repo1.maven.org/maven2")]
        registry: String,
        /// Persistent scratch parent. Omitted → private system temp dir.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Fetch a gem from RubyGems, verify SHA-256, parse the nested archive, scan extconf.rb + gemspec + Ruby sources.
    GemsFetch {
        /// Gem spec: `<name>` or `<name>@<version>`.
        pkg: String,
        /// RubyGems registry base URL.
        #[arg(long, default_value = "https://rubygems.org")]
        registry: String,
        /// Persistent scratch parent. Omitted → private system temp dir.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Fetch a Composer package from Packagist, verify SHA-1, safe-extract, scan.
    ComposerFetch {
        /// Package spec: `vendor/package` or `vendor/package@version`.
        pkg: String,
        /// Packagist registry base URL.
        #[arg(long, default_value = "https://repo.packagist.org")]
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
enum AgentOp {
    /// Statically scan one or more paths as agent surfaces.
    Scan {
        /// Directories or files: `.claude` trees, skill dirs, `.mcp.json`, AGENTS.md.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// AGT-02 Check mode: compare descriptions against this approved
        /// baseline file and flag drift. Mutually exclusive with
        /// `--update-baseline`.
        #[arg(long, value_name = "FILE", conflicts_with = "update_baseline")]
        baseline: Option<PathBuf>,
        /// AGT-02 Update mode: (re)write this baseline from the current
        /// surface and mark it approved (a trust action; no drift finding).
        #[arg(long, value_name = "FILE")]
        update_baseline: Option<PathBuf>,
        /// Enable the optional external semantic judge. Off by default.
        #[arg(long, requires = "llm_judge_command")]
        llm_judge: bool,
        /// Executable implementing the versioned LLM judge stdin/stdout JSON protocol.
        #[arg(long, value_name = "FILE", requires = "llm_judge")]
        llm_judge_command: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum CorpusOp {
    /// Run every case in the corpus and verify expected decision and rules.
    Test {
        /// Path to the corpus directory (must contain `index.json`).
        #[arg(long, default_value = "corpus")]
        corpus: PathBuf,
    },
    /// Compute explicitly scoped metrics for a frozen corpus evaluation contract.
    Eval {
        /// Path to the corpus directory containing an evaluation-enabled index.
        #[arg(long, default_value = "corpus/agent")]
        corpus: PathBuf,
        #[arg(long, value_enum, default_value_t = EvaluationFormat::Text)]
        format: EvaluationFormat,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum EvaluationFormat {
    Text,
    Json,
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
        Cmd::NugetFetch {
            pkg,
            registry,
            cache_dir,
            format,
        } => cmd_nuget_fetch(&pkg, registry, cache_dir, format),
        Cmd::MavenFetch {
            pkg,
            registry,
            cache_dir,
            format,
        } => cmd_maven_fetch(&pkg, registry, cache_dir, format),
        Cmd::GemsFetch {
            pkg,
            registry,
            cache_dir,
            format,
        } => cmd_gems_fetch(&pkg, registry, cache_dir, format),
        Cmd::ComposerFetch {
            pkg,
            registry,
            cache_dir,
            format,
        } => cmd_composer_fetch(&pkg, registry, cache_dir, format),
        Cmd::Agent {
            op:
                AgentOp::Scan {
                    paths,
                    format,
                    baseline,
                    update_baseline,
                    llm_judge,
                    llm_judge_command,
                },
        } => agent::cmd_agent_scan(
            &paths,
            format,
            baseline.as_deref(),
            update_baseline.as_deref(),
            llm_judge,
            llm_judge_command.as_deref(),
        ),
        Cmd::Corpus {
            op: CorpusOp::Test { corpus },
        } => corpus::cmd_test(&corpus),
        Cmd::Corpus {
            op: CorpusOp::Eval { corpus, format },
        } => corpus::cmd_eval(&corpus, format),
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

fn cmd_nuget_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
) -> Result<ExitCode> {
    let pkg_ref = NugetRef::parse(pkg).with_context(|| format!("parse NuGet spec `{pkg}`"))?;
    let opts = NugetFetchOptions {
        registry,
        cache_dir,
        ..NugetFetchOptions::default()
    };
    let transport = NugetHttpTransport::new();
    let report = fetch_and_scan_nuget(&pkg_ref, &opts, &transport)
        .with_context(|| format!("nuget-fetch + scan {pkg}"))?;
    emit_report(&report, format)
}

fn cmd_maven_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
) -> Result<ExitCode> {
    let pkg_ref =
        MavenRef::parse(pkg).with_context(|| format!("parse Maven coordinate `{pkg}`"))?;
    let opts = MavenFetchOptions {
        registry,
        cache_dir,
        ..MavenFetchOptions::default()
    };
    let transport = MavenHttpTransport::new();
    let report = fetch_and_scan_maven(&pkg_ref, &opts, &transport)
        .with_context(|| format!("maven-fetch + scan {pkg}"))?;
    emit_report(&report, format)
}

fn cmd_gems_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
) -> Result<ExitCode> {
    let pkg_ref = GemRef::parse(pkg).with_context(|| format!("parse RubyGems spec `{pkg}`"))?;
    let opts = GemFetchOptions {
        registry,
        cache_dir,
        ..GemFetchOptions::default()
    };
    let transport = GemsHttpTransport::new();
    let report = fetch_and_scan_gems(&pkg_ref, &opts, &transport)
        .with_context(|| format!("gems-fetch + scan {pkg}"))?;
    emit_report(&report, format)
}

fn cmd_composer_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
) -> Result<ExitCode> {
    let pkg_ref =
        ComposerRef::parse(pkg).with_context(|| format!("parse Composer spec `{pkg}`"))?;
    let opts = ComposerFetchOptions {
        registry,
        cache_dir,
        ..ComposerFetchOptions::default()
    };
    let transport = ComposerHttpTransport::new();
    let report = fetch_and_scan_composer(&pkg_ref, &opts, &transport)
        .with_context(|| format!("composer-fetch + scan {pkg}"))?;
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
        Format::Sarif => println!(
            "{}",
            serde_json::to_string_pretty(&sarif::render_reports(std::slice::from_ref(report))?)?
        ),
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

pub(crate) fn print_report_text(report: &ScanReport) {
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
