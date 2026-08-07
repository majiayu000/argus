//! argus CLI binary and subcommand router.

mod agent;
mod corpus;
mod corpus_path;
mod execution;
mod intel;
mod lockfile_scan;
mod report;
mod risk_args;
mod router;

mod rule_args;
mod sarif;
mod sarif_vulns;
mod vulns;

use anyhow::{bail, Context, Result};
use argus_composer::ComposerFetcher;
use argus_core::{ExecutionContext, ScanReport};
use argus_crates::CratesFetcher;
use argus_fetch::{FetchOptions, PackageRef};
use argus_go::GoFetcher;
use argus_lockfile::{
    parse_lockfile, BoundedInput, DetectionRequest, FormatHint, PolicyOptions, MAX_INPUT_BYTES,
};
use argus_maven::MavenFetcher;
use argus_nuget::NugetFetcher;
use argus_pipeline::{CommonFetchOptions, EcosystemFetcher};
use argus_pypi::{PreferredFormat as PypiPreferredFormat, PypiFetchOptions, PypiPackageRef};
use argus_rubygems::GemsFetcher;
use argus_rules::RuleSession;
use argus_transport::HttpTransport;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use report::emit_report;
pub(crate) use report::print_report_text;
use rule_args::RuleArgs;

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
    /// Scan a package directory or one supported dependency lockfile.
    Scan {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Explicit lockfile format, validated together with the basename.
        #[arg(long, value_enum)]
        lockfile_format: Option<router::LockfileFormatArg>,
        /// Additional exact DNS host accepted for HTTPS/SSH lockfile sources.
        #[arg(long = "allow-registry-host", value_name = "HOST")]
        allow_registry_host: Vec<String>,
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
        #[command(flatten)]
        vulns: vulns::ScanVulnsArgs,
        #[command(flatten)]
        rules: RuleArgs,
        #[command(flatten)]
        risk: risk_args::RiskArgs,
        #[command(flatten)]
        execution: execution::ExecutionArgs,
    },
    /// Fetch and statically scan every dependency one lockfile resolves.
    ///
    /// Answers the CI question the single-package commands cannot: is
    /// anything in this dependency tree unsafe. Dependencies that could not
    /// be scanned are reported explicitly rather than dropped.
    LockfileScan(lockfile_scan::LockfileScanArgs),
    /// Agent supply-chain surface commands (MCP configs, skills, hooks, AGENTS.md).
    Agent {
        #[command(subcommand)]
        op: AgentOp,
    },
    /// Offline known-malicious package intelligence commands.
    Intel {
        #[command(subcommand)]
        op: intel::IntelOp,
    },
    /// Query OSV for known vulnerabilities in exact package versions.
    Vulns {
        #[command(subcommand)]
        op: router::VulnsOp,
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
        /// Evaluate bounded npm version-shape and rapid-publish metadata
        /// anomalies. Disabled by default; enabling may issue one npm search
        /// request for the resolved version's publisher.
        #[arg(long)]
        metadata_anomaly: bool,
        /// Persistent cache directory for bounded npm search responses.
        /// Used only with `--metadata-anomaly`.
        #[arg(long)]
        metadata_cache_dir: Option<PathBuf>,
        /// Additional host name that the tarball URL is allowed to resolve
        /// to (the registry host is always accepted). Pass multiple times
        /// for multiple hosts. Use this for custom registries that delegate
        /// tarball storage to a separate CDN or object store.
        #[arg(long = "allow-tarball-host", value_name = "HOST")]
        allow_tarball_host: Vec<String>,
        /// Layer full Sigstore signature verification (Fulcio chain +
        /// Rekor inclusion + DSSE + OIDC identity allowlist) on top of
        /// the always-on subject-digest check. Requires `argus-fetch` built
        /// with `--features sigstore`. Feature-off requests fail closed with a
        /// hard error before network access; enabled verification requires at least one `--sigstore-identity`.
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
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
        #[command(flatten)]
        vulns: vulns::ScanVulnsArgs,
        #[command(flatten)]
        rules: RuleArgs,
        #[command(flatten)]
        risk: risk_args::RiskArgs,
        #[command(flatten)]
        execution: execution::ExecutionArgs,
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
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
        #[command(flatten)]
        vulns: vulns::ScanVulnsArgs,
        #[command(flatten)]
        rules: RuleArgs,
        #[command(flatten)]
        risk: risk_args::RiskArgs,
        #[command(flatten)]
        execution: execution::ExecutionArgs,
    },
    /// Fetch a crate from crates.io, verify SHA-256, safe-extract, scan build.rs + Rust sources. Spec: `<name>` or `<name>@<version>`.
    CratesFetch(EcosystemFetchArgs),
    /// Fetch a Go module from a GOPROXY, verify the dirhash h1 checksum, safe-extract the zip, scan init/exec/network surfaces. Spec: `<module-path>` or `<module-path>@<version>`.
    GoFetch(EcosystemFetchArgs),
    /// Fetch a package from NuGet, verify catalog SHA-512, safe-extract .nupkg, scan. Spec: `<id>` or `<id>@<version>`.
    NugetFetch(EcosystemFetchArgs),
    /// Fetch a jar from Maven Central, verify checksum, safe-extract, scan pom.xml + resources. Spec: `groupId:artifactId` or `groupId:artifactId:version`.
    MavenFetch(EcosystemFetchArgs),
    /// Fetch a gem from RubyGems, verify SHA-256, parse the nested archive, scan extconf.rb + gemspec + Ruby sources. Spec: `<name>` or `<name>@<version>`.
    GemsFetch(EcosystemFetchArgs),
    /// Fetch a Composer package from Packagist, verify SHA-1, safe-extract, scan. Spec: `vendor/package` or `vendor/package@version`.
    ComposerFetch(EcosystemFetchArgs),
    /// Regression-corpus operations.
    Corpus {
        #[command(subcommand)]
        op: CorpusOp,
    },
}

/// Arguments shared by every non-npm ecosystem fetch subcommand. npm's
/// `fetch` keeps its own richer flag set (Sigstore, metadata anomaly);
/// `pypi-fetch` adds `--prefer` on top of its own handler.
#[derive(clap::Args, Debug)]
struct EcosystemFetchArgs {
    /// Package spec (see this subcommand's help for the exact syntax).
    pkg: String,
    /// Registry base URL. Defaults to the ecosystem's canonical registry.
    #[arg(long)]
    registry: Option<String>,
    /// Persistent scratch parent. Omitted → private system temp dir.
    #[arg(long)]
    cache_dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    #[command(flatten)]
    intel: intel::ScanIntelArgs,
    #[command(flatten)]
    vulns: vulns::ScanVulnsArgs,
    #[command(flatten)]
    rules: RuleArgs,
    #[command(flatten)]
    risk: risk_args::RiskArgs,
    #[command(flatten)]
    execution: execution::ExecutionArgs,
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
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["update_baseline", "update_snapshot"]
        )]
        baseline: Option<PathBuf>,
        /// AGT-02 Update mode: (re)write this baseline from the current
        /// surface and mark it approved (a trust action; no drift finding).
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["baseline", "check_snapshot", "update_snapshot"]
        )]
        update_baseline: Option<PathBuf>,
        /// AGT-04 Check mode: compare the complete high-context inventory
        /// against this approved snapshot.
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["update_baseline", "update_snapshot"]
        )]
        check_snapshot: Option<PathBuf>,
        /// AGT-04 Update mode: atomically approve the current complete
        /// high-context inventory.
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["baseline", "update_baseline", "check_snapshot"]
        )]
        update_snapshot: Option<PathBuf>,
        /// Enable the optional external semantic judge. Off by default.
        #[arg(long, requires = "llm_judge_command")]
        llm_judge: bool,
        /// Executable implementing the versioned LLM judge stdin/stdout JSON protocol.
        #[arg(long, value_name = "FILE", requires = "llm_judge")]
        llm_judge_command: Option<PathBuf>,
        #[command(flatten)]
        rules: RuleArgs,
        #[command(flatten)]
        execution: execution::ExecutionArgs,
    },
}

#[derive(Subcommand, Debug)]
enum CorpusOp {
    /// Run every case in the corpus and verify expected decision and rules.
    Test {
        /// Path to the corpus directory (must contain `index.json`).
        #[arg(long, default_value = "corpus")]
        corpus: PathBuf,
        #[command(flatten)]
        execution: execution::ExecutionArgs,
    },
    /// Compute explicitly scoped metrics for a frozen corpus evaluation contract.
    Eval {
        /// Path to the corpus directory containing an evaluation-enabled index.
        #[arg(long, default_value = "corpus/agent")]
        corpus: PathBuf,
        #[arg(long, value_enum, default_value_t = EvaluationFormat::Text)]
        format: EvaluationFormat,
        #[command(flatten)]
        execution: execution::ExecutionArgs,
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
    let scan_started_at = Utc::now();
    match cli.cmd {
        Cmd::Scan {
            path,
            format,
            lockfile_format,
            allow_registry_host,
            intel,
            vulns,
            rules,
            risk,
            execution,
        } => {
            let execution = execution.resolve()?;
            cmd_scan(
                &path,
                format,
                lockfile_format,
                &allow_registry_host,
                intel,
                vulns,
                risk,
                scan_started_at,
                rules.load()?,
                &execution,
            )
        }
        Cmd::LockfileScan(args) => lockfile_scan::run(args),
        Cmd::Intel { op } => intel::cmd_intel(op),
        Cmd::Vulns { op } => vulns::cmd_vulns(op),
        Cmd::Fetch {
            pkg,
            registry,
            cache_dir,
            metadata_anomaly,
            metadata_cache_dir,
            allow_tarball_host,
            verify_sigstore,
            sigstore_issuer,
            sigstore_identity,
            format,
            intel,
            vulns,
            rules,
            risk,
            execution,
        } => {
            let execution = execution.resolve()?;
            cmd_fetch(
                &pkg,
                registry,
                cache_dir,
                metadata_anomaly,
                metadata_cache_dir,
                allow_tarball_host,
                verify_sigstore,
                sigstore_issuer,
                sigstore_identity,
                format,
                intel,
                vulns,
                risk,
                scan_started_at,
                rules.load()?,
                &execution,
            )
        }
        Cmd::PypiFetch {
            pkg,
            registry,
            cache_dir,
            prefer,
            format,
            intel,
            vulns,
            rules,
            risk,
            execution,
        } => {
            let execution = execution.resolve()?;
            cmd_pypi_fetch(
                &pkg,
                registry,
                cache_dir,
                prefer.into(),
                format,
                intel,
                vulns,
                risk,
                scan_started_at,
                rules.load()?,
                &execution,
            )
        }
        Cmd::CratesFetch(args) => {
            cmd_ecosystem_fetch(&CratesFetcher, "crates-fetch", args, scan_started_at)
        }
        Cmd::GoFetch(args) => cmd_ecosystem_fetch(&GoFetcher, "go-fetch", args, scan_started_at),
        Cmd::NugetFetch(args) => {
            cmd_ecosystem_fetch(&NugetFetcher, "nuget-fetch", args, scan_started_at)
        }
        Cmd::MavenFetch(args) => {
            cmd_ecosystem_fetch(&MavenFetcher, "maven-fetch", args, scan_started_at)
        }
        Cmd::GemsFetch(args) => {
            cmd_ecosystem_fetch(&GemsFetcher, "gems-fetch", args, scan_started_at)
        }
        Cmd::ComposerFetch(args) => {
            cmd_ecosystem_fetch(&ComposerFetcher, "composer-fetch", args, scan_started_at)
        }
        Cmd::Agent {
            op:
                AgentOp::Scan {
                    paths,
                    format,
                    baseline,
                    update_baseline,
                    check_snapshot,
                    update_snapshot,
                    llm_judge,
                    llm_judge_command,
                    rules,
                    execution,
                },
        } => {
            let execution = execution.resolve()?;
            agent::cmd_agent_scan(
                &paths,
                format,
                baseline.as_deref(),
                update_baseline.as_deref(),
                check_snapshot.as_deref(),
                update_snapshot.as_deref(),
                llm_judge,
                llm_judge_command.as_deref(),
                rules.load()?,
                &execution,
            )
        }
        Cmd::Corpus {
            op: CorpusOp::Test { corpus, execution },
        } => {
            let execution = execution.resolve()?;
            corpus::cmd_test(&corpus, &execution)
        }
        Cmd::Corpus {
            op:
                CorpusOp::Eval {
                    corpus,
                    format,
                    execution,
                },
        } => {
            let execution = execution.resolve()?;
            corpus::cmd_eval(&corpus, format, &execution)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_scan(
    path: &Path,
    format: Format,
    lockfile_format: Option<router::LockfileFormatArg>,
    allow_registry_hosts: &[String],
    intel: intel::ScanIntelArgs,
    vulns: vulns::ScanVulnsArgs,
    risk: risk_args::RiskArgs,
    scan_started_at: DateTime<Utc>,
    rules: RuleSession,
    execution: &ExecutionContext,
) -> Result<ExitCode> {
    let report = scan_path(
        path,
        lockfile_format,
        allow_registry_hosts,
        &rules,
        execution,
    )?;
    finish_scan(
        report,
        format,
        intel,
        vulns,
        risk,
        scan_started_at,
        &rules,
        execution,
    )
}

fn cmd_ecosystem_fetch(
    fetcher: &dyn EcosystemFetcher,
    label: &str,
    args: EcosystemFetchArgs,
    scan_started_at: DateTime<Utc>,
) -> Result<ExitCode> {
    let execution = args.execution.resolve()?;
    let rules = args.rules.load()?;
    let registry = args
        .registry
        .unwrap_or_else(|| fetcher.default_registry().to_string());
    let opts = CommonFetchOptions {
        registry,
        cache_dir: args.cache_dir,
    };
    let transport = HttpTransport::new();
    let report = fetcher
        .fetch_and_scan_with_context(&args.pkg, &opts, &transport, &rules, &execution)
        .with_context(|| format!("{label} + scan {}", args.pkg))?;
    finish_scan(
        report,
        args.format,
        args.intel,
        args.vulns,
        args.risk,
        scan_started_at,
        &rules,
        &execution,
    )
}

#[allow(clippy::too_many_arguments)]
fn cmd_pypi_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    prefer: PypiPreferredFormat,
    format: Format,
    intel: intel::ScanIntelArgs,
    vulns: vulns::ScanVulnsArgs,
    risk: risk_args::RiskArgs,
    scan_started_at: DateTime<Utc>,
    rules: RuleSession,
    execution: &ExecutionContext,
) -> Result<ExitCode> {
    let pkg_ref =
        PypiPackageRef::parse(pkg).with_context(|| format!("parse PyPI package spec `{pkg}`"))?;
    let opts = PypiFetchOptions {
        registry,
        cache_dir,
        prefer,
        ..PypiFetchOptions::default()
    };
    let transport = HttpTransport::new();
    let report = argus_pypi::fetch_and_scan_pypi_with_rules_and_context(
        &pkg_ref, &opts, &transport, &rules, execution,
    )
    .with_context(|| format!("pypi-fetch + scan {pkg}"))?;
    finish_scan(
        report,
        format,
        intel,
        vulns,
        risk,
        scan_started_at,
        &rules,
        execution,
    )
}

#[allow(clippy::too_many_arguments)]
fn cmd_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    metadata_anomaly: bool,
    metadata_cache_dir: Option<PathBuf>,
    allow_tarball_host: Vec<String>,
    verify_sigstore: bool,
    sigstore_issuer: String,
    sigstore_identity: Vec<String>,
    format: Format,
    intel: intel::ScanIntelArgs,
    vulns: vulns::ScanVulnsArgs,
    risk: risk_args::RiskArgs,
    scan_started_at: DateTime<Utc>,
    rules: RuleSession,
    execution: &ExecutionContext,
) -> Result<ExitCode> {
    let pkg_ref = PackageRef::parse(pkg).with_context(|| format!("parse package spec `{pkg}`"))?;
    if metadata_cache_dir.is_some() && !metadata_anomaly {
        anyhow::bail!("--metadata-cache-dir requires --metadata-anomaly");
    }
    if cfg!(feature = "sigstore") && verify_sigstore && sigstore_identity.is_empty() {
        anyhow::bail!(
            "--verify-sigstore requires at least one --sigstore-identity regex (an empty allowlist silently rejects every signed bundle)"
        );
    }
    let opts = FetchOptions {
        registry,
        cache_dir,
        metadata_anomaly,
        metadata_cache_dir,
        tarball_host_allowlist: allow_tarball_host,
        verify_sigstore,
        sigstore_issuer,
        sigstore_identity_patterns: sigstore_identity,
        ..FetchOptions::default()
    };
    let transport = HttpTransport::new();
    let report = argus_fetch::fetch_and_scan_with_rules_and_context(
        &pkg_ref, &opts, &transport, &rules, execution,
    )
    .with_context(|| format!("fetch + scan {pkg}"))?;
    finish_scan(
        report,
        format,
        intel,
        vulns,
        risk,
        scan_started_at,
        &rules,
        execution,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_scan(
    mut report: ScanReport,
    format: Format,
    intel: intel::ScanIntelArgs,
    vulns: vulns::ScanVulnsArgs,
    risk: risk_args::RiskArgs,
    scan_started_at: DateTime<Utc>,
    rules: &RuleSession,
    execution: &ExecutionContext,
) -> Result<ExitCode> {
    intel::apply_malicious_snapshot(&mut report, intel.malicious_db.as_deref(), scan_started_at)?;
    rules.finalize_package(&mut report);
    vulns::apply_osv_query(&mut report, &vulns, rules, execution)?;
    // Scored last: the assessment must see the complete finding set, including
    // intelligence and vulnerability findings added above.
    risk.apply(&mut report)?;
    emit_report(&report, format)
}

fn scan_path(
    path: &Path,
    lockfile_format: Option<router::LockfileFormatArg>,
    allow_registry_hosts: &[String],
    rules: &RuleSession,
    execution: &ExecutionContext,
) -> Result<ScanReport> {
    if path.is_dir() {
        if lockfile_format.is_some() || !allow_registry_hosts.is_empty() {
            bail!(
                "--lockfile-format and --allow-registry-host are valid only when scanning one lockfile"
            );
        }
        argus_rules::scan_package_dir_with_rules_and_context(path, rules, execution)
            .with_context(|| format!("scan dir {}", path.display()))
    } else if path.is_file() {
        scan_lockfile_path(
            path,
            lockfile_format.map(FormatHint::from),
            allow_registry_hosts,
            rules,
            execution,
        )
    } else {
        bail!("path is neither a directory nor a file: {}", path.display());
    }
}

pub(crate) fn scan_lockfile_path(
    path: &Path,
    explicit_format: Option<FormatHint>,
    allow_registry_hosts: &[String],
    rules: &RuleSession,
    execution: &ExecutionContext,
) -> Result<ScanReport> {
    let (bytes, parsed) = read_and_parse_lockfile_bytes(path, explicit_format)?;
    let policy = PolicyOptions::new(allow_registry_hosts)
        .with_context(|| format!("validate lockfile host policy for {}", path.display()))?;
    let rel = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("lockfile path is not valid UTF-8"))?;
    let input = BoundedInput::new(&bytes, rel)
        .with_context(|| format!("bound lockfile {}", path.display()))?;
    argus_lockfile::evaluate_with_rules_and_context(
        &parsed, path, &policy, &input, rules, execution,
    )
    .with_context(|| format!("evaluate lockfile {}", path.display()))
}

/// Security-sensitive lockfile input boundary shared by `scan` and the
/// `vulns lockfile` command (#136): bounded read, UTF-8 basename check, and
/// format detection live in exactly one place.
pub(crate) fn read_and_parse_lockfile(
    path: &Path,
    explicit_format: Option<FormatHint>,
) -> Result<argus_lockfile::ParseOutput> {
    read_and_parse_lockfile_bytes(path, explicit_format).map(|(_, parsed)| parsed)
}

fn read_and_parse_lockfile_bytes(
    path: &Path,
    explicit_format: Option<FormatHint>,
) -> Result<(Vec<u8>, argus_lockfile::ParseOutput)> {
    if !path.is_file() {
        bail!("lockfile path is not a file: {}", path.display());
    }
    let bytes = read_lockfile_bytes(path)?;
    let path_label = path.to_string_lossy();
    let input = BoundedInput::new(&bytes, &path_label)
        .with_context(|| format!("bound lockfile {}", path.display()))?;
    let basename = path.file_name().and_then(|name| name.to_str());
    if basename.is_none() && explicit_format.is_none() {
        bail!(
            "lockfile basename is not UTF-8; pass --lockfile-format for {}",
            path.display()
        );
    }
    let parsed = parse_lockfile(
        &input,
        DetectionRequest {
            basename,
            explicit_format,
        },
    )
    .with_context(|| format!("parse lockfile {}", path.display()))?;
    Ok((bytes, parsed))
}

/// Read the lockfile through a single no-follow descriptor.
///
/// A `File::open` after an `is_file()` probe both follows symlinks and leaves
/// a TOCTOU window between the check and the read, so the bounded regular-file
/// primitive does the type check on the descriptor it actually reads.
fn read_lockfile_bytes(path: &Path) -> Result<Vec<u8>> {
    argus_core::fs::read_bounded_regular_file(path, MAX_INPUT_BYTES)
        .with_context(|| format!("read bounded regular lockfile {}", path.display()))
}
