//! argus CLI binary and subcommand router.

mod agent;
mod corpus;
mod corpus_path;
mod intel;
mod report;
mod router;
mod sarif;
mod sarif_vulns;
mod vulns;

use anyhow::{bail, Context, Result};
use argus_composer::{
    fetch_and_scan_composer, ComposerFetchOptions, ComposerRef,
    HttpTransport as ComposerHttpTransport,
};
use argus_core::ScanReport;
use argus_crates::{
    fetch_and_scan_crate, CrateRef, CratesFetchOptions, HttpTransport as CratesHttpTransport,
};
use argus_fetch::{fetch_and_scan, FetchOptions, HttpTransport, PackageRef};
use argus_go::{fetch_and_scan_go, GoFetchOptions, GoModuleRef, HttpTransport as GoHttpTransport};
use argus_lockfile::{
    evaluate as evaluate_lockfile, parse_lockfile, BoundedInput, DetectionRequest, FormatHint,
    PolicyOptions, MAX_INPUT_BYTES,
};
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
use argus_rules::scan_package_dir;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use report::emit_report;
pub(crate) use report::print_report_text;

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
        lockfile_format: Option<LockfileFormatArg>,
        /// Additional exact DNS host accepted for HTTPS/SSH lockfile sources.
        #[arg(long = "allow-registry-host", value_name = "HOST")]
        allow_registry_host: Vec<String>,
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
    },
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
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
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
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
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
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
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
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
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
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
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
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
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
        #[command(flatten)]
        intel: intel::ScanIntelArgs,
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
enum LockfileFormatArg {
    PackageLock,
    Yarn,
    Pnpm,
    Poetry,
    Uv,
    Cargo,
    GoSum,
    Bundler,
    Composer,
}

impl From<LockfileFormatArg> for FormatHint {
    fn from(value: LockfileFormatArg) -> Self {
        match value {
            LockfileFormatArg::PackageLock => Self::PackageLock,
            LockfileFormatArg::Yarn => Self::Yarn,
            LockfileFormatArg::Pnpm => Self::Pnpm,
            LockfileFormatArg::Poetry => Self::Poetry,
            LockfileFormatArg::Uv => Self::Uv,
            LockfileFormatArg::Cargo => Self::Cargo,
            LockfileFormatArg::GoSum => Self::GoSum,
            LockfileFormatArg::Bundler => Self::Bundler,
            LockfileFormatArg::Composer => Self::Composer,
        }
    }
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
        } => cmd_scan(
            &path,
            format,
            lockfile_format,
            &allow_registry_host,
            intel,
            scan_started_at,
        ),
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
        } => cmd_fetch(
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
            scan_started_at,
        ),
        Cmd::PypiFetch {
            pkg,
            registry,
            cache_dir,
            prefer,
            format,
            intel,
        } => cmd_pypi_fetch(
            &pkg,
            registry,
            cache_dir,
            prefer.into(),
            format,
            intel,
            scan_started_at,
        ),
        Cmd::CratesFetch {
            pkg,
            registry,
            cache_dir,
            format,
            intel,
        } => cmd_crates_fetch(&pkg, registry, cache_dir, format, intel, scan_started_at),
        Cmd::GoFetch {
            pkg,
            registry,
            cache_dir,
            format,
            intel,
        } => cmd_go_fetch(&pkg, registry, cache_dir, format, intel, scan_started_at),
        Cmd::NugetFetch {
            pkg,
            registry,
            cache_dir,
            format,
            intel,
        } => cmd_nuget_fetch(&pkg, registry, cache_dir, format, intel, scan_started_at),
        Cmd::MavenFetch {
            pkg,
            registry,
            cache_dir,
            format,
            intel,
        } => cmd_maven_fetch(&pkg, registry, cache_dir, format, intel, scan_started_at),
        Cmd::GemsFetch {
            pkg,
            registry,
            cache_dir,
            format,
            intel,
        } => cmd_gems_fetch(&pkg, registry, cache_dir, format, intel, scan_started_at),
        Cmd::ComposerFetch {
            pkg,
            registry,
            cache_dir,
            format,
            intel,
        } => cmd_composer_fetch(&pkg, registry, cache_dir, format, intel, scan_started_at),
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
                },
        } => agent::cmd_agent_scan(
            &paths,
            format,
            baseline.as_deref(),
            update_baseline.as_deref(),
            check_snapshot.as_deref(),
            update_snapshot.as_deref(),
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

fn cmd_scan(
    path: &Path,
    format: Format,
    lockfile_format: Option<LockfileFormatArg>,
    allow_registry_hosts: &[String],
    intel: intel::ScanIntelArgs,
    scan_started_at: DateTime<Utc>,
) -> Result<ExitCode> {
    let report = scan_path(path, lockfile_format, allow_registry_hosts)?;
    finish_scan(report, format, intel, scan_started_at)
}

fn cmd_crates_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
    intel: intel::ScanIntelArgs,
    scan_started_at: DateTime<Utc>,
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
    finish_scan(report, format, intel, scan_started_at)
}

fn cmd_go_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
    intel: intel::ScanIntelArgs,
    scan_started_at: DateTime<Utc>,
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
    finish_scan(report, format, intel, scan_started_at)
}

fn cmd_nuget_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
    intel: intel::ScanIntelArgs,
    scan_started_at: DateTime<Utc>,
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
    finish_scan(report, format, intel, scan_started_at)
}

fn cmd_maven_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
    intel: intel::ScanIntelArgs,
    scan_started_at: DateTime<Utc>,
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
    finish_scan(report, format, intel, scan_started_at)
}

fn cmd_gems_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
    intel: intel::ScanIntelArgs,
    scan_started_at: DateTime<Utc>,
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
    finish_scan(report, format, intel, scan_started_at)
}

fn cmd_composer_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    format: Format,
    intel: intel::ScanIntelArgs,
    scan_started_at: DateTime<Utc>,
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
    finish_scan(report, format, intel, scan_started_at)
}

fn cmd_pypi_fetch(
    pkg: &str,
    registry: String,
    cache_dir: Option<PathBuf>,
    prefer: PypiPreferredFormat,
    format: Format,
    intel: intel::ScanIntelArgs,
    scan_started_at: DateTime<Utc>,
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
    finish_scan(report, format, intel, scan_started_at)
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
    scan_started_at: DateTime<Utc>,
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
    let report = fetch_and_scan(&pkg_ref, &opts, &transport)
        .with_context(|| format!("fetch + scan {pkg}"))?;
    finish_scan(report, format, intel, scan_started_at)
}

fn finish_scan(
    mut report: ScanReport,
    format: Format,
    intel: intel::ScanIntelArgs,
    scan_started_at: DateTime<Utc>,
) -> Result<ExitCode> {
    intel::apply_malicious_snapshot(&mut report, intel.malicious_db.as_deref(), scan_started_at)?;
    emit_report(&report, format)
}

fn scan_path(
    path: &Path,
    lockfile_format: Option<LockfileFormatArg>,
    allow_registry_hosts: &[String],
) -> Result<ScanReport> {
    if path.is_dir() {
        if lockfile_format.is_some() || !allow_registry_hosts.is_empty() {
            bail!(
                "--lockfile-format and --allow-registry-host are valid only when scanning one lockfile"
            );
        }
        scan_package_dir(path).with_context(|| format!("scan dir {}", path.display()))
    } else if path.is_file() {
        scan_lockfile_path(
            path,
            lockfile_format.map(FormatHint::from),
            allow_registry_hosts,
        )
    } else {
        bail!("path is neither a directory nor a file: {}", path.display());
    }
}

pub(crate) fn scan_lockfile_path(
    path: &Path,
    explicit_format: Option<FormatHint>,
    allow_registry_hosts: &[String],
) -> Result<ScanReport> {
    let file =
        std::fs::File::open(path).with_context(|| format!("open lockfile {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((MAX_INPUT_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read lockfile {}", path.display()))?;
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
    let policy = PolicyOptions::new(allow_registry_hosts)
        .with_context(|| format!("validate lockfile host policy for {}", path.display()))?;
    evaluate_lockfile(&parsed, path, &policy)
        .with_context(|| format!("evaluate lockfile {}", path.display()))
}
