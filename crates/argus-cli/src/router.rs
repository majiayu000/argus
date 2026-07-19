//! Clap-only routing types for the explicit vulnerability query surface.

use argus_core::Ecosystem;
use argus_lockfile::FormatHint;
use argus_osv::severity::SeverityLevel;
use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub(crate) enum VulnsOp {
    /// Query one exact package coordinate.
    Package {
        #[arg(long, value_enum)]
        ecosystem: EcosystemArg,
        #[arg(long)]
        name: String,
        #[arg(long)]
        version: String,
        #[command(flatten)]
        common: VulnsCommonArgs,
    },
    /// Query every complete external coordinate in one supported lockfile.
    Lockfile {
        path: PathBuf,
        /// Explicit lockfile format, validated together with the basename.
        #[arg(long, value_enum)]
        lockfile_format: Option<VulnsLockfileFormat>,
        #[command(flatten)]
        common: VulnsCommonArgs,
    },
}

#[derive(Args, Debug)]
pub(crate) struct VulnsCommonArgs {
    /// Required secure OSV cache directory.
    #[arg(long, value_name = "DIR", required = true)]
    pub(crate) cache_dir: PathBuf,
    /// Disable all network access and require a complete cache snapshot.
    #[arg(long)]
    pub(crate) offline: bool,
    /// Authorize a complete stale cache snapshot in offline mode.
    #[arg(long, requires = "offline")]
    pub(crate) allow_stale: bool,
    /// Maximum fresh-cache age in seconds.
    #[arg(
        long,
        default_value_t = 86_400,
        value_parser = clap::value_parser!(u64).range(0..=2_592_000)
    )]
    pub(crate) max_age_seconds: u64,
    /// Block when an active advisory meets or exceeds this normalized severity.
    #[arg(long, value_enum)]
    pub(crate) fail_on_severity: Option<VulnsSeverity>,
    /// Successful report format.
    #[arg(long, value_enum, default_value_t = VulnsFormat::Text)]
    pub(crate) format: VulnsFormat,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum EcosystemArg {
    #[value(name = "npm")]
    Npm,
    #[value(name = "pypi")]
    PyPi,
    #[value(name = "crates.io")]
    CratesIo,
    #[value(name = "go")]
    Go,
    #[value(name = "nuget")]
    NuGet,
    #[value(name = "maven")]
    Maven,
    #[value(name = "rubygems")]
    RubyGems,
    #[value(name = "packagist")]
    Packagist,
}

impl From<EcosystemArg> for Ecosystem {
    fn from(value: EcosystemArg) -> Self {
        match value {
            EcosystemArg::Npm => Self::Npm,
            EcosystemArg::PyPi => Self::PyPi,
            EcosystemArg::CratesIo => Self::CratesIo,
            EcosystemArg::Go => Self::Go,
            EcosystemArg::NuGet => Self::NuGet,
            EcosystemArg::Maven => Self::Maven,
            EcosystemArg::RubyGems => Self::RubyGems,
            EcosystemArg::Packagist => Self::Packagist,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum VulnsLockfileFormat {
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

impl From<VulnsLockfileFormat> for FormatHint {
    fn from(value: VulnsLockfileFormat) -> Self {
        match value {
            VulnsLockfileFormat::PackageLock => Self::PackageLock,
            VulnsLockfileFormat::Yarn => Self::Yarn,
            VulnsLockfileFormat::Pnpm => Self::Pnpm,
            VulnsLockfileFormat::Poetry => Self::Poetry,
            VulnsLockfileFormat::Uv => Self::Uv,
            VulnsLockfileFormat::Cargo => Self::Cargo,
            VulnsLockfileFormat::GoSum => Self::GoSum,
            VulnsLockfileFormat::Bundler => Self::Bundler,
            VulnsLockfileFormat::Composer => Self::Composer,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum VulnsSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<VulnsSeverity> for SeverityLevel {
    fn from(value: VulnsSeverity) -> Self {
        match value {
            VulnsSeverity::Low => Self::Low,
            VulnsSeverity::Medium => Self::Medium,
            VulnsSeverity::High => Self::High,
            VulnsSeverity::Critical => Self::Critical,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum VulnsFormat {
    Text,
    Json,
    Sarif,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_mappings_cover_every_closed_enum_variant() {
        for (input, expected) in [
            (EcosystemArg::Npm, Ecosystem::Npm),
            (EcosystemArg::PyPi, Ecosystem::PyPi),
            (EcosystemArg::CratesIo, Ecosystem::CratesIo),
            (EcosystemArg::Go, Ecosystem::Go),
            (EcosystemArg::NuGet, Ecosystem::NuGet),
            (EcosystemArg::Maven, Ecosystem::Maven),
            (EcosystemArg::RubyGems, Ecosystem::RubyGems),
            (EcosystemArg::Packagist, Ecosystem::Packagist),
        ] {
            assert_eq!(Ecosystem::from(input), expected);
        }
        for (input, expected) in [
            (VulnsLockfileFormat::PackageLock, FormatHint::PackageLock),
            (VulnsLockfileFormat::Yarn, FormatHint::Yarn),
            (VulnsLockfileFormat::Pnpm, FormatHint::Pnpm),
            (VulnsLockfileFormat::Poetry, FormatHint::Poetry),
            (VulnsLockfileFormat::Uv, FormatHint::Uv),
            (VulnsLockfileFormat::Cargo, FormatHint::Cargo),
            (VulnsLockfileFormat::GoSum, FormatHint::GoSum),
            (VulnsLockfileFormat::Bundler, FormatHint::Bundler),
            (VulnsLockfileFormat::Composer, FormatHint::Composer),
        ] {
            assert_eq!(FormatHint::from(input), expected);
        }
        for (input, expected) in [
            (VulnsSeverity::Low, SeverityLevel::Low),
            (VulnsSeverity::Medium, SeverityLevel::Medium),
            (VulnsSeverity::High, SeverityLevel::High),
            (VulnsSeverity::Critical, SeverityLevel::Critical),
        ] {
            assert_eq!(SeverityLevel::from(input), expected);
        }
    }
}
