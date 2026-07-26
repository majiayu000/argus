//! OSV schema parsing, validation, and per-ecosystem version comparison.
//!
//! Extracted from `argus-intel` (#135): the malicious-package intelligence
//! crate previously owned the entire OSV schema layer plus every ecosystem
//! version comparator, and `argus-osv` (the online client) depended on the
//! intelligence crate to reach them — an inverted layering where schema
//! evolution meant touching "intelligence". `argus-intel` and `argus-osv`
//! now sit side by side on top of this crate.

mod gem_version;
mod go_version;
mod maven_version;
mod profile;
mod record;
mod version_number;
mod versions;

pub use record::{
    match_osv_affected, parse_osv_record, parse_record, validate_osv_coordinate, validate_text,
    OsvAffected, OsvAffectedMatch, OsvEvent, OsvIntervalMatch, OsvPackage, OsvRange, OsvRangeMatch,
    OsvRecord, OsvReference, OsvSeverity, SUPPORTED_SCHEMA_VERSIONS,
};
pub use versions::{compare_versions, parse_version};

use argus_core::Ecosystem;

/// Map an OSV ecosystem string to the internal [`Ecosystem`] enum. Returns
/// `None` for ecosystems argus does not scan.
pub fn ecosystem_from_osv(value: &str) -> Option<Ecosystem> {
    match value {
        "npm" => Some(Ecosystem::Npm),
        "PyPI" => Some(Ecosystem::PyPi),
        "crates.io" => Some(Ecosystem::CratesIo),
        "Go" => Some(Ecosystem::Go),
        "NuGet" => Some(Ecosystem::NuGet),
        "Maven" => Some(Ecosystem::Maven),
        "RubyGems" => Some(Ecosystem::RubyGems),
        "Packagist" => Some(Ecosystem::Packagist),
        _ => None,
    }
}
