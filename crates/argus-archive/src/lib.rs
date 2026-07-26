//! Path-safe archive extraction shared by every argus ecosystem scanner.
//!
//! Consolidates the previously per-ecosystem copies (#132): the npm/PyPI/
//! crates/RubyGems tar.gz extractor (from argus-fetch) and five verbatim
//! copies of the safe ZIP extractor (wheel, jar, .nupkg, Composer dist,
//! Go module zip). Nothing in an archive is ever executed; every entry
//! passes path-safety, symlink, and byte-cap checks before extraction.

mod tar;
mod zip;

pub use crate::tar::extract_tarball;
pub use crate::zip::{extract_zip, extract_zip_to_memory, ExtractedZipFile};
