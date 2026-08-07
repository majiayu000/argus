//! Path-safe archive extraction shared by every argus ecosystem scanner.
//!
//! Consolidates the previously per-ecosystem copies (#132): the npm/PyPI/
//! crates/RubyGems tar.gz extractor (from argus-fetch) and five verbatim
//! copies of the safe ZIP extractor (wheel, jar, .nupkg, Composer dist,
//! Go module zip). Nothing in an archive is ever executed; every entry
//! passes path-safety, symlink, and byte-cap checks before extraction.

mod tar;
mod zip;

use anyhow::{bail, Result};
use std::path::Path;

pub use crate::tar::extract_tarball;
pub use crate::zip::{extract_zip, extract_zip_to_memory, ExtractedZipFile};

#[derive(Clone, Copy)]
pub(crate) struct ArchiveLimits {
    pub entries: usize,
    pub path_bytes: usize,
    pub path_depth: usize,
    pub total_path_bytes: usize,
}

pub(crate) const DEFAULT_ARCHIVE_LIMITS: ArchiveLimits = ArchiveLimits {
    entries: 100_000,
    path_bytes: 4_096,
    path_depth: 128,
    total_path_bytes: 64 * 1024 * 1024,
};

pub(crate) struct ArchiveBudget {
    limits: ArchiveLimits,
    entries: usize,
    total_path_bytes: usize,
}

impl ArchiveBudget {
    pub(crate) fn new(limits: ArchiveLimits) -> Self {
        Self {
            limits,
            entries: 0,
            total_path_bytes: 0,
        }
    }

    pub(crate) fn observe(&mut self, path: &Path, label: &str) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("{label} entry count overflow"))?;
        if self.entries > self.limits.entries {
            bail!("{label} entry count exceeds cap {}", self.limits.entries);
        }
        let path_bytes = path.as_os_str().len();
        if path_bytes > self.limits.path_bytes {
            bail!(
                "{label} path length exceeds cap {}: {}",
                self.limits.path_bytes,
                path.display()
            );
        }
        let depth = path.components().count();
        if depth > self.limits.path_depth {
            bail!(
                "{label} path depth exceeds cap {}: {}",
                self.limits.path_depth,
                path.display()
            );
        }
        self.total_path_bytes = self
            .total_path_bytes
            .checked_add(path_bytes)
            .ok_or_else(|| anyhow::anyhow!("{label} path byte accounting overflow"))?;
        if self.total_path_bytes > self.limits.total_path_bytes {
            bail!(
                "{label} cumulative path bytes exceed cap {}",
                self.limits.total_path_bytes
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn archive_budget_accepts_exact_limits_and_rejects_plus_one() {
        let limits = ArchiveLimits {
            entries: 2,
            path_bytes: 3,
            path_depth: 2,
            total_path_bytes: 6,
        };
        let mut exact = ArchiveBudget::new(limits);
        exact.observe(Path::new("a/b"), "test").expect("first");
        exact
            .observe(Path::new("c/d"), "test")
            .expect("exact limits");
        assert!(exact.observe(Path::new("e/f"), "test").is_err());

        let mut path = ArchiveBudget::new(limits);
        assert!(path.observe(Path::new("abcd"), "test").is_err());
        let mut depth = ArchiveBudget::new(limits);
        assert!(depth.observe(Path::new("a/b/c"), "test").is_err());
        let mut cumulative = ArchiveBudget::new(limits);
        cumulative.observe(Path::new("abc"), "test").expect("first");
        cumulative
            .observe(Path::new("de"), "test")
            .expect("below cap");
        assert!(cumulative.observe(Path::new("fg"), "test").is_err());
    }
}
