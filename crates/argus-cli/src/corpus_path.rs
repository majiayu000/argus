use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
pub(crate) enum CaseKind {
    Fixture,
    Lockfile,
}

pub(crate) fn resolve_case_path(
    index_root: &Path,
    declared: &Path,
    kind: CaseKind,
) -> Result<PathBuf> {
    if declared.is_absolute() {
        bail!("case path must be relative: {}", declared.display());
    }

    let canonical_root = std::fs::canonicalize(index_root)
        .with_context(|| format!("resolve corpus index root {}", index_root.display()))?;
    let joined = index_root.join(declared);
    let canonical_case = std::fs::canonicalize(&joined)
        .with_context(|| format!("case path unavailable at {}", joined.display()))?;
    if canonical_case.strip_prefix(&canonical_root).is_err() {
        bail!(
            "case path escapes index root: {} resolves outside {}",
            declared.display(),
            canonical_root.display()
        );
    }

    let metadata = std::fs::metadata(&canonical_case)
        .with_context(|| format!("inspect case path {}", canonical_case.display()))?;
    match kind {
        CaseKind::Fixture if !metadata.is_dir() => bail!(
            "fixture path must be a directory: {}",
            canonical_case.display()
        ),
        CaseKind::Lockfile if !metadata.is_file() => bail!(
            "lockfile path must be a regular file: {}",
            canonical_case.display()
        ),
        CaseKind::Fixture | CaseKind::Lockfile => {}
    }

    Ok(canonical_case)
}
