//! Path-safe ZIP extraction shared by every ZIP-shaped ecosystem artifact
//! (wheel, jar, .nupkg, Composer dist, Go module zip).
//!
//! Consolidates five previously verbatim copies (#132). Hard rules, applied
//! before any byte is written:
//!
//! - Reject absolute paths and any `..` component (`enclosed_name` plus an
//!   explicit component walk).
//! - Reject entries whose external attributes mark them as symlinks.
//! - Enforce `max_extracted_bytes` across the whole archive with overflow-
//!   checked accounting; an entry that overruns the remaining budget fails
//!   the extraction.
//! - Bound entry count and path complexity before any filesystem mutation.
//!
//! `label` names the artifact kind in error messages (for example
//! `"wheel entry"`), preserving each ecosystem's diagnostics.

use crate::{ArchiveBudget, DEFAULT_ARCHIVE_LIMITS};
use anyhow::{anyhow, bail, Context, Result};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// One in-memory extracted file from [`extract_zip_to_memory`].
#[derive(Debug)]
pub struct ExtractedZipFile {
    /// Raw in-zip name with `\` normalised to `/` (the canonical name for
    /// Go dirhash computation).
    pub zip_name: String,
    pub bytes: Vec<u8>,
}

/// Extract a ZIP archive onto disk under `dest_root`.
pub fn extract_zip(
    zip_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    label: &str,
) -> Result<()> {
    for_each_entry(zip_bytes, max_extracted_bytes, label, |path, file, cap| {
        if file.is_dir() {
            let dest = dest_root.join(path);
            std::fs::create_dir_all(&dest).with_context(|| format!("mkdir {}", dest.display()))?;
            return Ok(0);
        }
        let dest = dest_root.join(path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir parent {}", parent.display()))?;
        }
        let mut out =
            std::fs::File::create(&dest).with_context(|| format!("create {}", dest.display()))?;
        let mut limited = file.take(cap);
        std::io::copy(&mut limited, &mut out).with_context(|| format!("write {}", dest.display()))
    })
    .map(|_| ())
}

/// Extract a ZIP archive into memory, keeping raw in-zip names. Directory
/// entries are skipped.
pub fn extract_zip_to_memory(
    zip_bytes: &[u8],
    max_extracted_bytes: u64,
    label: &str,
) -> Result<Vec<ExtractedZipFile>> {
    let mut files = Vec::new();
    for_each_entry(zip_bytes, max_extracted_bytes, label, |path, file, cap| {
        if file.is_dir() {
            return Ok(0);
        }
        let mut buf = Vec::new();
        let written =
            file.take(cap)
                .read_to_end(&mut buf)
                .with_context(|| format!("read {label} `{}`", path.display()))? as u64;
        let zip_name = file.name().replace('\\', "/");
        files.push(ExtractedZipFile {
            zip_name,
            bytes: buf,
        });
        Ok(written)
    })?;
    Ok(files)
}

/// Shared safety walk: validates every entry path, refuses symlinks, and
/// enforces the byte cap around the caller-provided sink. The sink receives
/// the validated relative path, the entry reader, and the per-entry read cap
/// (`remaining + 1` so an overrun is detectable), and returns bytes written.
fn for_each_entry(
    zip_bytes: &[u8],
    max_extracted_bytes: u64,
    label: &str,
    mut sink: impl FnMut(&Path, &mut zip::read::ZipFile<'_>, u64) -> Result<u64>,
) -> Result<u64> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive =
        zip::ZipArchive::new(reader).with_context(|| format!("open {label} archive as ZIP"))?;

    let mut total: u64 = 0;
    if archive.len() > DEFAULT_ARCHIVE_LIMITS.entries {
        bail!(
            "{label} entry count exceeds cap {}",
            DEFAULT_ARCHIVE_LIMITS.entries
        );
    }
    let mut budget = ArchiveBudget::new(DEFAULT_ARCHIVE_LIMITS);
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("read {label} {i}"))?;

        // Path safety: reject any entry path that is absolute or contains
        // `..`. ZIP names are not necessarily UTF-8, but `enclosed_name`
        // returns `Some` only if the path is safe to extract under a root.
        let path: PathBuf = match file.enclosed_name() {
            Some(p) => p.to_owned(),
            None => bail!(
                "{label} {} has an unsafe path; refusing to extract",
                file.name()
            ),
        };
        budget.observe(&path, label)?;
        for comp in path.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    bail!("{label} `{}` traverses parent dir", path.display())
                }
                _ => bail!("{label} `{}` has unsafe path component", path.display()),
            }
        }

        // External attributes can mark an entry as a symlink. We refuse.
        // POSIX: S_IFLNK = 0o120000
        let mode = file.unix_mode().unwrap_or(0);
        if (mode & 0o170000) == 0o120000 {
            bail!("refusing to extract symlink {label} `{}`", path.display());
        }

        let remaining = max_extracted_bytes
            .checked_sub(total)
            .ok_or_else(|| anyhow!("{label} size accounting overflow"))?;

        let written = sink(&path, &mut file, remaining + 1)?;
        if written > remaining {
            bail!(
                "{label} extracted size exceeds cap {max_extracted_bytes} (entry {} overran)",
                path.display()
            );
        }
        total = total
            .checked_add(written)
            .ok_or_else(|| anyhow!("{label} size accounting overflow"))?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (path, body) in files {
                writer.start_file(*path, opts).unwrap();
                writer.write_all(body).unwrap();
            }
            writer.finish().unwrap();
        }
        buf
    }

    #[test]
    fn extracts_nested_files() {
        let zip = make_zip(&[("a/b.txt", b"hello"), ("c.txt", b"world")]);
        let dir = tempfile::tempdir().unwrap();
        extract_zip(&zip, dir.path(), 1024, "test entry").unwrap();
        assert_eq!(std::fs::read(dir.path().join("a/b.txt")).unwrap(), b"hello");
        assert_eq!(std::fs::read(dir.path().join("c.txt")).unwrap(), b"world");
    }

    #[test]
    fn rejects_path_traversal() {
        let zip = make_zip(&[("../evil.txt", b"x")]);
        let dir = tempfile::tempdir().unwrap();
        let err = extract_zip(&zip, dir.path(), 1024, "test entry").unwrap_err();
        assert!(format!("{err:#}").contains("unsafe path"), "got: {err:#}");
    }

    #[test]
    fn rejects_absolute_path() {
        let zip = make_zip(&[("/abs.txt", b"x")]);
        let dir = tempfile::tempdir().unwrap();
        let err = extract_zip(&zip, dir.path(), 1024, "test entry").unwrap_err();
        assert!(format!("{err:#}").contains("unsafe path"), "got: {err:#}");
    }

    #[test]
    fn enforces_byte_cap() {
        let zip = make_zip(&[("big.txt", &[0u8; 64][..])]);
        let dir = tempfile::tempdir().unwrap();
        let err = extract_zip(&zip, dir.path(), 16, "test entry").unwrap_err();
        assert!(format!("{err:#}").contains("exceeds cap"), "got: {err:#}");
    }

    #[test]
    fn memory_extraction_keeps_zip_names_and_cap() {
        let zip = make_zip(&[("m@v1.0.0/go.mod", b"module m")]);
        let files = extract_zip_to_memory(&zip, 1024, "module zip entry").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].zip_name, "m@v1.0.0/go.mod");
        assert_eq!(files[0].bytes.as_slice(), b"module m");
        let err = extract_zip_to_memory(&zip, 2, "module zip entry").unwrap_err();
        assert!(format!("{err:#}").contains("exceeds cap"), "got: {err:#}");
    }
}
