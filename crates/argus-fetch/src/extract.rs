//! Safe tarball extraction.
//!
//! npm tarballs always wrap the package source inside a top-level directory
//! literally named `package/`. We accept that layout and reject anything
//! that tries to escape it. No script ever runs as part of extraction —
//! `tar::Archive::unpack` is the only operation, and we filter every entry
//! through path-safety checks first.

use anyhow::{anyhow, bail, Context, Result};
use flate2::read::GzDecoder;
use std::path::{Component, Path, PathBuf};
use tar::EntryType;

/// Extract `tarball_bytes` (gzipped tar) under `dest_root` and return the
/// path that holds the package contents. The package root is the inner
/// `package/` directory if present, else the extraction root itself.
///
/// Hard rules:
/// - Reject absolute paths.
/// - Reject any path component equal to `..`.
/// - Reject symlinks, hardlinks, devices, fifos.
/// - Reject extracted-byte totals over `max_extracted_bytes`.
pub fn extract_tarball(
    tarball_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<PathBuf> {
    let gz = GzDecoder::new(tarball_bytes);
    let mut archive = tar::Archive::new(gz);

    let mut total: u64 = 0;
    let mut saw_package_dir = false;

    for entry in archive.entries().context("read tar entries")? {
        let mut entry = entry.context("read tar entry")?;
        let header_path = entry
            .path()
            .context("tar entry path is not UTF-8 / valid")?
            .into_owned();

        check_path_safety(&header_path)
            .with_context(|| format!("unsafe entry path: {}", header_path.display()))?;

        match entry.header().entry_type() {
            EntryType::Regular | EntryType::Continuous => {}
            EntryType::Directory => {
                let dest = dest_root.join(&header_path);
                std::fs::create_dir_all(&dest)
                    .with_context(|| format!("mkdir {}", dest.display()))?;
                if header_path
                    .components()
                    .next()
                    .map(|c| c.as_os_str() == "package")
                    .unwrap_or(false)
                {
                    saw_package_dir = true;
                }
                continue;
            }
            other => {
                bail!(
                    "refusing to extract non-regular entry `{}` ({:?})",
                    header_path.display(),
                    other
                );
            }
        }

        let size = entry.header().size().unwrap_or(0);
        total = total
            .checked_add(size)
            .ok_or_else(|| anyhow!("tar size overflow"))?;
        if total > max_extracted_bytes {
            bail!("extracted size {total} exceeds cap {max_extracted_bytes}");
        }

        let dest = dest_root.join(&header_path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir parent {}", parent.display()))?;
        }
        let mut out =
            std::fs::File::create(&dest).with_context(|| format!("create {}", dest.display()))?;
        std::io::copy(&mut entry, &mut out).with_context(|| format!("write {}", dest.display()))?;

        if header_path
            .components()
            .next()
            .map(|c| c.as_os_str() == "package")
            .unwrap_or(false)
        {
            saw_package_dir = true;
        }
    }

    Ok(if saw_package_dir {
        dest_root.join("package")
    } else {
        dest_root.to_path_buf()
    })
}

pub(crate) fn check_path_safety(p: &Path) -> Result<()> {
    if p.is_absolute() {
        bail!("absolute path");
    }
    for comp in p.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => bail!("`..` traversal"),
            Component::RootDir | Component::Prefix(_) => bail!("absolute prefix"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    /// Build a tiny gzipped tar in memory. Entries: (rel_path, body).
    fn make_targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = tar::Builder::new(&mut gz);
            for (path, body) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_entry_type(EntryType::Regular);
                header.set_cksum();
                builder.append(&header, *body).unwrap();
            }
            builder.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[test]
    fn extracts_package_dir() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = make_targz(&[
            ("package/package.json", br#"{"name":"x","version":"1.0.0"}"#),
            ("package/index.js", b"module.exports = {};"),
        ]);
        let pkg = extract_tarball(&bytes, dir.path(), 10_000_000).unwrap();
        assert_eq!(pkg, dir.path().join("package"));
        assert!(pkg.join("package.json").exists());
        assert!(pkg.join("index.js").exists());
    }

    // The `tar::Builder` API itself refuses to write `..` or absolute paths,
    // so the malicious-path attack vector can only come from a hand-crafted
    // tarball. We exercise the safety check directly here; the same function
    // gates every real extraction inside `extract_tarball`.
    #[test]
    fn check_path_safety_rejects_parent_dir() {
        let err = check_path_safety(Path::new("package/../etc/passwd"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("..") || err.contains("traversal"),
            "got: {err}"
        );
    }

    #[test]
    fn check_path_safety_rejects_absolute() {
        assert!(check_path_safety(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn check_path_safety_accepts_normal_paths() {
        check_path_safety(Path::new("package/index.js")).unwrap();
        check_path_safety(Path::new("package/nested/lib.js")).unwrap();
        check_path_safety(Path::new("./package/index.js")).unwrap();
    }

    #[test]
    fn enforces_size_cap() {
        let dir = tempfile::tempdir().unwrap();
        let big = vec![b'x'; 2048];
        let bytes = make_targz(&[("package/big", &big)]);
        let err = extract_tarball(&bytes, dir.path(), 1024)
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds cap"), "got: {err}");
    }
}
