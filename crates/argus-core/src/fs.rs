//! Filesystem primitives shared across argus crates.
//!
//! `atomic_write_bytes` is the standard "write to a sibling temp file,
//! fsync, then rename over the destination" primitive (moved from
//! argus-agent, fault-injection test matrix included). Consolidated here
//! per #139 — argus-fetch's metadata cache previously carried an inline
//! copy of the same steps.
//!
//! NOT consolidated: `argus-intel`'s Unix snapshot writer implements a
//! strictly stronger contract at the file-descriptor level (directory
//! fsync phases, verified backups, inode-restoring rollback, cleanup-state
//! reporting) that a NamedTempFile-based primitive cannot express;
//! flattening it onto this helper would weaken real durability guarantees.

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tempfile::{Builder, NamedTempFile};

const CREATE_TEMP: &str = "create_temp";
const WRITE: &str = "write";
const FLUSH: &str = "flush";
const FILE_SYNC: &str = "file_sync";
const PERSIST: &str = "persist";

/// Open a local regular file without following its final symlink and read at
/// most `maximum_bytes` bytes.
///
/// Security scanners must not use an untrusted path with `read` or
/// `read_to_string`: a FIFO/device can block forever and a regular file can
/// allocate without bound. Unix opens are non-blocking and no-follow so the
/// type check is performed on the descriptor that is actually read.
pub fn read_bounded_regular_file(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>> {
    let file = open_regular_file(path)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect regular file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("path is not a regular file: {}", path.display());
    }
    if metadata.len() > maximum_bytes as u64 {
        bail!(
            "regular file exceeds {maximum_bytes} byte limit (maximum): {}",
            path.display()
        );
    }

    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(maximum_bytes));
    file.take((maximum_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read bounded regular file {}", path.display()))?;
    if bytes.len() > maximum_bytes {
        bail!(
            "regular file grew beyond {maximum_bytes} byte limit while reading: {}",
            path.display()
        );
    }
    Ok(bytes)
}

pub fn read_bounded_utf8_regular_file(path: &Path, maximum_bytes: usize) -> Result<String> {
    String::from_utf8(read_bounded_regular_file(path, maximum_bytes)?)
        .with_context(|| format!("decode UTF-8 regular file {}", path.display()))
}

#[cfg(unix)]
fn open_regular_file(path: &Path) -> Result<File> {
    use rustix::fs::{open, Mode, OFlags};

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .with_context(|| {
        format!(
            "open regular file {} without following links",
            path.display()
        )
    })?;
    Ok(File::from(descriptor))
}

#[cfg(windows)]
fn open_regular_file(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    // Open the reparse point itself so the descriptor-level metadata check in
    // `read_bounded_regular_file` rejects symlinks/junctions without a
    // check-then-open race.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| {
            format!(
                "open regular file {} without following links",
                path.display()
            )
        })
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file(path: &Path) -> Result<File> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect regular file {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("path is a symlink: {}", path.display());
    }
    File::open(path).with_context(|| format!("open regular file {}", path.display()))
}

pub fn atomic_write_bytes(path: &Path, bytes: &[u8], temporary_prefix: &str) -> Result<()> {
    write_bytes_inner(path, bytes, temporary_prefix, |_| Ok(()))
}

fn write_bytes_inner(
    path: &Path,
    bytes: &[u8],
    temporary_prefix: &str,
    mut fault: impl FnMut(&'static str) -> std::io::Result<()>,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    fault(CREATE_TEMP).context("create temporary file")?;
    let mut temporary = Builder::new()
        .prefix(temporary_prefix)
        .tempfile_in(parent)
        .with_context(|| format!("create temporary file next to {}", path.display()))?;

    if let Err(error) = fault(WRITE).and_then(|()| temporary.write_all(bytes)) {
        return close_after_io_error(temporary, "write", path, error);
    }
    if let Err(error) = fault(FLUSH).and_then(|()| temporary.flush()) {
        return close_after_io_error(temporary, "flush", path, error);
    }
    if let Err(error) = fault(FILE_SYNC).and_then(|()| temporary.as_file().sync_all()) {
        return close_after_io_error(temporary, "sync", path, error);
    }
    if let Err(error) = fault(PERSIST) {
        return close_after_io_error(temporary, "persist", path, error);
    }

    match temporary.persist(path) {
        Ok(_) => Ok(()),
        Err(error) => {
            let tempfile::PersistError {
                error: persist_error,
                file,
            } = error;
            let temporary_path = file.path().to_path_buf();
            match file.close() {
                Ok(()) => Err(persist_error)
                    .with_context(|| format!("replace destination {}", path.display())),
                Err(cleanup_error) => bail!(
                    "replace destination {}: {persist_error}; cleanup temporary file {}: \
                     {cleanup_error}",
                    path.display(),
                    temporary_path.display()
                ),
            }
        }
    }
}

fn close_after_io_error(
    temporary: NamedTempFile,
    operation: &str,
    destination: &Path,
    operation_error: std::io::Error,
) -> Result<()> {
    let temporary_path = temporary.path().to_path_buf();
    match temporary.close() {
        Ok(()) => Err(operation_error)
            .with_context(|| format!("{operation} temporary file for {}", destination.display())),
        Err(cleanup_error) => bail!(
            "{operation} temporary file for {}: {operation_error}; cleanup temporary file {}: \
             {cleanup_error}",
            destination.display(),
            temporary_path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fault {
        CreateTemp,
        Write,
        Flush,
        FileSync,
        Persist,
    }

    impl Fault {
        fn operation(self) -> &'static str {
            match self {
                Self::CreateTemp => CREATE_TEMP,
                Self::Write => WRITE,
                Self::Flush => FLUSH,
                Self::FileSync => FILE_SYNC,
                Self::Persist => PERSIST,
            }
        }
    }

    fn write_with_fault(path: &Path, bytes: &[u8], fault: Fault) -> Result<()> {
        write_bytes_inner(path, bytes, ".argus-atomic-test-", |operation| {
            if operation == fault.operation() {
                Err(std::io::Error::other(format!(
                    "synthetic {operation} failure"
                )))
            } else {
                Ok(())
            }
        })
    }

    fn temporary_files(parent: &Path) -> Vec<std::path::PathBuf> {
        fs::read_dir(parent)
            .expect("read test directory")
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".argus-atomic-test-")
            })
            .map(|entry| entry.path())
            .collect()
    }

    #[test]
    fn atomic_write_fault_matrix() {
        let faults = [
            Fault::CreateTemp,
            Fault::Write,
            Fault::Flush,
            Fault::FileSync,
            Fault::Persist,
        ];

        for fault in faults {
            let directory = tempfile::tempdir().expect("test directory");
            let existing = directory.path().join("existing.json");
            fs::write(&existing, b"approved bytes").expect("write existing destination");
            let existing_mtime = fs::metadata(&existing)
                .expect("existing metadata")
                .modified()
                .expect("existing mtime");

            let error = write_with_fault(&existing, b"replacement bytes", fault)
                .expect_err("fault must fail the write");
            assert!(
                format!("{error:#}").contains("synthetic"),
                "unexpected {fault:?} error: {error:#}"
            );
            assert_eq!(
                fs::read(&existing).expect("read preserved destination"),
                b"approved bytes",
                "{fault:?} changed destination bytes"
            );
            assert_eq!(
                fs::metadata(&existing)
                    .expect("preserved metadata")
                    .modified()
                    .expect("preserved mtime"),
                existing_mtime,
                "{fault:?} changed destination mtime"
            );
            assert!(
                temporary_files(directory.path()).is_empty(),
                "{fault:?} leaked a temporary file"
            );

            let missing = directory.path().join("missing.json");
            write_with_fault(&missing, b"partial bytes", fault)
                .expect_err("fault must fail the missing-destination write");
            assert!(!missing.exists(), "{fault:?} created a partial destination");
            assert!(
                temporary_files(directory.path()).is_empty(),
                "{fault:?} leaked a temporary file for a missing destination"
            );
        }
    }

    #[test]
    fn bounded_regular_read_rejects_oversized_input() {
        let directory = tempfile::tempdir().expect("test directory");
        let path = directory.path().join("large.txt");
        fs::write(&path, b"12345").expect("write fixture");
        let error = read_bounded_regular_file(&path, 4).expect_err("oversized file");
        assert!(format!("{error:#}").contains("exceeds 4 byte limit"));
        assert_eq!(
            read_bounded_regular_file(&path, 5).expect("exact bound"),
            b"12345"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_regular_read_rejects_symlinks_and_devices() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("test directory");
        let target = directory.path().join("target.txt");
        let link = directory.path().join("link.txt");
        fs::write(&target, b"secret").expect("write target");
        symlink(&target, &link).expect("create symlink");
        assert!(read_bounded_regular_file(&link, 1024).is_err());
        assert!(read_bounded_regular_file(Path::new("/dev/null"), 1024).is_err());
    }
}
