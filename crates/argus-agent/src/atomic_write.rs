use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::Path;
use tempfile::{Builder, NamedTempFile};

const CREATE_TEMP: &str = "create_temp";
const WRITE: &str = "write";
const FLUSH: &str = "flush";
const FILE_SYNC: &str = "file_sync";
const PERSIST: &str = "persist";

pub(crate) fn write_bytes(path: &Path, bytes: &[u8], temporary_prefix: &str) -> Result<()> {
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
}
