use super::{validate_snapshot, AtomicCleanupState, AtomicWriteOutcome, SnapshotEnvelope};
use anyhow::{bail, Context, Result};
use rustix::fd::OwnedFd;
use rustix::fs::{self as unix_fs, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectorySync {
    Prepared,
    PreReplacementCleaned,
    Replaced,
    Cleaned,
    RolledBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    RollbackMutation,
    BackupOpen,
    BackupMetadata,
    BackupUnlink,
}

trait AtomicFs {
    fn sync_directory(&self, directory: &OwnedFd, phase: DirectorySync) -> std::io::Result<()>;

    fn check_fault(&self, _point: FaultPoint) -> std::io::Result<()> {
        Ok(())
    }
}

struct RealAtomicFs;

impl AtomicFs for RealAtomicFs {
    fn sync_directory(&self, directory: &OwnedFd, _phase: DirectorySync) -> std::io::Result<()> {
        unix_fs::fsync(directory).map_err(Into::into)
    }
}

pub(super) fn open_snapshot(path: &Path) -> Result<(File, u64)> {
    let (directory, name) = open_parent(path)?;
    let descriptor = unix_fs::openat(
        &directory,
        &name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .with_context(|| format!("open snapshot {} without following links", path.display()))?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .with_context(|| format!("read snapshot metadata {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("snapshot must be a local regular file: {}", path.display());
    }
    Ok((file, metadata.len()))
}

pub(super) fn write_atomic(path: &Path, snapshot: &SnapshotEnvelope) -> Result<AtomicWriteOutcome> {
    write_atomic_with(path, snapshot, &RealAtomicFs)
}

fn write_atomic_with(
    path: &Path,
    snapshot: &SnapshotEnvelope,
    atomic_fs: &impl AtomicFs,
) -> Result<AtomicWriteOutcome> {
    let (directory, destination) = open_parent(path)?;
    let existing = open_existing_regular(&directory, &destination, path)?;
    let (temporary_name, mut temporary) =
        create_unique_file(&directory, "new").context("create temporary snapshot")?;

    let preparation = (|| -> Result<()> {
        serde_json_canonicalizer::to_writer(snapshot, &mut temporary)
            .context("serialize intelligence snapshot")?;
        temporary
            .write_all(b"\n")
            .context("terminate intelligence snapshot")?;
        temporary.flush().context("flush intelligence snapshot")?;
        temporary
            .sync_all()
            .context("fsync intelligence snapshot")?;
        temporary
            .seek(SeekFrom::Start(0))
            .context("rewind intelligence snapshot")?;
        let roundtrip: SnapshotEnvelope =
            serde_json::from_reader(&mut temporary).context("re-read temporary snapshot")?;
        validate_snapshot(&roundtrip).context("validate temporary snapshot before replacement")
    })();
    if let Err(error) = preparation {
        return cleanup_before_replace(
            &directory,
            OsStr::new(&temporary_name),
            None,
            atomic_fs,
            error,
        );
    }
    drop(temporary);

    let backup_name = match existing {
        Some(existing) => {
            match create_verified_backup(&directory, &destination, &existing, atomic_fs) {
                Ok(name) => Some(name),
                Err(error) => {
                    return cleanup_before_replace(
                        &directory,
                        OsStr::new(&temporary_name),
                        None,
                        atomic_fs,
                        error,
                    );
                }
            }
        }
        None => None,
    };

    if let Err(error) = atomic_fs.sync_directory(&directory, DirectorySync::Prepared) {
        return cleanup_before_replace(
            &directory,
            OsStr::new(&temporary_name),
            backup_name.as_deref().map(OsStr::new),
            atomic_fs,
            anyhow::Error::new(error).context("fsync prepared snapshot directory"),
        );
    }
    if let Err(error) = unix_fs::renameat(&directory, &temporary_name, &directory, &destination) {
        return cleanup_before_replace(
            &directory,
            OsStr::new(&temporary_name),
            backup_name.as_deref().map(OsStr::new),
            atomic_fs,
            anyhow::Error::new(error).context("atomically replace intelligence snapshot"),
        );
    }

    if let Err(sync_error) = atomic_fs.sync_directory(&directory, DirectorySync::Replaced) {
        return rollback_replacement(
            &directory,
            &destination,
            backup_name.as_deref().map(OsStr::new),
            atomic_fs,
            anyhow::Error::new(sync_error).context("fsync replaced snapshot directory"),
        );
    }

    if let Some(backup) = &backup_name {
        if let Err(error) = atomic_fs.check_fault(FaultPoint::BackupUnlink) {
            return Ok(AtomicWriteOutcome::CommittedWithCleanupWarning {
                backup_name: backup.clone(),
                state: AtomicCleanupState::Pending,
                cause: error.to_string(),
            });
        }
        if let Err(error) = unix_fs::unlinkat(&directory, backup.as_str(), AtFlags::empty()) {
            return Ok(AtomicWriteOutcome::CommittedWithCleanupWarning {
                backup_name: backup.clone(),
                state: AtomicCleanupState::Pending,
                cause: error.to_string(),
            });
        }
        if let Err(error) = atomic_fs.sync_directory(&directory, DirectorySync::Cleaned) {
            return Ok(AtomicWriteOutcome::CommittedWithCleanupWarning {
                backup_name: backup.clone(),
                state: AtomicCleanupState::DurabilityUncertain,
                cause: error.to_string(),
            });
        }
    }
    Ok(AtomicWriteOutcome::Committed)
}

fn rollback_replacement(
    directory: &OwnedFd,
    destination: &OsStr,
    backup: Option<&OsStr>,
    atomic_fs: &impl AtomicFs,
    original_error: anyhow::Error,
) -> Result<AtomicWriteOutcome> {
    if let Err(rollback_error) = atomic_fs.check_fault(FaultPoint::RollbackMutation) {
        bail!(
            "{original_error:#}; rollback failed and snapshot state is uncertain: {rollback_error}"
        );
    }
    let rollback = if let Some(backup) = backup {
        unix_fs::renameat(directory, backup, directory, destination)
    } else {
        unix_fs::unlinkat(directory, destination, AtFlags::empty())
    };
    if let Err(rollback_error) = rollback {
        bail!(
            "{original_error:#}; rollback failed and snapshot state is uncertain: {rollback_error}"
        );
    }
    if let Err(sync_error) = atomic_fs.sync_directory(directory, DirectorySync::RolledBack) {
        bail!(
            "{original_error:#}; rollback changed the visible path but its durability is uncertain: \
             {sync_error}"
        );
    }
    Err(original_error.context("replacement rolled back to the prior snapshot"))
}

fn cleanup_before_replace(
    directory: &OwnedFd,
    temporary: &OsStr,
    backup: Option<&OsStr>,
    atomic_fs: &impl AtomicFs,
    original_error: anyhow::Error,
) -> Result<AtomicWriteOutcome> {
    let mut cleanup_errors = Vec::new();
    if let Err(error) = unlink_if_present(directory, temporary) {
        cleanup_errors.push(format!("temporary cleanup failed: {error}"));
    }
    if let Some(backup) = backup {
        if let Err(error) = unlink_if_present(directory, backup) {
            cleanup_errors.push(format!("backup cleanup failed: {error}"));
        }
    }
    if !cleanup_errors.is_empty() {
        bail!(
            "{original_error:#}; pre-replacement cleanup incomplete: {}",
            cleanup_errors.join("; ")
        )
    }
    if let Err(error) = atomic_fs.sync_directory(directory, DirectorySync::PreReplacementCleaned) {
        bail!(
            "{original_error:#}; pre-replacement cleanup directory fsync failed and cleanup \
             durability is uncertain: {error}"
        );
    }
    Err(original_error)
}

fn unlink_if_present(directory: &OwnedFd, name: &OsStr) -> std::io::Result<()> {
    match unix_fs::unlinkat(directory, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn create_verified_backup(
    directory: &OwnedFd,
    destination: &OsStr,
    existing: &File,
    atomic_fs: &impl AtomicFs,
) -> Result<String> {
    let expected = existing
        .metadata()
        .context("read existing snapshot identity")?;
    for _ in 0..128 {
        let backup = unique_name("old");
        match unix_fs::linkat(directory, destination, directory, &backup, AtFlags::empty()) {
            Ok(()) => {
                let verification = (|| -> Result<()> {
                    atomic_fs
                        .check_fault(FaultPoint::BackupOpen)
                        .context("open snapshot backup without following links")?;
                    let descriptor = unix_fs::openat(
                        directory,
                        backup.as_str(),
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                        Mode::empty(),
                    )
                    .context("open snapshot backup without following links")?;
                    atomic_fs
                        .check_fault(FaultPoint::BackupMetadata)
                        .context("read snapshot backup identity")?;
                    let actual = File::from(descriptor)
                        .metadata()
                        .context("read snapshot backup identity")?;
                    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
                        bail!("snapshot destination changed while creating its rollback backup");
                    }
                    Ok(())
                })();
                match verification {
                    Ok(()) => return Ok(backup),
                    Err(error) => {
                        return cleanup_linked_backup(
                            directory,
                            OsStr::new(&backup),
                            atomic_fs,
                            error,
                        );
                    }
                }
            }
            Err(Errno::EXIST) => continue,
            Err(error) => return Err(error).context("create rollback backup for snapshot"),
        }
    }
    bail!("could not allocate a unique rollback backup name");
}

fn cleanup_linked_backup(
    directory: &OwnedFd,
    backup: &OsStr,
    atomic_fs: &impl AtomicFs,
    original_error: anyhow::Error,
) -> Result<String> {
    if let Err(error) = unlink_if_present(directory, backup) {
        bail!(
            "{original_error:#}; newly linked backup cleanup failed and snapshot state is \
             uncertain: {error}"
        );
    }
    if let Err(error) = atomic_fs.sync_directory(directory, DirectorySync::PreReplacementCleaned) {
        bail!(
            "{original_error:#}; newly linked backup was removed but cleanup durability is \
             uncertain: {error}"
        );
    }
    Err(original_error)
}

fn create_unique_file(directory: &OwnedFd, purpose: &str) -> Result<(String, File)> {
    for _ in 0..128 {
        let name = unique_name(purpose);
        match unix_fs::openat(
            directory,
            name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(descriptor) => return Ok((name, File::from(descriptor))),
            Err(Errno::EXIST) => continue,
            Err(error) => return Err(error).context("create fd-relative temporary file"),
        }
    }
    bail!("could not allocate a unique temporary snapshot name");
}

fn unique_name(purpose: &str) -> String {
    let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".argus-intel-{purpose}-{}-{counter}", std::process::id())
}

fn open_existing_regular(
    directory: &OwnedFd,
    destination: &OsStr,
    path: &Path,
) -> Result<Option<File>> {
    match unix_fs::openat(
        directory,
        destination,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => {
            let file = File::from(descriptor);
            let metadata = file
                .metadata()
                .with_context(|| format!("inspect snapshot destination {}", path.display()))?;
            if !metadata.file_type().is_file() {
                bail!(
                    "snapshot destination is not a regular file: {}",
                    path.display()
                );
            }
            Ok(Some(file))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "inspect snapshot destination {} without following links",
                path.display()
            )
        }),
    }
}

fn open_parent(path: &Path) -> Result<(OwnedFd, OsString)> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("snapshot path has no parent: {}", path.display()))?;
    let destination = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("snapshot path has no file name: {}", path.display()))?
        .to_os_string();
    let start = if parent.is_absolute() { "/" } else { "." };
    let mut directory = unix_fs::open(
        start,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .with_context(|| format!("open snapshot path anchor `{start}`"))?;
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = unix_fs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .with_context(|| {
                    format!(
                        "open snapshot parent component `{}` without following links",
                        name.to_string_lossy()
                    )
                })?;
            }
            Component::ParentDir => bail!("snapshot path contains `..`"),
            Component::Prefix(_) => bail!("snapshot path contains an unsupported prefix"),
        }
    }
    Ok((directory, destination))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::CANONICAL_SOURCE;
    use crate::snapshot::{finalize_snapshot, SnapshotEnvelope, SNAPSHOT_FORMAT_VERSION};
    use chrono::{TimeZone, Utc};

    struct FailAfterReplacement;

    impl AtomicFs for FailAfterReplacement {
        fn sync_directory(&self, directory: &OwnedFd, phase: DirectorySync) -> std::io::Result<()> {
            if phase == DirectorySync::Replaced {
                return Err(std::io::Error::other(
                    "injected post-replacement fsync failure",
                ));
            }
            unix_fs::fsync(directory).map_err(Into::into)
        }
    }

    struct FailReplacementAndRollback;

    impl AtomicFs for FailReplacementAndRollback {
        fn sync_directory(&self, directory: &OwnedFd, phase: DirectorySync) -> std::io::Result<()> {
            if phase == DirectorySync::Replaced {
                return Err(std::io::Error::other(
                    "injected post-replacement fsync failure",
                ));
            }
            unix_fs::fsync(directory).map_err(Into::into)
        }

        fn check_fault(&self, point: FaultPoint) -> std::io::Result<()> {
            if point == FaultPoint::RollbackMutation {
                return Err(std::io::Error::other("injected rollback failure"));
            }
            Ok(())
        }
    }

    struct FailPreparedDirectorySync;

    impl AtomicFs for FailPreparedDirectorySync {
        fn sync_directory(&self, directory: &OwnedFd, phase: DirectorySync) -> std::io::Result<()> {
            if phase == DirectorySync::Prepared {
                return Err(std::io::Error::other(
                    "injected prepared-directory fsync failure",
                ));
            }
            unix_fs::fsync(directory).map_err(Into::into)
        }
    }

    struct FailBackupUnlink;

    impl AtomicFs for FailBackupUnlink {
        fn sync_directory(
            &self,
            directory: &OwnedFd,
            _phase: DirectorySync,
        ) -> std::io::Result<()> {
            unix_fs::fsync(directory).map_err(Into::into)
        }

        fn check_fault(&self, point: FaultPoint) -> std::io::Result<()> {
            if point == FaultPoint::BackupUnlink {
                return Err(std::io::Error::other("injected backup unlink failure"));
            }
            Ok(())
        }
    }

    struct FailBackupVerification(FaultPoint);

    impl AtomicFs for FailBackupVerification {
        fn sync_directory(
            &self,
            directory: &OwnedFd,
            _phase: DirectorySync,
        ) -> std::io::Result<()> {
            unix_fs::fsync(directory).map_err(Into::into)
        }

        fn check_fault(&self, point: FaultPoint) -> std::io::Result<()> {
            if point == self.0 {
                return Err(std::io::Error::other(format!("injected {point:?} failure")));
            }
            Ok(())
        }
    }

    struct FailCleanupDurability;

    impl AtomicFs for FailCleanupDurability {
        fn sync_directory(&self, directory: &OwnedFd, phase: DirectorySync) -> std::io::Result<()> {
            if phase == DirectorySync::Cleaned {
                return Err(std::io::Error::other(
                    "injected cleanup directory fsync failure",
                ));
            }
            unix_fs::fsync(directory).map_err(Into::into)
        }
    }

    struct FailPreReplacementCleanupDurability;

    impl AtomicFs for FailPreReplacementCleanupDurability {
        fn sync_directory(&self, directory: &OwnedFd, phase: DirectorySync) -> std::io::Result<()> {
            if phase == DirectorySync::PreReplacementCleaned {
                return Err(std::io::Error::other(
                    "injected pre-replacement cleanup fsync failure",
                ));
            }
            unix_fs::fsync(directory).map_err(Into::into)
        }
    }

    fn empty_snapshot() -> SnapshotEnvelope {
        finalize_snapshot(SnapshotEnvelope {
            format_version: SNAPSHOT_FORMAT_VERSION,
            source: CANONICAL_SOURCE.to_string(),
            revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
            schema_versions: vec!["1.7.4".to_string()],
            archive_sha256: "0".repeat(64),
            records_sha256: String::new(),
            imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            records: Vec::new(),
            snapshot_sha256: String::new(),
        })
        .unwrap()
    }

    #[test]
    fn restores_prior_inode_after_post_replacement_fsync_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("intel.json");
        std::fs::write(&path, b"prior snapshot bytes").unwrap();
        let original = std::fs::metadata(&path).unwrap();

        let error = write_atomic_with(&path, &empty_snapshot(), &FailAfterReplacement).unwrap_err();

        assert!(
            format!("{error:#}").contains("rolled back"),
            "unexpected error: {error:#}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"prior snapshot bytes");
        let restored = std::fs::metadata(&path).unwrap();
        assert_eq!(original.dev(), restored.dev());
        assert_eq!(original.ino(), restored.ino());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn removes_new_path_after_first_write_fsync_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("intel.json");

        let error = write_atomic_with(&path, &empty_snapshot(), &FailAfterReplacement).unwrap_err();

        assert!(
            format!("{error:#}").contains("rolled back"),
            "unexpected error: {error:#}"
        );
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn reports_state_uncertain_when_rollback_itself_fails() {
        let directory = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("intel.json");
        std::fs::write(&path, b"prior snapshot bytes").unwrap();

        let error =
            write_atomic_with(&path, &empty_snapshot(), &FailReplacementAndRollback).unwrap_err();

        assert!(format!("{error:#}").contains("snapshot state is uncertain"));
        assert_ne!(std::fs::read(&path).unwrap(), b"prior snapshot bytes");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn invalid_snapshot_is_removed_before_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("intel.json");
        std::fs::write(&path, b"prior snapshot bytes").unwrap();
        let mut invalid = empty_snapshot();
        invalid.snapshot_sha256 = "f".repeat(64);

        let error = write_atomic_with(&path, &invalid, &RealAtomicFs).unwrap_err();

        assert!(format!("{error:#}").contains("snapshot envelope SHA-256 mismatch"));
        assert_eq!(std::fs::read(&path).unwrap(), b"prior snapshot bytes");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn prepared_directory_sync_failure_cleans_temporary_and_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("intel.json");
        std::fs::write(&path, b"prior snapshot bytes").unwrap();
        let original = std::fs::metadata(&path).unwrap();

        let error =
            write_atomic_with(&path, &empty_snapshot(), &FailPreparedDirectorySync).unwrap_err();

        assert!(format!("{error:#}").contains("fsync prepared snapshot directory"));
        assert_eq!(std::fs::read(&path).unwrap(), b"prior snapshot bytes");
        assert_eq!(original.ino(), std::fs::metadata(&path).unwrap().ino());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn backup_open_failure_unlinks_and_syncs_new_hardlink() {
        backup_verification_failure_cleans_link(FaultPoint::BackupOpen);
    }

    #[test]
    fn backup_metadata_failure_unlinks_and_syncs_new_hardlink() {
        backup_verification_failure_cleans_link(FaultPoint::BackupMetadata);
    }

    fn backup_verification_failure_cleans_link(point: FaultPoint) {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let path = root.join("intel.json");
        std::fs::write(&path, b"prior snapshot bytes").unwrap();
        let original = std::fs::metadata(&path).unwrap();

        let error = write_atomic_with(&path, &empty_snapshot(), &FailBackupVerification(point))
            .unwrap_err();

        assert!(format!("{error:#}").contains("snapshot backup"));
        assert_eq!(std::fs::read(&path).unwrap(), b"prior snapshot bytes");
        assert_eq!(original.ino(), std::fs::metadata(&path).unwrap().ino());
        assert_eq!(
            std::fs::read_dir(root).unwrap().count(),
            1,
            "temporary file and newly linked backup must both be removed"
        );
    }

    #[test]
    fn committed_cleanup_pending_retains_named_backup() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let path = root.join("intel.json");
        std::fs::write(&path, b"prior snapshot bytes").unwrap();

        let outcome = write_atomic_with(&path, &empty_snapshot(), &FailBackupUnlink).unwrap();

        let AtomicWriteOutcome::CommittedWithCleanupWarning {
            backup_name,
            state,
            cause,
        } = outcome
        else {
            panic!("expected committed cleanup warning");
        };
        assert_eq!(state, AtomicCleanupState::Pending);
        assert!(cause.contains("injected backup unlink failure"));
        assert!(root.join(backup_name).is_file());
        assert_ne!(std::fs::read(&path).unwrap(), b"prior snapshot bytes");
    }

    #[test]
    fn committed_cleanup_fsync_failure_reports_durability_uncertain() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let path = root.join("intel.json");
        std::fs::write(&path, b"prior snapshot bytes").unwrap();

        let outcome = write_atomic_with(&path, &empty_snapshot(), &FailCleanupDurability).unwrap();

        let AtomicWriteOutcome::CommittedWithCleanupWarning {
            backup_name,
            state,
            cause,
        } = outcome
        else {
            panic!("expected committed cleanup warning");
        };
        assert_eq!(state, AtomicCleanupState::DurabilityUncertain);
        assert!(cause.contains("injected cleanup directory fsync failure"));
        assert!(!root.join(backup_name).exists());
        assert_ne!(std::fs::read(&path).unwrap(), b"prior snapshot bytes");
    }

    #[test]
    fn pre_replacement_cleanup_is_directory_synced() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let path = root.join("intel.json");
        std::fs::write(&path, b"prior snapshot bytes").unwrap();
        let mut invalid = empty_snapshot();
        invalid.snapshot_sha256 = "f".repeat(64);

        let error =
            write_atomic_with(&path, &invalid, &FailPreReplacementCleanupDurability).unwrap_err();

        assert!(format!("{error:#}").contains("cleanup durability is uncertain"));
        assert_eq!(std::fs::read(&path).unwrap(), b"prior snapshot bytes");
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
    }
}
