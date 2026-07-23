//! AGT-04 canonical high-context inventory snapshots.

use crate::atomic_write;
use anyhow::{bail, Context, Result};
use argus_core::{Finding, Severity};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub(crate) const RULE_SYMLINK_CHANGED: &str = "AGT-04-symlink-changed";
pub(crate) const RULE_ENTRY_ADDED: &str = "AGT-04-entry-added";
pub(crate) const RULE_ENTRY_REMOVED: &str = "AGT-04-entry-removed";
pub(crate) const RULE_ENTRY_TYPE_CHANGED: &str = "AGT-04-entry-type-changed";
pub(crate) const RULE_CONTENT_MODIFIED: &str = "AGT-04-content-modified";

const SNAPSHOT_VERSION: u32 = 1;
const DIGEST_LEN: usize = 64;
const HASH_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryType {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Snapshot {
    pub(crate) version: u32,
    pub(crate) entries: BTreeMap<String, SnapshotEntry>,
}

impl Snapshot {
    pub(crate) fn new(entries: BTreeMap<String, SnapshotEntry>) -> Self {
        Self {
            version: SNAPSHOT_VERSION,
            entries,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub(crate) enum SnapshotEntry {
    File { digest: String },
    Directory,
    Symlink { link_target_digest: String },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum RawSnapshotEntry {
    File { digest: String },
    Directory {},
    Symlink { link_target_digest: String },
}

struct RawEntries(BTreeMap<String, RawSnapshotEntry>);

impl<'de> Deserialize<'de> for RawEntries {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EntriesVisitor;

        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = RawEntries;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object with unique logical-path keys")
            }

            fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = BTreeSet::new();
                let mut entries = BTreeMap::new();
                while let Some(path) = access.next_key::<String>()? {
                    if !seen.insert(path.clone()) {
                        return Err(de::Error::custom(format!(
                            "duplicate snapshot entry path `{path}`"
                        )));
                    }
                    let entry = access.next_value::<RawSnapshotEntry>()?;
                    entries.insert(path, entry);
                }
                Ok(RawEntries(entries))
            }
        }

        deserializer.deserialize_map(EntriesVisitor)
    }
}

impl<'de> Deserialize<'de> for Snapshot {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawSnapshot {
            version: u32,
            entries: RawEntries,
        }

        let raw = RawSnapshot::deserialize(deserializer)?;
        if raw.version != SNAPSHOT_VERSION {
            return Err(de::Error::custom(format!(
                "unsupported snapshot version {}; expected {SNAPSHOT_VERSION}",
                raw.version
            )));
        }

        let mut entries = BTreeMap::new();
        for (path, raw_entry) in raw.entries.0 {
            validate_logical_path(&path).map_err(de::Error::custom)?;
            let entry = match raw_entry {
                RawSnapshotEntry::File { digest } => {
                    validate_digest(&digest).map_err(de::Error::custom)?;
                    SnapshotEntry::File { digest }
                }
                RawSnapshotEntry::Directory {} => SnapshotEntry::Directory,
                RawSnapshotEntry::Symlink { link_target_digest } => {
                    validate_digest(&link_target_digest).map_err(de::Error::custom)?;
                    SnapshotEntry::Symlink { link_target_digest }
                }
            };
            entries.insert(path, entry);
        }

        Ok(Snapshot::new(entries))
    }
}

pub(crate) fn load(path: &Path) -> Result<Snapshot> {
    let bytes = std::fs::read(path).with_context(|| format!("read snapshot {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse snapshot {}", path.display()))
}

pub(crate) fn save(path: &Path, snapshot: &Snapshot) -> Result<()> {
    let bytes = render(snapshot)?;
    atomic_write::write_bytes(path, &bytes, ".argus-snapshot-")
        .with_context(|| format!("write snapshot {}", path.display()))
}

pub(crate) fn render(snapshot: &Snapshot) -> Result<Vec<u8>> {
    let mut text = serde_json::to_string_pretty(snapshot).context("serialize snapshot")?;
    text.push('\n');
    Ok(text.into_bytes())
}

pub(crate) fn capture_entry(path: &Path, expected_type: EntryType) -> Result<SnapshotEntry> {
    let before = ObservedMetadata::read(path)
        .with_context(|| format!("inspect snapshot entry {}", path.display()))?;
    if before.entry_type != expected_type {
        bail!(
            "snapshot entry type changed while scanning {}",
            path.display()
        );
    }

    let entry = match expected_type {
        EntryType::File => SnapshotEntry::File {
            digest: hash_file(path)
                .with_context(|| format!("hash snapshot file {}", path.display()))?,
        },
        EntryType::Directory => SnapshotEntry::Directory,
        EntryType::Symlink => SnapshotEntry::Symlink {
            link_target_digest: hash_symlink_target(path)
                .with_context(|| format!("hash snapshot symlink {}", path.display()))?,
        },
    };

    let after = ObservedMetadata::read(path)
        .with_context(|| format!("reinspect snapshot entry {}", path.display()))?;
    if before != after {
        bail!("snapshot entry changed while scanning {}", path.display());
    }
    Ok(entry)
}

pub(crate) fn compare(approved: &Snapshot, current: &Snapshot) -> Vec<Finding> {
    let paths: BTreeSet<_> = approved
        .entries
        .keys()
        .chain(current.entries.keys())
        .cloned()
        .collect();
    let mut findings = Vec::new();

    for path in paths {
        let old = approved.entries.get(&path);
        let new = current.entries.get(&path);
        if old == new {
            continue;
        }
        let (rule_id, change) = if old.is_some_and(SnapshotEntry::is_symlink)
            || new.is_some_and(SnapshotEntry::is_symlink)
        {
            (RULE_SYMLINK_CHANGED, "symlink_changed")
        } else {
            match (old, new) {
                (None, Some(_)) => (RULE_ENTRY_ADDED, "entry_added"),
                (Some(_), None) => (RULE_ENTRY_REMOVED, "entry_removed"),
                (Some(old), Some(new)) if old.kind() != new.kind() => {
                    (RULE_ENTRY_TYPE_CHANGED, "entry_type_changed")
                }
                (Some(SnapshotEntry::File { .. }), Some(SnapshotEntry::File { .. })) => {
                    (RULE_CONTENT_MODIFIED, "content_modified")
                }
                _ => continue,
            }
        };

        let evidence = format!(
            "change={change};old_kind={};new_kind={};old_digest={};new_digest={}",
            old.map_or("null", SnapshotEntry::kind),
            new.map_or("null", SnapshotEntry::kind),
            old.and_then(SnapshotEntry::digest).unwrap_or("null"),
            new.and_then(SnapshotEntry::digest).unwrap_or("null"),
        );
        let mut finding = Finding::new(
            rule_id,
            Severity::Medium,
            format!("agent surface inventory change: {change}"),
        )
        .at(path);
        finding.evidence = Some(vec![evidence]);
        findings.push(finding);
    }

    findings
}

impl SnapshotEntry {
    fn kind(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Directory => "directory",
            Self::Symlink { .. } => "symlink",
        }
    }

    fn digest(&self) -> Option<&str> {
        match self {
            Self::File { digest } => Some(digest),
            Self::Directory => None,
            Self::Symlink { link_target_digest } => Some(link_target_digest),
        }
    }

    fn is_symlink(&self) -> bool {
        matches!(self, Self::Symlink { .. })
    }
}

fn validate_logical_path(path: &str) -> std::result::Result<(), &'static str> {
    if path.is_empty() {
        return Err("snapshot path must not be empty");
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err("snapshot path must be a relative path without a trailing slash");
    }
    if path.contains('\\') {
        return Err("snapshot path must use forward slashes");
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err("snapshot path contains an invalid segment");
    }
    let first = path.split('/').next().unwrap_or(path);
    if first.len() >= 2 && first.as_bytes()[0].is_ascii_alphabetic() && first.as_bytes()[1] == b':'
    {
        return Err("snapshot path must not contain a platform prefix");
    }
    Ok(())
}

fn validate_digest(digest: &str) -> std::result::Result<(), &'static str> {
    if digest.len() != DIGEST_LEN
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("snapshot digest must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_SIZE];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_symlink_target(path: &Path) -> Result<String> {
    let target = std::fs::read_link(path)?;
    let mut hasher = Sha256::new();
    update_with_os_str(&mut hasher, target.as_os_str());
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn update_with_os_str(hasher: &mut Sha256, value: &std::ffi::OsStr) {
    use std::os::unix::ffi::OsStrExt;
    hasher.update(value.as_bytes());
}

#[cfg(windows)]
fn update_with_os_str(hasher: &mut Sha256, value: &std::ffi::OsStr) {
    use std::os::windows::ffi::OsStrExt;
    for unit in value.encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ObservedMetadata {
    entry_type: EntryType,
    len: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl ObservedMetadata {
    fn read(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        let file_type = metadata.file_type();
        let entry_type = if file_type.is_symlink() {
            EntryType::Symlink
        } else if file_type.is_file() {
            EntryType::File
        } else if file_type.is_dir() {
            EntryType::Directory
        } else {
            bail!("unsupported filesystem entry type");
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                entry_type,
                len: metadata.len(),
                modified: metadata.modified()?,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                entry_type,
                len: metadata.len(),
                modified: metadata.modified()?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn file(digest: &str) -> SnapshotEntry {
        SnapshotEntry::File {
            digest: digest.to_string(),
        }
    }

    fn symlink(digest: &str) -> SnapshotEntry {
        SnapshotEntry::Symlink {
            link_target_digest: digest.to_string(),
        }
    }

    fn snapshot(entries: &[(&str, SnapshotEntry)]) -> Snapshot {
        Snapshot::new(
            entries
                .iter()
                .map(|(path, entry)| ((*path).to_string(), entry.clone()))
                .collect(),
        )
    }

    #[test]
    fn strict_empty_snapshot_round_trips_deterministically() {
        let parsed: Snapshot =
            serde_json::from_str(r#"{"version":1,"entries":{}}"#).expect("valid snapshot");
        assert_eq!(parsed.len(), 0);
        let rendered = render(&parsed).expect("render");
        assert!(rendered.ends_with(b"\n"));
        assert_eq!(
            serde_json::from_slice::<Snapshot>(&rendered).expect("round trip"),
            parsed
        );
    }

    #[test]
    fn duplicate_entry_keys_are_rejected() {
        for input in [
            format!(
                r#"{{"version":1,"entries":{{"AGENTS.md":{{"kind":"file","digest":"{A}"}},"AGENTS.md":{{"kind":"file","digest":"{B}"}}}}}}"#
            ),
            format!(
                r#"{{"version":1,"entries":{{"AGENTS.md":{{"kind":"file","digest":"{A}"}},"\u0041GENTS.md":{{"kind":"file","digest":"{B}"}}}}}}"#
            ),
        ] {
            let error = serde_json::from_str::<Snapshot>(&input)
                .expect_err("duplicate decoded key must fail");
            assert!(error.to_string().contains("duplicate snapshot entry"));
        }
    }

    #[test]
    fn strict_schema_rejects_invalid_version_path_digest_and_shape() {
        let invalid = [
            r#"{"version":2,"entries":{}}"#.to_string(),
            r#"{"version":1,"entries":{},"extra":true}"#.to_string(),
            format!(r#"{{"version":1,"entries":{{"":{{"kind":"file","digest":"{A}"}}}}}}"#),
            format!(r#"{{"version":1,"entries":{{"a/../b":{{"kind":"file","digest":"{A}"}}}}}}"#),
            format!(r#"{{"version":1,"entries":{{"a\\b":{{"kind":"file","digest":"{A}"}}}}}}"#),
            format!(r#"{{"version":1,"entries":{{"C:foo":{{"kind":"file","digest":"{A}"}}}}}}"#),
            format!(r#"{{"version":1,"entries":{{"z:bar":{{"kind":"file","digest":"{A}"}}}}}}"#),
            r#"{"version":1,"entries":{"x":{"kind":"file","digest":"ABC"}}}"#.to_string(),
            format!(r#"{{"version":1,"entries":{{"x":{{"kind":"directory","digest":"{A}"}}}}}}"#),
            format!(r#"{{"version":1,"entries":{{"x":{{"kind":"symlink","digest":"{A}"}}}}}}"#),
            r#"{"version":1,"entries":{"x":{"kind":"other"}}}"#.to_string(),
        ];
        for input in invalid {
            assert!(
                serde_json::from_str::<Snapshot>(&input).is_err(),
                "accepted {input}"
            );
        }
    }

    #[test]
    fn five_change_rules_are_medium_with_exact_evidence() {
        let approved = snapshot(&[
            ("added-later", SnapshotEntry::Directory),
            ("content", file(A)),
            ("removed", SnapshotEntry::Directory),
            ("symlink", symlink(A)),
            ("type", file(A)),
        ]);
        let current = snapshot(&[
            ("added", SnapshotEntry::Directory),
            ("added-later", SnapshotEntry::Directory),
            ("content", file(B)),
            ("symlink", file(B)),
            ("type", SnapshotEntry::Directory),
        ]);
        let findings = compare(&approved, &current);
        assert_eq!(findings.len(), 5);
        assert!(findings
            .iter()
            .all(|finding| finding.severity == Severity::Medium));
        let actual: Vec<_> = findings
            .iter()
            .map(|finding| {
                (
                    finding.rule_id.as_str(),
                    finding.location.as_deref().unwrap(),
                    finding.evidence.as_ref().unwrap()[0].as_str(),
                )
            })
            .collect();
        assert_eq!(
            actual,
            vec![
                (
                    RULE_ENTRY_ADDED,
                    "added",
                    "change=entry_added;old_kind=null;new_kind=directory;old_digest=null;new_digest=null",
                ),
                (
                    RULE_CONTENT_MODIFIED,
                    "content",
                    &format!(
                        "change=content_modified;old_kind=file;new_kind=file;old_digest={A};new_digest={B}"
                    ),
                ),
                (
                    RULE_ENTRY_REMOVED,
                    "removed",
                    "change=entry_removed;old_kind=directory;new_kind=null;old_digest=null;new_digest=null",
                ),
                (
                    RULE_SYMLINK_CHANGED,
                    "symlink",
                    &format!(
                        "change=symlink_changed;old_kind=symlink;new_kind=file;old_digest={A};new_digest={B}"
                    ),
                ),
                (
                    RULE_ENTRY_TYPE_CHANGED,
                    "type",
                    &format!(
                        "change=entry_type_changed;old_kind=file;new_kind=directory;old_digest={A};new_digest=null"
                    ),
                ),
            ]
        );
    }

    #[test]
    fn empty_inventory_transition_priority_is_symlink_first() {
        let empty = Snapshot::new(BTreeMap::new());
        for (entry, from_empty_rule, to_empty_rule) in [
            (file(A), RULE_ENTRY_ADDED, RULE_ENTRY_REMOVED),
            (
                SnapshotEntry::Directory,
                RULE_ENTRY_ADDED,
                RULE_ENTRY_REMOVED,
            ),
            (symlink(A), RULE_SYMLINK_CHANGED, RULE_SYMLINK_CHANGED),
        ] {
            let populated = snapshot(&[("entry", entry)]);
            assert_eq!(compare(&empty, &populated)[0].rule_id, from_empty_rule);
            assert_eq!(compare(&populated, &empty)[0].rule_id, to_empty_rule);
        }
        assert!(compare(&empty, &empty).is_empty());
    }

    #[test]
    fn file_capture_hashes_every_chunk() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("large.bin");
        let mut bytes = vec![b'a'; HASH_BUFFER_SIZE * 2];
        bytes.extend_from_slice(b"tail");
        std::fs::write(&path, &bytes).expect("large file");
        let expected = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(
            capture_entry(&path, EntryType::File).expect("capture"),
            file(&expected)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_digest_never_leaks_target() {
        use std::os::unix::fs::symlink as create_symlink;

        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("link");
        let target = "private-target-name";
        create_symlink(target, &path).expect("symlink");
        let entry = capture_entry(&path, EntryType::Symlink).expect("capture");
        let expected = format!("{:x}", Sha256::digest(target.as_bytes()));
        assert_eq!(entry, symlink(&expected));
        let rendered = render(&snapshot(&[("AGENTS.md", entry)])).expect("render");
        assert!(!String::from_utf8(rendered).unwrap().contains(target));
    }

    #[test]
    fn declared_entry_type_mismatch_fails_closed() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("entry");
        std::fs::write(&path, b"content").expect("file");
        assert!(capture_entry(&path, EntryType::Directory).is_err());
    }
}
