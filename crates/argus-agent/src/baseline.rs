//! AGT-02 — description hash drift baseline (GH-64).
//!
//! Detects rug-pull: an agent-surface description (MCP tool/server
//! `description`, or `SKILL.md` frontmatter `name`/`description`) that was
//! once human-approved and later silently mutated. AGT-02 answers only
//! "did an approved description change since it was baselined?" — the
//! malice judgment stays with AGT-01 (lexical) and GH-59 (intent misfit).
//!
//! Like the other rule modules, nothing from the scanned tree is executed;
//! descriptions are hashed as opaque UTF-8 bytes (SHA-256, hex). Evidence
//! shows only the first 12 hex chars of the old/new hashes, never the
//! description plaintext (which may itself carry injection language).

use crate::{atomic_write, SurfaceFile, SurfaceKind};
use anyhow::{Context, Result};
use argus_core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// Drift of an approved description → medium (allow-with-approval).
pub const RULE_DRIFT: &str = "AGT-02";
/// A baselined entry is no longer present on the scanned surface → info.
pub const RULE_ENTRY_MISSING: &str = "AGT-02-baseline-entry-missing";
/// The baseline file itself could not be read/parsed → info.
pub const RULE_BASELINE_UNREADABLE: &str = "AGT-02-baseline-unreadable";

const HASH_PREFIX_LEN: usize = 12;

/// One description-class entry keyed by a stable locator `"<rel>#<locator>"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescEntry {
    pub key: String,
    pub hash: String,
}

/// Persisted baseline: version + sorted key → hex-hash map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub entries: BTreeMap<String, String>,
}

impl Baseline {
    /// Build a baseline from freshly extracted entries.
    pub fn from_entries(entries: Vec<DescEntry>) -> Self {
        Baseline {
            version: 1,
            entries: entries.into_iter().map(|e| (e.key, e.hash)).collect(),
        }
    }
}

/// Read + parse a baseline file. Missing file or malformed JSON → `Err`
/// (the caller turns this into an info finding, never a panic).
pub fn load(path: &Path) -> Result<Baseline> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read baseline {}", path.display()))?;
    let baseline: Baseline =
        serde_json::from_str(&raw).with_context(|| format!("parse baseline {}", path.display()))?;
    Ok(baseline)
}

/// Write a baseline deterministically, then atomically replace the target path
/// on filesystems that support same-directory atomic rename. Replacement
/// creates a new inode and intentionally does not preserve hard-link, symlink,
/// permission, ACL, or extended-attribute identity from an existing target.
pub fn save(path: &Path, baseline: &Baseline) -> Result<()> {
    let mut text = serde_json::to_string_pretty(baseline)
        .with_context(|| format!("serialize baseline {}", path.display()))?;
    text.push('\n');
    atomic_write::write_bytes(path, text.as_bytes(), ".argus-baseline-")
        .with_context(|| format!("write baseline {}", path.display()))
}

/// Extract every description-class entry from the collected surface files.
pub fn extract_entries(files: &[SurfaceFile]) -> Vec<DescEntry> {
    let mut entries = Vec::new();
    for file in files {
        match file.kind {
            SurfaceKind::McpConfig => extract_mcp(file, &mut entries),
            SurfaceKind::Instruction => {
                let name = file.rel.rsplit('/').next().unwrap_or(&file.rel);
                if name.eq_ignore_ascii_case("SKILL.md") {
                    extract_skill(file, &mut entries);
                }
            }
            SurfaceKind::Script => {}
        }
    }
    entries
}

/// Compare current descriptions against an approved baseline, pushing
/// findings: drift → AGT-02 medium; baseline entry now missing → info;
/// a brand-new (un-baselined) entry → nothing (AGT-01/03/05 cover new
/// surface, per product non-goal).
pub fn check_drift(baseline: &Baseline, files: &[SurfaceFile], findings: &mut Vec<Finding>) {
    let current: BTreeMap<String, String> = extract_entries(files)
        .into_iter()
        .map(|e| (e.key, e.hash))
        .collect();

    for (key, old_hash) in &baseline.entries {
        let (rel, locator) = split_key(key);
        match current.get(key) {
            Some(new_hash) if new_hash != old_hash => {
                let mut finding = Finding::new(
                    RULE_DRIFT,
                    Severity::Medium,
                    format!(
                        "approved agent description drifted at `{locator}` (re-approval required)"
                    ),
                )
                .at(rel);
                finding.evidence = Some(vec![format!(
                    "{key} old={} new={}",
                    prefix(old_hash),
                    prefix(new_hash)
                )]);
                findings.push(finding);
            }
            Some(_) => {} // unchanged → clean
            None => {
                findings.push(
                    Finding::new(
                        RULE_ENTRY_MISSING,
                        Severity::Info,
                        format!("baseline entry no longer present on scanned surface: `{key}`"),
                    )
                    .at(rel),
                );
            }
        }
    }
}

fn extract_mcp(file: &SurfaceFile, out: &mut Vec<DescEntry>) {
    // Parse failure → skip this file's extraction; config.rs already emits an
    // info finding for unparseable configs (product edge case 3).
    let Ok(value) = serde_json::from_str::<Value>(&file.content) else {
        return;
    };
    if let Some(servers) = value.get("mcpServers").and_then(Value::as_object) {
        for (name, server) in servers {
            if let Some(desc) = server.get("description").and_then(Value::as_str) {
                push_entry(
                    out,
                    &file.rel,
                    &format!("mcpServers.{name}.description"),
                    desc,
                );
            }
            extract_tools(
                out,
                &file.rel,
                &format!("mcpServers.{name}"),
                server.get("tools"),
            );
        }
    }
    // Top-level `tools[]` (some configs list tools outside a server block).
    extract_tools(out, &file.rel, "", value.get("tools"));
}

fn extract_tools(out: &mut Vec<DescEntry>, rel: &str, parent: &str, tools: Option<&Value>) {
    let Some(tools) = tools.and_then(Value::as_array) else {
        return;
    };
    for (i, tool) in tools.iter().enumerate() {
        if let Some(desc) = tool.get("description").and_then(Value::as_str) {
            let locator = if parent.is_empty() {
                format!("tools[{i}].description")
            } else {
                format!("{parent}.tools[{i}].description")
            };
            push_entry(out, rel, &locator, desc);
        }
    }
}

/// Extract `name` / `description` scalars from a `SKILL.md` YAML frontmatter
/// block. No frontmatter → no entries (not an error, per product invariant).
fn extract_skill(file: &SurfaceFile, out: &mut Vec<DescEntry>) {
    let Some(frontmatter) = frontmatter_block(&file.content) else {
        return;
    };
    for field in ["name", "description"] {
        if let Some(value) = frontmatter_scalar(frontmatter, field) {
            push_entry(out, &file.rel, &format!("frontmatter.{field}"), &value);
        }
    }
}

/// Return the YAML frontmatter body (between the leading `---` fences).
fn frontmatter_block(content: &str) -> Option<&str> {
    let rest = content.strip_prefix("---")?;
    // The opening fence must be its own line.
    let rest = rest
        .strip_prefix('\n')
        .or_else(|| rest.strip_prefix("\r\n"))?;
    let end = rest.find("\n---")?;
    Some(&rest[..end])
}

/// Extract a top-level scalar `key: value` from a frontmatter block.
/// Only simple single-line scalars are read (matches the metadata AGT-02
/// baselines); block/multiline YAML is intentionally out of scope.
fn frontmatter_scalar(block: &str, key: &str) -> Option<String> {
    for line in block.lines() {
        let trimmed = line.trim_end();
        let Some(rest) = trimmed.strip_prefix(key) else {
            continue;
        };
        let Some(rest) = rest.strip_prefix(':') else {
            continue;
        };
        let value = rest.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        if value.is_empty() {
            return None;
        }
        return Some(value.to_string());
    }
    None
}

fn push_entry(out: &mut Vec<DescEntry>, rel: &str, locator: &str, desc: &str) {
    out.push(DescEntry {
        key: format!("{rel}#{locator}"),
        hash: hash_desc(desc),
    });
}

/// Stable, cross-platform content hash: SHA-256 of the UTF-8 bytes, hex.
fn hash_desc(desc: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(desc.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn prefix(hash: &str) -> &str {
    &hash[..HASH_PREFIX_LEN.min(hash.len())]
}

/// Split `"<rel>#<locator>"` into `(rel, locator)`; a key without `#`
/// degrades to `(key, key)` so `location` is still populated.
fn split_key(key: &str) -> (&str, &str) {
    match key.split_once('#') {
        Some((rel, locator)) => (rel, locator),
        None => (key, key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mcp(rel: &str, content: &str) -> SurfaceFile {
        SurfaceFile {
            rel: rel.into(),
            content: content.into(),
            kind: SurfaceKind::McpConfig,
        }
    }

    fn skill(rel: &str, content: &str) -> SurfaceFile {
        SurfaceFile {
            rel: rel.into(),
            content: content.into(),
            kind: SurfaceKind::Instruction,
        }
    }

    #[test]
    fn extracts_mcp_server_and_tool_descriptions() {
        let f = mcp(
            ".mcp.json",
            r#"{"mcpServers":{"fs":{"description":"file server","tools":[{"description":"read a file"}]}}}"#,
        );
        let entries = extract_entries(&[f]);
        let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
        assert!(
            keys.contains(&".mcp.json#mcpServers.fs.description"),
            "{keys:?}"
        );
        assert!(
            keys.contains(&".mcp.json#mcpServers.fs.tools[0].description"),
            "{keys:?}"
        );
    }

    #[test]
    fn extracts_skill_frontmatter_name_and_description() {
        let f = skill(
            "SKILL.md",
            "---\nname: demo\ndescription: does a thing\n---\n# body\n",
        );
        let entries = extract_entries(&[f]);
        let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
        assert!(keys.contains(&"SKILL.md#frontmatter.name"), "{keys:?}");
        assert!(
            keys.contains(&"SKILL.md#frontmatter.description"),
            "{keys:?}"
        );
    }

    #[test]
    fn skill_without_frontmatter_yields_no_entries() {
        let f = skill("SKILL.md", "# just a heading\nno frontmatter here\n");
        assert!(extract_entries(&[f]).is_empty());
    }

    #[test]
    fn hash_is_deterministic_for_same_bytes() {
        assert_eq!(hash_desc("read a file"), hash_desc("read a file"));
        assert_ne!(hash_desc("read a file"), hash_desc("read every file"));
    }

    #[test]
    fn unparseable_mcp_config_is_skipped_not_paniced() {
        let f = mcp(".mcp.json", "{ not json");
        assert!(extract_entries(&[f]).is_empty());
    }

    #[test]
    fn save_load_roundtrip_is_stable() {
        let dir = std::env::temp_dir().join(format!(
            "argus-baseline-rt-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");
        let baseline = Baseline::from_entries(vec![
            DescEntry {
                key: "b#x".into(),
                hash: "beef".into(),
            },
            DescEntry {
                key: "a#y".into(),
                hash: "cafe".into(),
            },
        ]);
        save(&path, &baseline).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.entries.len(), 2);
        // BTreeMap → deterministic sorted serialization.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.find("\"a#y\"").unwrap() < text.find("\"b#x\"").unwrap());
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn save_replaces_target_instead_of_rewriting_shared_inode() {
        let dir = std::env::temp_dir().join(format!(
            "argus-baseline-atomic-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");
        let previous_link = dir.join("previous.json");
        let previous = Baseline::from_entries(vec![DescEntry {
            key: "old#description".into(),
            hash: "old-hash".into(),
        }]);
        let replacement = Baseline::from_entries(vec![DescEntry {
            key: "new#description".into(),
            hash: "new-hash".into(),
        }]);

        save(&path, &previous).unwrap();
        std::fs::hard_link(&path, &previous_link).unwrap();
        save(&path, &replacement).unwrap();

        assert!(load(&path).unwrap().entries.contains_key("new#description"));
        assert!(
            load(&previous_link)
                .unwrap()
                .entries
                .contains_key("old#description"),
            "save rewrote the existing inode instead of replacing it"
        );
    }

    #[test]
    fn persist_failure_preserves_destination_and_cleans_temp() {
        let dir = std::env::temp_dir().join(format!(
            "argus-baseline-failure-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let destination = dir.join("baseline.json");
        std::fs::create_dir_all(&destination).unwrap();
        let sentinel = destination.join("sentinel");
        std::fs::write(&sentinel, "unchanged").unwrap();
        let baseline = Baseline::from_entries(Vec::new());

        assert!(save(&destination, &baseline).is_err());
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "unchanged");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".argus-baseline-")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporary files leaked: {leftovers:?}"
        );
    }

    #[test]
    fn load_missing_file_is_err_not_panic() {
        assert!(load(Path::new("/nonexistent/argus-baseline.json")).is_err());
    }

    #[test]
    fn drift_fires_medium_with_hash_prefix_evidence() {
        let approved = mcp(
            ".mcp.json",
            r#"{"mcpServers":{"fs":{"description":"old"}}}"#,
        );
        let baseline = Baseline::from_entries(extract_entries(&[approved]));

        let mutated = mcp(
            ".mcp.json",
            r#"{"mcpServers":{"fs":{"description":"new"}}}"#,
        );
        let mut findings = Vec::new();
        check_drift(&baseline, &[mutated], &mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_DRIFT);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].location.as_deref(), Some(".mcp.json"));
        let evidence = findings[0].evidence.as_ref().unwrap();
        assert_eq!(evidence.len(), 1);
        assert!(
            evidence[0].starts_with(".mcp.json#mcpServers.fs.description old="),
            "{evidence:?}"
        );
    }

    #[test]
    fn unchanged_surface_yields_no_finding() {
        let f = mcp(
            ".mcp.json",
            r#"{"mcpServers":{"fs":{"description":"same"}}}"#,
        );
        let baseline = Baseline::from_entries(extract_entries(std::slice::from_ref(&f)));
        let mut findings = Vec::new();
        check_drift(&baseline, &[f], &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn missing_entry_is_info_new_entry_is_silent() {
        // Baseline knows `fs`; current surface has `net` instead.
        let baseline = Baseline::from_entries(extract_entries(&[mcp(
            ".mcp.json",
            r#"{"mcpServers":{"fs":{"description":"gone"}}}"#,
        )]));
        let current = mcp(
            ".mcp.json",
            r#"{"mcpServers":{"net":{"description":"brand new"}}}"#,
        );
        let mut findings = Vec::new();
        check_drift(&baseline, &[current], &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ENTRY_MISSING);
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
