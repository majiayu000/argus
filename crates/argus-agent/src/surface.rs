//! Canonical agent-surface membership classifier.

use anyhow::{anyhow, Result};
use std::ffi::OsStr;
use std::path::{Component, Path};

/// Which agent surface a filesystem entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceKind {
    /// Instruction text consumed by an agent.
    Instruction,
    /// MCP or agent configuration with existing semantic checks.
    McpConfig,
    /// Hook and skill scripts with existing semantic checks.
    Script,
    /// A high-context member tracked by AGT-04 but not semantically scanned.
    InventoryOnly,
}

/// Filesystem shape of the scan root used to build snapshot coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanRootEntryType {
    File,
    Directory,
}

/// Root-derived coordinate prefix used only by snapshot-mode classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRootContext {
    prefix: Option<String>,
}

impl ScanRootContext {
    /// Build context from an already-canonicalized scan root.
    pub fn from_canonical_scan_root(root: &Path, entry_type: ScanRootEntryType) -> Result<Self> {
        let classification_root = match entry_type {
            ScanRootEntryType::File => root.parent().unwrap_or_else(|| Path::new("")),
            ScanRootEntryType::Directory => root,
        };
        let components: Vec<_> = classification_root
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value),
                _ => None,
            })
            .collect();

        let prefix_components = components
            .iter()
            .rposition(|component| *component == OsStr::new(".claude"))
            .map(|index| &components[index..])
            .or_else(|| {
                components
                    .iter()
                    .rposition(|component| *component == OsStr::new("hooks"))
                    .map(|index| &components[index..])
            });
        let prefix = prefix_components
            .map(join_components)
            .transpose()?
            .filter(|value| !value.is_empty());

        Ok(Self { prefix })
    }

    fn qualify(&self, logical_path: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{prefix}/{logical_path}"),
            None => logical_path.to_string(),
        }
    }

    fn qualify_skill_dirs(&self, logical_skill_dirs: &[String]) -> Vec<String> {
        logical_skill_dirs
            .iter()
            .map(|directory| {
                let directory = directory.strip_suffix('/').unwrap_or(directory);
                if directory.is_empty() {
                    return self
                        .prefix
                        .as_ref()
                        .map_or_else(String::new, |prefix| format!("{prefix}/"));
                }
                let qualified = self.qualify(directory);
                format!("{qualified}/")
            })
            .collect()
    }
}

fn join_components(components: &[&OsStr]) -> Result<String> {
    components
        .iter()
        .map(|component| {
            component
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("scan root coordinate contains a non-UTF-8 component"))
        })
        .collect::<Result<Vec<_>>>()
        .map(|components| components.join("/"))
}

/// Coordinate interpretation for the single canonical membership rule set.
#[derive(Debug, Clone, Copy)]
pub enum CoordinatePolicy<'a> {
    /// Preserve the historical scan-root-relative coordinate exactly.
    LegacyRootRelative,
    /// Add only the root-aware `.claude` or `hooks` prefix held by the context.
    SnapshotRootAware(&'a ScanRootContext),
}

const SCRIPT_EXTS: &[&str] = &[".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".mjs", ".rb"];
const INVENTORY_BASENAMES: &[&str] = &[
    ".cursorrules",
    ".aider.conf.yml",
    ".continuerules",
    ".codexrules",
    ".windsurfrules",
];

/// Classify a non-empty, forward-slash scan-root-relative logical path.
///
/// Both policies use the same membership rules. Root-aware qualification is
/// confined to this module and never changes the logical path used in reports.
pub fn classify(
    policy: CoordinatePolicy<'_>,
    logical_path: &str,
    logical_skill_dirs: &[String],
) -> Option<SurfaceKind> {
    let (classification_path, skill_dirs) = match policy {
        CoordinatePolicy::LegacyRootRelative => {
            (logical_path.to_string(), logical_skill_dirs.to_vec())
        }
        CoordinatePolicy::SnapshotRootAware(context) => (
            context.qualify(logical_path),
            context.qualify_skill_dirs(logical_skill_dirs),
        ),
    };
    classify_rules(&classification_path, &skill_dirs)
}

fn classify_rules(path: &str, skill_dirs: &[String]) -> Option<SurfaceKind> {
    let file_name = path.rsplit('/').next().unwrap_or(path);
    let lower = file_name.to_ascii_lowercase();
    let behind_legacy_prune = path
        .split('/')
        .take(path.split('/').count().saturating_sub(1))
        .any(|segment| matches!(segment, ".git" | "node_modules"));

    let semantic_kind = if matches!(lower.as_str(), "agents.md" | "claude.md" | "skill.md")
        || (in_claude_dir(path) && lower.ends_with(".md"))
    {
        Some(SurfaceKind::Instruction)
    } else if matches!(lower.as_str(), ".mcp.json" | "mcp.json" | ".claude.json")
        || (in_claude_dir(path) && lower.starts_with("settings") && lower.ends_with(".json"))
    {
        Some(SurfaceKind::McpConfig)
    } else if SCRIPT_EXTS
        .iter()
        .any(|extension| lower.ends_with(extension))
        && (in_agent_hooks_dir(path)
            || skill_dirs
                .iter()
                .any(|directory| path.starts_with(directory.as_str())))
    {
        Some(SurfaceKind::Script)
    } else {
        None
    };

    let supported = semantic_kind.is_some()
        || in_claude_dir(path)
        || path == "hooks"
        || INVENTORY_BASENAMES.contains(&lower.as_str());
    if behind_legacy_prune && supported {
        return Some(SurfaceKind::InventoryOnly);
    }
    semantic_kind.or_else(|| supported.then_some(SurfaceKind::InventoryOnly))
}

fn in_claude_dir(path: &str) -> bool {
    path.split('/').any(|segment| segment == ".claude")
}

fn in_agent_hooks_dir(path: &str) -> bool {
    if path.starts_with("hooks/") {
        return true;
    }

    let mut previous = None;
    path.split('/').any(|segment| {
        let is_claude_hook = previous == Some(".claude") && segment == "hooks";
        previous = Some(segment);
        is_claude_hook
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy(path: &str, skill_dirs: &[String]) -> Option<SurfaceKind> {
        classify(CoordinatePolicy::LegacyRootRelative, path, skill_dirs)
    }

    #[test]
    fn classifies_existing_semantic_shapes() {
        assert_eq!(legacy("AGENTS.md", &[]), Some(SurfaceKind::Instruction));
        assert_eq!(legacy("sub/CLAUDE.md", &[]), Some(SurfaceKind::Instruction));
        assert_eq!(
            legacy(".claude/rules/x.md", &[]),
            Some(SurfaceKind::Instruction)
        );
        assert_eq!(legacy(".mcp.json", &[]), Some(SurfaceKind::McpConfig));
        assert_eq!(
            legacy(".claude/settings.local.json", &[]),
            Some(SurfaceKind::McpConfig)
        );
        assert_eq!(
            legacy(".claude/hooks/pre.sh", &[]),
            Some(SurfaceKind::Script)
        );
        assert_eq!(legacy("hooks/pre.sh", &[]), Some(SurfaceKind::Script));
        let skill_dirs = vec!["myskill/".to_string()];
        assert_eq!(
            legacy("myskill/run.py", &skill_dirs),
            Some(SurfaceKind::Script)
        );
        assert_eq!(legacy("src/main.rs", &[]), None);
    }

    #[test]
    fn inventory_only_shapes_and_pruned_ancestors_are_closed() {
        for path in [
            ".claude",
            ".claude/cache",
            ".claude/cache/blob.bin",
            ".cursorrules",
            "nested/.aider.conf.yml",
            ".continuerules",
            ".codexrules",
            ".windsurfrules",
            "hooks",
        ] {
            assert_eq!(
                legacy(path, &[]),
                Some(SurfaceKind::InventoryOnly),
                "{path}"
            );
        }
        assert_eq!(
            legacy("node_modules/pkg/AGENTS.md", &[]),
            Some(SurfaceKind::InventoryOnly)
        );
        assert_eq!(
            legacy(".claude/.git/policy.md", &[]),
            Some(SurfaceKind::InventoryOnly)
        );
        assert_eq!(legacy(".git/config", &[]), None);
    }

    #[test]
    fn coordinate_policy_classification_matrix() {
        let sandbox = tempfile::tempdir().expect("sandbox");
        let claude = sandbox.path().join(".claude");
        let rules = claude.join("rules");
        let hooks = sandbox.path().join("hooks");
        std::fs::create_dir_all(&rules).expect("rules");
        std::fs::create_dir_all(&hooks).expect("hooks");

        assert_eq!(legacy("settings.json", &[]), None);
        assert_eq!(legacy("policy.md", &[]), None);
        assert_eq!(legacy("pre.sh", &[]), None);

        let claude_context =
            ScanRootContext::from_canonical_scan_root(&claude, ScanRootEntryType::Directory)
                .expect("claude context");
        assert_eq!(
            classify(
                CoordinatePolicy::SnapshotRootAware(&claude_context),
                "settings.json",
                &[],
            ),
            Some(SurfaceKind::McpConfig)
        );

        let rules_context =
            ScanRootContext::from_canonical_scan_root(&rules, ScanRootEntryType::Directory)
                .expect("rules context");
        assert_eq!(
            classify(
                CoordinatePolicy::SnapshotRootAware(&rules_context),
                "policy.md",
                &[],
            ),
            Some(SurfaceKind::Instruction)
        );

        let settings_context = ScanRootContext::from_canonical_scan_root(
            &claude.join("settings.json"),
            ScanRootEntryType::File,
        )
        .expect("settings context");
        assert_eq!(
            classify(
                CoordinatePolicy::SnapshotRootAware(&settings_context),
                "settings.json",
                &[],
            ),
            Some(SurfaceKind::McpConfig)
        );

        let hooks_context =
            ScanRootContext::from_canonical_scan_root(&hooks, ScanRootEntryType::Directory)
                .expect("hooks context");
        assert_eq!(
            classify(
                CoordinatePolicy::SnapshotRootAware(&hooks_context),
                "pre.sh",
                &[],
            ),
            Some(SurfaceKind::Script)
        );
        let hook_file_context = ScanRootContext::from_canonical_scan_root(
            &hooks.join("pre.sh"),
            ScanRootEntryType::File,
        )
        .expect("hook file context");
        assert_eq!(
            classify(
                CoordinatePolicy::SnapshotRootAware(&hook_file_context),
                "pre.sh",
                &[],
            ),
            Some(SurfaceKind::Script)
        );
    }

    #[test]
    fn root_aware_skill_dirs_do_not_probe_ancestors() {
        let sandbox = tempfile::tempdir().expect("sandbox");
        let claude = sandbox.path().join(".claude");
        let context =
            ScanRootContext::from_canonical_scan_root(&claude, ScanRootEntryType::Directory)
                .expect("claude context");
        assert_eq!(
            classify(
                CoordinatePolicy::SnapshotRootAware(&context),
                "tool/run.py",
                &[],
            ),
            Some(SurfaceKind::InventoryOnly)
        );
        assert_eq!(
            classify(
                CoordinatePolicy::SnapshotRootAware(&context),
                "tool/run.py",
                &["tool/".to_string()],
            ),
            Some(SurfaceKind::Script)
        );

        let ordinary = sandbox.path().join("ordinary");
        let ordinary_context =
            ScanRootContext::from_canonical_scan_root(&ordinary, ScanRootEntryType::Directory)
                .expect("ordinary context");
        assert_eq!(
            classify(
                CoordinatePolicy::SnapshotRootAware(&ordinary_context),
                "tool/run.py",
                &["".to_string()],
            ),
            Some(SurfaceKind::Script)
        );
    }
}
