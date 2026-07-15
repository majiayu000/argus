//! Surface classifier: decides which files are agent surfaces and which
//! rules apply. Files outside these shapes are never scanned (product
//! invariant P6 — defensive quotes in ordinary source code must not fire).

/// Which agent surface a file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceKind {
    /// `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, `.claude/**/*.md` — AGT-01.
    Instruction,
    /// `.mcp.json`, `mcp.json`, `.claude.json`, `.claude/settings*.json` —
    /// AGT-01 (description fields) + AGT-05.
    McpConfig,
    /// Hook scripts and skill-directory scripts — AGT-03.
    Script,
}

const SCRIPT_EXTS: &[&str] = &[".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".mjs", ".rb"];

/// Classify a relative path (forward slashes). `skill_dirs` lists directory
/// prefixes (possibly `""` for root) that contain a `SKILL.md`.
pub fn classify(rel: &str, skill_dirs: &[String]) -> Option<SurfaceKind> {
    let file_name = rel.rsplit('/').next().unwrap_or(rel);
    let lower = file_name.to_ascii_lowercase();

    // Instruction files.
    if matches!(lower.as_str(), "agents.md" | "claude.md" | "skill.md") {
        return Some(SurfaceKind::Instruction);
    }
    if in_claude_dir(rel) && lower.ends_with(".md") {
        return Some(SurfaceKind::Instruction);
    }

    // MCP / agent config files.
    if matches!(lower.as_str(), ".mcp.json" | "mcp.json" | ".claude.json") {
        return Some(SurfaceKind::McpConfig);
    }
    if in_claude_dir(rel) && lower.starts_with("settings") && lower.ends_with(".json") {
        return Some(SurfaceKind::McpConfig);
    }

    // Hook scripts: anything under a hooks/ directory inside .claude, or a
    // top-level hooks/ directory (skill packs ship hooks there too).
    let is_script_ext = SCRIPT_EXTS.iter().any(|ext| lower.ends_with(ext));
    if is_script_ext {
        if in_agent_hooks_dir(rel) {
            return Some(SurfaceKind::Script);
        }
        // Scripts living in a directory tree that carries a SKILL.md.
        if skill_dirs.iter().any(|d| rel.starts_with(d.as_str())) {
            return Some(SurfaceKind::Script);
        }
    }

    None
}

fn in_claude_dir(rel: &str) -> bool {
    rel.split('/').any(|seg| seg == ".claude")
}

fn in_agent_hooks_dir(rel: &str) -> bool {
    if rel.starts_with("hooks/") {
        return true;
    }

    let mut previous = None;
    rel.split('/').any(|segment| {
        let is_claude_hook = previous == Some(".claude") && segment == "hooks";
        previous = Some(segment);
        is_claude_hook
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_instruction_files() {
        assert_eq!(classify("AGENTS.md", &[]), Some(SurfaceKind::Instruction));
        assert_eq!(
            classify("sub/CLAUDE.md", &[]),
            Some(SurfaceKind::Instruction)
        );
        assert_eq!(
            classify(".claude/rules/x.md", &[]),
            Some(SurfaceKind::Instruction)
        );
    }

    #[test]
    fn classifies_configs() {
        assert_eq!(classify(".mcp.json", &[]), Some(SurfaceKind::McpConfig));
        assert_eq!(
            classify(".claude/settings.local.json", &[]),
            Some(SurfaceKind::McpConfig)
        );
    }

    #[test]
    fn classifies_scripts_only_in_hook_or_skill_trees() {
        assert_eq!(
            classify(".claude/hooks/pre.sh", &[]),
            Some(SurfaceKind::Script)
        );
        assert_eq!(classify("hooks/pre.sh", &[]), Some(SurfaceKind::Script));
        let skill_dirs = vec!["myskill/".to_string()];
        assert_eq!(
            classify("myskill/run.py", &skill_dirs),
            Some(SurfaceKind::Script)
        );
        // Ordinary source files are out of scope.
        assert_eq!(classify("src/main.rs", &[]), None);
        assert_eq!(classify("scripts/build.sh", &[]), None);
        assert_eq!(classify("src/hooks/use_data.ts", &[]), None);
    }
}
