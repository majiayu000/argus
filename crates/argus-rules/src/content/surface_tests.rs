use super::*;

#[test]
fn prose_documentation_is_not_a_credential_surface() {
    for rel in [
        "README.md",
        "docs/publishing.md",
        "CHANGELOG.markdown",
        "guide.rst",
        "NOTES.txt",
        "manual.adoc",
    ] {
        assert!(!is_credential_scan_surface(rel), "{rel}");
    }
}

#[test]
fn agent_instruction_files_stay_in_scope() {
    // A shipped CLAUDE.md naming a credential path is read by the user's
    // agent. There the path is a payload, not documentation.
    for rel in [
        "CLAUDE.md",
        "sub/CLAUDE.md",
        "AGENTS.md",
        ".cursorrules",
        ".windsurfrules",
        ".claude/commands/deploy.md",
        "pkg/.claude/skills/x.md",
    ] {
        assert!(is_credential_scan_surface(rel), "{rel}");
    }
}

#[test]
fn executable_and_unknown_surfaces_stay_in_scope() {
    // Nothing escapes by choosing an unusual name: only prose is excluded.
    for rel in [
        "index.js",
        "setup.py",
        "build.rs",
        "install.sh",
        "hooks/pre-commit",
        "config.json",
        "data.yaml",
        "weird.qqq",
    ] {
        assert!(is_credential_scan_surface(rel), "{rel}");
    }
}

#[test]
fn documented_credential_path_no_longer_fires_but_source_still_does() {
    let quoted = r#"It mounts "~/.ssh/id_ed25519" too."#;

    let mut docs = Vec::new();
    scan_text_file(
        &TextFile {
            rel: "README.md".to_string(),
            content: quoted.to_string(),
        },
        &mut docs,
    );
    assert!(
        !docs.iter().any(|f| f.rule_id == "credential-access"),
        "documentation must not fire: {docs:?}"
    );

    let mut source = Vec::new();
    scan_text_file(
        &TextFile {
            rel: "index.js".to_string(),
            content: quoted.to_string(),
        },
        &mut source,
    );
    assert!(
        source.iter().any(|f| f.rule_id == "credential-access"),
        "source must still fire: {source:?}"
    );

    let mut agent = Vec::new();
    scan_text_file(
        &TextFile {
            rel: "CLAUDE.md".to_string(),
            content: quoted.to_string(),
        },
        &mut agent,
    );
    assert!(
        agent.iter().any(|f| f.rule_id == "credential-access"),
        "agent instruction file must still fire: {agent:?}"
    );
}
