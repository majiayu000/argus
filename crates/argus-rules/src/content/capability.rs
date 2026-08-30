use argus_syntax::{Fact, FactKind};
use regex::Regex;
use std::sync::OnceLock;

pub(super) fn credential_path_offset(body: &str) -> Option<usize> {
    credential_path_regex()
        .find(body)
        .map(|matched| matched.start())
}

pub(super) fn syntax_sensitive_read(facts: &[Fact]) -> Option<usize> {
    facts.iter().find_map(|fact| {
        let callee = fact.callee.as_deref()?.to_ascii_lowercase();
        let reads_file = match fact.kind {
            FactKind::Call => {
                callee == "open"
                    || callee.ends_with(".open")
                    || callee.ends_with(".read_text")
                    || callee.ends_with(".read_bytes")
                    || callee.ends_with(".readfile")
                    || callee.ends_with(".readfilesync")
            }
            FactKind::Command => matches!(callee.as_str(), "cat" | "source" | "."),
            _ => false,
        };
        // The sensitive literal may flow through a local collection before the
        // read (for example `targets.map(path => readFileSync(path))`). The
        // caller already proved that this same executable file contains the
        // bounded credential path; the syntax fact proves that it also reads a
        // file rather than merely documenting the path.
        reads_file.then_some(fact.line)
    })
}

/// A quoted host-credential path, bounded to one string and one line.
fn credential_path_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"[\"'][^\"'\n]*(\.npmrc|\.env|\.ssh/[^\"'\n]+|\.aws/credentials)[^\"'\n]*[\"']"#,
        )
        .expect("valid credential path regex")
    })
}
