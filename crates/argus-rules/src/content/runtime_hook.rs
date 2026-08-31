use argus_syntax::{Fact, FactKind};
use regex::Regex;
use std::sync::OnceLock;

pub(super) fn matches_runtime_hook(body: &str, syntax_facts: Option<&[Fact]>) -> bool {
    syntax_facts.map_or_else(
        || legacy_assignment_regex().is_match(body),
        |facts| facts.iter().any(is_runtime_hook_fact),
    )
}

fn is_runtime_hook_fact(fact: &Fact) -> bool {
    match fact.kind {
        FactKind::Assignment => assignment_regex().is_match(&fact.text),
        FactKind::Call if fact.callee.as_deref() == Some("Object.defineProperty") => {
            let Some(receiver) = fact.arguments.first() else {
                return false;
            };
            let Some(property) = fact.arguments.get(1) else {
                return false;
            };
            is_global(receiver.resolved.as_deref().unwrap_or(&receiver.raw))
                && property
                    .resolved
                    .as_deref()
                    .is_some_and(is_identifier_property)
        }
        _ => false,
    }
}

fn is_global(value: &str) -> bool {
    matches!(value.trim(), "globalThis" | "window" | "global")
}

fn is_identifier_property(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte == b'$' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric())
}

fn assignment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x) ^
            (?:globalThis|window|global)
            (?:
                \s* \. \s* [A-Za-z_$][A-Za-z0-9_$]*
              | \s* \[ \s* ["'] [A-Za-z_$][A-Za-z0-9_$]* ["'] \s* \]
            ){1,2}
            \s* =
            "#,
        )
        .expect("runtime hook assignment regex")
    })
}

fn legacy_assignment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            (?:globalThis|window|global)
            \s* \. \s* [A-Za-z_$][A-Za-z0-9_$]*
            (?: \s* \. \s* [A-Za-z_$][A-Za-z0-9_$]* )?
            \s* = \s* [^=]
            "#,
        )
        .expect("legacy runtime hook regex")
    })
}
