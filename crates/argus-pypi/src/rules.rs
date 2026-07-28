//! Python-specific detection rules.
//!
//! These complement the ecosystem-agnostic rules in `argus-rules`
//! (`credential-access`, `network-exfiltration`, `runtime-hook`,
//! `wallet-interception`, `ai-context-poisoning`, etc.) which we still
//! apply by calling `argus_rules::scan_text_file` on every Python file
//! we extract.

#[cfg(test)]
use argus_core::Finding;
use regex::Regex;
use std::sync::OnceLock;

/// Top-level `sys.modules[...] = ...` or `__builtins__.X = ...` rewrite,
/// which is how a wheel can hijack downstream imports.
pub fn import_time_hook_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            (?:
                sys\.modules \s* \[ \s* [\"'][^\"']+[\"'] \s* \] \s* = |
                __builtins__\.\w+ \s* = |
                importlib\.(?:metadata\.)?reload \s* \(
            )
            "#,
        )
        .unwrap()
    })
}

/// Push name-based findings (typosquatting + low-reputation) onto the
/// running findings list.
#[cfg(test)]
pub fn push_name_findings(name: &str, findings: &mut Vec<Finding>) -> anyhow::Result<()> {
    argus_rules::RuleSession::builtin()?.push_typosquat_findings(
        argus_core::Ecosystem::PyPi,
        name,
        "PyPI name",
        findings,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_setup_does_not_fire() {
        let benign = r#"
            from setuptools import setup, find_packages
            setup(name='demo', version='1.0', packages=find_packages())
        "#;
        assert!(!import_time_hook_regex().is_match(benign));
    }

    #[test]
    fn import_time_hook_fires() {
        assert!(import_time_hook_regex().is_match("sys.modules['foo'] = malicious"));
        assert!(import_time_hook_regex().is_match("__builtins__.input = stealer"));
    }

    #[test]
    fn typosquat_rrequests() {
        let mut f = Vec::new();
        push_name_findings("rrequests", &mut f).unwrap();
        let rules: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(rules.contains(&"typosquatting"), "got: {rules:?}");
        assert!(rules.contains(&"low-reputation"));
    }

    #[test]
    fn legitimate_name_does_not_fire() {
        let mut f = Vec::new();
        push_name_findings("requests", &mut f).unwrap();
        assert!(f.is_empty());
    }
}
