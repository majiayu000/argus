//! Name-based rules: typosquatting, dependency confusion, native-build pattern.

use crate::{PackageContext, RuleSession};
use anyhow::Result;
use argus_core::{Ecosystem, Finding, Severity};

/// Substrings that strongly suggest an unscoped, internal-looking package name.
pub const INTERNAL_HINTS: &[&str] = &["internal", "corp", "company", "private", "intranet"];

pub fn run(ctx: &PackageContext, rules: &RuleSession, findings: &mut Vec<Finding>) -> Result<()> {
    let name = match ctx.package.name.as_deref() {
        Some(n) if !n.is_empty() => n,
        _ => return Ok(()),
    };

    let initial_len = findings.len();
    rules.push_typosquat_findings(Ecosystem::Npm, name, "name", findings)?;
    for finding in &mut findings[initial_len..] {
        finding.location = Some("package.json".to_string());
    }

    // dependency-confusion: unscoped, internal-looking name on a public-registry
    // package. The `99.99.99` version pattern is a known attacker tactic, but
    // even without it the internal substring is enough signal to block.
    if is_dep_confusion(name) {
        findings.push(
            Finding::new(
                "dependency-confusion",
                Severity::High,
                format!("unscoped name `{name}` looks like an internal-only package"),
            )
            .at("package.json"),
        );
        findings.push(
            Finding::new(
                "public-registry-internal-name",
                Severity::High,
                "an internal-looking name resolved from the public registry would be a dependency-confusion hit",
            )
            .at("package.json"),
        );
    }

    // known-native-build-pattern: optionalDependencies keyed by `@<scope>/<platform>-<arch>`.
    if has_platform_optdeps(ctx) {
        findings.push(
            Finding::new(
                "known-native-build-pattern",
                Severity::Info,
                "optionalDependencies declare platform-arch native builds (esbuild/sharp-style)",
            )
            .at("package.json"),
        );
    }
    Ok(())
}

fn is_dep_confusion(name: &str) -> bool {
    if name.starts_with('@') {
        return false; // scoped names are not the dep-confusion shape we care about
    }
    let lower = name.to_ascii_lowercase();
    INTERNAL_HINTS.iter().any(|hint| lower.contains(hint))
}

fn has_platform_optdeps(ctx: &PackageContext) -> bool {
    let platform_tokens = ["darwin", "linux", "win32", "freebsd", "netbsd", "openbsd"];
    let arch_tokens = ["arm64", "x64", "x86", "ia32", "arm"];

    ctx.package.optional_dependencies.keys().any(|k| {
        let lower = k.to_ascii_lowercase();
        platform_tokens.iter().any(|p| lower.contains(p))
            && arch_tokens.iter().any(|a| lower.contains(a))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_unscoped_name_is_dep_confusion() {
        assert!(is_dep_confusion("internal-auth-client"));
        assert!(!is_dep_confusion("@acme/internal-auth-client"));
        assert!(!is_dep_confusion("react"));
    }
}
