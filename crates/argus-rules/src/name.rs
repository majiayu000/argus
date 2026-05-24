//! Name-based rules: typosquatting, dependency confusion, native-build pattern.

use crate::PackageContext;
use argus_core::{Finding, Severity};

/// Popular npm package names that are common typosquat targets. Kept tiny on
/// purpose — full reputation data belongs in the registry-intelligence phase.
pub const POPULAR_PACKAGES: &[&str] = &[
    "react",
    "react-dom",
    "react-native",
    "lodash",
    "express",
    "axios",
    "vue",
    "next",
    "webpack",
    "eslint",
    "prettier",
    "typescript",
    "tslib",
    "chalk",
    "commander",
    "moment",
    "request",
    "rxjs",
    "uuid",
    "minimist",
    "ua-parser-js",
];

/// Substrings that strongly suggest an unscoped, internal-looking package name.
pub const INTERNAL_HINTS: &[&str] = &["internal", "corp", "company", "private", "intranet"];

pub fn run(ctx: &PackageContext, findings: &mut Vec<Finding>) {
    let name = match ctx.package.name.as_deref() {
        Some(n) if !n.is_empty() => n,
        _ => return,
    };

    // typosquatting: edit distance <= 1 against a popular name, and not the
    // popular name itself.
    if let Some(target) = closest_within(name, 1) {
        findings.push(
            Finding::new(
                "typosquatting",
                Severity::High,
                format!("name `{name}` is one edit away from popular package `{target}`"),
            )
            .at("package.json"),
        );
        findings.push(
            Finding::new(
                "low-reputation",
                Severity::Medium,
                format!("typosquat candidate `{name}` has no established reputation"),
            )
            .at("package.json"),
        );
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
}

fn closest_within(name: &str, max_distance: usize) -> Option<&'static str> {
    let name_l = name.to_ascii_lowercase();
    if POPULAR_PACKAGES.iter().any(|p| *p == name_l) {
        return None;
    }
    POPULAR_PACKAGES
        .iter()
        .copied()
        .find(|p| levenshtein(&name_l, p) <= max_distance)
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

/// Iterative Levenshtein distance. Inputs are short package names, so the
/// O(n*m) table is fine.
fn levenshtein(a: &str, b: &str) -> usize {
    if a == b {
        return 0;
    }
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr: Vec<usize> = vec![0; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (curr[j - 1] + 1).min(prev[j] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typosquat_react_domm() {
        assert_eq!(levenshtein("react-domm", "react-dom"), 1);
        assert_eq!(closest_within("react-domm", 1), Some("react-dom"));
    }

    #[test]
    fn popular_name_itself_is_not_typosquat() {
        assert_eq!(closest_within("react", 1), None);
    }

    #[test]
    fn internal_unscoped_name_is_dep_confusion() {
        assert!(is_dep_confusion("internal-auth-client"));
        assert!(!is_dep_confusion("@acme/internal-auth-client"));
        assert!(!is_dep_confusion("react"));
    }
}
