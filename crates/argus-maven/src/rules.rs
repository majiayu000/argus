//! Maven-specific detection rules.
//!
//! These complement the ecosystem-agnostic rules in `argus-rules`
//! (`credential-access`, `network-exfiltration`, `ai-context-poisoning`,
//! etc.) which we still apply by calling `argus_rules::scan_text_file` on
//! every extracted text resource.
//!
//! The Maven-specific surfaces are:
//! - dangerous build plugins declared in `pom.xml` (build-time execution);
//! - embedded build scripts (`.sh`/`.bat`/`.ps1`) inside the jar;
//! - typosquats of popular Maven coordinates.

use argus_core::{Finding, Severity};

/// Popular Maven artifactIds that are common typosquat targets. Drawn from
/// Maven Central download statistics + recent attack reports. We match on
/// the artifactId (the trailing coordinate segment) since that is what a
/// consumer typically types and misremembers.
pub const POPULAR_MAVEN_ARTIFACTS: &[&str] = &[
    // logging
    "slf4j-api",
    "logback-classic",
    "log4j-core",
    "log4j-api",
    "commons-logging",
    // apache commons
    "commons-lang3",
    "commons-io",
    "commons-collections4",
    "commons-codec",
    "commons-text",
    // json / serialization
    "jackson-databind",
    "jackson-core",
    "jackson-annotations",
    "gson",
    "guava",
    // web / spring
    "spring-core",
    "spring-context",
    "spring-web",
    "spring-boot",
    "spring-boot-starter",
    // testing
    "junit",
    "junit-jupiter-api",
    "mockito-core",
    "assertj-core",
    "hamcrest",
    // http / netty
    "okhttp",
    "httpclient",
    "netty-all",
    "retrofit",
    // db
    "mysql-connector-java",
    "postgresql",
    "h2",
    "hikaricp",
    // misc heavy hitters
    "lombok",
    "kotlin-stdlib",
    "scala-library",
    "protobuf-java",
    "snakeyaml",
];

/// Push name-based findings (typosquatting + low-reputation) onto the
/// running findings list, matching against the artifactId.
pub fn push_name_findings(artifact: &str, findings: &mut Vec<Finding>) {
    let lower = artifact.to_ascii_lowercase();
    if POPULAR_MAVEN_ARTIFACTS.iter().any(|p| *p == lower) {
        return; // legitimate artifact
    }
    if let Some(target) = POPULAR_MAVEN_ARTIFACTS
        .iter()
        .copied()
        .find(|p| argus_rules::levenshtein(&lower, p) <= 1)
    {
        findings.push(Finding::new(
            "typosquatting",
            Severity::High,
            format!(
                "Maven artifactId `{artifact}` is one edit away from popular artifact `{target}`"
            ),
        ));
        findings.push(Finding::new(
            "low-reputation",
            Severity::Medium,
            format!("typosquat candidate `{artifact}` has no established reputation"),
        ));
    }
}

/// True if a jar entry path is an embedded build/launcher script we want to
/// flag structurally (the *presence* of such a script in a jar is unusual).
pub fn is_embedded_build_script(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    lower.ends_with(".sh")
        || lower.ends_with(".bat")
        || lower.ends_with(".ps1")
        || lower.ends_with(".cmd")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typosquat_guava_fires() {
        let mut f = Vec::new();
        push_name_findings("guaava", &mut f);
        let rules: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(rules.contains(&"typosquatting"), "got: {rules:?}");
        assert!(rules.contains(&"low-reputation"), "got: {rules:?}");
    }

    #[test]
    fn legitimate_artifact_does_not_fire() {
        let mut f = Vec::new();
        push_name_findings("guava", &mut f);
        assert!(f.is_empty());
        // case-insensitive match too
        let mut f2 = Vec::new();
        push_name_findings("Guava", &mut f2);
        assert!(f2.is_empty());
    }

    #[test]
    fn embedded_build_script_detection() {
        assert!(is_embedded_build_script("install.sh"));
        assert!(is_embedded_build_script("tools/setup.BAT"));
        assert!(is_embedded_build_script("hook.ps1"));
        assert!(!is_embedded_build_script("META-INF/MANIFEST.MF"));
        assert!(!is_embedded_build_script("com/example/App.class"));
    }
}
