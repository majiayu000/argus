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

#[cfg(test)]
use argus_core::Finding;

/// Push name-based findings (typosquatting + low-reputation) onto the
/// running findings list, matching against the artifactId.
#[cfg(test)]
pub fn push_name_findings(artifact: &str, findings: &mut Vec<Finding>) -> anyhow::Result<()> {
    argus_rules::RuleSession::builtin()?.push_typosquat_findings(
        argus_core::Ecosystem::Maven,
        &format!("legacy:{artifact}"),
        "Maven artifactId",
        findings,
    )
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
        push_name_findings("guaava", &mut f).unwrap();
        let rules: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(rules.contains(&"typosquatting"), "got: {rules:?}");
        assert!(rules.contains(&"low-reputation"), "got: {rules:?}");
    }

    #[test]
    fn legitimate_artifact_does_not_fire() {
        let mut f = Vec::new();
        push_name_findings("guava", &mut f).unwrap();
        assert!(f.is_empty());
        // case-insensitive match too
        let mut f2 = Vec::new();
        push_name_findings("Guava", &mut f2).unwrap();
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
