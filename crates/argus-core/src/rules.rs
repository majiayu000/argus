//! Central rule registry: the single source of truth for every rule id an
//! argus engine can emit, its decision-policy class, and its human-readable
//! description.
//!
//! Before this registry existed, rule identity was a bare `String` on
//! [`crate::Finding`] and the decision policy lived in three hardcoded
//! string arrays inside `argus-rules` — an ecosystem crate adding a rule
//! had to remember to edit a foreign crate's array, and nothing could
//! detect a missed registration. The registry replaces string-set membership with a
//! typed per-rule [`RulePolicy`], and SARIF output takes its rule
//! descriptions from here instead of synthesizing `"Argus finding: {id}"`.
//!
//! Invariants:
//! - One entry per rule id ([`registry_ids_are_unique`] enforces this).
//! - A rule id may be constructed at MULTIPLE severities (e.g.
//!   `provenance-signature-unverified` is Info on the unsupported-bundle
//!   path and High on hard verification errors), so the registry
//!   deliberately does NOT model a fixed severity — [`RulePolicy::InfoOnly`]
//!   interacts with the severity chosen at the construction site.
//! - Unregistered ids fail closed: [`policy`] returns
//!   [`RulePolicy::Blocking`] for ids it does not know, so forgetting to
//!   register a new rule can only over-block, never under-block.

/// Decision-policy class of a rule. Mirrors the semantics previously
/// encoded by `INFO_ONLY_RULES` / `APPROVAL_ONLY_RULES` /
/// `DOWNGRADE_SAFE_RULES` in `argus-rules::decision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulePolicy {
    /// Structural signal that carries no policy weight at `Severity::Info`
    /// (stripped from decision input). The SAME id at a higher severity
    /// still participates and blocks.
    InfoOnly,
    /// Bounded anomaly that requires explicit human approval when it is
    /// the only policy-weighted evidence; never downgrades an unrelated
    /// blocking finding.
    ApprovalOnly,
    /// When paired with `known-native-build-pattern` and no blocking
    /// evidence, drops the decision from Block to AllowWithApproval.
    DowngradeSafe,
    /// Any policy-weighted occurrence pushes the decision to Block.
    Blocking,
}

/// Registry entry for one rule id.
#[derive(Debug)]
pub struct RuleDef {
    /// Stable rule identifier as emitted in `Finding.rule_id`.
    pub id: &'static str,
    /// Decision-policy class (see [`RulePolicy`]).
    pub policy: RulePolicy,
    /// One-sentence human-readable description; feeds SARIF
    /// `shortDescription` and report tooling.
    pub description: &'static str,
}

/// Look up a rule definition by id.
pub fn rule_def(id: &str) -> Option<&'static RuleDef> {
    ALL_RULES.iter().find(|rule| rule.id == id)
}

/// Decision-policy class for a rule id. Unregistered ids fail closed to
/// [`RulePolicy::Blocking`].
pub fn policy(id: &str) -> RulePolicy {
    rule_def(id).map_or(RulePolicy::Blocking, |rule| rule.policy)
}

/// How findings are folded into a [`crate::Decision`].
///
/// The two profiles are the previously divergent aggregators from
/// `argus-rules::decision` (packages) and `argus-agent::decision` (agent
/// surfaces), now living behind one entry point so the divergence is
/// explicit and maintained in one place. A genuinely severity-weighted
/// scoring model (where the profiles converge) is future work gated on a
/// labeled benchmark — see issues #145/#146.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationProfile {
    /// Package scans: policy-class driven. Any policy-weighted finding
    /// blocks regardless of severity; `ApprovalOnly` findings alone yield
    /// AllowWithApproval; `DowngradeSafe` findings paired with
    /// `known-native-build-pattern` downgrade Block to AllowWithApproval.
    PolicyDriven,
    /// Agent-surface scans: severity driven. Critical/High block, Medium
    /// requires approval, Low/Info carry no weight. There is no
    /// native-build allowlist on this surface.
    SeverityDriven,
}

/// Fold findings into a decision under the given profile.
pub fn aggregate(findings: &[crate::Finding], profile: AggregationProfile) -> crate::Decision {
    match profile {
        AggregationProfile::PolicyDriven => aggregate_policy_driven(findings),
        AggregationProfile::SeverityDriven => aggregate_severity_driven(findings),
    }
}

fn aggregate_policy_driven(findings: &[crate::Finding]) -> crate::Decision {
    use crate::{Decision, Severity};
    use std::collections::BTreeSet;

    if findings.is_empty() {
        return Decision::Allow;
    }

    // Strip pure-info findings; the same rule id at a higher severity must
    // still influence the decision. Unregistered ids fail closed to
    // Blocking.
    let decision_ids: BTreeSet<&str> = findings
        .iter()
        .filter(|finding| {
            finding.severity != Severity::Info || policy(&finding.rule_id) != RulePolicy::InfoOnly
        })
        .map(|finding| finding.rule_id.as_str())
        .collect();

    if decision_ids.is_empty() {
        return Decision::Allow;
    }

    let residual_ids: BTreeSet<&str> = decision_ids
        .iter()
        .copied()
        .filter(|id| policy(id) != RulePolicy::ApprovalOnly)
        .collect();

    if residual_ids.is_empty() {
        return Decision::AllowWithApproval;
    }

    let has_native_build = residual_ids.contains("known-native-build-pattern");
    let has_high_risk = residual_ids
        .iter()
        .any(|id| policy(id) != RulePolicy::DowngradeSafe);

    if has_native_build && !has_high_risk {
        Decision::AllowWithApproval
    } else {
        Decision::Block
    }
}

fn aggregate_severity_driven(findings: &[crate::Finding]) -> crate::Decision {
    use crate::{Decision, Severity};

    let mut has_medium = false;
    for finding in findings {
        match finding.severity {
            Severity::Critical | Severity::High => return Decision::Block,
            Severity::Medium => has_medium = true,
            Severity::Low | Severity::Info => {}
        }
    }
    if has_medium {
        Decision::AllowWithApproval
    } else {
        Decision::Allow
    }
}

use RulePolicy::{ApprovalOnly, Blocking, DowngradeSafe, InfoOnly};

macro_rules! rule {
    ($id:literal, $policy:expr, $desc:literal) => {
        RuleDef {
            id: $id,
            policy: $policy,
            description: $desc,
        }
    };
}

/// Every rule id any argus engine can emit, grouped by owning engine.
pub const ALL_RULES: &[RuleDef] = &[
    // --- shared content/name rules (argus-rules; also reused by agent) ---
    rule!("ai-context-poisoning", Blocking, "Writes to an AI-agent context file (.cursorrules, CLAUDE.md, ...), planting instructions that persist across sessions"),
    rule!("binary-execution", Blocking, "Executes a bundled native binary at install time"),
    rule!("binary-file", Blocking, "Package ships a native binary artifact"),
    rule!("credential-access", Blocking, "References host secret files or credentials (.npmrc/.env/.ssh/.aws)"),
    rule!("dependency-confusion", Blocking, "Unscoped internal-looking package name (dependency-confusion candidate)"),
    rule!("github-write-api", Blocking, "Calls the GitHub API with a mutating method (PUT/POST/PATCH/DELETE)"),
    rule!("known-native-build-pattern", DowngradeSafe, "Matches a well-known legitimate native-build package pattern (esbuild/sharp/fsevents-like)"),
    rule!("lifecycle-script", DowngradeSafe, "Declares an install-time lifecycle script"),
    rule!("low-reputation", Blocking, "Typosquat-adjacent name with no established reputation"),
    rule!("network-exfiltration", Blocking, "Sends data to an external host at install/load time"),
    rule!("npm-publish", Blocking, "Invokes `npm publish` from within the package"),
    rule!("pre-scan-execution-marker", Blocking, "Script writes a marker path on the host before scanning could run"),
    rule!("public-registry-internal-name", Blocking, "Internal-style name resolves on the public registry"),
    rule!("remote-download", Blocking, "Script downloads a remote payload"),
    rule!("runtime-hook", Blocking, "Overrides a global object (globalThis/window/global) at module load"),
    rule!("shell-pipe-execution", Blocking, "Pipes downloaded content into a shell"),
    rule!("token-harvest", Blocking, "Collects npm/GitHub tokens for self-republish or exfiltration"),
    rule!("typosquatting", Blocking, "Package name is within edit distance 1 of a popular package"),
    rule!("wallet-interception", Blocking, "Accesses a browser crypto wallet (ethereum/eth_sendTransaction)"),
    // --- npm metadata + provenance (argus-fetch) ---
    rule!("missing-provenance", InfoOnly, "Package was not published with an OIDC provenance attestation"),
    rule!("npm-rapid-publish-unassessed", InfoOnly, "Rapid-publish anomaly could not be assessed from bounded history"),
    rule!("npm-version-shape-unassessed", InfoOnly, "Version-shape anomaly could not be assessed from bounded history"),
    rule!("provenance-fetch-blocked", Blocking, "Attestations URL was rejected by the host/scheme guard"),
    rule!("provenance-fetch-failed", Blocking, "Attestations document could not be fetched"),
    rule!("provenance-no-sha512-subject", Blocking, "Attestations carried no sha512 subject digest to cross-check"),
    rule!("provenance-parse-failed", Blocking, "Attestations document is unparseable"),
    rule!("provenance-signature-invalid", Blocking, "Sigstore signature verification failed"),
    rule!("provenance-signature-untrusted-issuer", InfoOnly, "Signature is cryptographically valid but the OIDC identity is not allowlisted"),
    rule!("provenance-signature-unverified", InfoOnly, "Signature verification did not run or could not handle the bundle"),
    rule!("provenance-signature-verified", InfoOnly, "Attestation passed full Sigstore verification"),
    rule!("provenance-subject-mismatch", Blocking, "Attestation subject digest does not match the downloaded tarball"),
    rule!("provenance-verified-subject", InfoOnly, "Attestation subject digest matches the downloaded tarball"),
    rule!("rapid-publish-window", ApprovalOnly, "Publisher pushed many packages within a short window"),
    rule!("version-shape-anomaly", ApprovalOnly, "Version/publish shape deviates from the package's bounded history"),
    // --- crates.io (argus-crates) ---
    rule!("build-rs-execution", InfoOnly, "Crate declares a build.rs build script (structural)"),
    rule!("build-rs-include-bytes", Blocking, "build.rs embeds binary bytes paired with decryption logic"),
    rule!("build-rs-network", Blocking, "build.rs performs network access"),
    rule!("build-rs-subprocess", Blocking, "build.rs spawns a subprocess"),
    rule!("embedded-binary-blob", InfoOnly, "Crate embeds binary blobs via include_bytes! (structural)"),
    rule!("proc-macro-crate", InfoOnly, "Crate is a proc-macro (compile-time execution surface, structural)"),
    rule!("xor-decryption-loop", Blocking, "Contains an XOR-decryption loop over embedded data"),
    // --- PyPI (argus-pypi) ---
    rule!("import-time-hook", Blocking, "Rewrites Python builtins or import machinery at load time"),
    rule!("pypi-sdist-no-manifest", InfoOnly, "sdist carries no build manifest (structural)"),
    rule!("setup-eval", Blocking, "setup.py calls exec/eval during install"),
    rule!("setup-py-execution", Blocking, "setup.py contains imperative install-time execution"),
    rule!("setup-remote-download", Blocking, "setup.py downloads remote content during install"),
    rule!("setup-subprocess", Blocking, "setup.py spawns a subprocess during install"),
    // --- RubyGems (argus-rubygems) ---
    rule!("extconf-remote-download", Blocking, "extconf.rb downloads remote content at build time"),
    rule!("extconf-subprocess", Blocking, "extconf.rb spawns a subprocess at build time"),
    rule!("gem-declared-executable", InfoOnly, "Gem declares an executable installed onto PATH (structural)"),
    rule!("gem-env-token-exfil", Blocking, "Reads credential environment variables and sends them out"),
    rule!("gem-native-build", InfoOnly, "Gem contains an extconf.rb native build step (structural)"),
    rule!("gem-post-install-message", Blocking, "Gem prints a post-install message"),
    rule!("native-extension", Blocking, "Gem builds a native extension at install time"),
    // --- Composer (argus-composer) ---
    rule!("autoload-files-execution", InfoOnly, "autoload.files runs at autoloader build (ubiquitous, structural)"),
    rule!("composer-manifest-parse-error", InfoOnly, "composer.json could not be parsed (scan continued)"),
    rule!("composer-plugin-package", DowngradeSafe, "Package is a composer-plugin (runs inside Composer)"),
    rule!("lifecycle-script-shell", Blocking, "Lifecycle hook contains a shell-exec command string"),
    rule!("php-dynamic-exec", Blocking, "PHP dynamic execution or eval(base64_decode(...)) obfuscation"),
    rule!("unverified-artifact-integrity", Blocking, "Registry advertised no dist.shasum; artifact integrity unverifiable"),
    // --- Maven (argus-maven) ---
    rule!("maven-antrun-plugin", Blocking, "pom.xml declares maven-antrun-plugin (build-time arbitrary Ant tasks)"),
    rule!("maven-build-script-plugin", Blocking, "pom.xml declares a Groovy build-scripting plugin"),
    rule!("maven-bytecode-not-inspected", InfoOnly, "Compiled .class bytecode was not inspected (honesty disclosure)"),
    rule!("maven-embedded-build-script", Blocking, "JAR embeds a build script"),
    rule!("maven-exec-plugin", Blocking, "pom.xml declares exec-maven-plugin (build-time command execution)"),
    rule!("maven-executable-jar", InfoOnly, "JAR declares Main-Class or launch scripts (structural)"),
    rule!("maven-no-pom", InfoOnly, "Standalone pom.xml was not available (structural)"),
    rule!("maven-weak-integrity-only", InfoOnly, "Only a weak SHA-1 checksum was available for the artifact"),
    // --- NuGet (argus-nuget) ---
    rule!("msbuild-exec-task", Blocking, "MSBuild .targets/.props executes a command at build time"),
    rule!("msbuild-inline-task", Blocking, "MSBuild UsingTask loads an inline/assembly task"),
    rule!("nuget-content-files", InfoOnly, "Package injects contentFiles into the consuming project (structural)"),
    rule!("nuget-install-script", Blocking, "Package ships an install-time PowerShell hook"),
    rule!("nuget-integrity-unverifiable", InfoOnly, "Catalog packageHash was unavailable; content digest unverified"),
    rule!("nuget-no-manifest", InfoOnly, "Package carries no .nuspec manifest (structural)"),
    rule!("powershell-download-exec", Blocking, "PowerShell downloads and executes remote content"),
    rule!("powershell-obfuscation", Blocking, "PowerShell uses encoded-command obfuscation"),
    // --- Go modules (argus-go) ---
    rule!("go-cgo-system", Blocking, "cgo preamble calls system()/popen()"),
    rule!("go-init-env-exfil", Blocking, "Import-time init reads environment variables alongside egress"),
    rule!("go-init-exec", Blocking, "Import-time init spawns a process"),
    rule!("go-init-function", InfoOnly, "Module declares func init() import-time execution (structural)"),
    rule!("go-init-network", Blocking, "Import-time init performs network egress"),
    rule!("go-integrity-unverified", InfoOnly, "GOPROXY served no usable .ziphash; module bytes unauthenticated"),
    rule!("go-obfuscated-payload", Blocking, "Decodes an obfuscated payload and executes it"),
    rule!("go-package-var-exec", InfoOnly, "Package-level var initializer executes at import (structural)"),
    // --- lockfiles (argus-lockfile) ---
    rule!("lockfile-http-resolved", Blocking, "Lockfile resolves a dependency over plaintext HTTP"),
    rule!("lockfile-integrity-invalid", Blocking, "Lockfile integrity digest is malformed or invalid"),
    rule!("lockfile-integrity-missing", Blocking, "Lockfile is missing a required integrity digest"),
    rule!("lockfile-integrity-unavailable", InfoOnly, "Lockfile format carries no registry artifact hash (explicit uncertainty)"),
    rule!("lockfile-integrity-weak", ApprovalOnly, "Only weak integrity evidence is available for a lockfile entry"),
    rule!("lockfile-mutable-vcs-ref", Blocking, "Lockfile pins a VCS dependency to a mutable ref"),
    rule!("untrusted-registry-host", Blocking, "Lockfile resolves from a non-allowlisted registry host"),
    // --- intelligence + vulnerabilities (argus-intel / argus-osv) ---
    rule!("known-malicious-package", Blocking, "Package matches the OpenSSF malicious-packages intelligence snapshot"),
    rule!("known-vulnerability", Blocking, "Package version matches a known OSV vulnerability advisory"),
    rule!("vulnerability-data-stale", Blocking, "OSV results were served from an authorized stale cache"),
    // --- AI-agent surface (argus-agent). These flow through argus-agent's
    // own severity-based decision today; policies here future-proof a
    // unified aggregator and feed SARIF descriptions. ---
    rule!("AGT-01-injection-language", Blocking, "Instruction file contains injection/override language aimed at the agent"),
    rule!("AGT-02", Blocking, "Approved skill description drifted from its baseline hash"),
    rule!("AGT-02-baseline-entry-missing", InfoOnly, "Baseline entry no longer exists in the scan tree"),
    rule!("AGT-02-baseline-unreadable", InfoOnly, "Baseline file was unreadable or unparseable"),
    rule!("AGT-03-remote-exec", Blocking, "Skill combines remote download with shell execution"),
    rule!("AGT-03-secret-exfil", Blocking, "Skill combines credential reads with network egress"),
    rule!("AGT-04-content-modified", Blocking, "High-context file content changed since the approved snapshot"),
    rule!("AGT-04-entry-added", Blocking, "High-context file appeared that is not in the approved snapshot"),
    rule!("AGT-04-entry-removed", Blocking, "High-context file from the approved snapshot disappeared"),
    rule!("AGT-04-entry-type-changed", Blocking, "High-context inventory entry changed type since the snapshot"),
    rule!("AGT-04-symlink-changed", Blocking, "High-context symlink target changed since the snapshot"),
    rule!("AGT-05-config-unparseable", InfoOnly, "Agent config file is not valid JSON"),
    rule!("AGT-05-enable-all-project-mcp", Blocking, "Config blindly trusts all project MCP servers"),
    rule!("AGT-05-enabled-mcpjson-servers", Blocking, "Config pre-approves specific MCP servers"),
    rule!("AGT-05-mcp-always-load", Blocking, "MCP server is configured to always load with full trust"),
    rule!("AGT-05-posttooluse-output-rewrite", Blocking, "Hook rewrites tool output after execution"),
    rule!("agent-config-write", Blocking, "Skill writes to agent configuration"),
    rule!("capability-manifest", Blocking, "Fallback disclosure of the skill's observed capability set"),
    rule!("capability-misfit", Blocking, "Observed capabilities do not fit the skill's declared intent"),
    rule!("hook-persistence", Blocking, "Skill installs a persistent hook"),
    rule!("llm-intent-judge", InfoOnly, "External LLM judge verdict on skill intent (advisory)"),
    rule!("obfuscation", Blocking, "Content hides its behaviour behind encoding or obfuscation"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_ids_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for rule in ALL_RULES {
            assert!(seen.insert(rule.id), "duplicate rule id: {}", rule.id);
        }
    }

    #[test]
    fn descriptions_are_non_empty() {
        for rule in ALL_RULES {
            assert!(
                !rule.description.is_empty(),
                "empty description: {}",
                rule.id
            );
        }
    }

    #[test]
    fn unregistered_ids_fail_closed_to_blocking() {
        assert_eq!(policy("some-future-unregistered-rule"), Blocking);
    }

    /// The exact contents of the three legacy string arrays from
    /// `argus-rules::decision` — the registry must preserve their policy
    /// classification bit-for-bit (migration guard).
    #[test]
    fn legacy_policy_arrays_are_preserved() {
        const LEGACY_INFO_ONLY: &[&str] = &[
            "missing-provenance",
            "provenance-verified-subject",
            "provenance-signature-verified",
            "provenance-signature-untrusted-issuer",
            "provenance-signature-unverified",
            "proc-macro-crate",
            "build-rs-execution",
            "embedded-binary-blob",
            "pypi-sdist-no-manifest",
            "autoload-files-execution",
            "composer-manifest-parse-error",
            "gem-native-build",
            "gem-declared-executable",
            "maven-bytecode-not-inspected",
            "maven-executable-jar",
            "maven-weak-integrity-only",
            "maven-no-pom",
            "nuget-integrity-unverifiable",
            "nuget-no-manifest",
            "nuget-content-files",
            "go-init-function",
            "go-package-var-exec",
            "go-integrity-unverified",
            "npm-version-shape-unassessed",
            "npm-rapid-publish-unassessed",
            "lockfile-integrity-unavailable",
        ];
        const LEGACY_APPROVAL_ONLY: &[&str] = &[
            "version-shape-anomaly",
            "rapid-publish-window",
            "lockfile-integrity-weak",
        ];
        const LEGACY_DOWNGRADE_SAFE: &[&str] = &[
            "lifecycle-script",
            "known-native-build-pattern",
            "composer-plugin-package",
        ];
        for id in LEGACY_INFO_ONLY {
            assert_eq!(policy(id), InfoOnly, "policy drift for {id}");
        }
        for id in LEGACY_APPROVAL_ONLY {
            assert_eq!(policy(id), ApprovalOnly, "policy drift for {id}");
        }
        for id in LEGACY_DOWNGRADE_SAFE {
            assert_eq!(policy(id), DowngradeSafe, "policy drift for {id}");
        }
    }
}
