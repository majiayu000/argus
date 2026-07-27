//! Go module `.zip` extraction and scan.
//!
//! A Go module zip is a flat ZIP archive whose every entry is prefixed
//! `<module>@<version>/...` (Go's module zip layout). Extraction is ZIP,
//! NOT tar.gz; ZIP extraction is the shared `argus_archive` implementation.
//! There is no shared ZIP helper in argus-fetch, so the ZIP-safe extractor
//! below is the same hardened pattern used by `argus_pypi::wheel`:
//! `enclosed_name()` + `Component` checks + `unix_mode()` symlink rejection
//! + a `take(remaining + 1)` size cap.
//!
//! Go modules ship pure source — no compiled bytecode — so unlike Maven /
//! NuGet the scanner CAN actually read everything it needs to. The only
//! blind spots are linked external C / `.syso` objects (binary, skipped)
//! and platform/build-tag selection (we conservatively scan all files).

use crate::{finding, rules, ArtifactScan};
use anyhow::{bail, Context, Result};
use argus_core::{Finding, Severity};
use argus_rules::{looks_binary, scan_text_file, RuleSession, TextFile};

const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// One extracted file plus the metadata the scanner and the dirhash need.
struct ExtractedFile {
    /// Full in-zip name including the `<module>@<version>/` prefix. Used
    /// verbatim for dirhash recomputation.
    zip_name: String,
    /// Raw bytes (needed for the dirhash over every file, text or binary).
    bytes: Vec<u8>,
}

/// Result of extracting a module zip: every file (for dirhash) plus the
/// detected module path from `go.mod`.
#[derive(Debug)]
pub struct ExtractedModule {
    files: Vec<(String, Vec<u8>)>,
    module_path: Option<String>,
}

impl ExtractedModule {
    /// All `(zip_name, bytes)` pairs in the module, suitable for
    /// [`crate::dirhash::compute_h1`].
    pub fn files(&self) -> &[(String, Vec<u8>)] {
        &self.files
    }

    /// Module path parsed from the embedded `go.mod`, if present.
    pub fn module_path(&self) -> Option<&str> {
        self.module_path.as_deref()
    }
}

/// Safe-extract a Go module `.zip` into memory.
///
/// Returns every file's full zip name + bytes (needed to recompute the
/// `h1:` dirhash over the exact bytes the proxy advertised) and the
/// module path parsed from the embedded `go.mod`.
///
/// The bytes are kept in memory rather than written to disk because the
/// dirhash must be computed over the original file bytes, and the rule
/// scan operates on text we already hold. We still apply the same path /
/// symlink / size-cap safety the disk extractor enforces, so a malicious
/// zip cannot blow up memory or smuggle traversal names.
pub fn extract_module_zip(zip_bytes: &[u8], max_extracted_bytes: u64) -> Result<ExtractedModule> {
    let mut files: Vec<ExtractedFile> =
        argus_archive::extract_zip_to_memory(zip_bytes, max_extracted_bytes, "module zip entry")
            .context("extract Go module zip")?
            .into_iter()
            .map(|file| ExtractedFile {
                zip_name: file.zip_name,
                bytes: file.bytes,
            })
            .collect();
    files.sort_by(|left, right| left.zip_name.cmp(&right.zip_name));

    // Locate the embedded go.mod (entry name ends with `/go.mod` or is
    // exactly `go.mod`) and parse the module directive.
    let mut module_path: Option<String> = None;
    for f in &files {
        if f.zip_name.ends_with("/go.mod") || f.zip_name == "go.mod" {
            if let Ok(text) = std::str::from_utf8(&f.bytes) {
                if let Some(p) = crate::metadata::parse_go_mod_module(text) {
                    module_path = Some(p);
                    break;
                }
            }
        }
    }

    let files = files.into_iter().map(|f| (f.zip_name, f.bytes)).collect();

    Ok(ExtractedModule { files, module_path })
}

/// Scan an already-extracted module: apply ecosystem-agnostic content
/// rules to every `.go` source plus the Go-specific trigger-surface rules.
pub fn scan_extracted_module(module: &ExtractedModule) -> ArtifactScan {
    let rules = RuleSession::builtin().expect("embedded built-in rule catalog must be valid");
    scan_extracted_module_with_rules(module, &rules)
        .expect("built-in rule session cannot fail while scanning external rules")
}

pub fn scan_extracted_module_with_rules(
    module: &ExtractedModule,
    rules: &RuleSession,
) -> Result<ArtifactScan> {
    if rules.external_rule_count() > 0 && module.files.len() > argus_rules::MAX_EXTERNAL_SCAN_FILES
    {
        bail!(
            "external-rule scan exceeds {} regular files",
            argus_rules::MAX_EXTERNAL_SCAN_FILES
        );
    }
    let mut findings: Vec<Finding> = Vec::new();

    let init_re = rules::init_func_regex();
    let var_re = rules::package_var_exec_regex();
    let net_re = rules::network_regex();
    let env_re = rules::env_read_regex();
    let decode_re = rules::decode_regex();
    let cgo_re = rules::cgo_import_regex();
    let c_sys_re = rules::c_system_regex();

    for (zip_name, bytes) in &module.files {
        let rel = strip_module_prefix(zip_name);
        rules
            .scan_bytes(zip_name, bytes, &mut findings)
            .with_context(|| format!("run configured rules on Go module file `{zip_name}`"))?;
        if bytes.len() as u64 > TEXT_MAX_BYTES {
            continue;
        }
        if looks_binary(bytes) {
            continue; // e.g. `.syso` object blobs — a genuine blind spot.
        }
        let content = String::from_utf8_lossy(bytes).into_owned();

        // Ecosystem-agnostic content rules first (credential-access,
        // ai-context-poisoning, runtime-hook, …).
        scan_text_file(
            &TextFile {
                rel: rel.clone(),
                content: content.clone(),
            },
            &mut findings,
        );

        // The Go-specific trigger surface only applies to `.go` source.
        if !rel.ends_with(".go") {
            continue;
        }

        let has_init = init_re.is_match(&content);
        let has_var_exec = var_re.is_match(&content);
        let import_context = has_init || has_var_exec;

        // Structural meta-findings: Info-only, MUST be in INFO_ONLY_RULES.
        if has_init {
            findings.push(
                finding(
                    "go-init-function",
                    Severity::Info,
                    format!("`{rel}` declares a top-level func init() that runs at import time"),
                )
                .at(rel.clone()),
            );
        }
        if has_var_exec {
            findings.push(
                finding(
                    "go-package-var-exec",
                    Severity::Info,
                    format!(
                        "`{rel}` has a package-level var initializer that runs code at import time"
                    ),
                )
                .at(rel.clone()),
            );
        }

        let has_exec = rules::detect_exec_call(&content);
        let has_net = net_re.is_match(&content);
        let has_env = env_re.is_match(&content);
        let has_decode = decode_re.is_match(&content);

        // Dangerous calls only escalate when they co-occur with an
        // import-time execution context in the SAME file (file-level
        // proximity heuristic — see rules.rs disclaimer).
        if import_context && has_exec {
            findings.push(
                finding(
                    "go-init-exec",
                    Severity::Critical,
                    format!("`{rel}` invokes os/exec or syscall.Exec from an import-time init/var context"),
                )
                .at(rel.clone()),
            );
        }
        if import_context && has_net {
            findings.push(
                finding(
                    "go-init-network",
                    Severity::Critical,
                    format!("`{rel}` performs network egress (net.Dial/http) from an import-time init/var context"),
                )
                .at(rel.clone()),
            );
        }
        if import_context && has_env && (has_net || has_exec) {
            findings.push(
                finding(
                    "go-init-env-exfil",
                    Severity::High,
                    format!("`{rel}` reads environment (os.Getenv/os.Environ) alongside a network/exec call in an import-time context — possible env exfiltration"),
                )
                .at(rel.clone()),
            );
        }
        if import_context && has_decode && (has_exec || content.contains("reflect.")) {
            findings.push(
                finding(
                    "go-obfuscated-payload",
                    Severity::Critical,
                    format!("`{rel}` decodes a base64/hex blob then executes/reflects it in an import-time context — obfuscated payload pattern"),
                )
                .at(rel.clone()),
            );
        }

        // cgo with embedded C calling system()/popen() in the preamble.
        if cgo_re.is_match(&content) && c_sys_re.is_match(&content) {
            findings.push(
                finding(
                    "go-cgo-system",
                    Severity::High,
                    format!("`{rel}` embeds cgo C code that calls system()/popen()"),
                )
                .at(rel.clone()),
            );
        }
    }

    rules.validate_external_limits(&findings)?;
    rules.normalize_findings(&mut findings);

    Ok(ArtifactScan {
        findings,
        name: module.module_path().map(str::to_string),
        version: None,
    })
}

/// Strip the leading `<module>@<version>/` directory from a Go module zip
/// entry name so findings show a repo-relative path.
fn strip_module_prefix(zip_name: &str) -> String {
    // Go's module zip prefix is `<module>@<version>/`, where `<module>`
    // itself contains `/` (e.g. `github.com/foo/bar@v1.0.0/main.go`). The
    // prefix therefore ends at the first `/` AFTER the `@`. Strip it only
    // when both an `@` and a following `/` are present.
    if let Some(at) = zip_name.find('@') {
        if let Some(slash_off) = zip_name[at..].find('/') {
            let prefix_end = at + slash_off + 1; // include the `/`
            return zip_name[prefix_end..].to_string();
        }
    }
    zip_name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write as _;

    #[test]
    fn strip_prefix_removes_module_version() {
        assert_eq!(
            strip_module_prefix("github.com/foo/bar@v1.0.0/main.go"),
            "main.go"
        );
        assert_eq!(
            strip_module_prefix("example.com/m@v1.0.0/pkg/x.go"),
            "pkg/x.go"
        );
    }

    #[test]
    fn strip_prefix_keeps_unprefixed() {
        assert_eq!(strip_module_prefix("plain/path.go"), "plain/path.go");
    }

    fn external_session() -> RuleSession {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("rules.yaml"),
            "schema_version: 1\nrules:\n  - { id: \"go-bounded-external\", description: \"bounded\", policy_class: blocking, default_severity: low, help_uri: \"https://example.test/go-bounded\", languages: [go], matcher: { kind: literal, pattern: \"marker\" } }\n",
        )
        .unwrap();
        RuleSession::load(Some(temp.path()), &[]).unwrap()
    }

    fn module_zip(paths: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
            let options: zip::write::FileOptions<()> = zip::write::FileOptions::default();
            for path in paths {
                writer.start_file(*path, options).unwrap();
                writer.write_all(b"marker").unwrap();
            }
            writer.finish().unwrap();
        }
        bytes
    }

    #[test]
    fn external_file_count_accepts_limit_and_rejects_plus_one() {
        let rules = external_session();
        let files = (0..argus_rules::MAX_EXTERNAL_SCAN_FILES)
            .map(|index| (format!("example.test/m@v1.0.0/{index:05}.go"), Vec::new()))
            .collect::<Vec<_>>();
        let exact = ExtractedModule {
            files: files.clone(),
            module_path: Some("example.test/m".to_string()),
        };
        scan_extracted_module_with_rules(&exact, &rules).unwrap();

        let mut overflow_files = files;
        overflow_files.push(("example.test/m@v1.0.0/overflow.go".to_string(), Vec::new()));
        let overflow = ExtractedModule {
            files: overflow_files,
            module_path: Some("example.test/m".to_string()),
        };
        assert!(scan_extracted_module_with_rules(&overflow, &rules).is_err());
    }

    #[test]
    fn zip_entry_permutations_produce_identical_sorted_findings() {
        let a = "example.test/m@v1.0.0/a.go";
        let z = "example.test/m@v1.0.0/z.go";
        let first = extract_module_zip(&module_zip(&[z, a]), 1024 * 1024).unwrap();
        let second = extract_module_zip(&module_zip(&[a, z]), 1024 * 1024).unwrap();
        assert_eq!(
            first
                .files()
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            [a, z]
        );
        let rules = external_session();
        let first = scan_extracted_module_with_rules(&first, &rules).unwrap();
        let second = scan_extracted_module_with_rules(&second, &rules).unwrap();
        assert_eq!(
            serde_json::to_vec(&first.findings).unwrap(),
            serde_json::to_vec(&second.findings).unwrap()
        );
    }
}
