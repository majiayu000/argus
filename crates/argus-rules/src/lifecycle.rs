//! Lifecycle-script and pre-scan marker rules.

use crate::PackageContext;
use argus_core::{Finding, Severity};
use regex::Regex;

const LIFECYCLE_SCRIPT_NAMES: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "preuninstall",
    "uninstall",
    "postuninstall",
];

/// Pattern used by the `blocked-marker` fixture and similar real attacks:
/// writing to a host-controlled path during a lifecycle script.
fn marker_write_regex() -> Regex {
    Regex::new(
        r#"(?x)
        fs\s*\.\s*(write|append|create)[A-Za-z]*Sync\s*\(\s*[\"']
        (
            /tmp/ |
            /var/tmp/ |
            ~/ |
            \$HOME/ |
            /etc/ |
            /usr/local/
        )
        "#,
    )
    .unwrap()
}

pub fn run(ctx: &PackageContext, findings: &mut Vec<Finding>) {
    // lifecycle-script: any matching script key with a non-empty body.
    for name in LIFECYCLE_SCRIPT_NAMES {
        if let Some(body) = ctx.package.scripts.get(*name) {
            if !body.trim().is_empty() {
                findings.push(
                    Finding::new(
                        "lifecycle-script",
                        Severity::High,
                        format!("package.json declares `{name}` script: {body}"),
                    )
                    .at("package.json"),
                );
            }
        }
    }

    // pre-scan-execution-marker: script files that write host-side marker paths.
    let re = marker_write_regex();
    for file in &ctx.text_files {
        if !is_script_file(&file.rel) {
            continue;
        }
        if re.is_match(&file.content) {
            findings.push(
                Finding::new(
                    "pre-scan-execution-marker",
                    Severity::High,
                    "lifecycle script writes a host-controlled marker path",
                )
                .at(&file.rel),
            );
        }
    }
}

fn is_script_file(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    lower.ends_with(".js")
        || lower.ends_with(".cjs")
        || lower.ends_with(".mjs")
        || lower.ends_with(".ts")
        || lower.ends_with(".sh")
}
