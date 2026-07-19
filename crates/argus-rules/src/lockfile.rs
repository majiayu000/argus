//! Lockfile rules. Currently parses npm `package-lock.json` v3-style trees
//! and flags entries whose `resolved` URL is plain HTTP or points at a
//! non-allowlisted registry host.

use anyhow::{Context, Result};
use argus_core::{ArtifactKind, Decision, Finding, ScanReport, Severity};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Registry hosts we accept by default. Anything else triggers
/// `untrusted-registry-host` and downstream block.
const TRUSTED_REGISTRY_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "npm.pkg.github.com",
];

#[derive(Debug, Deserialize)]
struct NpmLockfile {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    packages: BTreeMap<String, LockEntry>,
}

#[derive(Debug, Deserialize, Default)]
struct LockEntry {
    #[serde(default)]
    resolved: Option<String>,
}

pub fn scan_lockfile(path: &Path) -> Result<ScanReport> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read lockfile {}", path.display()))?;
    let parsed: NpmLockfile =
        serde_json::from_str(&raw).with_context(|| format!("parse lockfile {}", path.display()))?;

    let mut findings: Vec<Finding> = Vec::new();

    let file_label = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("lockfile")
        .to_string();

    for (key, entry) in &parsed.packages {
        let Some(resolved) = entry.resolved.as_deref() else {
            continue;
        };
        let is_http = resolved.starts_with("http://");
        if is_http {
            findings.push(
                Finding::new(
                    "lockfile-http-resolved",
                    Severity::Critical,
                    format!(
                        "lockfile entry `{}` resolves over plain HTTP ({resolved})",
                        display_key(key)
                    ),
                )
                .at(&file_label),
            );
        }
        if let Ok(host) = argus_core::url::host_of(resolved) {
            // Trust requires both an allow-listed host *and* HTTPS. A plain-
            // HTTP URL is untrusted even when the host name itself is the
            // public npm registry, because the transport is MITM-able.
            let host_trusted = TRUSTED_REGISTRY_HOSTS.contains(&host.as_str()) && !is_http;
            if !host_trusted {
                let detail = if is_http {
                    format!(
                        "lockfile entry `{}` reaches `{host}` over plain HTTP",
                        display_key(key)
                    )
                } else {
                    format!(
                        "lockfile entry `{}` resolves from non-allowlisted host `{host}`",
                        display_key(key)
                    )
                };
                findings.push(
                    Finding::new("untrusted-registry-host", Severity::High, detail).at(&file_label),
                );
            }
        }
    }

    let decision = if findings.is_empty() {
        Decision::Allow
    } else {
        Decision::Block
    };

    Ok(ScanReport {
        artifact: ArtifactKind::Lockfile,
        path: path.to_path_buf(),
        package_name: parsed.name,
        package_version: parsed.version,
        decision,
        findings,
        coordinate: None,
        intelligence: None,
    })
}

fn display_key(key: &str) -> &str {
    if key.is_empty() {
        "<root>"
    } else {
        key
    }
}
