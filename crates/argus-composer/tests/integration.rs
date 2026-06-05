//! End-to-end integration tests for `fetch_and_scan_composer` via MockTransport.

use argus_composer::{fetch_and_scan_composer, ComposerFetchOptions, ComposerRef};
use argus_core::Decision;
use argus_test_support::MockTransport;
use sha1::{Digest, Sha1};
use std::io::Write;

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

/// Build a minimal Composer ZIP with the given (path, body) entries.
fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
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

fn sha1_hex(b: &[u8]) -> String {
    hex::encode(Sha1::digest(b))
}

/// Build a minimal p2 metadata JSON for `vendor/package` at `version` with
/// the given dist URL and shasum.
fn p2_json(vendor: &str, package: &str, version: &str, dist_url: &str, shasum: &str) -> String {
    format!(
        r#"{{
          "packages": {{
            "{vendor}/{package}": [
              {{
                "version": "{version}",
                "version_normalized": "{version}.0",
                "dist": {{
                  "type": "zip",
                  "url": "{dist_url}",
                  "reference": "abc123",
                  "shasum": "{shasum}"
                }}
              }}
            ]
          }}
        }}"#
    )
}

/// Build a p2 metadata JSON with inline lifecycle scripts.
fn p2_json_with_scripts(
    vendor: &str,
    package: &str,
    version: &str,
    dist_url: &str,
    shasum: &str,
    scripts_json: &str,
) -> String {
    format!(
        r#"{{
          "packages": {{
            "{vendor}/{package}": [
              {{
                "version": "{version}",
                "dist": {{
                  "type": "zip",
                  "url": "{dist_url}",
                  "reference": "abc123",
                  "shasum": "{shasum}"
                }},
                "scripts": {scripts_json}
              }}
            ]
          }}
        }}"#
    )
}

fn default_opts(registry: &str) -> ComposerFetchOptions {
    ComposerFetchOptions {
        registry: registry.to_string(),
        cache_dir: None,
        ..ComposerFetchOptions::default()
    }
}

// ---------------------------------------------------------------------------
// 1. Malicious post-install-cmd shell exec → lifecycle-script-shell + Block
// ---------------------------------------------------------------------------

#[test]
fn malicious_post_install_shell_exec_blocks() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/pkg/legacy.zip/refs/tags/1.0.0";

    let composer_json = br#"{
        "name": "vendor/pkg",
        "version": "1.0.0",
        "scripts": {
            "post-install-cmd": "php -r 'system($_GET[0]);'"
        }
    }"#;
    let zip = make_zip(&[("vendor-pkg-abc/composer.json", composer_json)]);
    let shasum = sha1_hex(&zip);

    let meta = p2_json("vendor", "pkg", "1.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/p2/vendor/pkg.json"), meta.into_bytes());
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/pkg@1.0.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let rule_ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"lifecycle-script-shell"),
        "expected lifecycle-script-shell, got: {rule_ids:?}"
    );
    assert_eq!(report.decision, Decision::Block);
}

// ---------------------------------------------------------------------------
// 1b. Malicious script declared ONLY in p2 registry metadata (not in the
//     committed composer.json) must still be detected — the inline-metadata
//     scan path (belt-and-suspenders) covers packages that strip scripts from
//     the shipped manifest.
// ---------------------------------------------------------------------------

#[test]
fn malicious_script_in_p2_metadata_only_blocks() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/pkg/legacy.zip/refs/tags/1.0.0";

    // The committed composer.json is clean — no scripts at all.
    let composer_json = br#"{
        "name": "vendor/pkg",
        "version": "1.0.0"
    }"#;
    let zip = make_zip(&[("vendor-pkg-abc/composer.json", composer_json)]);
    let shasum = sha1_hex(&zip);

    // The shell-exec lifecycle hook lives ONLY in the registry metadata.
    let meta = p2_json_with_scripts(
        "vendor",
        "pkg",
        "1.0.0",
        dist_url,
        &shasum,
        r#"{"post-install-cmd": "php -r 'system($_GET[0]);'"}"#,
    );

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/p2/vendor/pkg.json"), meta.into_bytes());
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/pkg@1.0.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let rule_ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"lifecycle-script-shell"),
        "expected lifecycle-script-shell from inline p2 metadata, got: {rule_ids:?}"
    );
    assert_eq!(report.decision, Decision::Block);
}

// ---------------------------------------------------------------------------
// 2. Benign PHP-callable lifecycle script → lifecycle-script + AllowWithApproval
// ---------------------------------------------------------------------------

#[test]
fn benign_lifecycle_script_yields_allow_with_approval() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/pkg/legacy.zip/refs/tags/1.0.0";

    let composer_json = br#"{
        "name": "vendor/pkg",
        "version": "1.0.0",
        "scripts": {
            "post-autoload-dump": ["MyVendor\\Installer::postAutoload"]
        }
    }"#;
    let zip = make_zip(&[("vendor-pkg-abc/composer.json", composer_json)]);
    let shasum = sha1_hex(&zip);
    let meta = p2_json("vendor", "pkg", "1.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/p2/vendor/pkg.json"), meta.into_bytes());
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/pkg@1.0.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let rule_ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"lifecycle-script"),
        "expected lifecycle-script, got: {rule_ids:?}"
    );
    assert!(
        !rule_ids.contains(&"lifecycle-script-shell"),
        "unexpected lifecycle-script-shell, got: {rule_ids:?}"
    );
    assert_eq!(report.decision, Decision::AllowWithApproval);
}

// ---------------------------------------------------------------------------
// 3. Clean package → Allow
// ---------------------------------------------------------------------------

#[test]
fn clean_package_allows() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/clean/legacy.zip/refs/tags/2.0.0";

    let composer_json = br#"{
        "name": "vendor/clean",
        "version": "2.0.0"
    }"#;
    let lib_php = b"<?php\nfunction hello() { return 'world'; }\n";
    let zip = make_zip(&[
        ("vendor-clean-abc/composer.json", composer_json),
        ("vendor-clean-abc/src/Helper.php", lib_php),
    ]);
    let shasum = sha1_hex(&zip);
    let meta = p2_json("vendor", "clean", "2.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/vendor/clean.json"),
        meta.into_bytes(),
    );
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/clean@2.0.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let high_or_above: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity,
                argus_core::Severity::Critical
                    | argus_core::Severity::High
                    | argus_core::Severity::Medium
            )
        })
        .collect();
    assert!(
        high_or_above.is_empty(),
        "expected no High+ findings, got: {high_or_above:?}"
    );
    assert_eq!(report.decision, Decision::Allow);
}

// ---------------------------------------------------------------------------
// 4. autoload.files structural Info → does NOT force Block
// ---------------------------------------------------------------------------

#[test]
fn autoload_files_info_does_not_block() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/helpers/legacy.zip/refs/tags/1.0.0";

    let composer_json = br#"{
        "name": "vendor/helpers",
        "version": "1.0.0",
        "autoload": {
            "files": ["src/helpers.php"]
        }
    }"#;
    let helpers_php = b"<?php\nfunction my_helper() { return 42; }\n";
    let zip = make_zip(&[
        ("vendor-helpers-abc/composer.json", composer_json),
        ("vendor-helpers-abc/src/helpers.php", helpers_php),
    ]);
    let shasum = sha1_hex(&zip);
    let meta = p2_json("vendor", "helpers", "1.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/vendor/helpers.json"),
        meta.into_bytes(),
    );
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/helpers@1.0.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let rule_ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"autoload-files-execution"),
        "expected autoload-files-execution Info finding, got: {rule_ids:?}"
    );
    // Info-only finding must not cause Block.
    assert_eq!(
        report.decision,
        Decision::Allow,
        "autoload-files-execution Info should not block"
    );
}

// ---------------------------------------------------------------------------
// 5. php-dynamic-exec in extracted file → High + Block
// ---------------------------------------------------------------------------

#[test]
fn php_dynamic_exec_blocks() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/malware/legacy.zip/refs/tags/1.0.0";

    let composer_json = br#"{"name": "vendor/malware", "version": "1.0.0"}"#;
    let evil_php = b"<?php eval(base64_decode($x)); ?>";
    let zip = make_zip(&[
        ("vendor-malware-abc/composer.json", composer_json),
        ("vendor-malware-abc/src/evil.php", evil_php),
    ]);
    let shasum = sha1_hex(&zip);
    let meta = p2_json("vendor", "malware", "1.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/vendor/malware.json"),
        meta.into_bytes(),
    );
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/malware@1.0.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let rule_ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"php-dynamic-exec"),
        "expected php-dynamic-exec, got: {rule_ids:?}"
    );
    assert_eq!(report.decision, Decision::Block);
}

// ---------------------------------------------------------------------------
// 6. Integrity match → no integrity error
// ---------------------------------------------------------------------------

#[test]
fn integrity_match_succeeds() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/good/legacy.zip/refs/tags/1.0.0";

    let composer_json = br#"{"name": "vendor/good", "version": "1.0.0"}"#;
    let zip = make_zip(&[("composer.json", composer_json)]);
    let shasum = sha1_hex(&zip); // correct SHA-1
    let meta = p2_json("vendor", "good", "1.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/vendor/good.json"),
        meta.into_bytes(),
    );
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/good@1.0.0").unwrap();
    let result = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport);
    assert!(result.is_ok(), "expected success, got: {result:?}");
}

// ---------------------------------------------------------------------------
// 7. Integrity mismatch → Err containing "SHA-1 mismatch"
// ---------------------------------------------------------------------------

#[test]
fn integrity_mismatch_errors() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/pkg/legacy.zip/refs/tags/1.0.0";

    let composer_json = br#"{"name": "vendor/pkg", "version": "1.0.0"}"#;
    let zip = make_zip(&[("composer.json", composer_json)]);
    let wrong_shasum = "0000000000000000000000000000000000000000";
    let meta = p2_json("vendor", "pkg", "1.0.0", dist_url, wrong_shasum);

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/p2/vendor/pkg.json"), meta.into_bytes());
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/pkg@1.0.0").unwrap();
    let err = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap_err();
    let err_chain = format!("{err:#}");
    assert!(
        err_chain.contains("SHA-1 mismatch"),
        "expected 'SHA-1 mismatch' in error chain, got: {err_chain}"
    );
}

// ---------------------------------------------------------------------------
// 8. Absent shasum (U-29) → scan succeeds, unverified-artifact-integrity High
// ---------------------------------------------------------------------------

#[test]
fn absent_shasum_emits_high_finding() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/nosig/legacy.zip/refs/tags/1.0.0";

    let composer_json = br#"{"name": "vendor/nosig", "version": "1.0.0"}"#;
    let zip = make_zip(&[("composer.json", composer_json)]);
    // empty shasum → unverified
    let meta = p2_json("vendor", "nosig", "1.0.0", dist_url, "");

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/vendor/nosig.json"),
        meta.into_bytes(),
    );
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/nosig@1.0.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let rule_ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"unverified-artifact-integrity"),
        "expected unverified-artifact-integrity, got: {rule_ids:?}"
    );
    // High finding → Block
    assert_eq!(report.decision, Decision::Block);
}

// ---------------------------------------------------------------------------
// 9. Host allowlist accept (codeload.github.com) and reject (evil host + HTTP)
// ---------------------------------------------------------------------------

#[test]
fn host_allowlist_rejects_unknown_host() {
    let registry = "https://mock.packagist";
    // evil host not in COMPOSER_DIST_ALLOWLIST
    let dist_url = "https://evil.example.invalid/vendor-pkg.zip";

    let composer_json = br#"{"name": "vendor/pkg", "version": "1.0.0"}"#;
    let zip = make_zip(&[("composer.json", composer_json)]);
    let shasum = sha1_hex(&zip);
    let meta = p2_json("vendor", "pkg", "1.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/p2/vendor/pkg.json"), meta.into_bytes());
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/pkg@1.0.0").unwrap();
    let err = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap_err();
    assert!(
        err.to_string().contains("evil.example.invalid") || err.to_string().contains("allowlist"),
        "expected allowlist rejection, got: {err}"
    );
}

#[test]
fn host_allowlist_rejects_http_dist_url() {
    let registry = "https://mock.packagist";
    // http:// instead of https://
    let dist_url = "http://codeload.github.com/vendor/pkg/legacy.zip";

    let composer_json = br#"{"name": "vendor/pkg", "version": "1.0.0"}"#;
    let zip = make_zip(&[("composer.json", composer_json)]);
    let shasum = sha1_hex(&zip);
    let meta = p2_json("vendor", "pkg", "1.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/p2/vendor/pkg.json"), meta.into_bytes());
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/pkg@1.0.0").unwrap();
    let err = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap_err();
    let err_chain = format!("{err:#}");
    assert!(
        err_chain.contains("non-HTTPS")
            || err_chain.contains("allowlist")
            || err_chain.contains("HTTPS"),
        "expected HTTPS enforcement, got: {err_chain}"
    );
}

// ---------------------------------------------------------------------------
// 10. Path-escape safety: ZIP with `../../etc/passwd` entry → Err
// ---------------------------------------------------------------------------

#[test]
fn path_escape_zip_entry_rejected() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/escape/legacy.zip/refs/tags/1.0.0";

    // Build a ZIP with a path-traversal entry name.
    let zip = {
        let mut buf = Vec::new();
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.start_file("../../etc/passwd", opts).unwrap();
        writer.write_all(b"root:x:0:0").unwrap();
        writer.finish().unwrap();
        buf
    };
    let shasum = sha1_hex(&zip);
    let meta = p2_json("vendor", "escape", "1.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/vendor/escape.json"),
        meta.into_bytes(),
    );
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/escape@1.0.0").unwrap();
    let err = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap_err();
    let err_chain = format!("{err:#}");
    assert!(
        err_chain.contains("traverses parent")
            || err_chain.contains("unsafe path")
            || err_chain.contains("path"),
        "expected path-traversal rejection, got: {err_chain}"
    );
}

// ---------------------------------------------------------------------------
// 10b. composer-plugin packages: bare plugin → AllowWithApproval (surfaced,
//      not hard-blocked); a plugin that also ships a shell hook → Block.
// ---------------------------------------------------------------------------

#[test]
fn bare_composer_plugin_is_allow_with_approval() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/plugin/legacy.zip/refs/tags/1.0.0";

    let composer_json = br#"{
        "name": "vendor/plugin",
        "version": "1.0.0",
        "type": "composer-plugin"
    }"#;
    let zip = make_zip(&[("vendor-plugin-abc/composer.json", composer_json)]);
    let shasum = sha1_hex(&zip);
    let meta = p2_json("vendor", "plugin", "1.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/vendor/plugin.json"),
        meta.into_bytes(),
    );
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/plugin@1.0.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"composer-plugin-package"),
        "plugin surface must be flagged, got: {ids:?}"
    );
    // A bare plugin (no shell hook / dynamic exec) requires approval, not a
    // hard block — composer plugins are common and legitimate.
    assert_eq!(report.decision, Decision::AllowWithApproval, "got: {ids:?}");
}

#[test]
fn composer_plugin_with_shell_hook_blocks() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/vendor/plugin/legacy.zip/refs/tags/1.0.0";

    let composer_json = br#"{
        "name": "vendor/plugin",
        "version": "1.0.0",
        "type": "composer-plugin",
        "scripts": { "post-install-cmd": "bash -c 'id'" }
    }"#;
    let zip = make_zip(&[("vendor-plugin-abc/composer.json", composer_json)]);
    let shasum = sha1_hex(&zip);
    let meta = p2_json("vendor", "plugin", "1.0.0", dist_url, &shasum);

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/vendor/plugin.json"),
        meta.into_bytes(),
    );
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("vendor/plugin@1.0.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"composer-plugin-package"), "got: {ids:?}");
    assert!(ids.contains(&"lifecycle-script-shell"), "got: {ids:?}");
    assert_eq!(report.decision, Decision::Block, "got: {ids:?}");
}

// ---------------------------------------------------------------------------
// 11. Typosquatting
// ---------------------------------------------------------------------------

#[test]
fn typosquat_near_popular_package_fires() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/monlog/monolog/legacy.zip/refs/tags/1.0.0";

    let composer_json = br#"{"name": "monlog/monolog", "version": "1.0.0"}"#;
    let zip = make_zip(&[("composer.json", composer_json)]);
    let shasum = sha1_hex(&zip);
    // Note: p2 key must match what fetch_and_scan_composer constructs
    let meta = format!(
        r#"{{"packages": {{"monlog/monolog": [{{"version": "1.0.0", "dist": {{"type": "zip", "url": "{dist_url}", "reference": "x", "shasum": "{shasum}"}}}}]}}}}"#
    );

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/monlog/monolog.json"),
        meta.into_bytes(),
    );
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("monlog/monolog@1.0.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let rule_ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"typosquatting"),
        "expected typosquatting, got: {rule_ids:?}"
    );
    assert!(
        rule_ids.contains(&"low-reputation"),
        "expected low-reputation, got: {rule_ids:?}"
    );
}

#[test]
fn exact_popular_package_no_typosquat_findings() {
    let registry = "https://mock.packagist";
    let dist_url = "https://codeload.github.com/monolog/monolog/legacy.zip/refs/tags/3.5.0";

    let composer_json = br#"{"name": "monolog/monolog", "version": "3.5.0"}"#;
    let zip = make_zip(&[("composer.json", composer_json)]);
    let shasum = sha1_hex(&zip);
    let meta = format!(
        r#"{{"packages": {{"monolog/monolog": [{{"version": "3.5.0", "dist": {{"type": "zip", "url": "{dist_url}", "reference": "x", "shasum": "{shasum}"}}}}]}}}}"#
    );

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/p2/monolog/monolog.json"),
        meta.into_bytes(),
    );
    transport.insert(dist_url, zip);

    let pkg = ComposerRef::parse("monolog/monolog@3.5.0").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();

    let rule_ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        !rule_ids.contains(&"typosquatting"),
        "unexpected typosquatting for exact match, got: {rule_ids:?}"
    );
}

// ---------------------------------------------------------------------------
// 12. Version resolution: first non-dev version selected when None requested
// ---------------------------------------------------------------------------

#[test]
fn version_resolution_skips_dev() {
    let registry = "https://mock.packagist";
    let dist_url_stable = "https://codeload.github.com/vendor/lib/legacy.zip/refs/tags/2.0.0";
    let dist_url_dev = "https://codeload.github.com/vendor/lib/legacy.zip/refs/heads/main";

    let composer_json = br#"{"name": "vendor/lib", "version": "2.0.0"}"#;
    let zip = make_zip(&[("composer.json", composer_json)]);
    let shasum = sha1_hex(&zip);

    // p2 puts newest first; stable 2.0.0 before dev-main
    let meta = format!(
        r#"{{
          "packages": {{
            "vendor/lib": [
              {{"version": "2.0.0", "dist": {{"type": "zip", "url": "{dist_url_stable}", "reference": "x", "shasum": "{shasum}"}}}},
              {{"version": "dev-main", "dist": {{"type": "zip", "url": "{dist_url_dev}", "reference": "y", "shasum": "0000000000000000000000000000000000000000"}}}}
            ]
          }}
        }}"#
    );

    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/p2/vendor/lib.json"), meta.into_bytes());
    transport.insert(dist_url_stable, zip);

    // Request without version → should pick 2.0.0
    let pkg = ComposerRef::parse("vendor/lib").unwrap();
    let report = fetch_and_scan_composer(&pkg, &default_opts(registry), &transport).unwrap();
    assert_eq!(report.package_version.as_deref(), Some("2.0.0"));
}
