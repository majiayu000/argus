//! End-to-end Day 3 wiring test: run `fetch_and_scan` with
//! `verify_sigstore = true` against the real npm `sigstore@2.3.1`
//! attestations + tarball, and assert the new `provenance-signature-*`
//! findings appear with the expected rule IDs and severities.
//!
//! The full Sigstore Verified path is currently blocked by the upstream
//! `intoto/0.0.2` gap (see argus-verify Day 2 and design doc §10), so the
//! happy-path assertion is "fires `provenance-signature-invalid` with the
//! upstream gap diagnostic" — pinned as a living contract that flips
//! green the day the gap closes.
//!
//! Gated on the `sigstore` feature so the default build does not have to
//! drag in the heavy Sigstore dep tree.

#![cfg(feature = "sigstore")]

use argus_fetch::{fetch_and_scan, FetchOptions, PackageRef};
use argus_test_support::MockTransport;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha512};

const REAL_TARBALL: &[u8] = include_bytes!("../../argus-verify/src/testdata/sigstore-2.3.1.tgz");
const REAL_ATTESTATIONS: &[u8] = include_bytes!("../src/testdata/sigstore_2_3_1_attestations.json");

fn build_packument(tarball_url: &str, attestations_url: &str, integrity: &str) -> String {
    format!(
        r#"{{
          "name": "sigstore",
          "dist-tags": {{"latest": "2.3.1"}},
          "versions": {{
            "2.3.1": {{
              "dist": {{
                "tarball": "{tarball_url}",
                "integrity": "{integrity}",
                "attestations": {{
                  "url": "{attestations_url}",
                  "provenance": {{}}
                }}
              }}
            }}
          }}
        }}"#
    )
}

fn make_opts(registry: &str, verify_sigstore: bool, identities: &[&str]) -> FetchOptions {
    FetchOptions {
        registry: registry.to_string(),
        verify_sigstore,
        sigstore_identity_patterns: identities.iter().map(|s| s.to_string()).collect(),
        ..FetchOptions::default()
    }
}

fn install_routes(transport: &MockTransport, registry: &str) -> (String, String) {
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(REAL_TARBALL)));
    let tarball_url = format!("{registry}/sigstore/-/sigstore-2.3.1.tgz");
    let attestations_url = format!("{registry}/-/npm/v1/attestations/sigstore@2.3.1");
    let packument = build_packument(&tarball_url, &attestations_url, &integrity);

    transport.insert(&format!("{registry}/sigstore"), packument.into_bytes());
    transport.insert(&tarball_url, REAL_TARBALL.to_vec());
    transport.insert(&attestations_url, REAL_ATTESTATIONS.to_vec());
    (tarball_url, attestations_url)
}

#[test]
fn verify_sigstore_real_npm_bundle_is_unsupported_and_never_blocks() {
    // The real npm v0.2 bundle hits the upstream intoto/0.0.2 gap inside
    // sigstore-verify 0.8.0. npm ships two attestations for sigstore@2.3.1:
    // the keyring-publish bundle (no x509 chain -> Unsupported) and the
    // SLSA-provenance bundle (intoto/0.0.2 without RFC3161 -> Unsupported,
    // the documented capability gap). Both must surface as Info
    // `provenance-signature-unverified` — a capability gap of this build is
    // NOT evidence of a bad signature, and mapping it to Critical
    // `provenance-signature-invalid` used to Block every real npm package
    // under --verify-sigstore.
    let transport = MockTransport::new();
    let registry = "https://mock.registry";
    install_routes(&transport, registry);

    let opts = make_opts(
        registry,
        true,
        &[r"^https://github\.com/sigstore/sigstore-js/.+$"],
    );
    let pkg = PackageRef::parse("sigstore@2.3.1").unwrap();
    let report = fetch_and_scan(&pkg, &opts, &transport).expect("fetch_and_scan");
    let ids = report.rule_ids();

    // Subject-digest cross-check (M1) still fires.
    assert!(
        ids.iter().any(|id| id == "provenance-verified-subject"),
        "expected provenance-verified-subject (M1 layer) in: {ids:?}"
    );
    // Both attestations surface as Unsupported -> Info unverified.
    assert!(
        ids.iter().any(|id| id == "provenance-signature-unverified"),
        "expected provenance-signature-unverified (Unsupported path) in: {ids:?}"
    );
    // The gap must never be reported as an invalid signature. The day
    // upstream widens the V1 fallback, argus-verify's fixture test flips
    // and `provenance-signature-verified` appears here instead.
    assert!(
        !ids.iter().any(|id| id == "provenance-signature-invalid"),
        "intoto/0.0.2 gap leaked through as provenance-signature-invalid: {ids:?}"
    );
    // And the signature layer must not push the decision to Block: every
    // provenance-signature-* finding in this scenario is Info.
    for f in &report.findings {
        if f.rule_id.starts_with("provenance-signature-") {
            assert_eq!(
                f.severity,
                argus_core::Severity::Info,
                "expected Info severity for {}: {}",
                f.rule_id,
                f.detail
            );
        }
    }
}

#[test]
fn verify_sigstore_off_skips_signature_layer() {
    // Same fixtures, but with verify_sigstore=false (the default). The M1
    // subject-digest layer fires, but no provenance-signature-* findings
    // should appear at all.
    let transport = MockTransport::new();
    let registry = "https://mock.registry";
    install_routes(&transport, registry);

    let opts = make_opts(registry, false, &[]);
    let pkg = PackageRef::parse("sigstore@2.3.1").unwrap();
    let report = fetch_and_scan(&pkg, &opts, &transport).expect("fetch_and_scan");
    let ids = report.rule_ids();

    assert!(
        ids.iter().any(|id| id == "provenance-verified-subject"),
        "expected M1 subject-digest finding in: {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id.starts_with("provenance-signature-")),
        "expected no signature-layer findings when --verify-sigstore is off; got: {ids:?}"
    );
}
