//! End-to-end Day 3 wiring test: run `fetch_and_scan` with
//! `verify_sigstore = true` against the real npm `sigstore@2.3.1`
//! attestations + tarball, and assert the new `provenance-signature-*`
//! findings appear with the expected rule IDs and severities.
//!
//! The real npm intoto/0.0.2 SLSA bundle must complete the full
//! cryptographic verification chain, while corrupted or policy-mismatched
//! material must still fail closed.
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
    install_routes_with_artifact(
        transport,
        registry,
        REAL_ATTESTATIONS.to_vec(),
        REAL_TARBALL.to_vec(),
    )
}

fn install_routes_with_attestations(
    transport: &MockTransport,
    registry: &str,
    attestations: Vec<u8>,
) -> (String, String) {
    install_routes_with_artifact(transport, registry, attestations, REAL_TARBALL.to_vec())
}

fn install_routes_with_artifact(
    transport: &MockTransport,
    registry: &str,
    attestations: Vec<u8>,
    artifact: Vec<u8>,
) -> (String, String) {
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&artifact)));
    let tarball_url = format!("{registry}/sigstore/-/sigstore-2.3.1.tgz");
    let attestations_url = format!("{registry}/-/npm/v1/attestations/sigstore@2.3.1");
    let packument = build_packument(&tarball_url, &attestations_url, &integrity);

    transport.insert(&format!("{registry}/sigstore"), packument.into_bytes());
    transport.insert(&tarball_url, artifact);
    transport.insert(&attestations_url, attestations);
    (tarball_url, attestations_url)
}

#[test]
fn verify_sigstore_real_npm_bundle_is_verified() {
    // npm ships two attestations for sigstore@2.3.1: the keyring-publish
    // bundle remains Unsupported, while the Fulcio-backed SLSA bundle must
    // pass every cryptographic and identity check.
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
    // The npm-keyring bundle remains Unsupported -> Info unverified.
    assert!(
        ids.iter().any(|id| id == "provenance-signature-unverified"),
        "expected provenance-signature-unverified (Unsupported path) in: {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id == "provenance-signature-verified"),
        "expected provenance-signature-verified in: {ids:?}"
    );
    assert!(!ids.iter().any(|id| id == "provenance-signature-invalid"));
    assert_ne!(report.decision, argus_core::Decision::Block);
}

#[test]
fn corrupted_dsse_signature_is_critical_and_blocks() {
    let mut attestations: serde_json::Value = serde_json::from_slice(REAL_ATTESTATIONS).unwrap();
    attestations["attestations"][1]["bundle"]["dsseEnvelope"]["signatures"][0]["sig"] =
        serde_json::Value::String("AA==".to_string());

    let transport = MockTransport::new();
    let registry = "https://mock.registry";
    install_routes_with_attestations(
        &transport,
        registry,
        serde_json::to_vec(&attestations).unwrap(),
    );

    let opts = make_opts(
        registry,
        true,
        &[r"^https://github\.com/sigstore/sigstore-js/.+$"],
    );
    let pkg = PackageRef::parse("sigstore@2.3.1").unwrap();
    let report = fetch_and_scan(&pkg, &opts, &transport).expect("fetch_and_scan");

    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "provenance-signature-invalid"
            && finding.severity == argus_core::Severity::Critical
    }));
    assert_eq!(report.decision, argus_core::Decision::Block);
}

#[test]
fn downgraded_bundle_without_inclusion_material_is_critical_and_blocks() {
    for remove_checkpoint_only in [false, true] {
        let mut attestations: serde_json::Value =
            serde_json::from_slice(REAL_ATTESTATIONS).unwrap();
        let bundle = &mut attestations["attestations"][1]["bundle"];
        bundle["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.1".into();
        if remove_checkpoint_only {
            bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
                .as_object_mut()
                .unwrap()
                .remove("checkpoint");
        } else {
            bundle["verificationMaterial"]["tlogEntries"][0]
                .as_object_mut()
                .unwrap()
                .remove("inclusionProof");
        }

        let transport = MockTransport::new();
        let registry = "https://mock.registry";
        install_routes_with_attestations(
            &transport,
            registry,
            serde_json::to_vec(&attestations).unwrap(),
        );

        let opts = make_opts(
            registry,
            true,
            &[r"^https://github\.com/sigstore/sigstore-js/.+$"],
        );
        let pkg = PackageRef::parse("sigstore@2.3.1").unwrap();
        let report = fetch_and_scan(&pkg, &opts, &transport).expect("fetch_and_scan");

        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "provenance-signature-invalid"
                && finding.severity == argus_core::Severity::Critical
        }));
        assert_eq!(report.decision, argus_core::Decision::Block);
    }
}

#[test]
fn downloaded_artifact_bytes_are_bound_by_sha512_and_tampering_blocks() {
    let mut artifact = REAL_TARBALL.to_vec();
    *artifact.last_mut().unwrap() ^= 1;

    let transport = MockTransport::new();
    let registry = "https://mock.registry";
    install_routes_with_artifact(&transport, registry, REAL_ATTESTATIONS.to_vec(), artifact);

    let opts = make_opts(
        registry,
        true,
        &[r"^https://github\.com/sigstore/sigstore-js/.+$"],
    );
    let pkg = PackageRef::parse("sigstore@2.3.1").unwrap();
    let report = fetch_and_scan(&pkg, &opts, &transport).expect("fetch_and_scan");

    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "provenance-subject-mismatch"
            && finding.severity == argus_core::Severity::Critical
    }));
    assert_eq!(report.decision, argus_core::Decision::Block);
}

#[test]
fn identity_mismatch_is_critical_and_blocks() {
    let transport = MockTransport::new();
    let registry = "https://mock.registry";
    install_routes(&transport, registry);

    let opts = make_opts(registry, true, &[r"^https://example\.invalid/.+$"]);
    let pkg = PackageRef::parse("sigstore@2.3.1").unwrap();
    let report = fetch_and_scan(&pkg, &opts, &transport).expect("fetch_and_scan");

    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "provenance-signature-invalid"
            && finding.severity == argus_core::Severity::Critical
    }));
    assert_eq!(report.decision, argus_core::Decision::Block);
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
