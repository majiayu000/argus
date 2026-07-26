//! Fail-closed contract for builds WITHOUT the `sigstore` feature: asking
//! for `--verify-sigstore` must be a hard error, never an Info finding plus
//! an Allow ("thought it was verified, it wasn't").

#![cfg(not(feature = "sigstore"))]

use argus_fetch::{fetch_and_scan, FetchOptions, PackageRef};
use argus_test_support::MockTransport;

#[test]
fn verify_sigstore_without_feature_is_a_hard_error() {
    // No routes installed on purpose: the guard must reject the request
    // before any network access happens.
    let transport = MockTransport::new();
    let opts = FetchOptions {
        verify_sigstore: true,
        ..FetchOptions::default()
    };
    let pkg = PackageRef::parse("chalk@5.3.0").unwrap();

    let err = fetch_and_scan(&pkg, &opts, &transport)
        .expect_err("verify_sigstore without the sigstore feature must fail closed");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("sigstore"),
        "error must name the missing feature, got: {msg}"
    );
}
