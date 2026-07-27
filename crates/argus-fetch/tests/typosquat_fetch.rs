use argus_core::{Decision, ScanReport, Severity};
use argus_fetch::{fetch_and_scan_with_rules, FetchOptions, PackageRef};
use argus_rules::RuleSession;
use argus_test_support::MockTransport;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use tar::Header;

fn make_targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = tar::Builder::new(&mut gzip);
        for (path, body) in entries {
            let mut header = Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            archive.append(&header, *body).unwrap();
        }
        archive.finish().unwrap();
    }
    gzip.finish().unwrap()
}

fn fetch_named_fixture_with_rules(name: &str, rules: &RuleSession) -> anyhow::Result<ScanReport> {
    let cache = tempfile::tempdir()?;
    let registry = "https://mock.registry";
    let package_json = format!(r#"{{"name":"{name}","version":"1.0.0"}}"#);
    let tarball = make_targz(&[
        ("package/package.json", package_json.as_bytes()),
        ("package/index.js", b"module.exports = {};"),
    ]);
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let tarball_url = format!("{registry}/{name}/-/{name}-1.0.0.tgz");
    let packument = format!(
        r#"{{
          "name": "{name}",
          "dist-tags": {{"latest": "1.0.0"}},
          "versions": {{
            "1.0.0": {{"dist": {{"tarball": "{tarball_url}", "integrity": "{integrity}"}}}}
          }}
        }}"#
    );
    let transport = MockTransport::new();
    transport.insert(&format!("{registry}/{name}"), packument.into_bytes());
    transport.insert(&tarball_url, tarball);
    let opts = FetchOptions {
        registry: registry.to_string(),
        cache_dir: Some(cache.path().to_path_buf()),
        ..FetchOptions::default()
    };
    fetch_and_scan_with_rules(&PackageRef::parse(name)?, &opts, &transport, rules)
}

#[test]
fn npm_fetch_uses_typed_typosquat_parameters_and_independent_switches() {
    let distance_two = RuleSession::load(
        None,
        &[
            "typosquatting=param:max_edit_distance=2".to_string(),
            "low-reputation=off".to_string(),
        ],
    )
    .unwrap();
    let report = fetch_named_fixture_with_rules("react-dxx", &distance_two).unwrap();
    let typosquat = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "typosquatting")
        .expect("distance-two typosquat finding");
    assert_eq!(typosquat.severity, Severity::High);
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.rule_id == "low-reputation"));
    assert_eq!(report.decision, Decision::Block);
    assert_eq!(report.rules.as_ref(), distance_two.metadata());

    for (overrides, expected_rules, expected_decision) in [
        (
            vec!["typosquatting=off".to_string()],
            vec!["low-reputation"],
            Decision::Block,
        ),
        (
            vec!["low-reputation=off".to_string()],
            vec!["typosquatting"],
            Decision::Block,
        ),
        (
            vec![
                "typosquatting=off".to_string(),
                "low-reputation=off".to_string(),
            ],
            Vec::new(),
            Decision::Allow,
        ),
    ] {
        let session = RuleSession::load(None, &overrides).unwrap();
        let report = fetch_named_fixture_with_rules("reactt", &session).unwrap();
        let relevant = report
            .findings
            .iter()
            .filter(|finding| {
                matches!(finding.rule_id.as_str(), "typosquatting" | "low-reputation")
            })
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(relevant, expected_rules, "overrides: {overrides:?}");
        assert_eq!(
            report.decision, expected_decision,
            "overrides: {overrides:?}"
        );
    }
}
