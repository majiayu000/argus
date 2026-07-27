use argus_rules::{
    scan_package_dir_with_rules, scan_package_dir_with_rules_and_context, RuleSession,
    MAX_EXTERNAL_INPUT_BYTES, MAX_EXTERNAL_SCAN_FILES,
};
use serde_json::{Map, Value};
use std::fs;

fn external_session() -> RuleSession {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("rules.yaml"),
        "schema_version: 1\nrules:\n  - { id: \"lifecycle-bounded-external\", description: \"bounded\", policy_class: blocking, default_severity: low, help_uri: \"https://example.test/lifecycle-bounded\", languages: [bash], matcher: { kind: literal, pattern: \"never-match\" } }\n",
    )
    .unwrap();
    RuleSession::load(Some(temp.path()), &[]).unwrap()
}

fn write_package(root: &std::path::Path, count: usize) {
    let scripts = (0..count)
        .map(|index| (format!("script-{index:05}"), Value::String(String::new())))
        .collect::<Map<_, _>>();
    let package = serde_json::json!({
        "name": "virtual-limit",
        "version": "1.0.0",
        "scripts": scripts,
    });
    fs::write(
        root.join("package.json"),
        serde_json::to_vec(&package).unwrap(),
    )
    .unwrap();
}

#[test]
fn lifecycle_surface_count_accepts_limit_and_rejects_plus_one() {
    let rules = external_session();
    let execution =
        argus_core::ExecutionContext::new(argus_core::ScanConcurrency::new(64).unwrap()).unwrap();
    let package = tempfile::tempdir().unwrap();
    write_package(package.path(), MAX_EXTERNAL_SCAN_FILES - 1);
    scan_package_dir_with_rules_and_context(package.path(), &rules, &execution).unwrap();

    write_package(package.path(), MAX_EXTERNAL_SCAN_FILES);
    assert!(scan_package_dir_with_rules_and_context(package.path(), &rules, &execution).is_err());
}

#[test]
fn external_package_manifest_size_is_bounded_before_parse() {
    let rules = external_session();
    let package = tempfile::tempdir().unwrap();
    fs::write(
        package.path().join("package.json"),
        vec![b' '; MAX_EXTERNAL_INPUT_BYTES + 1],
    )
    .unwrap();
    assert!(scan_package_dir_with_rules(package.path(), &rules).is_err());
}
