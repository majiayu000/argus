use serde_json::Value;
use std::fs;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};

fn argus(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .env("PATH", "/argus-test-no-executables")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .output()
        .expect("run argus CLI")
}

fn write_rule(root: &Path, id: &str, language: &str, marker: &str) {
    fs::create_dir_all(root).unwrap();
    fs::write(
        root.join("external.yaml"),
        format!(
            r#"schema_version: 1
rules:
  - id: "{id}"
    description: "external marker detected"
    policy_class: blocking
    default_severity: high
    help_uri: "https://example.test/rules#{id}"
    languages: [{language}]
    matcher: {{ kind: literal, pattern: "{marker}" }}
"#
        ),
    )
    .unwrap();
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "JSON output: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn package_lifecycle_rule_and_override_are_auditable_in_all_formats() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("package");
    let rules = temp.path().join("rules");
    fs::create_dir(&package).unwrap();
    fs::write(
        package.join("package.json"),
        r#"{"name":"clean-demo","version":"1.0.0","scripts":{"../spoof\n":"echo ARGUS_EXTERNAL_MARKER"}}"#,
    )
    .unwrap();
    write_rule(
        &rules,
        "external-lifecycle",
        "bash",
        "ARGUS_EXTERNAL_MARKER",
    );

    let package_path = package.to_str().unwrap();
    let rules_path = rules.to_str().unwrap();
    let output = argus(&[
        "scan",
        package_path,
        "--rules-dir",
        rules_path,
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let report = json(&output);
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["rule_id"] == "external-lifecycle")
        .expect("external lifecycle finding");
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["location"], "package.json:scripts/..%2Fspoof%0A.sh");
    assert_eq!(
        finding["evidence"][0],
        "package.json:scripts/..%2Fspoof%0A.sh:1"
    );
    assert_eq!(report["rules"]["digest"].as_str().unwrap().len(), 64);

    let text = argus(&[
        "scan",
        package_path,
        "--rules-dir",
        rules_path,
        "--rule-override",
        "external-lifecycle=off",
    ]);
    assert_eq!(text.status.code(), Some(0));
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("rules_disabled: external-lifecycle"));
    assert!(text.contains("rules_overrides: external-lifecycle=off"));
    assert!(text.contains("findings: none"));

    let sarif = argus(&[
        "scan",
        package_path,
        "--rules-dir",
        rules_path,
        "--format",
        "sarif",
    ]);
    assert_eq!(sarif.status.code(), Some(1));
    let sarif = json(&sarif);
    assert_eq!(
        sarif["runs"][0]["properties"]["argusRules"]["digest"],
        report["rules"]["digest"]
    );
    let descriptor = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"] == "external-lifecycle")
        .unwrap();
    assert_eq!(
        descriptor["helpUri"],
        "https://example.test/rules#external-lifecycle"
    );
}

#[test]
fn lockfile_and_agent_surfaces_execute_the_same_session() {
    let temp = tempfile::tempdir().unwrap();

    let lock_rules = temp.path().join("lock-rules");
    write_rule(&lock_rules, "external-lock", "json", "LOCK_MARKER");
    let lockfile = temp.path().join("package-lock.json");
    fs::write(
        &lockfile,
        r#"{"name":"LOCK_MARKER","version":"1.0.0","lockfileVersion":3,"packages":{}}"#,
    )
    .unwrap();
    let lock_output = argus(&[
        "scan",
        lockfile.to_str().unwrap(),
        "--rules-dir",
        lock_rules.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(lock_output.status.code(), Some(1));
    assert!(json(&lock_output)["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["rule_id"] == "external-lock"));

    let agent_rules = temp.path().join("agent-rules");
    write_rule(&agent_rules, "external-agent", "markdown", "AGENT_MARKER");
    let surface = temp.path().join("surface");
    fs::create_dir(&surface).unwrap();
    fs::write(
        surface.join("SKILL.md"),
        "---\nname: demo\ndescription: safe\n---\nAGENT_MARKER\n",
    )
    .unwrap();
    let agent_output = argus(&[
        "agent",
        "scan",
        surface.to_str().unwrap(),
        "--rules-dir",
        agent_rules.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(agent_output.status.code(), Some(1));
    let report = json(&agent_output);
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["rule_id"] == "external-agent"));
    assert_eq!(report["rules"]["external_rule_count"], 1);
}

#[test]
fn invalid_catalog_fails_without_report_and_default_output_is_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("package");
    fs::create_dir(&package).unwrap();
    fs::write(
        package.join("package.json"),
        r#"{"name":"clean-demo","version":"1.0.0"}"#,
    )
    .unwrap();

    let default = argus(&["scan", package.to_str().unwrap(), "--format", "json"]);
    assert_eq!(default.status.code(), Some(0));
    assert!(json(&default).get("rules").is_none());

    let rules = temp.path().join("bad-rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("bad.yaml"), "not: [valid").unwrap();
    let invalid = argus(&[
        "scan",
        package.to_str().unwrap(),
        "--rules-dir",
        rules.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("load effective rules"));
}

#[test]
fn every_fetch_command_loads_rules_before_network() {
    let temp = tempfile::tempdir().unwrap();
    let rules = temp.path().join("bad-rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("bad.yaml"), "not: [valid").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let registry = format!("http://{}", listener.local_addr().unwrap());
    let cases = [
        ("fetch", "demo@1.0.0"),
        ("pypi-fetch", "demo@1.0.0"),
        ("crates-fetch", "demo@1.0.0"),
        ("go-fetch", "example.com/demo@v1.0.0"),
        ("nuget-fetch", "Demo@1.0.0"),
        ("maven-fetch", "example:demo:1.0.0"),
        ("gems-fetch", "demo@1.0.0"),
        ("composer-fetch", "vendor/demo@1.0.0"),
    ];
    for (command, package) in cases {
        let output = argus(&[
            command,
            package,
            "--registry",
            &registry,
            "--rules-dir",
            rules.to_str().unwrap(),
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "{command} emitted a report before rejecting rules"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("load effective rules"),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn standalone_vulnerability_queries_reject_non_vulnerability_overrides() {
    let output = argus(&[
        "vulns",
        "package",
        "--ecosystem",
        "npm",
        "--name",
        "demo",
        "--version",
        "1.0.0",
        "--cache-dir",
        "/nonexistent/cache",
        "--offline",
        "--rule-override",
        "remote-download=off",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("accept overrides only"));
    assert!(!stderr.contains("offline cache snapshot is missing"));
}

#[test]
fn every_supported_scan_and_fetch_help_exposes_rule_flags() {
    let cases: &[&[&str]] = &[
        &["scan", "--help"],
        &["agent", "scan", "--help"],
        &["fetch", "--help"],
        &["pypi-fetch", "--help"],
        &["crates-fetch", "--help"],
        &["go-fetch", "--help"],
        &["nuget-fetch", "--help"],
        &["maven-fetch", "--help"],
        &["gems-fetch", "--help"],
        &["composer-fetch", "--help"],
    ];
    for args in cases {
        let output = argus(args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--rules-dir"), "{args:?}");
        assert!(stdout.contains("--rule-override"), "{args:?}");
    }
    for args in [
        ["vulns", "package", "--help"],
        ["vulns", "lockfile", "--help"],
    ] {
        let output = argus(&args);
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--rule-override"), "{args:?}");
        assert!(!stdout.contains("--rules-dir"), "{args:?}");
    }
}

#[test]
fn malformed_unknown_and_duplicate_overrides_fail_without_a_report() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"clean-demo","version":"1.0.0"}"#,
    )
    .unwrap();
    let path = temp.path().to_str().unwrap();
    let cases: &[&[&str]] = &[
        &["scan", path, "--rule-override", "remote-download=invalid"],
        &["scan", path, "--rule-override", "unknown-rule=off"],
        &[
            "scan",
            path,
            "--rule-override",
            "typosquatting=param:unknown=1",
        ],
        &[
            "scan",
            path,
            "--rule-override",
            "rapid-publish-window=param:package_threshold=251",
        ],
        &[
            "scan",
            path,
            "--rule-override",
            "remote-download=off",
            "--rule-override",
            "remote-download=severity:low",
        ],
    ];
    for args in cases {
        let output = argus(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(
            output.stdout.is_empty(),
            "{args:?} emitted a partial report"
        );
    }
}

#[test]
fn typed_parameter_override_emits_sorted_data_audit_metadata() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name":"clean-demo","version":"1.0.0"}"#,
    )
    .unwrap();
    let output = argus(&[
        "scan",
        temp.path().to_str().unwrap(),
        "--format",
        "json",
        "--rule-override",
        "typosquatting=param:max_edit_distance=2",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json(&output);
    assert_eq!(
        report["rules"]["parameter_overrides"][0],
        "typosquatting=param:max_edit_distance=2"
    );
    assert_eq!(report["rules"]["data"].as_array().unwrap().len(), 10);
    assert_eq!(report["rules"]["digest"].as_str().unwrap().len(), 64);
}

#[cfg(not(unix))]
#[test]
fn non_unix_rules_directory_fails_before_json_report_or_scan() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("package");
    let rules = temp.path().join("rules");
    fs::create_dir(&package).unwrap();
    fs::create_dir(&rules).unwrap();
    fs::write(
        package.join("package.json"),
        r#"{"name":"clean-demo","version":"1.0.0"}"#,
    )
    .unwrap();
    let output = argus(&[
        "scan",
        package.to_str().unwrap(),
        "--rules-dir",
        rules.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("--rules-dir is unsupported on non-Unix platforms"));
}
