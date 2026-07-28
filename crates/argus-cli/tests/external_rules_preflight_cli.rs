use std::fs;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn argus(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .env("PATH", "/argus-test-no-executables")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .output()
        .expect("run argus CLI")
}

fn rule(id: &str, matcher: &str) -> String {
    format!(
        "  - {{ id: \"{id}\", description: \"preflight fixture\", policy_class: blocking, default_severity: high, help_uri: \"https://example.test/preflight\", languages: [text], matcher: {matcher} }}\n"
    )
}

fn catalog(records: &str) -> String {
    format!("schema_version: 1\nrules:\n{records}")
}

fn make_invalid_rule_directories(root: &Path) -> Vec<PathBuf> {
    let invalid_yaml = root.join("invalid-yaml");
    fs::create_dir(&invalid_yaml).unwrap();
    fs::write(invalid_yaml.join("rules.yaml"), "not: [valid").unwrap();

    let invalid_regex = root.join("invalid-regex");
    fs::create_dir(&invalid_regex).unwrap();
    fs::write(
        invalid_regex.join("rules.yaml"),
        catalog(&rule("invalid-regex", r#"{ kind: regex, pattern: "[" }"#)),
    )
    .unwrap();

    let duplicate = root.join("duplicate");
    fs::create_dir(&duplicate).unwrap();
    let duplicate_rule = rule("duplicate-external", r#"{ kind: literal, pattern: "x" }"#);
    fs::write(
        duplicate.join("rules.yaml"),
        catalog(&format!("{duplicate_rule}{duplicate_rule}")),
    )
    .unwrap();

    let collision = root.join("collision");
    fs::create_dir(&collision).unwrap();
    fs::write(
        collision.join("rules.yaml"),
        catalog(&rule(
            "remote-download",
            r#"{ kind: literal, pattern: "x" }"#,
        )),
    )
    .unwrap();

    let oversized = root.join("oversized");
    fs::create_dir(&oversized).unwrap();
    fs::write(
        oversized.join("rules.yaml"),
        vec![b'#'; argus_rules::MAX_RULE_FILE_BYTES + 1],
    )
    .unwrap();

    let mut directories = vec![invalid_yaml, invalid_regex, duplicate, collision, oversized];
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let escaped = root.join("escaped-symlink");
        fs::create_dir(&escaped).unwrap();
        let outside = root.join("outside.yaml");
        fs::write(
            &outside,
            catalog(&rule("outside-rule", r#"{ kind: literal, pattern: "x" }"#)),
        )
        .unwrap();
        symlink(outside, escaped.join("rules.yaml")).unwrap();
        directories.push(escaped);
    }
    directories
}

#[test]
fn every_fetch_rejects_each_invalid_loader_state_before_network() {
    let temp = tempfile::tempdir().unwrap();
    let invalid_directories = make_invalid_rule_directories(temp.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let registry = format!("http://{}", listener.local_addr().unwrap());
    let commands = [
        ("fetch", "demo@1.0.0"),
        ("pypi-fetch", "demo@1.0.0"),
        ("crates-fetch", "demo@1.0.0"),
        ("go-fetch", "example.com/demo@v1.0.0"),
        ("nuget-fetch", "Demo@1.0.0"),
        ("maven-fetch", "example:demo:1.0.0"),
        ("gems-fetch", "demo@1.0.0"),
        ("composer-fetch", "vendor/demo@1.0.0"),
    ];
    for directory in invalid_directories {
        for (command, package) in commands {
            let output = argus(&[
                command,
                package,
                "--registry",
                &registry,
                "--rules-dir",
                directory.to_str().unwrap(),
            ]);
            assert_eq!(
                output.status.code(),
                Some(2),
                "{command} / {}: {}",
                directory.display(),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                output.stdout.is_empty(),
                "{command} emitted a partial report"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("load effective rules"),
                "{command} / {}",
                directory.display()
            );
        }
    }
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn invalid_rules_win_over_scan_agent_intel_and_osv_inputs() {
    let temp = tempfile::tempdir().unwrap();
    let rules = make_invalid_rule_directories(temp.path()).remove(0);
    let missing = temp.path().join("missing");
    let cases: &[&[&str]] = &[
        &[
            "scan",
            missing.to_str().unwrap(),
            "--rules-dir",
            rules.to_str().unwrap(),
        ],
        &[
            "agent",
            "scan",
            missing.to_str().unwrap(),
            "--baseline",
            missing.to_str().unwrap(),
            "--rules-dir",
            rules.to_str().unwrap(),
        ],
        &[
            "scan",
            missing.to_str().unwrap(),
            "--malicious-db",
            missing.to_str().unwrap(),
            "--osv",
            "--osv-cache-dir",
            missing.to_str().unwrap(),
            "--rules-dir",
            rules.to_str().unwrap(),
        ],
    ];
    for args in cases {
        let output = argus(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("load effective rules"),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains("neither a directory nor a file"));
    }
}

#[test]
fn invalid_behavioral_parameters_fail_before_npm_registry_network() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let registry = format!("http://{}", listener.local_addr().unwrap());
    let invalid = [
        "rapid-publish-window=param:package_threshold=251",
        "rapid-publish-window=param:maximum_search_objects=1",
        "version-shape-anomaly=param:minimum_predecessors=1",
        "typosquatting=param:max_edit_distance=3",
        "typosquatting=param:keyboard_enabled=maybe",
    ];
    for rule_override in invalid {
        let output = argus(&[
            "fetch",
            "demo@1.0.0",
            "--registry",
            &registry,
            "--metadata-anomaly",
            "--rule-override",
            rule_override,
        ]);
        assert_eq!(output.status.code(), Some(2), "{rule_override}");
        assert!(output.stdout.is_empty(), "{rule_override}");
    }
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn invalid_typosquat_parameter_fails_before_every_registry_network() {
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
            "--rule-override",
            "typosquatting=param:max_edit_distance=3",
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "{command} emitted a partial report"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("max_edit_distance") && stderr.contains("1..=2"),
            "{command}: {stderr}"
        );
    }
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn valid_rules_reach_the_loopback_registry() {
    let temp = tempfile::tempdir().unwrap();
    let rules = temp.path().join("valid");
    fs::create_dir(&rules).unwrap();
    fs::write(
        rules.join("rules.yaml"),
        catalog(&rule(
            "valid-external",
            r#"{ kind: literal, pattern: "x" }"#,
        )),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let registry = format!("http://{}", listener.local_addr().unwrap());
    let accepted = std::thread::spawn(move || listener.accept().is_ok());
    let output = argus(&[
        "fetch",
        "demo@1.0.0",
        "--registry",
        &registry,
        "--rules-dir",
        rules.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(accepted.join().unwrap());
}
