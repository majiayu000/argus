use serde_json::{json, Value};
use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};

const SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA256_SRI: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const SHA1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const H1: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn argus(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .env("PATH", "/argus-test-no-executables")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .output()
        .expect("run argus CLI")
}

fn write(path: &Path, raw: &str) {
    fs::write(path, raw).expect("write lockfile fixture");
}

fn package_lock(resolved: &str) -> String {
    format!(
        r#"{{
          "name":"root","version":"1.0.0","lockfileVersion":3,
          "packages":{{
            "":{{"name":"root","version":"1.0.0"}},
            "node_modules/demo":{{
              "version":"1.0.0",
              "resolved":"{resolved}",
              "integrity":"{SHA256_SRI}"
            }}
          }}
        }}"#
    )
}

fn representative_lockfiles() -> Vec<(&'static str, String)> {
    vec![
        ("package-lock.json", package_lock("https://registry.npmjs.org/demo.tgz")),
        (
            "yarn.lock",
            format!(
                "__metadata:\n  version: 4\n  cacheKey: 10c0\n\"demo@npm:^1\":\n  version: \"1.0.0\"\n  resolution: \"demo@npm:1.0.0\"\n  checksum: 10c0/{}\n",
                "0".repeat(64)
            ),
        ),
        (
            "pnpm-lock.yaml",
            format!(
                "lockfileVersion: '9.0'\npackages:\n  'demo@1.0.0':\n    resolution:\n      integrity: {SHA256_SRI}\nsnapshots:\n  'demo@1.0.0': {{}}\n"
            ),
        ),
        (
            "poetry.lock",
            format!(
                "[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\nfiles=[{{file=\"demo.whl\",hash=\"sha256:{SHA256}\"}}]\n[metadata]\nlock-version=\"2.1\"\npython-versions=\">=3.9\"\ncontent-hash=\"fixture\"\n"
            ),
        ),
        (
            "uv.lock",
            format!(
                "version=1\n[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\nsource={{registry=\"https://pypi.org/simple\"}}\nsdist={{url=\"https://files.pythonhosted.org/demo.tar.gz\",hash=\"sha256:{SHA256}\",size=1}}\n"
            ),
        ),
        (
            "Cargo.lock",
            format!(
                "version=4\n[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\nsource=\"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum=\"{SHA256}\"\n"
            ),
        ),
        (
            "go.sum",
            format!("example.com/demo v1.2.3 h1:{H1}\n"),
        ),
        (
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    demo (1.2.3)\nDEPENDENCIES\n  demo\nBUNDLED WITH\n  3.0.0\n".to_string(),
        ),
        (
            "composer.lock",
            json!({
                "content-hash": "fixture",
                "packages": [],
                "packages-dev": []
            })
            .to_string(),
        ),
    ]
}

#[test]
fn nine_formats_auto_detect_and_scan_without_process_or_network() {
    for (basename, raw) in representative_lockfiles() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join(basename);
        write(&path, &raw);
        let output = argus(&[
            "scan",
            path.to_str().expect("UTF-8 path"),
            "--format",
            "json",
        ]);
        assert!(
            matches!(output.status.code(), Some(0..=2)),
            "{basename}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{basename}");
        let report: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{basename}: {error}"));
        assert_eq!(report["artifact"], "lockfile", "{basename}");
        assert_ne!(report["decision"], Value::Null, "{basename}");
    }
}

#[test]
fn explicit_format_and_exact_host_allowlist_are_enforced() {
    let directory = tempfile::tempdir().expect("tempdir");
    let custom = directory.path().join("dependencies.snapshot");
    write(
        &custom,
        &package_lock("https://registry.npmjs.org/demo.tgz"),
    );

    let missing_format = argus(&["scan", custom.to_str().expect("path")]);
    assert_eq!(missing_format.status.code(), Some(2));
    assert!(missing_format.stdout.is_empty());

    let explicit_custom = argus(&[
        "scan",
        custom.to_str().expect("path"),
        "--lockfile-format",
        "package-lock",
        "--format",
        "json",
    ]);
    assert_eq!(explicit_custom.status.code(), Some(0));
    assert!(explicit_custom.stderr.is_empty());
    let report: Value =
        serde_json::from_slice(&explicit_custom.stdout).expect("explicit custom JSON");
    assert_eq!(report["decision"], "allow");

    let package_lock_path = directory.path().join("package-lock.json");
    write(
        &package_lock_path,
        &package_lock("https://cdn.example.test/demo.tgz"),
    );
    let blocked = argus(&[
        "scan",
        package_lock_path.to_str().expect("path"),
        "--lockfile-format",
        "package-lock",
        "--format",
        "json",
    ]);
    assert_eq!(blocked.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&blocked.stdout).expect("blocked JSON");
    assert!(report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .any(|finding| finding["rule_id"] == "untrusted-registry-host"));

    let conflicting_format = argus(&[
        "scan",
        package_lock_path.to_str().expect("path"),
        "--lockfile-format",
        "composer",
        "--format",
        "json",
    ]);
    assert_eq!(conflicting_format.status.code(), Some(2));
    assert!(conflicting_format.stdout.is_empty());
    assert!(String::from_utf8_lossy(&conflicting_format.stderr)
        .contains("conflicts with explicit format"));

    let allowed = argus(&[
        "scan",
        package_lock_path.to_str().expect("path"),
        "--lockfile-format",
        "package-lock",
        "--allow-registry-host",
        "CDN.Example.Test",
        "--allow-registry-host",
        "cdn.example.test",
        "--format",
        "json",
    ]);
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let report: Value = serde_json::from_slice(&allowed.stdout).expect("allowed JSON");
    assert_eq!(report["decision"], "allow");

    write(
        &package_lock_path,
        &package_lock("http://cdn.example.test/demo.tgz"),
    );
    let output = argus(&[
        "scan",
        package_lock_path.to_str().expect("path"),
        "--allow-registry-host",
        "cdn.example.test",
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).expect("HTTP JSON");
    assert!(report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .any(|finding| finding["rule_id"] == "lockfile-http-resolved"));
}

#[test]
fn lockfile_scan_opens_no_loopback_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sentinel");
    listener
        .set_nonblocking(true)
        .expect("make sentinel nonblocking");
    let address = listener.local_addr().expect("sentinel address");
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("package-lock.json");
    write(&path, &package_lock(&format!("http://{address}/demo.tgz")));
    let proxy = format!("http://{address}");

    // The artifact URL and every proxy alias converge on the sentinel. A direct
    // socket or an absolute-path downloader therefore cannot bypass this check.
    let output = Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(["scan", path.to_str().expect("path"), "--format", "json"])
        .env("PATH", "/argus-test-no-executables")
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("http_proxy", &proxy)
        .env("https_proxy", &proxy)
        .env("all_proxy", &proxy)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .expect("run scan against sentinel");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn poetry_and_uv_weak_sibling_artifacts_require_approval() {
    let directory = tempfile::tempdir().expect("tempdir");
    let fixtures = [
        (
            "poetry.lock",
            format!(
                "[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\nfiles=[\n  {{file=\"strong.whl\",hash=\"sha256:{SHA256}\"}},\n  {{file=\"weak.whl\",hash=\"sha1:{SHA1}\"}}\n]\n[metadata]\nlock-version=\"2.1\"\npython-versions=\">=3.9\"\ncontent-hash=\"fixture\"\n"
            ),
        ),
        (
            "uv.lock",
            format!(
                "version=1\n[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\nsource={{registry=\"https://pypi.org/simple\"}}\nsdist={{url=\"https://files.pythonhosted.org/demo.tar.gz\",hash=\"sha256:{SHA256}\",size=1}}\nwheels=[{{url=\"https://files.pythonhosted.org/demo.whl\",hash=\"sha1:{SHA1}\",size=1}}]\n"
            ),
        ),
    ];

    for (basename, raw) in fixtures {
        let path = directory.path().join(basename);
        write(&path, &raw);
        let output = argus(&["scan", path.to_str().expect("path"), "--format", "json"]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{basename}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{basename}");
        let report: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{basename}: {error}"));
        assert_eq!(report["decision"], "allow-with-approval", "{basename}");
        assert!(report["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding["rule_id"] == "lockfile-integrity-weak"));
    }
}

#[test]
fn text_json_and_sarif_preserve_lockfile_decisions() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("package-lock.json");
    write(&path, &package_lock("http://registry.npmjs.org/demo.tgz"));

    let text = argus(&["scan", path.to_str().expect("path")]);
    assert_eq!(text.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&text.stdout).contains("lockfile-http-resolved"));

    let json = argus(&["scan", path.to_str().expect("path"), "--format", "json"]);
    assert_eq!(json.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&json.stdout).expect("JSON report");
    assert_eq!(report["decision"], "block");

    let sarif = argus(&["scan", path.to_str().expect("path"), "--format", "sarif"]);
    assert_eq!(sarif.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&sarif.stdout).expect("SARIF report");
    assert_eq!(report["version"], "2.1.0");
    assert!(report["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .any(|result| result["ruleId"] == "lockfile-http-resolved"));
}

#[test]
fn operational_errors_exit_two_with_stderr_and_empty_stdout() {
    let directory = tempfile::tempdir().expect("tempdir");
    let cases = [
        (
            "unknown.lock",
            package_lock("https://registry.npmjs.org/demo.tgz"),
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":4,"packages":{}}"#.to_string(),
        ),
        (
            "yarn.lock",
            "# yarn lockfile v1\n__metadata:\n  version: 4\n".to_string(),
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{},"future":true}"#.to_string(),
        ),
        ("composer.lock", "{".to_string()),
    ];
    for (index, (basename, raw)) in cases.into_iter().enumerate() {
        let case = directory.path().join(format!("{index}-{basename}"));
        write(&case, &raw);
        let mut args = vec!["scan", case.to_str().expect("path"), "--format", "sarif"];
        if basename != "unknown.lock" {
            let explicit = match basename {
                "package-lock.json" => "package-lock",
                "yarn.lock" => "yarn",
                "composer.lock" => "composer",
                _ => unreachable!(),
            };
            args.extend(["--lockfile-format", explicit]);
        }
        let output = argus(&args);
        assert_eq!(output.status.code(), Some(2), "{basename}");
        assert!(output.stdout.is_empty(), "{basename}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("argus: error:"),
            "{basename}"
        );
    }

    let oversized = directory.path().join("package-lock.json");
    let file = fs::File::create(&oversized).expect("create oversized lockfile");
    file.set_len((argus_lockfile::MAX_INPUT_BYTES as u64) + 1)
        .expect("size oversized lockfile");
    let output = argus(&["scan", oversized.to_str().expect("path")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("maximum"));
}

#[test]
fn lockfile_only_flags_fail_closed_for_directory_scans() {
    let directory = tempfile::tempdir().expect("tempdir");
    let output = argus(&[
        "scan",
        directory.path().to_str().expect("path"),
        "--lockfile-format",
        "package-lock",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("valid only"));
}
