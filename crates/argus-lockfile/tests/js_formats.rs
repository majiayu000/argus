use argus_lockfile::{
    parse_lockfile, BoundedInput, DetectionRequest, FormatVersion, IntegrityState, LockfileError,
    LockfileFormat, ParseOutput, SourceKind, MAX_SCALAR_BYTES,
};

const SHA256_SRI: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const SHA1_SRI: &str = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const BERRY_CHECKSUM: &str =
    "10c0/0000000000000000000000000000000000000000000000000000000000000000";

fn parse_js_lockfile(basename: &str, raw: &str) -> Result<ParseOutput, LockfileError> {
    let input = BoundedInput::new(raw.as_bytes(), basename)?;
    parse_lockfile(
        &input,
        DetectionRequest {
            basename: Some(basename),
            explicit_format: None,
        },
    )
}

fn package_lock(version: u8, integrity: Option<&str>) -> String {
    let integrity = integrity
        .map(|value| format!(r#","integrity":"{value}""#))
        .unwrap_or_default();
    let compatibility = if version == 2 {
        format!(
            r#","dependencies":{{"demo":{{"version":"1.0.0","resolved":"https://registry.npmjs.org/demo/-/demo-1.0.0.tgz","integrity":"{SHA256_SRI}"}}}}"#
        )
    } else {
        String::new()
    };
    format!(
        r#"{{
          "name":"root","version":"1.0.0","lockfileVersion":{version},
          "packages":{{
            "":{{"name":"root","version":"1.0.0"}},
            "node_modules/demo":{{"version":"1.0.0","resolved":"https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"{integrity}}},
            "node_modules/git-pkg":{{"name":"git-pkg","version":"2.0.0","resolved":"git+https://github.com/acme/git-pkg.git#{COMMIT}"}},
            "node_modules/local-pkg":{{"name":"local-pkg","version":"3.0.0","resolved":"file:../local-pkg","link":true}}
          }}{compatibility}
        }}"#
    )
}

fn yarn_classic() -> String {
    format!(
        r#"# yarn lockfile v1
"demo@^1", "demo@~1":
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/demo/-/demo-1.0.0.tgz#{COMMIT}"
  dependencies:
    child "^2"

"git-pkg@git+https://github.com/acme/git-pkg.git#{COMMIT}":
  version "2.0.0"
  resolved "git+https://github.com/acme/git-pkg.git#{COMMIT}"

"local-pkg@workspace:*":
  version "3.0.0"
"#
    )
}

fn yarn_berry(version: u8, checksum: Option<&str>) -> String {
    let checksum = checksum
        .map(|value| format!("\n  checksum: {value}"))
        .unwrap_or_default();
    format!(
        r#"__metadata:
  version: {version}
  cacheKey: 10c0
"demo@npm:^1, demo@npm:~1":
  version: "1.0.0"
  resolution: "demo@npm:1.0.0"{checksum}
  languageName: node
  linkType: hard
  conditions:
    - os=linux
  dependencies:
    child: "npm:^2"
  peerDependencies:
    peer: "^3"
  dependenciesMeta:
    child:
      optional: true
  peerDependenciesMeta:
    peer:
      optional: true
"local-pkg@workspace:*":
  version: "3.0.0"
  resolution: "local-pkg@workspace:."
"#
    )
}

fn pnpm_lock(version: &str, key: &str, snapshot: bool) -> String {
    let snapshots = if snapshot {
        format!(
            r#"
snapshots:
  '{key}':
    dependencies:
      local-pkg: link:../local-pkg"#
        )
    } else {
        String::new()
    };
    format!(
        r#"lockfileVersion: '{version}'
packages:
  '{key}':
    resolution:
      integrity: {SHA256_SRI}
    os:
      - linux
    peerDependencies:
      peer-only: ^2
  'git-pkg@2.0.0':
    resolution:
      type: git
      repo: https://github.com/acme/git-pkg.git
      commit: {COMMIT}
  'file:../local-pkg':
    name: local-pkg
    version: "3.0.0"
    resolution: file:../local-pkg
importers:
  .:
    dependencies:
      demo:
        specifier: ^1
        version: "1.0.0"
    optionalDependencies:
      local-pkg: link:../local-pkg{snapshots}
"#
    )
}

#[test]
fn js_format_matrix() {
    let package_v2 =
        parse_js_lockfile("package-lock.json", &package_lock(2, Some(SHA256_SRI))).unwrap();
    assert_eq!(package_v2.detected.version, FormatVersion::PackageLock2);
    assert_eq!(package_v2.records.len(), 4);
    assert_eq!(package_v2.coverage.traversed_non_record_units, 1);

    let package_v3 =
        parse_js_lockfile("package-lock.json", &package_lock(3, Some(SHA256_SRI))).unwrap();
    assert_eq!(package_v3.detected.version, FormatVersion::PackageLock3);

    let classic = parse_js_lockfile("yarn.lock", &yarn_classic()).unwrap();
    assert_eq!(classic.detected.format, LockfileFormat::YarnClassic);
    assert_eq!(classic.records.len(), 4);
    assert_eq!(classic.coverage.traversed_non_record_units, 1);
    assert_eq!(
        classic
            .records
            .iter()
            .filter(|record| record.raw_name.as_deref() == Some("demo"))
            .count(),
        2
    );

    for version in [4, 6, 8] {
        let berry =
            parse_js_lockfile("yarn.lock", &yarn_berry(version, Some(BERRY_CHECKSUM))).unwrap();
        assert_eq!(berry.detected.format, LockfileFormat::YarnBerry);
        assert_eq!(berry.records.len(), 3);
        assert_eq!(berry.coverage.traversed_non_record_units, 4);
    }

    for (version, key, snapshot, expected) in [
        ("5.4", "/demo/1.0.0", false, FormatVersion::Pnpm5_4),
        ("6.0", "/demo@1.0.0", false, FormatVersion::Pnpm6_0),
        ("9.0", "demo@1.0.0", true, FormatVersion::Pnpm9_0),
    ] {
        let output =
            parse_js_lockfile("pnpm-lock.yaml", &pnpm_lock(version, key, snapshot)).unwrap();
        assert_eq!(output.detected.version, expected);
        assert_eq!(output.records.len(), if snapshot { 4 } else { 3 });
        assert_eq!(
            output.coverage.traversed_non_record_units,
            if snapshot { 4 } else { 3 }
        );
    }
}

#[test]
fn js_integrity_matrix() {
    let strong =
        parse_js_lockfile("package-lock.json", &package_lock(3, Some(SHA256_SRI))).unwrap();
    assert_eq!(
        record(&strong, "demo").integrity_state,
        IntegrityState::RequiredPresent
    );
    assert_eq!(
        record(&strong, "demo").integrity[0].algorithm.as_deref(),
        Some("sha256")
    );

    let missing = parse_js_lockfile("package-lock.json", &package_lock(3, None)).unwrap();
    assert_eq!(
        record(&missing, "demo").integrity_state,
        IntegrityState::RequiredMissing
    );

    let weak = parse_js_lockfile("package-lock.json", &package_lock(3, Some(SHA1_SRI))).unwrap();
    assert_eq!(
        record(&weak, "demo").integrity_state,
        IntegrityState::RequiredPresent
    );
    assert_eq!(
        record(&weak, "demo").integrity[0].algorithm.as_deref(),
        Some("sha1")
    );

    let invalid = parse_js_lockfile(
        "package-lock.json",
        &package_lock(3, Some("sha512-not-base64")),
    )
    .unwrap();
    assert_eq!(
        record(&invalid, "demo").integrity_state,
        IntegrityState::Invalid
    );

    let classic = parse_js_lockfile("yarn.lock", &yarn_classic()).unwrap();
    assert_eq!(
        record(&classic, "demo").integrity_state,
        IntegrityState::RequiredPresent
    );
    assert_eq!(
        record(&classic, "demo").integrity[0].algorithm.as_deref(),
        Some("sha1")
    );

    let berry_missing = parse_js_lockfile("yarn.lock", &yarn_berry(8, None)).unwrap();
    assert_eq!(
        record(&berry_missing, "demo").integrity_state,
        IntegrityState::RequiredMissing
    );
    let berry_invalid = parse_js_lockfile("yarn.lock", &yarn_berry(8, Some("10c0/xyz"))).unwrap();
    assert_eq!(
        record(&berry_invalid, "demo").integrity_state,
        IntegrityState::Invalid
    );

    let pnpm_invalid = pnpm_lock("6.0", "/demo@1.0.0", false).replace(SHA256_SRI, "sha512-invalid");
    let pnpm_invalid = parse_js_lockfile("pnpm-lock.yaml", &pnpm_invalid).unwrap();
    assert_eq!(
        record(&pnpm_invalid, "demo").integrity_state,
        IntegrityState::Invalid
    );
}

#[test]
fn js_sources_locators_conditions_and_occurrences_are_preserved() {
    let package =
        parse_js_lockfile("package-lock.json", &package_lock(3, Some(SHA256_SRI))).unwrap();
    assert_eq!(record(&package, "git-pkg").sources[0].kind, SourceKind::Git);
    assert_eq!(
        record(&package, "git-pkg").sources[0]
            .immutable_revision
            .as_deref(),
        Some(COMMIT)
    );
    assert_eq!(
        record(&package, "local-pkg").sources[0].kind,
        SourceKind::Workspace
    );
    assert_eq!(
        record(&package, "local-pkg").integrity_state,
        IntegrityState::UnavailableByFormat
    );
    assert_eq!(
        record(&package, "root").integrity_state,
        IntegrityState::UnavailableByFormat
    );
    assert!(record(&package, "demo")
        .locator
        .contains("node_modules/demo"));

    let berry = parse_js_lockfile("yarn.lock", &yarn_berry(8, Some(BERRY_CHECKSUM))).unwrap();
    assert_eq!(
        record(&berry, "local-pkg").sources[0].kind,
        SourceKind::Workspace
    );
    assert_eq!(
        record(&berry, "demo").condition.as_deref(),
        Some("os=linux")
    );

    let pnpm = parse_js_lockfile("pnpm-lock.yaml", &pnpm_lock("9.0", "demo@1.0.0", true)).unwrap();
    let demos = pnpm
        .records
        .iter()
        .filter(|record| record.raw_name.as_deref() == Some("demo"))
        .collect::<Vec<_>>();
    assert_eq!(demos.len(), 2);
    assert_ne!(demos[0].occurrence_index, demos[1].occurrence_index);
    assert!(demos.iter().all(|record| {
        record.integrity_state == IntegrityState::RequiredPresent
            && record.sources[0].kind == SourceKind::Registry
    }));
    assert_eq!(demos[0].condition.as_deref(), Some("os=linux"));

    let peer_variants = format!(
        r#"lockfileVersion: '9.0'
packages:
  'demo@1.0.0(peer@2.0.0)':
    resolution:
      integrity: {SHA256_SRI}
  'demo@1.0.0(peer@3.0.0)':
    resolution:
      integrity: {SHA256_SRI}
  'git-pkg@2.0.0':
    resolution: git+https://github.com/acme/git-pkg.git#{COMMIT}
snapshots:
  'demo@1.0.0(peer@2.0.0)': {{}}
  'demo@1.0.0(peer@3.0.0)': {{}}
"#
    );
    let peer_variants = parse_js_lockfile("pnpm-lock.yaml", &peer_variants).unwrap();
    assert_eq!(
        peer_variants
            .records
            .iter()
            .filter(|record| record.raw_name.as_deref() == Some("demo"))
            .count(),
        4
    );
    assert_eq!(
        record(&peer_variants, "git-pkg").sources[0]
            .immutable_revision
            .as_deref(),
        Some(COMMIT)
    );
}

#[test]
fn js_partial_analysis_matrix() {
    let package_unknown =
        r#"{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1","mystery":true}}}"#;
    assert_partial("package-lock.json", package_unknown);

    let package_v3_compatibility = r#"{"lockfileVersion":3,"packages":{},"dependencies":{}}"#;
    assert_partial("package-lock.json", package_v3_compatibility);

    let package_v2_mismatch = r#"{"lockfileVersion":2,"packages":{"node_modules/demo":{"version":"1.0.0"}},"dependencies":{"demo":{"version":"2.0.0"}}}"#;
    assert_partial("package-lock.json", package_v2_mismatch);

    let classic_unknown = "# yarn lockfile v1\n\"demo@^1\":\n  version \"1\"\n  mystery \"x\"\n";
    assert_partial("yarn.lock", classic_unknown);

    let berry_unknown =
        "__metadata:\n  version: 8\n\"demo@npm:^1\":\n  version: \"1\"\n  resolution: \"demo@npm:1\"\n  mystery: true\n";
    assert_partial("yarn.lock", berry_unknown);

    let pnpm_unknown = "lockfileVersion: '9.0'\npackages:\n  'demo@1.0.0':\n    mystery: true\n";
    assert_partial("pnpm-lock.yaml", pnpm_unknown);

    let pnpm_unresolved = format!(
        "lockfileVersion: '6.0'\npackages:\n  '/demo@1.0.0':\n    resolution:\n      integrity: {SHA256_SRI}\nimporters:\n  .:\n    dependencies:\n      missing: 2.0.0\n"
    );
    assert_partial("pnpm-lock.yaml", &pnpm_unresolved);

    let pnpm_old_snapshot = "lockfileVersion: '6.0'\npackages: {}\nsnapshots: {}\n";
    assert_partial("pnpm-lock.yaml", pnpm_old_snapshot);

    let pnpm_orphan_commit = format!(
        "lockfileVersion: '9.0'\npackages:\n  'demo@1.0.0':\n    resolution:\n      commit: {COMMIT}\n"
    );
    assert_partial("pnpm-lock.yaml", &pnpm_orphan_commit);
}

#[test]
fn pnpm_commit_requires_a_git_source_in_the_same_resolution() {
    let invalid = [
        format!(
            "lockfileVersion: '9.0'\npackages:\n  'demo@1.0.0':\n    resolution:\n      commit: {COMMIT}\n      tarball: https://registry.npmjs.org/demo/-/demo-1.0.0.tgz\n"
        ),
        format!(
            "lockfileVersion: '9.0'\npackages:\n  'demo@1.0.0':\n    resolution:\n      commit: {COMMIT}\n      path: ../demo\n"
        ),
        format!(
            "lockfileVersion: '9.0'\npackages:\n  'demo@1.0.0':\n    resolution:\n      commit: {COMMIT}\n      integrity: {SHA256_SRI}\n"
        ),
    ];
    for raw in invalid {
        assert_partial("pnpm-lock.yaml", &raw);
    }

    let valid = format!(
        "lockfileVersion: '9.0'\npackages:\n  'demo@1.0.0':\n    resolution:\n      type: git\n      repo: https://github.com/acme/demo.git\n      commit: {COMMIT}\n"
    );
    let valid = parse_js_lockfile("pnpm-lock.yaml", &valid).unwrap();
    let git = record(&valid, "demo");
    assert_eq!(git.sources[0].kind, SourceKind::Git);
    assert_eq!(git.sources[0].immutable_revision.as_deref(), Some(COMMIT));
}

#[test]
fn package_lock_descriptor_metadata_is_structurally_validated() {
    let valid = format!(
        r#"{{
          "name":"root","version":"1.0.0","lockfileVersion":3,
          "packages":{{
            "":{{
              "name":"root","version":"1.0.0",
              "dependencies":{{"demo":"^1"}},
              "devDependencies":{{"test-only":"^2"}},
              "workspaces":["packages/*"]
            }},
            "node_modules/demo":{{
              "version":"1.0.0",
              "resolved":"https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
              "integrity":"{SHA256_SRI}",
              "deprecated":"use demo-next",
              "dev":true,"optional":false,"devOptional":false,"peer":false,
              "extraneous":false,"inBundle":false,"hasInstallScript":true,
              "hasShrinkwrap":false,
              "license":"MIT",
              "bin":{{"demo":"bin/demo.js"}},
              "engines":{{"node":">=18"}},
              "dependencies":{{"child":"^2"}},
              "devDependencies":{{"test-only":"^2"}},
              "optionalDependencies":{{"optional-child":"^3"}},
              "peerDependencies":{{"peer-child":"^4"}},
              "acceptDependencies":{{"peer-child":"4"}},
              "peerDependenciesMeta":{{"peer-child":{{"optional":true}}}},
              "bundleDependencies":["child"],
              "os":["linux"],"cpu":["x64"],
              "funding":[
                "https://example.test/sponsor",
                {{"type":"individual","url":"https://example.test/donate"}}
              ]
            }}
          }}
        }}"#
    );
    let output = parse_js_lockfile("package-lock.json", &valid).unwrap();
    assert_eq!(output.coverage.record_units, 2);
    assert_eq!(output.coverage.traversed_non_record_units, 0);
    assert_eq!(output.coverage.total_units, 2);
    assert_eq!(output.coverage.recognized_units, 2);

    let invalid_types = [
        r#""deprecated":true"#,
        r#""hasShrinkwrap":"yes""#,
        r#""dependencies":{"child":42}"#,
        r#""acceptDependencies":{"peer":42}"#,
        r#""bundleDependencies":42"#,
        r#""bundleDependencies":["child",42]"#,
        r#""bin":{"demo":42}"#,
        r#""engines":{"node":18}"#,
        r#""os":["linux",42]"#,
        r#""funding":{"type":"individual"}"#,
        r#""peerDependenciesMeta":{"peer":{"optional":"yes"}}"#,
    ];
    for metadata in invalid_types {
        let raw = format!(
            r#"{{"lockfileVersion":3,"packages":{{
              "node_modules/demo":{{"version":"1.0.0",{metadata}}}
            }}}}"#
        );
        assert!(
            parse_js_lockfile("package-lock.json", &raw).is_err(),
            "invalid metadata was accepted: {metadata}"
        );
    }

    let nested_unknown = r#"{"lockfileVersion":3,"packages":{
      "node_modules/demo":{
        "version":"1.0.0",
        "funding":{"url":"https://example.test","injected":true}
      }
    }}"#;
    assert_partial("package-lock.json", nested_unknown);

    let registry_only_field = r#"{"lockfileVersion":3,"packages":{
      "node_modules/demo":{"version":"1.0.0","_hasShrinkwrap":true}
    }}"#;
    assert_partial("package-lock.json", registry_only_field);
}

#[test]
fn package_lock_registry_magic_is_normalized_exactly() {
    fn resolved_lock(version: u8, resolved: &str, integrity: bool) -> String {
        let integrity = if integrity {
            format!(r#","integrity":"{SHA256_SRI}""#)
        } else {
            String::new()
        };
        let compatibility = if version == 2 {
            r#","dependencies":{"demo":{"version":"1.0.0"}}"#
        } else {
            ""
        };
        format!(
            r#"{{
              "lockfileVersion":{version},
              "packages":{{
                "node_modules/demo":{{
                  "version":"1.0.0","resolved":"{resolved}"{integrity}
                }}
              }}{compatibility}
            }}"#
        )
    }

    for version in [2, 3] {
        let exact = parse_js_lockfile(
            "package-lock.json",
            &resolved_lock(version, "registry.npmjs.org", true),
        )
        .unwrap();
        let exact = record(&exact, "demo");
        assert_eq!(exact.sources[0].kind, SourceKind::Registry);
        assert_eq!(
            exact.sources[0].location.as_deref(),
            Some("https://registry.npmjs.org/")
        );
        assert_eq!(exact.integrity_state, IntegrityState::RequiredPresent);

        let missing = parse_js_lockfile(
            "package-lock.json",
            &resolved_lock(version, "registry.npmjs.org", false),
        )
        .unwrap();
        assert_eq!(
            record(&missing, "demo").integrity_state,
            IntegrityState::RequiredMissing
        );

        let near_miss = parse_js_lockfile(
            "package-lock.json",
            &resolved_lock(
                version,
                "https://registry.npmjs.org.evil.example/demo.tgz",
                true,
            ),
        )
        .unwrap();
        assert_eq!(record(&near_miss, "demo").sources[0].kind, SourceKind::Url);
    }
}

#[test]
fn js_coverage_inventory_probes() {
    let package_nested = format!(
        r#"{{"lockfileVersion":2,"packages":{{
          "node_modules/demo":{{"version":"1.0.0","integrity":"{SHA256_SRI}"}},
          "node_modules/child":{{"version":"2.0.0","integrity":"{SHA256_SRI}"}}
        }},"dependencies":{{"demo":{{"version":"1.0.0","requires":{{"child":"^2"}},
          "dependencies":{{"child":{{"version":"2.0.0"}}}}}}}}}}"#
    );
    let package_nested = parse_js_lockfile("package-lock.json", &package_nested).unwrap();
    assert_eq!(package_nested.coverage.record_units, 2);
    assert_eq!(package_nested.coverage.traversed_non_record_units, 2);
    assert_eq!(package_nested.coverage.total_units, 4);
    assert_eq!(package_nested.coverage.recognized_units, 4);

    let malformed_node = r#"{"lockfileVersion":2,"packages":{"node_modules/demo":{"version":"1"}},"dependencies":{"demo":{"version":"1","dependencies":{"ghost":"not-an-object"}}}}"#;
    assert!(parse_js_lockfile("package-lock.json", malformed_node).is_err());
    let malformed_requires = r#"{"lockfileVersion":2,"packages":{"node_modules/demo":{"version":"1"}},"dependencies":{"demo":{"version":"1","requires":{"ghost":42}}}}"#;
    assert!(parse_js_lockfile("package-lock.json", malformed_requires).is_err());

    let pnpm_edges = format!(
        r#"lockfileVersion: '9.0'
packages:
  'demo@1.0.0':
    resolution:
      integrity: {SHA256_SRI}
    dependencies:
      child: 2.0.0
    optionalDependencies:
      local: link:../local
    peerDependencies:
      peer-only: ^3
  'child@2.0.0':
    resolution:
      integrity: {SHA256_SRI}
importers:
  .:
    dependencies:
      demo: 1.0.0
    devDependencies:
      child: 2.0.0
    optionalDependencies:
      local: link:../local
"#
    );
    let pnpm_edges = parse_js_lockfile("pnpm-lock.yaml", &pnpm_edges).unwrap();
    assert_eq!(pnpm_edges.coverage.record_units, 2);
    assert_eq!(pnpm_edges.coverage.traversed_non_record_units, 6);
    assert_eq!(pnpm_edges.coverage.total_units, 8);
    assert_eq!(pnpm_edges.coverage.recognized_units, 8);

    let invalid_metadata = format!(
        "lockfileVersion: '9.0'\npackages:\n  'demo@1.0.0':\n    resolution:\n      integrity: {SHA256_SRI}\n    dependenciesMeta:\n      child:\n        injected: nope\n"
    );
    assert!(parse_js_lockfile("pnpm-lock.yaml", &invalid_metadata).is_err());
}

#[test]
fn yarn_classic_parser_enforces_scalar_budget_on_native_fields() {
    let oversized = "x".repeat(MAX_SCALAR_BYTES + 1);
    let cases = [
        format!("# yarn lockfile v1\n\"demo@^1\":\n  version \"{oversized}\"\n"),
        format!(
            "# yarn lockfile v1\n\"demo@^1\":\n  version \"1\"\n  resolved \"{oversized}\"\n"
        ),
        format!(
            "# yarn lockfile v1\n\"demo@^1\":\n  version \"1\"\n  integrity \"{oversized}\"\n"
        ),
        format!(
            "# yarn lockfile v1\n\"demo@^1\":\n  version \"1\"\n  dependencies:\n    child \"{oversized}\"\n"
        ),
    ];
    for raw in cases {
        assert!(matches!(
            parse_js_lockfile("yarn.lock", &raw),
            Err(LockfileError::ScalarTooLarge { .. })
        ));
    }
}

fn record<'a>(output: &'a ParseOutput, name: &str) -> &'a argus_lockfile::NormalizedDependency {
    output
        .records
        .iter()
        .find(|record| record.raw_name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("missing record for {name}"))
}

fn assert_partial(basename: &str, raw: &str) {
    assert!(
        matches!(
            parse_js_lockfile(basename, raw),
            Err(LockfileError::PartialAnalysis { unsupported_units, .. }) if unsupported_units > 0
        ),
        "{basename} did not fail as partial analysis"
    );
}
