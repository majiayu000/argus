use argus_lockfile::{
    parse_lockfile, parser_for, BoundedInput, DetectedLockfile, DetectionRequest, FormatVersion,
    IntegrityState, LockfileError, LockfileFormat, ParseOutput, SourceKind, MAX_SCALAR_BYTES,
    MAX_SCALAR_COUNT,
};
use serde_json::{json, Value};

fn parse(name: &str, raw: &str) -> Result<ParseOutput, LockfileError> {
    let input = BoundedInput::new(raw.as_bytes(), name).unwrap();
    parse_lockfile(
        &input,
        DetectionRequest {
            basename: Some(name),
            explicit_format: None,
        },
    )
}

fn parse_bundler_direct(raw: &str) -> Result<ParseOutput, LockfileError> {
    let input = BoundedInput::new(raw.as_bytes(), "Gemfile.lock").unwrap();
    parser_for(LockfileFormat::Bundler).parse(
        &input,
        &DetectedLockfile {
            format: LockfileFormat::Bundler,
            version: FormatVersion::Bundler3,
            evidence: vec!["direct parser boundary probe".to_string()],
        },
    )
}

fn gemfile(version: &str, checksums: Option<&str>) -> String {
    let checksums = checksums.map_or(String::new(), |lines| format!("\nCHECKSUMS\n{lines}"));
    format!(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    demo (1.2.3)\nDEPENDENCIES\n  demo\n{checksums}\nBUNDLED WITH\n  {version}\n"
    )
}

fn composer(packages: Vec<Value>, packages_dev: Vec<Value>) -> String {
    json!({
        "_readme": ["fixture"],
        "content-hash": "fixture",
        "packages": packages,
        "packages-dev": packages_dev,
        "aliases": [],
        "minimum-stability": "stable",
        "stability-flags": {},
        "prefer-stable": false,
        "prefer-lowest": false,
        "platform": {},
        "platform-dev": {},
        "plugin-api-version": "2.6.0"
    })
    .to_string()
}

#[test]
fn ruby_composer_format_matrix() {
    let versions = [
        ("2.4.22", FormatVersion::Bundler2, None),
        ("2.5.23", FormatVersion::Bundler2, None),
        ("2.6.2", FormatVersion::Bundler2, None),
        (
            "2.6.2",
            FormatVersion::Bundler2,
            Some(format!("  demo (1.2.3) sha256={}", "a".repeat(64))),
        ),
        ("3.1.0", FormatVersion::Bundler3, None),
        (
            "3.1.0",
            FormatVersion::Bundler3,
            Some(format!("  demo (1.2.3) sha256={}", "b".repeat(64))),
        ),
        ("4.0.0", FormatVersion::Bundler4, None),
        (
            "4.0.0",
            FormatVersion::Bundler4,
            Some(format!(
                "  demo (1.2.3) sha256={}\n  bundler (4.0.0) sha256={}",
                "c".repeat(64),
                "d".repeat(64)
            )),
        ),
    ];
    for (version, expected, checksums) in versions {
        let output = parse("Gemfile.lock", &gemfile(version, checksums.as_deref())).unwrap();
        assert_eq!(output.detected.version, expected, "{version}");
        assert_eq!(output.records.len(), 1, "{version}");
        assert_eq!(
            output.records[0].integrity_state,
            if checksums.is_some() {
                IntegrityState::RequiredPresent
            } else {
                IntegrityState::UnavailableByFormat
            },
            "{version}"
        );
        assert_eq!(
            output.metadata_integrity.len(),
            usize::from(
                version == "4.0.0"
                    && checksums
                        .as_deref()
                        .is_some_and(|value| value.contains("bundler")),
            ),
            "{version}"
        );
        output.coverage.validate().unwrap();
    }

    let commit = "0123456789abcdef0123456789abcdef01234567";
    let raw = composer(
        vec![json!({
            "name": "vendor/runtime",
            "version": "1.0.0",
            "dist": {
                "type": "zip",
                "url": "https://repo.packagist.org/dist.zip",
                "reference": commit,
                "shasum": "a".repeat(40)
            },
            "source": {
                "type": "git",
                "url": "https://github.com/vendor/runtime.git",
                "reference": commit
            },
            "require": {"php": "^8.2"},
            "provide": {"psr/log-implementation": "3.0"}
        })],
        vec![json!({
            "name": "vendor/dev-tool",
            "version": "2.0.0",
            "source": {
                "type": "git",
                "url": "https://github.com/vendor/dev-tool.git",
                "reference": "main"
            },
            "require-dev": {"vendor/runtime": "^1"}
        })],
    );
    let output = parse("composer.lock", &raw).unwrap();
    assert_eq!(output.detected.version, FormatVersion::ComposerSchema1);
    assert_eq!(output.records.len(), 2);
    assert_eq!(output.coverage.record_units, 2);
    assert_eq!(output.coverage.traversed_non_record_units, 3);
    let runtime = output
        .records
        .iter()
        .find(|record| record.raw_name.as_deref() == Some("vendor/runtime"))
        .unwrap();
    assert_eq!(runtime.condition.as_deref(), Some("packages"));
    assert_eq!(runtime.sources.len(), 2);
    assert!(runtime.sources.iter().any(|source| {
        source.kind == SourceKind::Url
            && source.location.as_deref() == Some("https://repo.packagist.org/dist.zip")
            && source.locator.ends_with(".dist.url")
    }));
    assert!(runtime.sources.iter().any(|source| {
        source.kind == SourceKind::Git
            && source.location.as_deref() == Some("https://github.com/vendor/runtime.git")
            && source.immutable_revision.as_deref() == Some(commit)
            && source.locator.ends_with(".source.url")
    }));
    let dev = output
        .records
        .iter()
        .find(|record| record.raw_name.as_deref() == Some("vendor/dev-tool"))
        .unwrap();
    assert_eq!(dev.condition.as_deref(), Some("packages-dev"));
    assert_eq!(dev.sources[0].kind, SourceKind::Git);
    assert_eq!(dev.sources[0].immutable_revision, None);
}

#[test]
fn ruby_composer_integrity_matrix() {
    let sha256 = "a".repeat(64);
    let sha1 = "b".repeat(40);
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let raw = format!(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    native (1.2.3-x86_64-linux)\nGIT\n  remote: https://github.com/vendor/git-gem.git\n  revision: {commit}\n  specs:\n    git-gem (2.0.0)\nPATH\n  remote: ../local\n  glob: '*.gemspec'\n  specs:\n    local-gem (3.0.0)\nPLATFORMS\n  ruby\n  x86_64-linux\nDEPENDENCIES\n  native\n  git-gem!\n  local-gem!\nCHECKSUMS\n  native (1.2.3-x86_64-linux) sha256={sha256},sha1={sha1}\n  git-gem (2.0.0)\n  local-gem (3.0.0)\nBUNDLED WITH\n  3.0.0\n"
    );
    let output = parse("Gemfile.lock", &raw).unwrap();
    assert_eq!(output.records.len(), 3);
    assert_eq!(output.coverage.record_units, 3);
    assert_eq!(output.coverage.traversed_non_record_units, 6);
    assert_eq!(output.coverage.total_units, 9);
    assert_eq!(output.coverage.recognized_units, 9);
    let native = output
        .records
        .iter()
        .find(|record| record.raw_name.as_deref() == Some("native"))
        .unwrap();
    assert_eq!(native.raw_version.as_deref(), Some("1.2.3"));
    assert_eq!(native.platform.as_deref(), Some("x86_64-linux"));
    assert_eq!(native.integrity_state, IntegrityState::RequiredPresent);
    assert_eq!(native.integrity.len(), 2);
    let git = output
        .records
        .iter()
        .find(|record| record.raw_name.as_deref() == Some("git-gem"))
        .unwrap();
    assert_eq!(git.sources[0].kind, SourceKind::Git);
    assert_eq!(git.sources[0].immutable_revision.as_deref(), Some(commit));
    assert_eq!(git.integrity_state, IntegrityState::UnavailableByFormat);
    let path = output
        .records
        .iter()
        .find(|record| record.raw_name.as_deref() == Some("local-gem"))
        .unwrap();
    assert_eq!(path.sources[0].kind, SourceKind::Path);

    let raw = composer(
        vec![
            json!({
                "name": "vendor/weak",
                "version": "1.0.0",
                "dist": {
                    "type": "zip",
                    "url": "https://repo.packagist.org/weak.zip",
                    "shasum": "A".repeat(40)
                }
            }),
            json!({
                "name": "vendor/empty",
                "version": "1.0.0",
                "dist": {
                    "type": "zip",
                    "url": "https://repo.packagist.org/empty.zip",
                    "shasum": ""
                }
            }),
            json!({
                "name": "vendor/invalid",
                "version": "1.0.0",
                "dist": {
                    "type": "zip",
                    "url": "https://repo.packagist.org/invalid.zip",
                    "shasum": "abcd"
                }
            }),
            json!({
                "name": "vendor/path",
                "version": "1.0.0",
                "dist": {"type": "path", "url": "../path", "shasum": null}
            }),
        ],
        vec![],
    );
    let output = parse("composer.lock", &raw).unwrap();
    let state = |name: &str| {
        output
            .records
            .iter()
            .find(|record| record.raw_name.as_deref() == Some(name))
            .unwrap()
            .integrity_state
    };
    assert_eq!(state("vendor/weak"), IntegrityState::OptionalPresent);
    let weak = output
        .records
        .iter()
        .find(|record| record.raw_name.as_deref() == Some("vendor/weak"))
        .unwrap();
    assert_eq!(
        weak.integrity
            .first()
            .and_then(|evidence| evidence.algorithm.as_deref()),
        Some("sha1")
    );
    assert_eq!(state("vendor/empty"), IntegrityState::OptionalAbsent);
    assert_eq!(state("vendor/invalid"), IntegrityState::Invalid);
    let path = output
        .records
        .iter()
        .find(|record| record.raw_name.as_deref() == Some("vendor/path"))
        .unwrap();
    assert_eq!(path.sources[0].kind, SourceKind::Path);
    assert_eq!(path.integrity_state, IntegrityState::UnavailableByFormat);
}

#[test]
fn bundler_missing_unmatched_duplicate_and_mixed_algorithms_fail_closed() {
    let unmatched = gemfile(
        "2.6.2",
        Some(&format!("  other (9.9.9) sha256={}", "a".repeat(64))),
    );
    assert!(parse("Gemfile.lock", &unmatched).is_err());

    let missing = gemfile("2.6.2", Some(""));
    let output = parse("Gemfile.lock", &missing).unwrap();
    assert_eq!(
        output.records[0].integrity_state,
        IntegrityState::RequiredMissing
    );

    let duplicate_lock_name = gemfile(
        "2.6.2",
        Some(&format!(
            "  demo (1.2.3) sha256={}\n  demo (1.2.3) sha1={}",
            "a".repeat(64),
            "b".repeat(40)
        )),
    );
    assert!(parse("Gemfile.lock", &duplicate_lock_name).is_err());

    let duplicate_algorithm = gemfile(
        "2.6.2",
        Some(&format!(
            "  demo (1.2.3) sha256={},sha256={}",
            "a".repeat(64),
            "b".repeat(64)
        )),
    );
    assert!(parse("Gemfile.lock", &duplicate_algorithm).is_err());

    let invalid = gemfile("2.6.2", Some("  demo (1.2.3) sha999=abcd"));
    let output = parse("Gemfile.lock", &invalid).unwrap();
    assert_eq!(output.records[0].integrity_state, IntegrityState::Invalid);

    let mixed_invalid = gemfile(
        "2.6.2",
        Some(&format!(
            "  demo (1.2.3) sha256={},sha1=bad",
            "a".repeat(64)
        )),
    );
    let output = parse("Gemfile.lock", &mixed_invalid).unwrap();
    assert_eq!(output.records[0].integrity_state, IntegrityState::Invalid);
}

#[test]
fn bundler_self_checksum_is_exact_unique_and_invalid_is_preserved() {
    let mismatch = gemfile(
        "4.0.0",
        Some(&format!(
            "  demo (1.2.3) sha256={}\n  bundler (4.0.1) sha256={}",
            "a".repeat(64),
            "b".repeat(64)
        )),
    );
    assert!(parse("Gemfile.lock", &mismatch).is_err());

    let duplicate = gemfile(
        "4.0.0",
        Some(&format!(
            "  demo (1.2.3) sha256={}\n  bundler (4.0.0) sha256={}\n  bundler (4.0.0) sha1={}",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(40)
        )),
    );
    assert!(parse("Gemfile.lock", &duplicate).is_err());

    let invalid = gemfile(
        "4.0.0",
        Some(&format!(
            "  demo (1.2.3) sha256={}\n  bundler (4.0.0) sha256=bad",
            "a".repeat(64)
        )),
    );
    let output = parse("Gemfile.lock", &invalid).unwrap();
    assert_eq!(output.metadata_integrity.len(), 1);
    assert_eq!(output.metadata_integrity[0].value.as_deref(), Some("bad"));

    let empty = gemfile(
        "4.0.0",
        Some(&format!(
            "  demo (1.2.3) sha256={}\n  bundler (4.0.0)",
            "a".repeat(64)
        )),
    );
    let output = parse("Gemfile.lock", &empty).unwrap();
    assert_eq!(output.metadata_integrity.len(), 1);
    assert_eq!(output.metadata_integrity[0].algorithm, None);
    assert_eq!(output.metadata_integrity[0].value, None);
}

#[test]
fn bundler_rejects_partial_sections_edges_and_old_checksums() {
    let unknown = "GEM\n  remote: https://rubygems.org/\n  specs:\n    demo (1.0.0)\nMYSTERY\n  value\nDEPENDENCIES\n  demo\nBUNDLED WITH\n  3.0.0\n";
    assert!(parse("Gemfile.lock", unknown).is_err());

    let unmatched_edge = "GEM\n  remote: https://rubygems.org/\n  specs:\n    demo (1.0.0)\n      missing (~> 1)\nDEPENDENCIES\n  demo\nBUNDLED WITH\n  3.0.0\n";
    assert!(parse("Gemfile.lock", unmatched_edge).is_err());

    let old_checksums = gemfile(
        "2.4.22",
        Some(&format!("  demo (1.2.3) sha256={}", "a".repeat(64))),
    );
    assert!(parse("Gemfile.lock", &old_checksums).is_err());
}

#[test]
fn bundler_preserves_duplicate_specs_and_mutable_git_revision() {
    let raw = "GIT\n  remote: https://github.com/vendor/demo.git\n  revision: main\n  specs:\n    demo (1.0.0)\n    demo (1.0.0)\nDEPENDENCIES\n  demo!\nBUNDLED WITH\n  3.0.0\n";
    let output = parse("Gemfile.lock", raw).unwrap();
    assert_eq!(output.records.len(), 2);
    assert_eq!(output.records[0].occurrence_index, 0);
    assert_eq!(output.records[1].occurrence_index, 1);
    assert!(output.records.iter().all(|record| {
        record.sources[0].kind == SourceKind::Git && record.sources[0].immutable_revision.is_none()
    }));
}

#[test]
fn composer_preserves_duplicates_groups_source_only_path_and_revisions() {
    let commit = "abcdef0123456789abcdef0123456789abcdef01";
    let raw = composer(
        vec![
            json!({
                "name": "vendor/duplicate",
                "version": "1.0.0",
                "source": {
                    "type": "git",
                    "url": "https://github.com/vendor/duplicate.git",
                    "reference": commit
                }
            }),
            json!({
                "name": "vendor/duplicate",
                "version": "1.0.0",
                "source": {
                    "type": "git",
                    "url": "https://github.com/vendor/duplicate.git",
                    "reference": "v1.0.0"
                }
            }),
            json!({
                "name": "vendor/local",
                "version": "dev-main",
                "source": {"type": "path", "url": "../local", "reference": null}
            }),
        ],
        vec![json!({
            "name": "vendor/dev",
            "version": "1.0.0"
        })],
    );
    let output = parse("composer.lock", &raw).unwrap();
    assert_eq!(output.records.len(), 4);
    let duplicates = output
        .records
        .iter()
        .filter(|record| record.raw_name.as_deref() == Some("vendor/duplicate"))
        .collect::<Vec<_>>();
    assert_eq!(duplicates.len(), 2);
    assert!(duplicates
        .iter()
        .any(|record| { record.sources[0].immutable_revision.as_deref() == Some(commit) }));
    assert!(duplicates
        .iter()
        .any(|record| record.sources[0].immutable_revision.is_none()));
    let local = output
        .records
        .iter()
        .find(|record| record.raw_name.as_deref() == Some("vendor/local"))
        .unwrap();
    assert_eq!(local.sources[0].kind, SourceKind::Path);
    assert_eq!(local.integrity_state, IntegrityState::UnavailableByFormat);
    let dev = output
        .records
        .iter()
        .find(|record| record.raw_name.as_deref() == Some("vendor/dev"))
        .unwrap();
    assert_eq!(dev.condition.as_deref(), Some("packages-dev"));
    assert_eq!(dev.sources[0].kind, SourceKind::UnavailableByFormat);
}

#[test]
fn composer_unknown_and_malformed_sections_fail_closed() {
    let cases = [
        r#"{"content-hash":"x","packages":[],"packages-dev":[],"future":[]}"#,
        r#"{"content-hash":"x","packages":[{"name":"a/b","version":"1","future":true}],"packages-dev":[]}"#,
        r#"{"content-hash":"x","packages":[{"name":"a/b","version":"1","dist":{"type":"zip","url":"https://repo.packagist.org/x","future":true}}],"packages-dev":[]}"#,
        r#"{"content-hash":"x","packages":[{"name":"a/b","version":"1","require":[]}],"packages-dev":[]}"#,
        r#"{"content-hash":"x","packages":[{"name":"a/b","version":"1","require":{"":"^1"}}],"packages-dev":[]}"#,
        r#"{"content-hash":"x","packages":[{"name":"a/b","version":"1","require":{"a/b":false}}],"packages-dev":[]}"#,
        r#"{"content-hash":"x","packages":[{"name":"a/b","version":"1","dist":{"type":"zip","url":42}}],"packages-dev":[]}"#,
        r#"{"content-hash":"x","packages":[{"name":"a/b","version":"1","dist":{"type":"future","url":"https://repo.packagist.org/x"}}],"packages-dev":[]}"#,
        r#"{"content-hash":"x","packages":[{"name":"a/b","version":"1","source":{"type":"svn","url":"https://example.test/x","reference":"1"}}],"packages-dev":[]}"#,
    ];
    for raw in cases {
        assert!(parse("composer.lock", raw).is_err(), "{raw}");
    }

    let duplicate = r#"{"content-hash":"x","packages":[],"packages":[],"packages-dev":[]}"#;
    assert!(matches!(
        parse("composer.lock", duplicate),
        Err(LockfileError::DuplicateKey { .. })
    ));
}

#[test]
fn composer_dist_mirrors_fail_before_policy() {
    let mirrors = [
        json!(["http://mirror.example.test/archive.zip"]),
        json!(["https://mirror.example.test/archive.zip"]),
        json!([]),
        json!("https://mirror.example.test/archive.zip"),
    ];
    for mirror_value in mirrors {
        let raw = composer(
            vec![json!({
                "name": "vendor/mirrored",
                "version": "1.0.0",
                "dist": {
                    "type": "zip",
                    "url": "https://repo.packagist.org/archive.zip",
                    "shasum": "a".repeat(40),
                    "mirrors": mirror_value
                },
                "source": {
                    "type": "git",
                    "url": "https://github.com/vendor/mirrored.git",
                    "reference": "0123456789abcdef0123456789abcdef01234567"
                }
            })],
            vec![],
        );
        assert!(parse("composer.lock", &raw).is_err());
    }
}

#[test]
fn composer_edge_sections_are_independently_counted_and_non_empty() {
    let all_edges = json!({
        "name": "vendor/all-edges",
        "version": "1.0.0",
        "require": {"vendor/require": "^1"},
        "require-dev": {"vendor/require-dev": "^1"},
        "conflict": {"vendor/conflict": "<1"},
        "provide": {"vendor/provide": "1"},
        "replace": {"vendor/replace": "1"},
        "suggest": {"vendor/suggest": "use it"}
    });
    let output = parse("composer.lock", &composer(vec![all_edges], vec![])).unwrap();
    assert_eq!(output.coverage.record_units, 1);
    assert_eq!(output.coverage.traversed_non_record_units, 6);
    assert_eq!(output.coverage.total_units, 7);
    assert_eq!(output.coverage.recognized_units, 7);

    for field in [
        "require",
        "require-dev",
        "conflict",
        "provide",
        "replace",
        "suggest",
    ] {
        let mut package = json!({
            "name": "vendor/empty-edge",
            "version": "1.0.0"
        });
        package
            .as_object_mut()
            .unwrap()
            .insert(field.to_string(), json!({"vendor/dependency": "  "}));
        assert!(
            parse("composer.lock", &composer(vec![package], vec![])).is_err(),
            "{field}"
        );
    }
}

#[test]
fn bundler_scalar_size_budget_allows_equality_and_rejects_plus_one() {
    let exact_remote = "x".repeat(MAX_SCALAR_BYTES);
    let exact = bundler_with_dependencies(&exact_remote, 0);
    parse_bundler_direct(&exact).unwrap_or_else(|error| panic!("exact scalar: {error}"));

    let over_remote = "x".repeat(MAX_SCALAR_BYTES + 1);
    let over = bundler_with_dependencies(&over_remote, 0);
    assert!(matches!(
        parse_bundler_direct(&over),
        Err(LockfileError::ScalarTooLarge { .. })
    ));
}

#[test]
fn bundler_scalar_count_budget_allows_equality_and_rejects_plus_one() {
    const BASE_SCALARS: usize = 10;
    let exact = bundler_with_dependencies("https://rubygems.org/", MAX_SCALAR_COUNT - BASE_SCALARS);
    let output = parse_bundler_direct(&exact).unwrap();
    assert_eq!(output.coverage.record_units, 1);
    assert_eq!(
        output.coverage.traversed_non_record_units,
        MAX_SCALAR_COUNT - BASE_SCALARS + 1
    );

    let over =
        bundler_with_dependencies("https://rubygems.org/", MAX_SCALAR_COUNT - BASE_SCALARS + 1);
    assert!(matches!(
        parse_bundler_direct(&over),
        Err(LockfileError::ScalarCountLimit { .. })
    ));
}

#[test]
fn composer_rejects_invalid_identity_without_partial_output() {
    let raw = composer(
        vec![json!({
            "name": "not-a-packagist-name",
            "version": "1.0.0",
            "dist": {"type": "zip", "url": "https://repo.packagist.org/x"}
        })],
        vec![],
    );
    assert!(matches!(
        parse("composer.lock", &raw),
        Err(LockfileError::InvalidModel { .. })
    ));
}

#[test]
fn parser_outputs_the_expected_closed_formats() {
    let bundler = parse("Gemfile.lock", &gemfile("3.0.0", None)).unwrap();
    assert_eq!(bundler.detected.format, LockfileFormat::Bundler);
    let composer = parse("composer.lock", &composer(vec![], vec![])).unwrap();
    assert_eq!(composer.detected.format, LockfileFormat::Composer);
}

fn bundler_with_dependencies(remote: &str, nested_dependencies: usize) -> String {
    let mut raw = format!("GEM\n  remote: {remote}\n  specs:\n    demo (1.0.0)\n");
    for _ in 0..nested_dependencies {
        raw.push_str("      demo\n");
    }
    raw.push_str("DEPENDENCIES\n  demo\nBUNDLED WITH\n  3.0.0\n");
    raw
}
