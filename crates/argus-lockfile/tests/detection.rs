use argus_core::{Ecosystem, PackageCoordinate};
use argus_lockfile::{
    detect_format, parse_lockfile, BoundedInput, Coverage, DetectedLockfile, DetectionRequest,
    FormatHint, FormatVersion, IntegrityEvidence, IntegrityState, LockfileError, LockfileFormat,
    NormalizedDependency, NormalizedSource, ParseOutput, SourceKind, MAX_SCALAR_BYTES,
    MAX_SCALAR_COUNT,
};

fn detect(basename: &str, raw: &str) -> Result<DetectedLockfile, LockfileError> {
    let input = BoundedInput::new(raw.as_bytes(), basename)?;
    detect_format(
        &input,
        DetectionRequest {
            basename: Some(basename),
            explicit_format: None,
        },
    )
}

fn detect_with_format(
    input: &BoundedInput<'_>,
    basename: Option<&str>,
    explicit_format: FormatHint,
) -> Result<DetectedLockfile, LockfileError> {
    detect_format(
        input,
        DetectionRequest {
            basename,
            explicit_format: Some(explicit_format),
        },
    )
}

#[test]
fn detect_matrix_accepts_the_closed_version_set() {
    let cases = [
        ("package-lock.json", r#"{"lockfileVersion":2,"packages":{}}"#, LockfileFormat::PackageLock, FormatVersion::PackageLock2),
        ("package-lock.json", r#"{"lockfileVersion":3,"packages":{}}"#, LockfileFormat::PackageLock, FormatVersion::PackageLock3),
        ("yarn.lock", "# yarn lockfile v1\n\"demo@^1\":\n  version \"1.0.0\"\n", LockfileFormat::YarnClassic, FormatVersion::YarnClassic1),
        ("yarn.lock", "# yarn lockfile v1\n\"demo@^1\", \"demo@~1\":\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/demo/-/demo-1.0.0.tgz\"\n", LockfileFormat::YarnClassic, FormatVersion::YarnClassic1),
        ("yarn.lock", "__metadata:\n  version: 4\n", LockfileFormat::YarnBerry, FormatVersion::YarnBerry4),
        ("yarn.lock", "__metadata:\n  version: 6\n", LockfileFormat::YarnBerry, FormatVersion::YarnBerry6),
        ("yarn.lock", "__metadata:\n  version: 8\n", LockfileFormat::YarnBerry, FormatVersion::YarnBerry8),
        ("pnpm-lock.yaml", "lockfileVersion: '5.4'\n", LockfileFormat::Pnpm, FormatVersion::Pnpm5_4),
        ("pnpm-lock.yaml", "lockfileVersion: '6.0'\n", LockfileFormat::Pnpm, FormatVersion::Pnpm6_0),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n", LockfileFormat::Pnpm, FormatVersion::Pnpm9_0),
        ("poetry.lock", "[[package]]\nname='demo'\nversion='1'\n[metadata]\nlock-version='1.1'\n", LockfileFormat::Poetry, FormatVersion::Poetry1_1),
        ("poetry.lock", "[[package]]\nname='demo'\nversion='1'\n[metadata]\nlock-version='2.0'\n", LockfileFormat::Poetry, FormatVersion::Poetry2_0),
        ("poetry.lock", "[[package]]\nname='demo'\nversion='1'\n[metadata]\nlock-version='2.1'\n", LockfileFormat::Poetry, FormatVersion::Poetry2_1),
        ("uv.lock", "version=1\n[[package]]\nname='demo'\nversion='1'\n", LockfileFormat::Uv, FormatVersion::Uv1),
        ("Cargo.lock", "version=3\n[[package]]\nname='demo'\nversion='1.0.0'\n", LockfileFormat::Cargo, FormatVersion::Cargo3),
        ("Cargo.lock", "version=4\n[[package]]\nname='demo'\nversion='1.0.0'\n", LockfileFormat::Cargo, FormatVersion::Cargo4),
        ("go.sum", "example.com/demo v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", LockfileFormat::GoSum, FormatVersion::GoSumGrammar1),
        ("Gemfile.lock", "GEM\n  specs:\nDEPENDENCIES\n  demo\nBUNDLED WITH\n   2.4.22\n", LockfileFormat::Bundler, FormatVersion::Bundler2),
        ("Gemfile.lock", "PATH\n  specs:\nDEPENDENCIES\n  demo\nBUNDLED WITH\n   3.1.0\n", LockfileFormat::Bundler, FormatVersion::Bundler3),
        ("Gemfile.lock", "GIT\n  revision: 0123456789012345678901234567890123456789\nDEPENDENCIES\n  demo\nBUNDLED WITH\n   4.0.0\n", LockfileFormat::Bundler, FormatVersion::Bundler4),
        ("composer.lock", r#"{"content-hash":"abc","packages":[],"packages-dev":[]}"#, LockfileFormat::Composer, FormatVersion::ComposerSchema1),
    ];

    for (basename, raw, expected_format, expected_version) in cases {
        let actual = detect(basename, raw).unwrap_or_else(|error| panic!("{basename}: {error}"));
        assert_eq!(actual.format, expected_format, "{basename}");
        assert_eq!(actual.version, expected_version, "{basename}");
        assert!(!actual.evidence.is_empty(), "{basename}");
    }
}

#[test]
fn supported_versions_reject_adjacent_or_malformed_versions() {
    let cases = [
        (
            "package-lock.json",
            r#"{"lockfileVersion":4,"packages":{}}"#,
        ),
        ("yarn.lock", "__metadata:\n  version: 9\n"),
        ("pnpm-lock.yaml", "lockfileVersion: '9.1'\n"),
        ("pnpm-lock.yaml", "lockfileVersion: 9\n"),
        (
            "poetry.lock",
            "[[package]]\nname='x'\n[metadata]\nlock-version='2.2'\n",
        ),
        ("uv.lock", "version=2\n[[package]]\nname='x'\n"),
        ("Cargo.lock", "version=5\n[[package]]\nname='x'\n"),
        ("Gemfile.lock", "GEM\nDEPENDENCIES\nBUNDLED WITH\n  5.0.0\n"),
    ];
    for (basename, raw) in cases {
        assert!(
            matches!(
                detect(basename, raw),
                Err(LockfileError::UnsupportedVersion { .. })
            ),
            "{basename}"
        );
    }
}

#[test]
fn missing_conflicting_and_ambiguous_detection_fail_closed() {
    let bytes = br#"{"lockfileVersion":3,"packages":{}}"#;
    let input = BoundedInput::new(bytes, "memory").unwrap();
    assert!(matches!(
        detect_format(&input, DetectionRequest::default()),
        Err(LockfileError::MissingBasename)
    ));

    let explicit = detect_format(
        &input,
        DetectionRequest {
            basename: None,
            explicit_format: Some(FormatHint::PackageLock),
        },
    )
    .unwrap();
    assert_eq!(explicit.format, LockfileFormat::PackageLock);

    assert!(matches!(
        detect("unknown.lock", "x"),
        Err(LockfileError::UnknownBasename { .. })
    ));
    assert!(matches!(
        detect("package-lock.json", "{}"),
        Err(LockfileError::SignatureMismatch { .. })
    ));

    let ambiguous = "# yarn lockfile v1\n__metadata:\n  version: 8\n";
    assert!(matches!(
        detect("yarn.lock", ambiguous),
        Err(LockfileError::AmbiguousFormat { .. })
    ));
    let quoted_ambiguous = "# yarn lockfile v1\n\"__metadata\": { version: 8 }\n";
    assert!(matches!(
        detect("yarn.lock", quoted_ambiguous),
        Err(LockfileError::AmbiguousFormat { .. })
    ));
    let nested_marker =
        "# yarn lockfile v1\n\"demo@^1\":\n  __metadata: not-a-root-marker\n  version \"1.0.0\"\n";
    assert_eq!(
        detect("yarn.lock", nested_marker).unwrap().format,
        LockfileFormat::YarnClassic
    );
}

#[test]
fn explicit_format_allows_nonstandard_utf8_basenames_but_not_known_conflicts() {
    let raw = br#"{"lockfileVersion":3,"packages":{}}"#;
    let input = BoundedInput::new(raw, "memory").unwrap();
    for basename in ["renamed.lock", "依赖.lock"] {
        let detected = detect_with_format(&input, Some(basename), FormatHint::PackageLock)
            .unwrap_or_else(|error| panic!("{basename}: {error}"));
        assert_eq!(detected.format, LockfileFormat::PackageLock, "{basename}");
        assert_eq!(detected.version, FormatVersion::PackageLock3, "{basename}");
    }
    assert!(matches!(
        detect_with_format(&input, Some("Cargo.lock"), FormatHint::PackageLock),
        Err(LockfileError::BasenameConflict { .. })
    ));

    let same_standard_name =
        detect_with_format(&input, Some("package-lock.json"), FormatHint::PackageLock).unwrap();
    assert_eq!(same_standard_name.format, LockfileFormat::PackageLock);

    let wrong_signature = BoundedInput::new(b"version=4\n[[package]]\n", "memory").unwrap();
    assert!(matches!(
        detect_with_format(
            &wrong_signature,
            Some("renamed.lock"),
            FormatHint::PackageLock
        ),
        Err(LockfileError::Parse { syntax: "JSON", .. })
    ));
    assert!(matches!(
        detect_format(
            &input,
            DetectionRequest {
                basename: Some("renamed.lock"),
                explicit_format: None,
            },
        ),
        Err(LockfileError::UnknownBasename { .. })
    ));
}

#[test]
fn duplicate_keys_are_rejected_before_signature_detection() {
    assert!(matches!(
        detect(
            "package-lock.json",
            r#"{"lockfileVersion":2,"lockfileVersion":3,"packages":{}}"#
        ),
        Err(LockfileError::DuplicateKey { syntax: "JSON", .. })
    ));
    assert!(matches!(
        detect(
            "Cargo.lock",
            "version=3\nversion=4\n[[package]]\nname='x'\n"
        ),
        Err(LockfileError::DuplicateKey { syntax: "TOML", .. })
    ));
    assert!(matches!(
        detect(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\nlockfileVersion: '9.0'\n"
        ),
        Err(LockfileError::DuplicateKey { syntax: "YAML", .. })
    ));
}

#[test]
fn bundler_checksums_version_gate_is_part_of_detection() {
    let raw = "GEM\n  specs:\nDEPENDENCIES\nCHECKSUMS\nBUNDLED WITH\n  2.4.22\n";
    assert!(matches!(
        detect("Gemfile.lock", raw),
        Err(LockfileError::SignatureMismatch { .. })
    ));

    let duplicate = "GEM\nDEPENDENCIES\nBUNDLED WITH\n  3.0.0\nBUNDLED WITH\n  3.0.0\n";
    assert!(matches!(
        detect("Gemfile.lock", duplicate),
        Err(LockfileError::SignatureMismatch { .. })
    ));
}

#[test]
fn custom_grammar_detection_enforces_scalar_size_equality_and_plus_one() {
    let classic_exact_token = format!("{}:", "a".repeat(MAX_SCALAR_BYTES - 1));
    let classic_exact = format!("# yarn lockfile v1\n{classic_exact_token}\n");
    assert!(detect("yarn.lock", &classic_exact).is_ok());
    let classic_over_token = format!("{}:", "a".repeat(MAX_SCALAR_BYTES));
    let classic_over = format!("# yarn lockfile v1\n{classic_over_token}\n");
    assert!(matches!(
        detect("yarn.lock", &classic_over),
        Err(LockfileError::ScalarTooLarge { .. })
    ));

    let bundler_exact_token = "a".repeat(MAX_SCALAR_BYTES);
    let bundler_exact =
        format!("GEM\n  {bundler_exact_token}\nDEPENDENCIES\nBUNDLED WITH\n  2.5.0\n");
    assert!(detect("Gemfile.lock", &bundler_exact).is_ok());
    let bundler_over_token = "a".repeat(MAX_SCALAR_BYTES + 1);
    let bundler_over =
        format!("GEM\n  {bundler_over_token}\nDEPENDENCIES\nBUNDLED WITH\n  2.5.0\n");
    assert!(matches!(
        detect("Gemfile.lock", &bundler_over),
        Err(LockfileError::ScalarTooLarge { .. })
    ));

    let go_exact_module = "a".repeat(MAX_SCALAR_BYTES);
    let go_exact =
        format!("{go_exact_module} v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    assert!(detect("go.sum", &go_exact).is_ok());
    let go_over_module = "a".repeat(MAX_SCALAR_BYTES + 1);
    let go_over =
        format!("{go_over_module} v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    assert!(matches!(
        detect("go.sum", &go_over),
        Err(LockfileError::ScalarTooLarge { .. })
    ));
}

#[test]
fn classic_detection_enforces_scalar_count_equality_and_plus_one() {
    let records = (MAX_SCALAR_COUNT - 1) / 3;
    assert_eq!(records * 3 + 1, MAX_SCALAR_COUNT);
    let mut classic = String::from("# yarn lockfile v1\n");
    for index in 0..records {
        classic.push_str(&format!(
            "\"package-{index}@1\":\n  version \"1\"\n  resolved \"registry\"\n"
        ));
    }
    assert!(detect("yarn.lock", &classic).is_ok());
    classic.push_str("  integrity \"sha512-AA==\"\n");
    assert!(matches!(
        detect("yarn.lock", &classic),
        Err(LockfileError::ScalarCountLimit { .. })
    ));
}

#[test]
fn go_sum_rejects_non_semver_versions() {
    let raw = "example.com/demo branch-name h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    assert!(matches!(
        detect("go.sum", raw),
        Err(LockfileError::SignatureMismatch { .. })
    ));
}

fn record(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    locator: &str,
    occurrence_index: u64,
) -> NormalizedDependency {
    NormalizedDependency {
        coordinate: Some(PackageCoordinate::new(ecosystem, name, version).unwrap()),
        format: LockfileFormat::PackageLock,
        sources: vec![NormalizedSource {
            kind: SourceKind::Registry,
            location: Some("https://registry.example.test/archive".into()),
            immutable_revision: None,
            locator: format!("{locator}.source"),
        }],
        integrity_state: IntegrityState::RequiredPresent,
        integrity: vec![IntegrityEvidence {
            algorithm: Some("sha512".into()),
            value: Some("fixture".into()),
            locator: locator.into(),
        }],
        raw_name: Some(name.into()),
        raw_version: Some(version.into()),
        locator: locator.into(),
        condition: None,
        platform: None,
        occurrence_index,
    }
}

#[test]
fn normalized_records_sort_stably_without_deduplicating_occurrences() {
    let first = record(Ecosystem::Npm, "demo", "2.0.0", "packages/demo", 2);
    let duplicate = record(Ecosystem::Npm, "demo", "2.0.0", "packages/demo", 1);
    let earlier = record(Ecosystem::Npm, "alpha", "1.0.0", "packages/alpha", 0);
    let detected = DetectedLockfile {
        format: LockfileFormat::PackageLock,
        version: FormatVersion::PackageLock3,
        evidence: vec!["fixture".into()],
    };
    let mut output = ParseOutput {
        detected,
        records: vec![first, earlier.clone(), duplicate.clone()],
        coverage: Coverage {
            total_units: 3,
            recognized_units: 3,
            unsupported_units: 0,
            record_units: 3,
            traversed_non_record_units: 0,
        },
        metadata_integrity: Vec::new(),
    };
    output.validate_and_sort().unwrap();
    assert_eq!(output.records.len(), 3);
    assert_eq!(output.records[0], earlier);
    assert_eq!(output.records[1], duplicate);
    assert_eq!(output.records[2].occurrence_index, 2);
}

#[test]
fn normalized_records_validate_coordinate_and_coverage_invariants() {
    let coverage = Coverage {
        total_units: 2,
        recognized_units: 1,
        unsupported_units: 1,
        record_units: 1,
        traversed_non_record_units: 1,
    };
    assert!(matches!(
        coverage.validate(),
        Err(LockfileError::PartialAnalysis { .. })
    ));

    let invalid_missing_coordinate = NormalizedDependency {
        coordinate: None,
        format: LockfileFormat::PackageLock,
        sources: vec![NormalizedSource {
            kind: SourceKind::Registry,
            location: Some("https://registry.example.test/demo".into()),
            immutable_revision: None,
            locator: "packages/demo.source".into(),
        }],
        integrity_state: IntegrityState::RequiredMissing,
        integrity: Vec::new(),
        raw_name: None,
        raw_version: None,
        locator: "packages/demo".into(),
        condition: Some("os=linux".into()),
        platform: Some("x86_64".into()),
        occurrence_index: 0,
    };
    let mut output = ParseOutput {
        detected: DetectedLockfile {
            format: LockfileFormat::PackageLock,
            version: FormatVersion::PackageLock3,
            evidence: vec!["fixture".into()],
        },
        records: vec![invalid_missing_coordinate],
        coverage: Coverage {
            total_units: 1,
            recognized_units: 1,
            unsupported_units: 0,
            record_units: 1,
            traversed_non_record_units: 0,
        },
        metadata_integrity: Vec::new(),
    };
    assert!(matches!(
        output.validate_and_sort(),
        Err(LockfileError::InvalidModel { .. })
    ));

    let local = NormalizedDependency {
        coordinate: None,
        format: LockfileFormat::PackageLock,
        sources: vec![NormalizedSource {
            kind: SourceKind::Workspace,
            location: Some("workspace:packages/demo".into()),
            immutable_revision: None,
            locator: "packages/demo.source".into(),
        }],
        integrity_state: IntegrityState::UnavailableByFormat,
        integrity: Vec::new(),
        raw_name: None,
        raw_version: None,
        locator: "packages/demo".into(),
        condition: None,
        platform: None,
        occurrence_index: 0,
    };
    let mut mixed = local.clone();
    mixed.sources.push(NormalizedSource {
        kind: SourceKind::Registry,
        location: Some("https://registry.example.test/demo".into()),
        immutable_revision: None,
        locator: "packages/demo.registry".into(),
    });
    let detected = DetectedLockfile {
        format: LockfileFormat::PackageLock,
        version: FormatVersion::PackageLock3,
        evidence: vec!["fixture".into()],
    };
    let coverage = Coverage {
        total_units: 1,
        recognized_units: 1,
        unsupported_units: 0,
        record_units: 1,
        traversed_non_record_units: 0,
    };
    let mut local_output = ParseOutput {
        detected: detected.clone(),
        records: vec![local],
        coverage,
        metadata_integrity: Vec::new(),
    };
    local_output.validate_and_sort().unwrap();
    let mut complete_local_identity = local_output.records[0].clone();
    complete_local_identity.raw_name = Some("demo".into());
    complete_local_identity.raw_version = Some("1.0.0".into());
    let mut complete_local_output = ParseOutput {
        detected: detected.clone(),
        records: vec![complete_local_identity],
        coverage,
        metadata_integrity: Vec::new(),
    };
    assert!(matches!(
        complete_local_output.validate_and_sort(),
        Err(LockfileError::InvalidModel { .. })
    ));
    let mut mixed_output = ParseOutput {
        detected,
        records: vec![mixed],
        coverage,
        metadata_integrity: Vec::new(),
    };
    assert!(matches!(
        mixed_output.validate_and_sort(),
        Err(LockfileError::InvalidModel { .. })
    ));
}

#[test]
fn normalized_records_preserve_and_sort_multiple_sources() {
    let mut dependency = record(
        Ecosystem::Packagist,
        "vendor/demo",
        "1.0.0",
        "packages[0]",
        0,
    );
    dependency.format = LockfileFormat::Composer;
    dependency.sources = vec![
        NormalizedSource {
            kind: SourceKind::Git,
            location: Some("https://github.com/vendor/demo.git".into()),
            immutable_revision: Some("0123456789012345678901234567890123456789".into()),
            locator: "packages[0].source.url".into(),
        },
        NormalizedSource {
            kind: SourceKind::Url,
            location: Some("https://api.github.com/vendor/demo.zip".into()),
            immutable_revision: None,
            locator: "packages[0].dist.url".into(),
        },
    ];
    let mut output = ParseOutput {
        detected: DetectedLockfile {
            format: LockfileFormat::Composer,
            version: FormatVersion::ComposerSchema1,
            evidence: vec!["fixture".into()],
        },
        records: vec![dependency],
        coverage: Coverage {
            total_units: 1,
            recognized_units: 1,
            unsupported_units: 0,
            record_units: 1,
            traversed_non_record_units: 0,
        },
        metadata_integrity: Vec::new(),
    };
    output.validate_and_sort().unwrap();
    assert_eq!(output.records[0].sources.len(), 2);
    assert_eq!(output.records[0].sources[0].kind, SourceKind::Url);
    assert_eq!(output.records[0].sources[1].kind, SourceKind::Git);
}

#[test]
fn normalized_records_preserve_composer_dist_and_source() {
    let raw = br#"{
      "content-hash":"fixture",
      "packages":[{
        "name":"vendor/demo",
        "version":"1.0.0",
        "dist":{
          "type":"zip",
          "url":"https://api.github.com/vendor/demo.zip",
          "reference":"0123456789012345678901234567890123456789",
          "shasum":""
        },
        "source":{
          "type":"git",
          "url":"https://github.com/vendor/demo.git",
          "reference":"0123456789012345678901234567890123456789"
        }
      }],
      "packages-dev":[]
    }"#;
    let input = BoundedInput::new(raw, "composer.lock").unwrap();
    let output = parse_lockfile(
        &input,
        DetectionRequest {
            basename: Some("composer.lock"),
            explicit_format: None,
        },
    )
    .unwrap();
    assert_eq!(output.records.len(), 1);
    assert_eq!(output.records[0].sources.len(), 2);
    assert_eq!(output.records[0].sources[0].locator, "packages[0].dist.url");
    assert_eq!(
        output.records[0].sources[1].locator,
        "packages[0].source.url"
    );
    assert_eq!(
        output.records[0].sources[1].immutable_revision.as_deref(),
        Some("0123456789012345678901234567890123456789")
    );
}

fn output_with(record: NormalizedDependency) -> ParseOutput {
    ParseOutput {
        detected: DetectedLockfile {
            format: record.format,
            version: FormatVersion::PackageLock3,
            evidence: vec!["model invariant fixture".into()],
        },
        records: vec![record],
        coverage: Coverage {
            total_units: 1,
            recognized_units: 1,
            unsupported_units: 0,
            record_units: 1,
            traversed_non_record_units: 0,
        },
        metadata_integrity: Vec::new(),
    }
}

fn assert_invalid_model(record: NormalizedDependency) {
    assert!(matches!(
        output_with(record).validate_and_sort(),
        Err(LockfileError::InvalidModel { .. })
    ));
}

#[test]
fn normalized_source_and_output_validation_fail_closed_matrix() {
    let source_cases = [
        NormalizedSource {
            kind: SourceKind::Registry,
            location: Some("https://registry.example.test".into()),
            immutable_revision: None,
            locator: String::new(),
        },
        NormalizedSource {
            kind: SourceKind::UnavailableByFormat,
            location: Some("unexpected".into()),
            immutable_revision: None,
            locator: "source".into(),
        },
        NormalizedSource {
            kind: SourceKind::Registry,
            location: None,
            immutable_revision: None,
            locator: "source".into(),
        },
        NormalizedSource {
            kind: SourceKind::Registry,
            location: Some("https://registry.example.test".into()),
            immutable_revision: Some("0".repeat(40)),
            locator: "source".into(),
        },
        NormalizedSource {
            kind: SourceKind::Git,
            location: Some("https://github.com/example/demo".into()),
            immutable_revision: Some("short".into()),
            locator: "source".into(),
        },
    ];
    for source in source_cases {
        assert!(matches!(
            source.validate(),
            Err(LockfileError::InvalidModel { .. })
        ));
    }

    let valid = record(Ecosystem::Npm, "demo", "1.0.0", "packages/demo", 0);
    let mut wrong_count = output_with(valid.clone());
    wrong_count.coverage.record_units = 2;
    wrong_count.coverage.total_units = 2;
    wrong_count.coverage.recognized_units = 2;
    assert!(matches!(
        wrong_count.validate_and_sort(),
        Err(LockfileError::CoverageMismatch { .. })
    ));

    let mut no_sources = valid.clone();
    no_sources.sources.clear();
    assert_invalid_model(no_sources);

    let mut invalid_coordinate = valid.clone();
    invalid_coordinate
        .coordinate
        .as_mut()
        .expect("fixture coordinate")
        .purl = "pkg:npm/tampered@1.0.0".into();
    assert_invalid_model(invalid_coordinate);

    let mut raw_mismatch = valid.clone();
    raw_mismatch.raw_name = Some("other".into());
    assert_invalid_model(raw_mismatch);

    let mut empty_locator = valid.clone();
    empty_locator.locator.clear();
    assert_invalid_model(empty_locator);

    let mut missing_evidence = valid.clone();
    missing_evidence.integrity.clear();
    assert_invalid_model(missing_evidence);

    let mut empty_evidence_locator = valid;
    empty_evidence_locator.integrity[0].locator.clear();
    assert_invalid_model(empty_evidence_locator);
}

#[test]
fn coverage_overflow_and_accounting_mismatch_are_typed() {
    let overflow = Coverage {
        total_units: usize::MAX,
        recognized_units: usize::MAX,
        unsupported_units: 0,
        record_units: usize::MAX,
        traversed_non_record_units: 1,
    };
    assert!(matches!(
        overflow.validate(),
        Err(LockfileError::CoverageMismatch { .. })
    ));
    let mismatch = Coverage {
        total_units: 3,
        recognized_units: 3,
        unsupported_units: 0,
        record_units: 1,
        traversed_non_record_units: 1,
    };
    assert!(matches!(
        mismatch.validate(),
        Err(LockfileError::CoverageMismatch { .. })
    ));
}

#[test]
fn lockfile_error_display_keeps_typed_operational_context() {
    macro_rules! bounded_error {
        ($variant:ident, $actual:expr, $maximum:expr) => {
            LockfileError::$variant {
                actual: $actual,
                maximum: $maximum,
            }
        };
    }

    let cases = vec![
        (bounded_error!(InputTooLarge, 2, 1), "input is 2 bytes"),
        (
            LockfileError::InvalidUtf8 {
                detail: "bad".into(),
            },
            "not UTF-8",
        ),
        (bounded_error!(NestingLimit, 65, 64), "nesting depth 65"),
        (bounded_error!(ScalarTooLarge, 2, 1), "scalar is 2 bytes"),
        (bounded_error!(ScalarCountLimit, 2, 1), "scalar count 2"),
        (bounded_error!(RecordLimit, 2, 1), "record count 2"),
        (
            bounded_error!(CanonicalOutputLimit, 2, 1),
            "canonical finding",
        ),
        (
            LockfileError::DuplicateKey {
                syntax: "TOML",
                key: "x".into(),
            },
            "duplicate TOML",
        ),
        (
            LockfileError::UnsupportedYamlFeature { feature: "alias" },
            "unsupported YAML",
        ),
        (
            LockfileError::Parse {
                syntax: "TOML",
                detail: "bad".into(),
            },
            "parse TOML",
        ),
        (LockfileError::MissingBasename, "basename is required"),
        (
            LockfileError::UnknownBasename {
                basename: "x.lock".into(),
            },
            "unknown lockfile",
        ),
        (
            LockfileError::BasenameConflict {
                basename: "x".into(),
                expected: "y".into(),
            },
            "conflicts",
        ),
        (
            LockfileError::SignatureMismatch {
                format: "uv".into(),
                detail: "bad".into(),
            },
            "signature mismatch",
        ),
        (
            LockfileError::AmbiguousFormat {
                evidence: vec!["a".into(), "b".into()],
            },
            "a; b",
        ),
        (
            LockfileError::UnsupportedVersion {
                format: "uv".into(),
                version: "2".into(),
            },
            "unsupported uv",
        ),
        (
            LockfileError::ParserUnavailable {
                format: LockfileFormat::Uv,
            },
            "Uv parser",
        ),
        (
            LockfileError::PartialAnalysis {
                total_units: 2,
                recognized_units: 1,
                unsupported_units: 1,
            },
            "partial analysis",
        ),
        (
            LockfileError::CoverageMismatch {
                detail: "bad".into(),
            },
            "coverage accounting",
        ),
        (
            LockfileError::InvalidModel {
                detail: "bad".into(),
            },
            "invalid normalized",
        ),
    ];
    for (error, expected) in cases {
        assert!(error.to_string().contains(expected), "{error}");
    }
}
