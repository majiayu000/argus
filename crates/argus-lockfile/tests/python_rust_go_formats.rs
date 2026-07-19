use argus_lockfile::{
    parse_lockfile, BoundedInput, DetectedLockfile, DetectionRequest, FormatVersion,
    IntegrityState, LockfileError, LockfileFormat, LockfileParser, ParseOutput, SourceKind,
    MAX_RECORDS, MAX_SCALAR_BYTES,
};

const SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA1: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const H1: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn parse_fixture(basename: &str, raw: &str) -> Result<ParseOutput, LockfileError> {
    let input = BoundedInput::new(raw.as_bytes(), basename)?;
    parse_lockfile(
        &input,
        DetectionRequest {
            basename: Some(basename),
            explicit_format: None,
        },
    )
}

fn poetry_fixture(version: &str, files: &str, source: &str) -> String {
    let package_files = if version == "1.1" {
        String::new()
    } else {
        format!("files = {files}\n")
    };
    let legacy_files = if version == "1.1" {
        format!("\n[metadata.files]\ndemo = {files}\n")
    } else {
        String::new()
    };
    format!(
        "[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n{package_files}{source}\
         dependencies = {{ child = {{ version = \"^1\", markers = \"python_version >= '3.9'\" }} }}\n\
         extras = {{ speed = [\"child\"] }}\n\
         marker = \"sys_platform == 'linux'\"\nplatform = \"linux\"\n\
         [metadata]\nlock-version = \"{version}\"\npython-versions = \">=3.9\"\n\
         content-hash = \"fixture\"{legacy_files}"
    )
}

fn uv_fixture(source: &str, distributions: &str) -> String {
    format!(
        "version = 1\nrevision = 3\nrequires-python = \">=3.9\"\n\
         resolution-markers = [\"python_version >= '3.9'\"]\n\
         [[package]]\nname = \"uv-demo\"\nversion = \"2.0.0\"\nsource = {source}\n\
         dependencies = [{{ name = \"child\", marker = \"sys_platform == 'linux'\" }}]\n\
         optional-dependencies = {{ speed = [{{ name = \"turbo\", marker = \"extra == 'speed'\" }}] }}\n\
         {distributions}"
    )
}

fn cargo_fixture(version: u8, packages: &str) -> String {
    format!("version = {version}\n{packages}")
}

#[test]
fn python_rust_go_format_matrix() {
    let files = format!("[{{ file = \"demo.whl\", hash = \"sha256:{SHA256}\" }}]");
    for version in ["1.1", "2.0", "2.1"] {
        let output = parse_fixture("poetry.lock", &poetry_fixture(version, &files, ""))
            .unwrap_or_else(|error| panic!("Poetry {version}: {error}"));
        assert_eq!(output.detected.format, LockfileFormat::Poetry);
        assert_eq!(output.records.len(), 1);
        assert_eq!(output.coverage.record_units, 1);
        assert_eq!(output.coverage.traversed_non_record_units, 3);
        assert_eq!(
            output.records[0].integrity_state,
            IntegrityState::RequiredPresent
        );
        assert_eq!(
            output.records[0].condition.as_deref(),
            Some("marker=sys_platform == 'linux'")
        );
        assert_eq!(output.records[0].platform.as_deref(), Some("linux"));
    }

    let uv = uv_fixture(
        "{ registry = \"https://pypi.org/simple\" }",
        &format!(
            "sdist = {{ url = \"https://files.pythonhosted.org/uv-demo.tar.gz\", hash = \"sha256:{SHA256}\", size = 42 }}\n\
             wheels = [{{ url = \"https://files.pythonhosted.org/uv_demo-2.0.0-py3-none-manylinux.whl\", hash = \"sha256:{SHA256}\", size = 43 }}]\n"
        ),
    );
    let output = parse_fixture("uv.lock", &uv).expect("uv 1 parses");
    assert_eq!(output.records.len(), 1);
    assert_eq!(output.records[0].sources.len(), 3);
    assert_eq!(output.coverage.traversed_non_record_units, 4);
    assert!(output.records[0]
        .condition
        .as_deref()
        .is_some_and(|value| value.contains("extra == 'speed'")));
    assert_eq!(output.records[0].platform.as_deref(), Some("manylinux"));

    for version in [3, 4] {
        let raw = cargo_fixture(
            version,
            &format!(
                "[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{SHA256}\"\ndependencies = [\"child 1.0.0\"]\n\
                 [[package]]\nname = \"child\"\nversion = \"1.0.0\"\n"
            ),
        );
        let output = parse_fixture("Cargo.lock", &raw)
            .unwrap_or_else(|error| panic!("Cargo {version}: {error}"));
        assert_eq!(output.records.len(), 2);
        assert_eq!(output.coverage.record_units, 2);
        assert_eq!(output.coverage.traversed_non_record_units, 1);
        assert!(output
            .records
            .iter()
            .any(|record| record.integrity_state == IntegrityState::RequiredPresent));
    }

    let go = format!("example.com/demo v1.2.3 h1:{H1}\nexample.com/demo v1.2.3/go.mod h1:{H1}");
    let output = parse_fixture("go.sum", &go).expect("go.sum module and go.mod parse");
    assert_eq!(output.records.len(), 2);
    assert_eq!(
        output
            .records
            .iter()
            .filter(|record| record.condition.as_deref() == Some("go.mod"))
            .count(),
        1
    );
    assert!(output.records.iter().all(|record| {
        record.sources.len() == 1 && record.sources[0].kind == SourceKind::UnavailableByFormat
    }));

    for (basename, raw) in [
        (
            "poetry.lock",
            "[[package]]\nname='x'\nversion='1'\n[metadata]\nlock-version='2.2'\n",
        ),
        ("uv.lock", "version=2\n[[package]]\nname='x'\nversion='1'\n"),
        (
            "Cargo.lock",
            "version=5\n[[package]]\nname='x'\nversion='1'\n",
        ),
    ] {
        assert!(matches!(
            parse_fixture(basename, raw),
            Err(LockfileError::UnsupportedVersion { .. })
        ));
    }
}

#[test]
fn python_rust_go_integrity_matrix() {
    let combinations = [
        (
            format!(
                "[{{file=\"ok.whl\",hash=\"sha256:{SHA256}\"}},\
                 {{file=\"bad.whl\",hash=\"sha256:abcd\"}}]"
            ),
            IntegrityState::Invalid,
            Some("sha256"),
        ),
        (
            format!("[{{file=\"ok.whl\",hash=\"sha256:{SHA256}\"}},{{file=\"missing.whl\"}}]"),
            IntegrityState::RequiredMissing,
            None,
        ),
        (
            format!(
                "[{{file=\"ok.whl\",hash=\"sha256:{SHA256}\"}},\
                 {{file=\"weak.whl\",hash=\"sha1:{SHA1}\"}}]"
            ),
            IntegrityState::RequiredPresent,
            Some("sha1"),
        ),
    ];
    for (files, expected, sibling_algorithm) in combinations {
        let output = parse_fixture("poetry.lock", &poetry_fixture("2.1", &files, ""))
            .expect("Poetry sibling artifacts parse");
        let record = &output.records[0];
        assert_eq!(record.integrity_state, expected);
        assert_eq!(record.integrity.len(), 2);
        assert_eq!(record.integrity[1].algorithm.as_deref(), sibling_algorithm);
        assert!(record.integrity[0].locator.contains("ok.whl"));
        assert!(record.integrity[1]
            .locator
            .contains(if sibling_algorithm == Some("sha1") {
                "weak.whl"
            } else if sibling_algorithm.is_none() {
                "missing.whl"
            } else {
                "bad.whl"
            }));
    }

    let uv_cases = [
        (
            format!(
                "wheels = [{{ url=\"https://files.pythonhosted.org/a.whl\", hash=\"sha256:{SHA256}\" }}]"
            ),
            IntegrityState::RequiredPresent,
        ),
        (
            "wheels = [{ url=\"https://files.pythonhosted.org/a.whl\" }]".to_string(),
            IntegrityState::RequiredMissing,
        ),
        (
            "wheels = [{ url=\"https://files.pythonhosted.org/a.whl\", hash=\"sha256:abcd\" }]".to_string(),
            IntegrityState::Invalid,
        ),
    ];
    for (distributions, expected) in uv_cases {
        let raw = uv_fixture("{ registry = \"https://pypi.org/simple\" }", &distributions);
        let output = parse_fixture("uv.lock", &raw).expect("uv integrity fixture parses");
        assert_eq!(output.records[0].integrity_state, expected);
        assert_eq!(output.records[0].integrity.len(), 1);
    }
    for source in [
        "{ editable = \".\" }",
        "{ path = \"../demo\" }",
        "{ virtual = \".\" }",
    ] {
        let output =
            parse_fixture("uv.lock", &uv_fixture(source, "")).expect("uv local source parses");
        assert_eq!(
            output.records[0].integrity_state,
            IntegrityState::UnavailableByFormat
        );
    }

    let cargo_cases = [
        (
            format!("source=\"registry+https://index.crates.io\"\nchecksum=\"{SHA256}\"\n"),
            IntegrityState::RequiredPresent,
        ),
        (
            "source=\"registry+https://index.crates.io\"\n".to_string(),
            IntegrityState::RequiredMissing,
        ),
        (
            "source=\"registry+https://index.crates.io\"\nchecksum=\"ABC\"\n".to_string(),
            IntegrityState::Invalid,
        ),
        ("".to_string(), IntegrityState::UnavailableByFormat),
    ];
    for (fields, expected) in cargo_cases {
        let raw = cargo_fixture(
            4,
            &format!("[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\n{fields}"),
        );
        let output = parse_fixture("Cargo.lock", &raw).expect("Cargo integrity fixture parses");
        assert_eq!(output.records[0].integrity_state, expected);
    }
}

#[test]
fn vcs_sources_distinguish_full_commits_from_mutable_refs() {
    for (reference, immutable) in [(COMMIT, true), ("main", false)] {
        let poetry_source = format!(
            "source = {{ type=\"git\", url=\"https://github.com/org/repo\", reference=\"{reference}\" }}\n"
        );
        let poetry = parse_fixture("poetry.lock", &poetry_fixture("2.1", "[]", &poetry_source))
            .expect("Poetry git parses");
        assert_eq!(
            poetry.records[0].sources[0].immutable_revision.is_some(),
            immutable
        );
        assert_eq!(
            poetry.records[0].integrity_state,
            IntegrityState::UnavailableByFormat
        );

        let uv_source =
            format!("{{ git = \"https://github.com/org/repo?rev={reference}#{reference}\" }}");
        let uv = parse_fixture("uv.lock", &uv_fixture(&uv_source, "")).expect("uv git parses");
        assert_eq!(
            uv.records[0].sources[0].immutable_revision.is_some(),
            immutable
        );

        let cargo_source =
            format!("git+https://github.com/org/repo?branch={reference}#{reference}");
        let cargo = parse_fixture(
            "Cargo.lock",
            &cargo_fixture(
                4,
                &format!(
                    "[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\nsource=\"{cargo_source}\"\n"
                ),
            ),
        )
        .expect("Cargo git parses");
        assert_eq!(
            cargo.records[0].sources[0].immutable_revision.is_some(),
            immutable
        );
    }
}

#[test]
fn duplicate_records_are_preserved_and_sorted_deterministically() {
    let package = format!(
        "[[package]]\nname=\"demo\"\nversion=\"1.0.0\"\n\
         source=\"registry+https://index.crates.io\"\nchecksum=\"{SHA256}\"\n"
    );
    let output = parse_fixture(
        "Cargo.lock",
        &cargo_fixture(4, &format!("{package}{package}")),
    )
    .expect("duplicate Cargo records parse");
    assert_eq!(output.records.len(), 2);
    assert_eq!(output.records[0].occurrence_index, 0);
    assert_eq!(output.records[1].occurrence_index, 1);
}

#[test]
fn unknown_sections_edges_and_partial_records_fail_closed() {
    let cases = [
        (
            "poetry.lock",
            "[[package]]\nname='demo'\nversion='1'\nunknown=true\n\
             [metadata]\nlock-version='2.1'\n",
        ),
        (
            "poetry.lock",
            "[[package]]\nname='demo'\nversion='1'\n\
             dependencies={child={version='1', mystery=true}}\n\
             [metadata]\nlock-version='2.1'\n",
        ),
        (
            "uv.lock",
            "version=1\n[[package]]\nname='demo'\nversion='1'\n\
             source={registry='https://pypi.org/simple'}\n\
             wheels=[{url='https://files.pythonhosted.org/a.whl',hash='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',mystery=true}]\n",
        ),
        (
            "uv.lock",
            "version=1\n[[package]]\nname='demo'\nversion='1'\n\
             source={registry='https://pypi.org/simple'}\n\
             dependencies=[{name='child',mystery=true}]\n",
        ),
        (
            "Cargo.lock",
            "version=4\n[[package]]\nname='demo'\nversion='1'\nmystery=true\n",
        ),
    ];
    for (basename, raw) in cases {
        assert!(
            matches!(
                parse_fixture(basename, raw),
                Err(LockfileError::PartialAnalysis {
                    unsupported_units,
                    ..
                }) if unsupported_units > 0
            ),
            "{basename}: {raw}"
        );
    }
    assert!(parse_fixture(
        "Cargo.lock",
        "version=4\n[[package]]\nname='demo'\nversion='1'\ndependencies=['child (broken']\n",
    )
    .is_err());
}

#[test]
fn legacy_poetry_files_must_associate_exactly_once() {
    let unmatched = format!(
        "[[package]]\nname='demo'\nversion='1'\n\
         [metadata]\nlock-version='1.1'\n\
         [metadata.files]\nother=[{{file='other.whl',hash='sha256:{SHA256}'}}]\n"
    );
    assert!(matches!(
        parse_fixture("poetry.lock", &unmatched),
        Err(LockfileError::PartialAnalysis { .. })
    ));

    let ambiguous = format!(
        "[[package]]\nname='demo'\nversion='1'\n\
         [[package]]\nname='demo'\nversion='2'\n\
         [metadata]\nlock-version='1.1'\n\
         [metadata.files]\ndemo=[{{file='demo.whl',hash='sha256:{SHA256}'}}]\n"
    );
    assert!(matches!(
        parse_fixture("poetry.lock", &ambiguous),
        Err(LockfileError::PartialAnalysis { .. })
    ));
}

#[test]
fn malformed_integrity_and_go_grammar_fail_before_a_report_exists() {
    for raw in [
        "example.com/demo v1.0.0 h1:AAAA".to_string(),
        format!("example.com/demo v1.0.0 sha256:{SHA256}"),
        format!("example.com/demo branch h1:{H1}"),
        format!("example.com/demo v1.0.0 h1:{H1}\n"),
    ] {
        let result = parse_fixture("go.sum", &raw);
        if raw.ends_with('\n') {
            assert!(
                result.is_ok(),
                "a single trailing newline is not a blank line"
            );
        } else {
            assert!(result.is_err(), "{raw}");
        }
    }
}

#[test]
fn typed_hashes_and_explicit_uv_sources_fail_closed() {
    let poetry_non_string = "[[package]]\nname='demo'\nversion='1'\n\
        files=[{file='demo.whl',hash=42}]\n\
        [metadata]\nlock-version='2.1'\n";
    assert!(matches!(
        parse_fixture("poetry.lock", poetry_non_string),
        Err(LockfileError::Parse { .. } | LockfileError::InvalidModel { .. })
    ));

    let uv_non_string = "version=1\n[[package]]\nname='demo'\nversion='1'\n\
        source={registry='https://pypi.org/simple'}\n\
        wheels=[{url='https://files.pythonhosted.org/demo.whl',hash=42}]\n";
    assert!(matches!(
        parse_fixture("uv.lock", uv_non_string),
        Err(LockfileError::Parse { .. } | LockfileError::InvalidModel { .. })
    ));

    let uv_missing_source = "version=1\n[[package]]\nname='demo'\nversion='1'\n";
    assert!(matches!(
        parse_fixture("uv.lock", uv_missing_source),
        Err(LockfileError::Parse { .. } | LockfileError::InvalidModel { .. })
    ));

    let poetry_empty_requirement = format!(
        "[[package]]\nname='demo'\nversion='1'\n\
         files=[{{file='demo.whl',hash='sha256:{SHA256}'}}]\n\
         dependencies={{child=''}}\n\
         [metadata]\nlock-version='2.1'\n"
    );
    assert!(matches!(
        parse_fixture("poetry.lock", &poetry_empty_requirement),
        Err(LockfileError::Parse { .. } | LockfileError::InvalidModel { .. })
    ));

    let poetry_empty_table = format!(
        "[[package]]\nname='demo'\nversion='1'\n\
         files=[{{file='demo.whl',hash='sha256:{SHA256}'}}]\n\
         dependencies={{child={{optional=true}}}}\n\
         [metadata]\nlock-version='2.1'\n"
    );
    assert!(matches!(
        parse_fixture("poetry.lock", &poetry_empty_table),
        Err(LockfileError::Parse { .. } | LockfileError::InvalidModel { .. })
    ));

    for (basename, raw) in [
        (
            "poetry.lock",
            "[[package]]\nname='demo'\nversion='1'\n\
             files=[{file='demo.whl',hash='blake3:abcd'}]\n\
             [metadata]\nlock-version='2.1'\n",
        ),
        (
            "uv.lock",
            "version=1\n[[package]]\nname='demo'\nversion='1'\n\
             source={registry='https://pypi.org/simple'}\n\
             wheels=[{url='https://files.pythonhosted.org/demo.whl',hash='blake3:abcd'}]\n",
        ),
    ] {
        let output = parse_fixture(basename, raw).expect("unknown string hash is normalized");
        assert_eq!(output.records[0].integrity_state, IntegrityState::Invalid);
    }
}

#[test]
fn cargo_dependencies_resolve_exact_identity_and_metadata_is_non_record() {
    let valid = format!(
        "version=4\n\
         [[package]]\nname='app'\nversion='1.0.0'\n\
         dependencies=['child 1.2.3 (registry+https://index.crates.io)']\n\
         [[package]]\nname='child'\nversion='1.2.3'\n\
         source='registry+https://index.crates.io'\nchecksum='{SHA256}'\n\
         [metadata]\nfixture={{nested=['bounded','opaque']}}\n"
    );
    let output = parse_fixture("Cargo.lock", &valid).expect("exact Cargo edge resolves");
    assert_eq!(output.coverage.record_units, 2);
    assert_eq!(output.coverage.traversed_non_record_units, 1);
    assert_eq!(output.coverage.total_units, 3);
    assert_eq!(output.coverage.recognized_units, 3);

    for dependency in [
        "ghost 1.0.0",
        "child 9.9.9",
        "child 1.2.3 (registry+https://other.invalid)",
        "child 1.2.3 (registry+https://index.crates.io",
    ] {
        let raw = format!(
            "version=4\n\
             [[package]]\nname='app'\nversion='1.0.0'\ndependencies=['{dependency}']\n\
             [[package]]\nname='child'\nversion='1.2.3'\n\
             source='registry+https://index.crates.io'\nchecksum='{SHA256}'\n"
        );
        assert!(matches!(
            parse_fixture("Cargo.lock", &raw),
            Err(LockfileError::Parse { .. } | LockfileError::InvalidModel { .. })
        ));
    }

    let ambiguous = format!(
        "version=4\n\
         [[package]]\nname='app'\nversion='1.0.0'\ndependencies=['child']\n\
         [[package]]\nname='child'\nversion='1.0.0'\n\
         source='registry+https://index.crates.io'\nchecksum='{SHA256}'\n\
         [[package]]\nname='child'\nversion='2.0.0'\n\
         source='registry+https://index.crates.io'\nchecksum='{SHA256}'\n"
    );
    assert!(matches!(
        parse_fixture("Cargo.lock", &ambiguous),
        Err(LockfileError::Parse { .. } | LockfileError::InvalidModel { .. })
    ));
}

#[test]
fn go_sum_parser_enforces_scalar_budget_without_detection() {
    fn parse_direct(raw: &str) -> Result<ParseOutput, LockfileError> {
        let input = BoundedInput::new(raw.as_bytes(), "go.sum")?;
        let detected = DetectedLockfile {
            format: LockfileFormat::GoSum,
            version: FormatVersion::GoSumGrammar1,
            evidence: vec!["direct parser boundary".to_string()],
        };
        argus_lockfile::parsers::go_sum::PARSER.parse(&input, &detected)
    }

    let equal = format!("{} v1.0.0 h1:{H1}", "a".repeat(MAX_SCALAR_BYTES));
    assert!(parse_direct(&equal).is_ok());
    let over = format!("{} v1.0.0 h1:{H1}", "a".repeat(MAX_SCALAR_BYTES + 1));
    assert!(matches!(
        parse_direct(&over),
        Err(LockfileError::ScalarTooLarge {
            actual,
            maximum
        }) if actual == MAX_SCALAR_BYTES + 1 && maximum == MAX_SCALAR_BYTES
    ));
}

fn parse_go_direct(
    raw: &str,
    format: LockfileFormat,
    version: FormatVersion,
) -> Result<ParseOutput, LockfileError> {
    let input = BoundedInput::new(raw.as_bytes(), "go.sum")?;
    let detected = DetectedLockfile {
        format,
        version,
        evidence: vec!["direct parser grammar fixture".to_string()],
    };
    argus_lockfile::parsers::go_sum::PARSER.parse(&input, &detected)
}

#[test]
fn go_sum_native_grammar_and_error_matrix() {
    let valid = format!("example.com/demo v1.0.0 h1:{H1}");
    assert!(matches!(
        parse_go_direct(&valid, LockfileFormat::Cargo, FormatVersion::Cargo4),
        Err(LockfileError::Parse { .. })
    ));
    for raw in [
        "example.com/demo v1.0.0",
        "example.com/demo  v1.0.0 h1:AAAA",
        "/demo v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "demo/ v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "demo//child v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "example.com/demo 1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "example.com/demo vnot-semver h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "example.com/demo v1.0.0 sha256:aaaaaaaa",
        "example.com/demo v1.0.0 h1:not-base64",
        "example.com/demo v1.0.0 h1:AAAA",
    ] {
        assert!(matches!(
            parse_go_direct(raw, LockfileFormat::GoSum, FormatVersion::GoSumGrammar1),
            Err(LockfileError::Parse { .. })
        ));
    }

    let duplicate = format!("{valid}\n{valid}");
    let output = parse_go_direct(
        &duplicate,
        LockfileFormat::GoSum,
        FormatVersion::GoSumGrammar1,
    )
    .expect("duplicate go.sum evidence is preserved");
    assert_eq!(output.records.len(), 2);
    assert_eq!(output.records[0].occurrence_index, 0);
    assert_eq!(output.records[1].occurrence_index, 1);

    let over_limit = format!("{}\n", valid).repeat(MAX_RECORDS + 1);
    assert!(matches!(
        parse_go_direct(
            over_limit.trim_end(),
            LockfileFormat::GoSum,
            FormatVersion::GoSumGrammar1
        ),
        Err(LockfileError::RecordLimit { .. })
    ));
}

#[test]
fn uv_metadata_sources_artifacts_and_edges_matrix() {
    let rich = format!(
        "version=1\nrevision=3\nrequires-python='>=3.9'\n\
         resolution-markers=['python_version >= \"3.9\"']\n\
         options={{exclude-newer='2025-01-01',prerelease=true,no-build=['legacy']}}\n\
         manifest={{members=['.'],requirements=[{{name='req',specifier='>=1'}}],\
         constraints=[{{name='constraint'}}],overrides=[{{name='override'}}],\
         dependency-groups={{dev=[{{name='dev'}}]}}}}\n\
         [[package]]\nname='demo'\nversion='1'\nsource={{registry='https://pypi.org/simple'}}\n\
         metadata={{provides-extras=['speed'],requires-dist=[{{name='child',version='1'}}],\
         requires-dev=[{{name='dev-child'}}]}}\n\
         sdist={{url='https://files.pythonhosted.org/demo.tar.gz',hash='sha512:{}',size=1}}\n",
        "a".repeat(128)
    );
    let output = parse_fixture("uv.lock", &rich).expect("known uv metadata is traversed");
    assert_eq!(
        output.records[0].integrity_state,
        IntegrityState::RequiredPresent
    );

    for source in [
        "{url='https://files.pythonhosted.org/demo.whl'}",
        "{directory='../demo'}",
        "{workspace='.'}",
    ] {
        let raw = format!("version=1\n[[package]]\nname='demo'\nversion='1'\nsource={source}\n");
        assert!(parse_fixture("uv.lock", &raw).is_ok(), "{source}");
    }

    let artifact_errors = [
        "source={path='.'}\nwheels=[{url='https://example.test/demo.whl'}]",
        "source={registry='https://pypi.org/simple'}\nwheels='bad'",
        "source={registry='https://pypi.org/simple'}\nwheels=[{hash='sha256:aa'}]",
        "source={registry='https://pypi.org/simple'}\nwheels=[{url='https://example.test/demo.whl',size=-1}]",
    ];
    for package_tail in artifact_errors {
        let raw = format!("version=1\n[[package]]\nname='demo'\nversion='1'\n{package_tail}\n");
        assert!(parse_fixture("uv.lock", &raw).is_err(), "{package_tail}");
    }

    for source in [
        "{}",
        "{registry='a',url='b'}",
        "{mystery='x'}",
        "{registry=1}",
    ] {
        let raw = format!("version=1\n[[package]]\nname='demo'\nversion='1'\nsource={source}\n");
        assert!(parse_fixture("uv.lock", &raw).is_err(), "{source}");
    }
}

#[test]
fn uv_invalid_root_and_dependency_metadata_fail_closed() {
    let cases = [
        "version=1\nrevision='bad'\n[[package]]\nname='x'\nversion='1'\nsource={path='.'}\n",
        "version=1\nrequires-python=3\n[[package]]\nname='x'\nversion='1'\nsource={path='.'}\n",
        "version=1\nresolution-markers='bad'\n[[package]]\nname='x'\nversion='1'\nsource={path='.'}\n",
        "version=1\noptions={exclude-newer={nested='bad'}}\n[[package]]\nname='x'\nversion='1'\nsource={path='.'}\n",
        "version=1\n[[package]]\nname='x'\nversion='1'\nsource={path='.'}\ndependencies='bad'\n",
        "version=1\n[[package]]\nname='x'\nversion='1'\nsource={path='.'}\ndependencies=[{name=''}]\n",
        "version=1\n[[package]]\nname='x'\nversion='1'\nsource={path='.'}\nmetadata={provides-extras='bad'}\n",
    ];
    for raw in cases {
        assert!(parse_fixture("uv.lock", raw).is_err(), "{raw}");
    }
}
