use argus_core::{Decision, Ecosystem, PackageCoordinate};
use argus_lockfile::{
    evaluate, Coverage, DetectedLockfile, FormatVersion, IntegrityEvidence, IntegrityState,
    LockfileFormat, NormalizedDependency, NormalizedSource, ParseOutput, PolicyError,
    PolicyOptions, SourceKind,
};
use std::path::{Path, PathBuf};

fn evidence(algorithm: &str, value: &str, locator: &str) -> IntegrityEvidence {
    IntegrityEvidence {
        algorithm: Some(algorithm.to_string()),
        value: Some(value.to_string()),
        locator: locator.to_string(),
    }
}

fn record(
    format: LockfileFormat,
    source: NormalizedSource,
    state: IntegrityState,
    integrity: Vec<IntegrityEvidence>,
    index: u64,
) -> NormalizedDependency {
    let name = format!("demo-{index}");
    let version = "1.0.0".to_string();
    NormalizedDependency {
        coordinate: Some(
            PackageCoordinate::new(Ecosystem::Npm, &name, &version).expect("coordinate"),
        ),
        format,
        sources: vec![source],
        integrity_state: state,
        integrity,
        raw_name: Some(name),
        raw_version: Some(version),
        locator: format!("records[{index}]"),
        condition: None,
        platform: None,
        occurrence_index: index,
    }
}

fn source(
    kind: SourceKind,
    location: Option<&str>,
    revision: Option<&str>,
    index: u64,
) -> NormalizedSource {
    NormalizedSource {
        kind,
        location: location.map(str::to_string),
        immutable_revision: revision.map(str::to_string),
        locator: format!("records[{index}].source"),
    }
}

fn output(records: Vec<NormalizedDependency>) -> ParseOutput {
    ParseOutput {
        detected: DetectedLockfile {
            format: records
                .first()
                .map_or(LockfileFormat::PackageLock, |record| record.format),
            version: FormatVersion::PackageLock3,
            evidence: vec!["test".to_string()],
        },
        coverage: Coverage {
            total_units: records.len(),
            recognized_units: records.len(),
            unsupported_units: 0,
            record_units: records.len(),
            traversed_non_record_units: 0,
        },
        records,
        metadata_integrity: Vec::new(),
    }
}

fn strong(index: u64) -> Vec<IntegrityEvidence> {
    vec![evidence(
        "sha256",
        &"a".repeat(64),
        &format!("records[{index}].integrity"),
    )]
}

fn rules(report: &argus_core::ScanReport) -> Vec<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect()
}

#[test]
fn source_policy() {
    let records = vec![
        record(
            LockfileFormat::PackageLock,
            source(
                SourceKind::Registry,
                Some("https://registry.npmjs.org/demo.tgz"),
                None,
                0,
            ),
            IntegrityState::RequiredPresent,
            strong(0),
            0,
        ),
        record(
            LockfileFormat::PackageLock,
            source(
                SourceKind::Registry,
                Some("http://registry.npmjs.org/demo.tgz"),
                None,
                1,
            ),
            IntegrityState::RequiredPresent,
            strong(1),
            1,
        ),
        record(
            LockfileFormat::PackageLock,
            source(
                SourceKind::Url,
                Some("https://cdn.example.test/demo.tgz"),
                None,
                2,
            ),
            IntegrityState::RequiredPresent,
            strong(2),
            2,
        ),
    ];
    let policy = PolicyOptions::new(["cdn.example.test", "registry.npmjs.org"]).expect("policy");
    let report = evaluate(&output(records), Path::new("package-lock.json"), &policy).expect("scan");
    assert_eq!(report.decision, Decision::Block);
    assert_eq!(
        rules(&report),
        vec!["lockfile-http-resolved", "untrusted-registry-host"]
    );
    assert!(report.findings[1]
        .detail
        .contains("plain HTTP is never trusted"));

    let unicode = record(
        LockfileFormat::PackageLock,
        source(
            SourceKind::Url,
            Some("https://bücher.example/archive.tgz"),
            None,
            0,
        ),
        IntegrityState::RequiredPresent,
        strong(0),
        0,
    );
    let policy = PolicyOptions::new(["BÜCHER.example"]).expect("IDNA allowlist");
    let report = evaluate(
        &output(vec![unicode]),
        Path::new("package-lock.json"),
        &policy,
    )
    .expect("IDNA scan");
    assert_eq!(report.decision, Decision::Allow);
    assert!(report.findings.is_empty());

    let berry_registry = record(
        LockfileFormat::YarnBerry,
        source(SourceKind::Registry, Some("demo-0@npm:1.0.0"), None, 0),
        IntegrityState::RequiredPresent,
        strong(0),
        0,
    );
    let report = evaluate(
        &output(vec![berry_registry]),
        Path::new("yarn.lock"),
        &PolicyOptions::default(),
    )
    .expect("Yarn Berry implicit npm registry scan");
    assert_eq!(report.decision, Decision::Allow);
    assert!(report.findings.is_empty());

    let deceptive_registry = record(
        LockfileFormat::YarnBerry,
        source(
            SourceKind::Registry,
            Some("https://evil.example@npm:1.0.0"),
            None,
            0,
        ),
        IntegrityState::RequiredPresent,
        strong(0),
        0,
    );
    assert!(matches!(
        evaluate(
            &output(vec![deceptive_registry]),
            Path::new("yarn.lock"),
            &PolicyOptions::default()
        ),
        Err(PolicyError::InvalidSourceLocator { .. })
    ));

    for invalid in [
        "https://example.com",
        "example.com:443",
        "*.example.com",
        ".example.com",
        "user@example.com",
        "127.0.0.1",
        "[::1]",
        "example.com/path",
    ] {
        assert!(
            matches!(
                PolicyOptions::new([invalid]),
                Err(PolicyError::InvalidAllowlistedHost { .. })
            ),
            "{invalid}"
        );
    }

    let invalid_url = record(
        LockfileFormat::PackageLock,
        source(SourceKind::Url, Some("https:/broken"), None, 0),
        IntegrityState::RequiredPresent,
        strong(0),
        0,
    );
    assert!(matches!(
        evaluate(
            &output(vec![invalid_url]),
            Path::new("package-lock.json"),
            &PolicyOptions::default()
        ),
        Err(PolicyError::InvalidSourceLocator { .. })
    ));

    let deceptive_shorthand = record(
        LockfileFormat::PackageLock,
        source(
            SourceKind::Git,
            Some("github:https://evil.example/repo"),
            None,
            0,
        ),
        IntegrityState::UnavailableByFormat,
        Vec::new(),
        0,
    );
    assert!(matches!(
        evaluate(
            &output(vec![deceptive_shorthand]),
            Path::new("package-lock.json"),
            &PolicyOptions::default()
        ),
        Err(PolicyError::InvalidSourceLocator { .. })
    ));
}

#[test]
fn vcs_refs() {
    let commit40 = "a".repeat(40);
    let commit64 = "b".repeat(64);
    let records = vec![
        record(
            LockfileFormat::Cargo,
            source(
                SourceKind::Git,
                Some(&format!("ssh://git@github.com/org/repo#{commit40}")),
                Some(&commit40),
                0,
            ),
            IntegrityState::UnavailableByFormat,
            Vec::new(),
            0,
        ),
        record(
            LockfileFormat::Cargo,
            source(
                SourceKind::Git,
                Some(&format!("git@github.com:org/repo#{commit64}")),
                Some(&commit64),
                1,
            ),
            IntegrityState::UnavailableByFormat,
            Vec::new(),
            1,
        ),
        record(
            LockfileFormat::Cargo,
            source(
                SourceKind::Git,
                Some("https://github.com/org/repo#main"),
                None,
                2,
            ),
            IntegrityState::UnavailableByFormat,
            Vec::new(),
            2,
        ),
    ];
    let report = evaluate(
        &output(records),
        Path::new("Cargo.lock"),
        &PolicyOptions::default(),
    )
    .expect("VCS scan");
    assert_eq!(report.decision, Decision::Block);
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "lockfile-mutable-vcs-ref")
            .count(),
        1
    );
    assert!(!rules(&report).contains(&"untrusted-registry-host"));

    let mut multi_source = record(
        LockfileFormat::Composer,
        source(
            SourceKind::Url,
            Some("https://repo.packagist.org/archive.zip"),
            None,
            0,
        ),
        IntegrityState::OptionalAbsent,
        Vec::new(),
        0,
    );
    multi_source.sources.push(source(
        SourceKind::Git,
        Some("git@example.test:vendor/demo#main"),
        None,
        1,
    ));
    let report = evaluate(
        &output(vec![multi_source]),
        Path::new("composer.lock"),
        &PolicyOptions::default(),
    )
    .expect("multi-source scan");
    assert_eq!(report.decision, Decision::Block);
    assert!(rules(&report).contains(&"lockfile-mutable-vcs-ref"));
    assert!(rules(&report).contains(&"untrusted-registry-host"));

    let malformed = record(
        LockfileFormat::Cargo,
        source(SourceKind::Git, Some("github.com/org/repo"), None, 0),
        IntegrityState::UnavailableByFormat,
        Vec::new(),
        0,
    );
    assert!(matches!(
        evaluate(
            &output(vec![malformed]),
            Path::new("Cargo.lock"),
            &PolicyOptions::default()
        ),
        Err(PolicyError::InvalidSourceLocator { .. })
    ));
}

#[test]
fn local_sources_are_closed_and_cannot_hide_network_locators() {
    let valid = vec![
        (LockfileFormat::PackageLock, SourceKind::Workspace, "."),
        (
            LockfileFormat::YarnClassic,
            SourceKind::Workspace,
            "workspace:*",
        ),
        (
            LockfileFormat::YarnBerry,
            SourceKind::Workspace,
            "demo-2@workspace:.",
        ),
        (
            LockfileFormat::YarnBerry,
            SourceKind::Path,
            "demo-3@patch:demo@npm:1.0.0#./patches/demo.patch",
        ),
        (LockfileFormat::Pnpm, SourceKind::Workspace, "link:../local"),
        (LockfileFormat::Poetry, SourceKind::Path, "../local"),
        (LockfileFormat::Uv, SourceKind::Path, "/opt/local"),
        (LockfileFormat::Cargo, SourceKind::Path, "workspace"),
        (LockfileFormat::Bundler, SourceKind::Path, "../gems"),
        (LockfileFormat::Composer, SourceKind::Path, "../vendor"),
    ];
    let records = valid
        .into_iter()
        .enumerate()
        .map(|(index, (format, kind, location))| {
            record(
                format,
                source(kind, Some(location), None, index as u64),
                IntegrityState::UnavailableByFormat,
                Vec::new(),
                index as u64,
            )
        })
        .collect();
    let report = evaluate(
        &output(records),
        Path::new("local-lockfile"),
        &PolicyOptions::default(),
    )
    .expect("closed local source matrix");
    assert_eq!(report.decision, Decision::Allow);

    for (kind, location) in [
        (SourceKind::Path, "https://evil.example/archive"),
        (SourceKind::Workspace, "ssh://evil.example/repository"),
        (SourceKind::Path, "file:https://evil.example/archive"),
        (SourceKind::Workspace, "workspace:git@example.test:repo"),
        (SourceKind::Path, "git@example.test:repo"),
        (SourceKind::Path, "example.test:repository"),
        (SourceKind::Path, "ftp://example.test/archive"),
    ] {
        let invalid = record(
            LockfileFormat::PackageLock,
            source(kind, Some(location), None, 0),
            IntegrityState::UnavailableByFormat,
            Vec::new(),
            0,
        );
        assert!(
            matches!(
                evaluate(
                    &output(vec![invalid]),
                    Path::new("package-lock.json"),
                    &PolicyOptions::default()
                ),
                Err(PolicyError::InvalidSourceLocator { .. })
            ),
            "{kind:?} {location}"
        );
    }
}

#[test]
fn integrity_matrix() {
    let weak = evidence("sha1", &"a".repeat(40), "records[1].integrity");
    let unknown = evidence("sha999", &"b".repeat(64), "records[2].integrity");
    let missing_sibling = evidence("sha256", &"c".repeat(64), "records[3].file[0]");
    let records = vec![
        record(
            LockfileFormat::PackageLock,
            source(SourceKind::Registry, Some("npm:demo-0@1.0.0"), None, 0),
            IntegrityState::RequiredPresent,
            strong(0),
            0,
        ),
        record(
            LockfileFormat::PackageLock,
            source(SourceKind::Registry, Some("npm:demo-1@1.0.0"), None, 1),
            IntegrityState::RequiredPresent,
            vec![weak],
            1,
        ),
        record(
            LockfileFormat::PackageLock,
            source(SourceKind::Registry, Some("npm:demo-2@1.0.0"), None, 2),
            IntegrityState::Invalid,
            vec![unknown],
            2,
        ),
        record(
            LockfileFormat::PackageLock,
            source(SourceKind::Registry, Some("npm:demo-3@1.0.0"), None, 3),
            IntegrityState::RequiredMissing,
            vec![missing_sibling],
            3,
        ),
        record(
            LockfileFormat::GoSum,
            source(SourceKind::UnavailableByFormat, None, None, 4),
            IntegrityState::UnavailableByFormat,
            Vec::new(),
            4,
        ),
    ];
    let report = evaluate(
        &output(records),
        Path::new("lockfile"),
        &PolicyOptions::default(),
    )
    .expect("integrity scan");
    assert_eq!(report.decision, Decision::Block);
    assert!(rules(&report).contains(&"lockfile-integrity-invalid"));
    assert!(rules(&report).contains(&"lockfile-integrity-missing"));
    assert!(rules(&report).contains(&"lockfile-integrity-weak"));
    assert!(rules(&report).contains(&"lockfile-integrity-unavailable"));

    let weak_only = record(
        LockfileFormat::Composer,
        source(
            SourceKind::Url,
            Some("https://repo.packagist.org/archive.zip"),
            None,
            0,
        ),
        IntegrityState::OptionalPresent,
        vec![evidence("sha1", &"d".repeat(40), "dist.shasum")],
        0,
    );
    let report = evaluate(
        &output(vec![weak_only]),
        Path::new("composer.lock"),
        &PolicyOptions::default(),
    )
    .expect("weak scan");
    assert_eq!(report.decision, Decision::AllowWithApproval);

    let conflict = record(
        LockfileFormat::PackageLock,
        source(SourceKind::Registry, Some("npm:demo-0@1.0.0"), None, 0),
        IntegrityState::RequiredPresent,
        vec![
            evidence("sha256", &"a".repeat(64), "integrity"),
            evidence("sha256", &"b".repeat(64), "integrity"),
        ],
        0,
    );
    let report = evaluate(
        &output(vec![conflict]),
        Path::new("package-lock.json"),
        &PolicyOptions::default(),
    )
    .expect("conflict scan");
    assert_eq!(report.decision, Decision::Block);
    assert!(rules(&report).contains(&"lockfile-integrity-invalid"));

    let missing_only = record(
        LockfileFormat::PackageLock,
        source(SourceKind::Registry, Some("npm:demo-0@1.0.0"), None, 0),
        IntegrityState::RequiredMissing,
        vec![IntegrityEvidence {
            algorithm: None,
            value: None,
            locator: "artifact-without-hash".to_string(),
        }],
        0,
    );
    let report = evaluate(
        &output(vec![missing_only]),
        Path::new("package-lock.json"),
        &PolicyOptions::default(),
    )
    .expect("missing-only scan");
    assert_eq!(report.decision, Decision::Block);
    assert_eq!(rules(&report), vec!["lockfile-integrity-missing"]);

    let mut empty_self_checksum = output(vec![record(
        LockfileFormat::Bundler,
        source(SourceKind::Registry, Some("https://rubygems.org/"), None, 0),
        IntegrityState::UnavailableByFormat,
        Vec::new(),
        0,
    )]);
    empty_self_checksum.metadata_integrity = vec![IntegrityEvidence {
        algorithm: None,
        value: None,
        locator: "line 12: bundler (4.0.0)".to_string(),
    }];
    let report = evaluate(
        &empty_self_checksum,
        Path::new("Gemfile.lock"),
        &PolicyOptions::default(),
    )
    .expect("empty Bundler self-checksum policy scan");
    assert_eq!(report.decision, Decision::Block);
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "lockfile-integrity-invalid"
            && finding.severity == argus_core::Severity::Critical
            && finding.detail.contains("metadata")
    }));

    let unavailable = (0..25)
        .map(|index| {
            record(
                LockfileFormat::GoSum,
                source(SourceKind::UnavailableByFormat, None, None, index),
                IntegrityState::UnavailableByFormat,
                Vec::new(),
                index,
            )
        })
        .collect();
    let report = evaluate(
        &output(unavailable),
        Path::new("go.sum"),
        &PolicyOptions::default(),
    )
    .expect("aggregated unavailable scan");
    assert_eq!(report.decision, Decision::Allow);
    assert_eq!(report.findings.len(), 1);
    assert!(report.findings[0].detail.contains("25 records"));
    assert_eq!(
        report.findings[0]
            .evidence
            .as_ref()
            .expect("locator evidence")
            .len(),
        20
    );
}

#[test]
fn integrity_is_evaluated_per_artifact_locator() {
    let source = source(SourceKind::Registry, Some("npm:demo-0@1.0.0"), None, 0);
    let sibling_strengths = record(
        LockfileFormat::PackageLock,
        source.clone(),
        IntegrityState::RequiredPresent,
        vec![
            evidence("sha256", &"a".repeat(64), "artifact-strong"),
            evidence("sha1", &"b".repeat(40), "artifact-weak"),
        ],
        0,
    );
    let report = evaluate(
        &output(vec![sibling_strengths]),
        Path::new("package-lock.json"),
        &PolicyOptions::default(),
    )
    .expect("sibling integrity scan");
    assert_eq!(report.decision, Decision::AllowWithApproval);
    assert_eq!(rules(&report), vec!["lockfile-integrity-weak"]);
    assert_eq!(
        report.findings[0].location.as_deref(),
        Some("artifact-weak")
    );

    let same_artifact = record(
        LockfileFormat::PackageLock,
        source.clone(),
        IntegrityState::RequiredPresent,
        vec![
            evidence("sha256", &"a".repeat(64), "artifact"),
            evidence("sha1", &"b".repeat(40), "artifact"),
        ],
        0,
    );
    let report = evaluate(
        &output(vec![same_artifact]),
        Path::new("package-lock.json"),
        &PolicyOptions::default(),
    )
    .expect("same-artifact integrity scan");
    assert_eq!(report.decision, Decision::Allow);
    assert!(report.findings.is_empty());

    let independent_values = record(
        LockfileFormat::PackageLock,
        source,
        IntegrityState::RequiredPresent,
        vec![
            evidence("sha256", &"a".repeat(64), "artifact-a"),
            evidence("sha256", &"b".repeat(64), "artifact-b"),
        ],
        0,
    );
    let report = evaluate(
        &output(vec![independent_values]),
        Path::new("package-lock.json"),
        &PolicyOptions::default(),
    )
    .expect("independent digest values");
    assert_eq!(report.decision, Decision::Allow);

    let mut metadata = output(Vec::new());
    metadata.metadata_integrity = vec![
        evidence("sha256", &"c".repeat(64), "metadata-strong"),
        evidence("sha1", &"d".repeat(40), "metadata-weak"),
    ];
    let report = evaluate(
        &metadata,
        Path::new("Gemfile.lock"),
        &PolicyOptions::default(),
    )
    .expect("metadata sibling integrity");
    assert_eq!(report.decision, Decision::AllowWithApproval);
    assert_eq!(
        report.findings[0].location.as_deref(),
        Some("metadata-weak")
    );
}

#[test]
fn lockfile_crate_has_no_process_socket_or_transport_surface() {
    fn collect_rust(path: &Path, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(path).expect("read source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                collect_rust(&path, files);
            } else if path.extension().is_some_and(|value| value == "rs") {
                files.push(path);
            }
        }
    }

    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    collect_rust(&crate_root.join("src"), &mut sources);
    sources.sort();
    let forbidden = [
        "std::process",
        "process::Command",
        "Command::new",
        "/bin/",
        "\\System32\\",
        "std::net",
        "::net::",
        "connect(",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "UnixStream",
        "UnixListener",
        "UnixDatagram",
    ];
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("read production source");
        for token in forbidden {
            assert!(
                !source.contains(token),
                "{} contains {token}",
                path.display()
            );
        }
    }

    let manifest: toml::Value = toml::from_str(
        &std::fs::read_to_string(crate_root.join("Cargo.toml")).expect("read crate manifest"),
    )
    .expect("parse crate manifest");
    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .expect("dependencies table");
    for dependency in [
        "ureq",
        "reqwest",
        "tokio",
        "hyper",
        "curl",
        "attohttpc",
        "isahc",
        "surf",
        "rustls",
        "native-tls",
        "socket2",
        "mio",
    ] {
        assert!(
            !dependencies.contains_key(dependency),
            "forbidden transport dependency {dependency}"
        );
    }
}
