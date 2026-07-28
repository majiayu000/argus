use argus_core::{Ecosystem, Severity};
use argus_rules::typosquat::match_typosquat;
use argus_rules::RuleSession;

const POSITIVE_CASES: [(Ecosystem, &str, &str); 8] = [
    (Ecosystem::Npm, "reactt", "react"),
    (Ecosystem::PyPi, "rrequests", "requests"),
    (Ecosystem::CratesIo, "toikio", "tokio"),
    (
        Ecosystem::Go,
        "github.com/gorilla/muux",
        "github.com/gorilla/mux",
    ),
    (Ecosystem::NuGet, "Newtonsoft.JSoon", "Newtonsoft.Json"),
    (Ecosystem::Maven, "org.example:guaava", "guava"),
    (Ecosystem::RubyGems, "bundelr", "bundler"),
    (Ecosystem::Packagist, "monlog/monolog", "monolog/monolog"),
];

#[test]
fn public_matcher_covers_all_ecosystems_and_registry_aliases() {
    for (ecosystem, candidate, target) in POSITIVE_CASES {
        let matched = match_typosquat(ecosystem, candidate, 1)
            .unwrap_or_else(|error| panic!("{ecosystem:?} `{candidate}` failed: {error}"))
            .unwrap_or_else(|| panic!("{ecosystem:?} `{candidate}` did not match"));
        assert_eq!(matched.target, target, "{ecosystem:?} `{candidate}`");
        assert_eq!(matched.dataset_version, 1);
        assert_eq!(matched.dataset_sha256.len(), 64);
    }

    let exact_or_registry_aliases = [
        (Ecosystem::Npm, "React"),
        (Ecosystem::PyPi, "typing_extensions"),
        (Ecosystem::CratesIo, "TOKIO"),
        (Ecosystem::Go, "github.com/gorilla/mux"),
        (Ecosystem::NuGet, "newtonsoft.json"),
        (Ecosystem::Maven, "org.example:Guava"),
        (Ecosystem::RubyGems, "bundler"),
        (Ecosystem::Packagist, "Monolog/Monolog"),
    ];
    for (ecosystem, candidate) in exact_or_registry_aliases {
        assert!(
            match_typosquat(ecosystem, candidate, 1)
                .unwrap_or_else(|error| panic!("{ecosystem:?} `{candidate}` failed: {error}"))
                .is_none(),
            "{ecosystem:?} exact/alias `{candidate}` was flagged"
        );
    }
}

#[test]
fn namespace_boundaries_avoid_unrelated_false_positives() {
    for (ecosystem, candidate) in [
        (Ecosystem::Npm, "@attacker/reactt"),
        (Ecosystem::Go, "evil.example/gorilla/muux"),
        (Ecosystem::Packagist, "attacker/monolog"),
    ] {
        assert!(
            match_typosquat(ecosystem, candidate, 1)
                .unwrap_or_else(|error| panic!("{ecosystem:?} `{candidate}` failed: {error}"))
                .is_none(),
            "{ecosystem:?} unrelated namespace `{candidate}` was flagged"
        );
    }

    // The frozen Maven v1 data intentionally preserves its legacy
    // artifact-only semantics across groups.
    assert!(match_typosquat(Ecosystem::Maven, "org.attacker:Guava", 1)
        .unwrap()
        .is_none());
    assert_eq!(
        match_typosquat(Ecosystem::Maven, "org.attacker:guaava", 1)
            .unwrap()
            .unwrap()
            .target,
        "guava"
    );
}

#[test]
fn typed_distance_severity_and_rule_switches_drive_public_session_behavior() {
    let distance_two_cases = [
        (Ecosystem::Npm, "react-dxx"),
        (Ecosystem::PyPi, "reqxxsts"),
        (Ecosystem::CratesIo, "acxxx-web"),
        (Ecosystem::Go, "github.com/aws/aws-sdk-xx"),
        (Ecosystem::NuGet, "Newtonxxft.Json"),
        (Ecosystem::Maven, "org.example:spring-xxre"),
        (Ecosystem::RubyGems, "activexxcord"),
        (Ecosystem::Packagist, "laravel/framewxxk"),
    ];
    let distance_two = RuleSession::load(
        None,
        &[
            "typosquatting=param:max_edit_distance=2".to_string(),
            "low-reputation=off".to_string(),
        ],
    )
    .unwrap();
    for (ecosystem, candidate) in distance_two_cases {
        let mut findings = Vec::new();
        RuleSession::builtin()
            .unwrap()
            .push_typosquat_findings(ecosystem, candidate, "package name", &mut findings)
            .unwrap();
        assert!(
            findings.is_empty(),
            "{ecosystem:?} distance two must be opt-in"
        );
        distance_two
            .push_typosquat_findings(ecosystem, candidate, "package name", &mut findings)
            .unwrap();
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            ["typosquatting"],
            "{ecosystem:?} typed distance-two session was not applied"
        );
    }
    assert_eq!(
        distance_two
            .metadata()
            .unwrap()
            .parameter_overrides
            .as_slice(),
        ["typosquatting=param:max_edit_distance=2"]
    );

    for (overrides, expected) in [
        (
            vec![
                "typosquatting=severity:critical".to_string(),
                "low-reputation=off".to_string(),
            ],
            vec![("typosquatting", Severity::Critical)],
        ),
        (
            vec!["typosquatting=off".to_string()],
            vec![("low-reputation", Severity::Medium)],
        ),
        (
            vec![
                "typosquatting=off".to_string(),
                "low-reputation=off".to_string(),
            ],
            Vec::new(),
        ),
    ] {
        for (ecosystem, candidate, _) in POSITIVE_CASES {
            let session = RuleSession::load(None, &overrides).unwrap();
            let mut findings = Vec::new();
            session
                .push_typosquat_findings(ecosystem, candidate, "package name", &mut findings)
                .unwrap();
            session.normalize_findings(&mut findings);
            assert_eq!(
                findings
                    .iter()
                    .map(|finding| (finding.rule_id.as_str(), finding.severity))
                    .collect::<Vec<_>>(),
                expected,
                "{ecosystem:?} overrides: {overrides:?}"
            );
        }
    }
}
