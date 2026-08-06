use super::*;
use crate::{Finding, Severity};
use std::collections::BTreeSet;
use std::str::FromStr;

const GENERIC_HELP: &str = "https://github.com/majiayu000/argus#rule-coverage-milestone-0";

fn external_rule(id: &str, matcher: &str) -> String {
    format!(
        r#"{{ id: "{id}", description: "external test rule", policy_class: blocking, default_severity: high, help_uri: "{GENERIC_HELP}", languages: [javascript], matcher: {matcher} }}"#
    )
}

fn external_catalog(records: &[String]) -> String {
    format!(
        "schema_version: 1\nrules:\n  - {}\n",
        records.join("\n  - ")
    )
}

fn assert_catalog_error(source: &str, origin: CatalogOrigin, expected: &str) {
    let error = RuleCatalog::parse_yaml(source, origin).unwrap_err();
    assert!(
        error.to_string().contains(expected),
        "expected `{expected}`, got `{error}`"
    );
}

#[test]
fn embedded_catalog_is_the_complete_deterministic_registry() {
    let catalog = builtin_catalog().unwrap();
    assert_eq!(catalog.schema_version(), 1);
    assert_eq!(catalog.rules().len(), 118);
    let mut ids = BTreeSet::new();
    let mut prior = None;
    for rule in catalog.rules() {
        assert!(ids.insert(rule.id.as_str()));
        assert!(!rule.description.trim().is_empty());
        assert_eq!(rule.default_severity, DefaultSeverity::DetectorOwned);
        assert!(rule.languages.is_empty());
        match &rule.matcher {
            RuleMatcher::Builtin { name, parameters } => {
                assert_eq!(name, &rule.id);
                match rule.id.as_str() {
                    "typosquatting" => assert!(parameters.typosquat().is_some()),
                    "version-shape-anomaly" => {
                        assert!(parameters.npm_version_shape().is_some())
                    }
                    "rapid-publish-window" => {
                        assert!(parameters.npm_rapid_publish().is_some())
                    }
                    _ => assert_eq!(parameters, &RuleParameters::None),
                }
            }
            other => panic!("built-in rule used non-builtin matcher: {other:?}"),
        }
        if let Some(prior) = prior {
            assert!(prior < rule.id.as_str());
        }
        prior = Some(rule.id.as_str());
    }
    assert_eq!(all_rules().len(), 118);
}

#[test]
fn lookup_preserves_descriptions_help_and_unknown_fail_closed() {
    let package = rule_def("remote-download").unwrap();
    assert_eq!(package.description, "Script downloads a remote payload");
    assert_eq!(package.help_uri.as_str(), GENERIC_HELP);
    let agent = rule_def("AGT-03-remote-exec").unwrap();
    assert_eq!(
        agent.help_uri.as_str(),
        "https://github.com/majiayu000/argus#agent-surface-rule-coverage-gh-57"
    );
    assert!(rule_def("not-registered").is_none());
    assert_eq!(policy("not-registered"), RulePolicy::Blocking);
}

#[test]
fn legacy_policy_arrays_are_preserved() {
    const LEGACY_INFO_ONLY: &[&str] = &[
        "missing-provenance",
        "provenance-verified-subject",
        "provenance-signature-verified",
        "provenance-signature-untrusted-issuer",
        "provenance-signature-unverified",
        "proc-macro-crate",
        "build-rs-execution",
        "embedded-binary-blob",
        "pypi-sdist-no-manifest",
        "autoload-files-execution",
        "composer-manifest-parse-error",
        "gem-native-build",
        "gem-declared-executable",
        "maven-bytecode-not-inspected",
        "maven-executable-jar",
        "maven-weak-integrity-only",
        "maven-no-pom",
        "nuget-integrity-unverifiable",
        "nuget-no-manifest",
        "nuget-content-files",
        "go-init-function",
        "go-package-var-exec",
        "go-integrity-unverified",
        "npm-version-shape-unassessed",
        "npm-rapid-publish-unassessed",
        "lockfile-integrity-unavailable",
    ];
    const LEGACY_APPROVAL_ONLY: &[&str] = &[
        "version-shape-anomaly",
        "rapid-publish-window",
        "lockfile-integrity-weak",
        "encoded-dynamic-execution",
    ];
    const LEGACY_DOWNGRADE_SAFE: &[&str] = &[
        "lifecycle-script",
        "known-native-build-pattern",
        "composer-plugin-package",
    ];
    for id in LEGACY_INFO_ONLY {
        assert_eq!(policy(id), RulePolicy::InfoOnly, "policy drift for {id}");
    }
    for id in LEGACY_APPROVAL_ONLY {
        assert_eq!(
            policy(id),
            RulePolicy::ApprovalOnly,
            "policy drift for {id}"
        );
    }
    for id in LEGACY_DOWNGRADE_SAFE {
        assert_eq!(
            policy(id),
            RulePolicy::DowngradeSafe,
            "policy drift for {id}"
        );
    }
}

#[test]
fn external_literal_and_regex_are_typed_compiled_and_sorted() {
    let source = external_catalog(&[
        external_rule(
            "z-regex",
            r#"{ kind: regex, pattern: "fetch\\([^)]*TOKEN" }"#,
        ),
        external_rule(
            "a-literal",
            r#"{ kind: literal, pattern: "process.env.TOKEN" }"#,
        ),
    ]);
    let catalog = RuleCatalog::parse_yaml(&source, CatalogOrigin::External).unwrap();
    assert_eq!(catalog.rules()[0].id.as_str(), "a-literal");
    assert_eq!(catalog.rules()[1].id.as_str(), "z-regex");
    assert_eq!(
        catalog.get("a-literal").unwrap().languages,
        vec![RuleLanguage::JavaScript]
    );
    assert_eq!(
        catalog
            .get("a-literal")
            .unwrap()
            .matcher
            .matches("const x = process.env.TOKEN"),
        Some(true)
    );
    assert_eq!(
        catalog
            .get("z-regex")
            .unwrap()
            .matcher
            .matches("fetch('/x', TOKEN)"),
        Some(true)
    );
}

#[test]
fn invalid_catalog_shapes_fail_closed() {
    let valid = external_rule("external-rule", r#"{ kind: literal, pattern: "needle" }"#);
    assert_catalog_error(
        "schema_version: 2\nrules: []\n",
        CatalogOrigin::External,
        "unsupported schema_version",
    );
    assert_catalog_error(
        "schema_version: 1\nrules: []\n",
        CatalogOrigin::External,
        "must not be empty",
    );
    assert_catalog_error(
        &format!("schema_version: 1\nunknown: true\nrules:\n  - {valid}\n"),
        CatalogOrigin::External,
        "unknown field",
    );
    let unknown_record = format!(
        "{}{}, unknown: true }}",
        "schema_version: 1\nrules:\n  - ",
        valid.strip_suffix(" }").unwrap()
    );
    assert_catalog_error(&unknown_record, CatalogOrigin::External, "unknown field");
    assert_catalog_error(
        &external_catalog(&[
            valid.replace("description: \"external test rule\"", "description: \"  \"")
        ]),
        CatalogOrigin::External,
        "description must contain",
    );
    assert_catalog_error(
        &external_catalog(&[valid.replace("policy_class: blocking", "policy_class: permissive")]),
        CatalogOrigin::External,
        "unsupported policy_class",
    );
    assert_catalog_error(
        &external_catalog(&[valid.replace("help_uri: \"https://", "help_uri: \"http://")]),
        CatalogOrigin::External,
        "absolute HTTPS",
    );
    assert_catalog_error(
        &external_catalog(&[
            valid.replace("default_severity: high", "default_severity: detector-owned")
        ]),
        CatalogOrigin::External,
        "require a fixed default_severity",
    );
    assert_catalog_error(
        &external_catalog(&[valid.replace("languages: [javascript]", "languages: []")]),
        CatalogOrigin::External,
        "require at least one language",
    );
    assert_catalog_error(
        &external_catalog(&[valid.replace(
            "description: \"external test rule\"",
            "description: first, description: second",
        )]),
        CatalogOrigin::External,
        "invalid YAML",
    );
    assert_catalog_error(
        "schema_version: 1\nrules:\n  - &rule { id: x, description: x, policy_class: blocking, default_severity: high, help_uri: \"https://example.test\", languages: [javascript], matcher: { kind: literal, pattern: x } }\n",
        CatalogOrigin::External,
        "aliases, anchors",
    );
    assert_catalog_error(
        "schema_version: 1\nrules:\n  - !custom { id: x, description: x, policy_class: blocking, default_severity: high, help_uri: \"https://example.test\", languages: [javascript], matcher: { kind: literal, pattern: x } }\n",
        CatalogOrigin::External,
        "aliases, anchors",
    );
}

#[test]
fn help_uri_rejects_controls_and_whitespace_before_url_parsing() {
    let record = external_rule(
        "help-uri-validation",
        r#"{ kind: literal, pattern: "needle" }"#,
    );
    for (name, invalid, expected) in [
        (
            "newline",
            r"https://example.test/path\nfragment",
            "ASCII control",
        ),
        (
            "tab",
            r"https://example.test/path\tfragment",
            "ASCII control",
        ),
        (
            "carriage-return",
            r"https://example.test/path\rfragment",
            "ASCII control",
        ),
        (
            "embedded-control",
            r"https://example.test/path\u001bfragment",
            "ASCII control",
        ),
        (
            "leading-whitespace",
            " https://example.test/path",
            "leading or trailing whitespace",
        ),
        (
            "trailing-whitespace",
            "https://example.test/path ",
            "leading or trailing whitespace",
        ),
    ] {
        let source = external_catalog(&[record.replace(GENERIC_HELP, invalid)]);
        let error = RuleCatalog::parse_yaml(&source, CatalogOrigin::External).unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "{name}: expected `{expected}`, got `{error}`"
        );
    }
}

#[test]
fn help_uri_is_canonical_and_fragment_preserving_for_stable_digests() {
    let matcher = r#"{ kind: literal, pattern: "needle" }"#;
    let canonical = external_catalog(&[external_rule("canonical-help", matcher)]);
    let equivalent = external_catalog(&[external_rule("canonical-help", matcher).replace(
        GENERIC_HELP,
        "HTTPS://GITHUB.COM:443/majiayu000/argus#rule-coverage-milestone-0",
    )]);
    let canonical = RuleCatalog::parse_yaml(&canonical, CatalogOrigin::External).unwrap();
    let equivalent = RuleCatalog::parse_yaml(&equivalent, CatalogOrigin::External).unwrap();
    assert_eq!(
        equivalent.rules()[0].help_uri.as_str(),
        GENERIC_HELP,
        "URL normalization must preserve the fragment"
    );
    assert_eq!(
        EffectiveRuleSet::build(&canonical, []).unwrap().digest(),
        EffectiveRuleSet::build(&equivalent, []).unwrap().digest()
    );
}

#[test]
fn invalid_ids_duplicates_languages_and_matchers_fail_closed() {
    for id in ["", "-starts-with-dash", "bad id", "bad/id"] {
        let source =
            external_catalog(&[external_rule(id, r#"{ kind: literal, pattern: "needle" }"#)]);
        assert_catalog_error(&source, CatalogOrigin::External, "rule id");
    }
    let duplicate = external_rule("duplicate-rule", r#"{ kind: literal, pattern: "needle" }"#);
    assert_catalog_error(
        &external_catalog(&[duplicate.clone(), duplicate]),
        CatalogOrigin::External,
        "duplicate rule id",
    );
    let unsupported_language =
        external_rule("language-rule", r#"{ kind: literal, pattern: "needle" }"#)
            .replace("[javascript]", "[javascript, brainfuck]");
    assert_catalog_error(
        &external_catalog(&[unsupported_language]),
        CatalogOrigin::External,
        "unsupported language",
    );
    let duplicate_language =
        external_rule("language-rule", r#"{ kind: literal, pattern: "needle" }"#)
            .replace("[javascript]", "[javascript, javascript]");
    assert_catalog_error(
        &external_catalog(&[duplicate_language]),
        CatalogOrigin::External,
        "contains a duplicate",
    );
    let bad_regex = external_rule("bad-regex", r#"{ kind: regex, pattern: "[" }"#);
    assert_catalog_error(
        &external_catalog(&[bad_regex]),
        CatalogOrigin::External,
        "invalid regex",
    );
    assert!(RuleCatalog::parse_yaml_bytes(&[0xff], CatalogOrigin::External).is_err());
    assert!(RuleId::parse(&"a".repeat(MAX_RULE_ID_BYTES)).is_ok());
    assert!(RuleId::parse(&"a".repeat(MAX_RULE_ID_BYTES + 1)).is_err());
}

#[test]
fn unsupported_matcher_combinations_and_collisions_fail_closed() {
    let external_builtin = external_rule(
        "external-builtin",
        "{ kind: builtin, name: external-builtin }",
    );
    assert_catalog_error(
        &external_catalog(&[external_builtin]),
        CatalogOrigin::External,
        "external rules cannot select",
    );
    let missing_pattern = external_rule("missing-pattern", "{ kind: literal }");
    assert_catalog_error(
        &external_catalog(&[missing_pattern]),
        CatalogOrigin::External,
        "missing required field `pattern`",
    );
    let extra_matcher_field = external_rule(
        "extra-matcher",
        "{ kind: literal, pattern: needle, name: other }",
    );
    assert_catalog_error(
        &external_catalog(&[extra_matcher_field]),
        CatalogOrigin::External,
        "unknown field",
    );
    let collision = external_rule("remote-download", r#"{ kind: literal, pattern: "needle" }"#);
    assert_catalog_error(
        &external_catalog(&[collision]),
        CatalogOrigin::External,
        "collides with a built-in",
    );
    let unsupported_parameters = r#"schema_version: 1
rules:
  - { id: "builtin-rule", description: "x", policy_class: blocking, default_severity: detector-owned, help_uri: "https://example.test", languages: [], matcher: { kind: builtin, name: "builtin-rule", parameters: { limit: 4 } } }
"#;
    assert_catalog_error(
        unsupported_parameters,
        CatalogOrigin::EmbeddedBuiltin,
        "unsupported built-in parameters",
    );
    let embedded_literal = external_rule(
        "embedded-literal",
        r#"{ kind: literal, pattern: "needle" }"#,
    )
    .replace("default_severity: high", "default_severity: detector-owned")
    .replace("languages: [javascript]", "languages: []");
    assert_catalog_error(
        &external_catalog(&[embedded_literal]),
        CatalogOrigin::EmbeddedBuiltin,
        "embedded rules must use",
    );
    let embedded_fixed = external_rule("embedded-fixed", "{ kind: builtin, name: embedded-fixed }")
        .replace("languages: [javascript]", "languages: []");
    assert_catalog_error(
        &external_catalog(&[embedded_fixed]),
        CatalogOrigin::EmbeddedBuiltin,
        "severity must be `detector-owned`",
    );
    let mismatched_name = external_rule("embedded-name", "{ kind: builtin, name: different-name }")
        .replace("default_severity: high", "default_severity: detector-owned")
        .replace("languages: [javascript]", "languages: []");
    assert_catalog_error(
        &external_catalog(&[mismatched_name]),
        CatalogOrigin::EmbeddedBuiltin,
        "matcher.name must equal",
    );
}

#[test]
fn override_parser_rejects_malformed_unknown_and_duplicates() {
    assert_eq!(
        RuleOverride::from_str("remote-download=off")
            .unwrap()
            .action,
        RuleOverrideAction::Off
    );
    assert_eq!(
        RuleOverride::from_str("remote-download=severity:medium")
            .unwrap()
            .action,
        RuleOverrideAction::Severity(Severity::Medium)
    );
    for value in [
        "remote-download",
        "remote-download=medium",
        "remote-download=severity:unknown",
    ] {
        assert!(RuleOverride::from_str(value).is_err(), "{value}");
    }
    let catalog = builtin_catalog().unwrap();
    let unknown = RuleOverride::from_str("unknown-rule=off").unwrap();
    assert!(EffectiveRuleSet::build(catalog, [unknown]).is_err());
    let duplicate = RuleOverride::from_str("remote-download=off").unwrap();
    assert!(EffectiveRuleSet::build(catalog, [duplicate.clone(), duplicate]).is_err());
}

#[test]
fn effective_ruleset_applies_only_off_or_severity_and_records_metadata() {
    let catalog = builtin_catalog().unwrap();
    let ruleset = EffectiveRuleSet::build(
        catalog,
        [
            RuleOverride::from_str("remote-download=severity:info").unwrap(),
            RuleOverride::from_str("lifecycle-script=off").unwrap(),
        ],
    )
    .unwrap();
    assert_eq!(ruleset.policy("remote-download"), RulePolicy::Blocking);
    assert_eq!(ruleset.disabled_rules().len(), 1);
    assert_eq!(ruleset.disabled_rules()[0].id.as_str(), "lifecycle-script");
    assert_eq!(
        ruleset.disabled_rules()[0].policy_class,
        RulePolicy::DowngradeSafe
    );
    let mut remote = Finding::new("remote-download", Severity::High, "x");
    assert!(ruleset.apply_to_finding(&mut remote));
    assert_eq!(remote.severity, Severity::Info);
    let mut lifecycle = Finding::new("lifecycle-script", Severity::High, "x");
    assert!(!ruleset.apply_to_finding(&mut lifecycle));
    let mut unknown = Finding::new("future-unknown", Severity::Low, "x");
    assert!(ruleset.apply_to_finding(&mut unknown));
    assert_eq!(unknown.severity, Severity::Low);
    assert_eq!(ruleset.policy("future-unknown"), RulePolicy::Blocking);
}

#[test]
fn effective_ruleset_digest_is_order_independent_and_state_sensitive() {
    let catalog = builtin_catalog().unwrap();
    let first = EffectiveRuleSet::build(
        catalog,
        [
            RuleOverride::from_str("remote-download=off").unwrap(),
            RuleOverride::from_str("setup-eval=severity:low").unwrap(),
        ],
    )
    .unwrap();
    let reordered = EffectiveRuleSet::build(
        catalog,
        [
            RuleOverride::from_str("setup-eval=severity:low").unwrap(),
            RuleOverride::from_str("remote-download=off").unwrap(),
        ],
    )
    .unwrap();
    let default = EffectiveRuleSet::build(catalog, []).unwrap();
    assert_eq!(first.digest(), reordered.digest());
    assert_ne!(first.digest(), default.digest());
    assert_eq!(first.digest().to_hex().len(), 64);
    assert_eq!(first.applied_overrides().len(), 2);
}

#[test]
fn catalogs_merge_deterministically_without_shadowing() {
    let first = RuleCatalog::parse_yaml(
        &external_catalog(&[external_rule(
            "external-z",
            r#"{ kind: literal, pattern: "z" }"#,
        )]),
        CatalogOrigin::External,
    )
    .unwrap();
    let second = RuleCatalog::parse_yaml(
        &external_catalog(&[external_rule(
            "external-a",
            r#"{ kind: regex, pattern: "a+" }"#,
        )]),
        CatalogOrigin::External,
    )
    .unwrap();
    let merged = first.merged_with(&second).unwrap();
    assert_eq!(merged.rules()[0].id.as_str(), "external-a");
    assert_eq!(merged.rules()[1].id.as_str(), "external-z");
    assert!(first.merged_with(&first).is_err());
    let complete = builtin_catalog().unwrap().merged_with(&merged).unwrap();
    assert_eq!(complete.rules().len(), 120);
}

#[test]
fn override_normalization_preserves_package_and_agent_decision_contracts() {
    let catalog = builtin_catalog().unwrap();
    let lowered = EffectiveRuleSet::build(
        catalog,
        [RuleOverride::from_str("remote-download=severity:info").unwrap()],
    )
    .unwrap();
    let mut package_finding = Finding::new("remote-download", Severity::High, "x");
    assert!(lowered.apply_to_finding(&mut package_finding));
    assert_eq!(package_finding.severity, Severity::Info);
    assert_eq!(
        aggregate(&[package_finding], AggregationProfile::PolicyDriven),
        crate::Decision::Block
    );

    let raised = EffectiveRuleSet::build(
        catalog,
        [RuleOverride::from_str("missing-provenance=severity:high").unwrap()],
    )
    .unwrap();
    let mut info_finding = Finding::new("missing-provenance", Severity::Info, "x");
    assert!(raised.apply_to_finding(&mut info_finding));
    assert_eq!(
        aggregate(&[info_finding], AggregationProfile::PolicyDriven),
        crate::Decision::Block
    );

    let mut agent_finding = Finding::new("remote-download", Severity::High, "x");
    assert!(lowered.apply_to_finding(&mut agent_finding));
    assert_eq!(
        aggregate(&[agent_finding], AggregationProfile::SeverityDriven),
        crate::Decision::Allow
    );
}

#[test]
fn invalid_external_values_are_not_reflected_in_diagnostics() {
    let cases = [
        (
            external_catalog(&[external_rule(
                "invalid id SECRET_ID",
                r#"{ kind: literal, pattern: "needle" }"#,
            )]),
            "SECRET_ID",
        ),
        (
            external_catalog(&[external_rule(
                "secret-regex",
                r#"{ kind: regex, pattern: "SECRET_REGEX[" }"#,
            )]),
            "SECRET_REGEX",
        ),
        (
            external_catalog(&[external_rule(
                "secret-language",
                r#"{ kind: literal, pattern: "needle" }"#,
            )])
            .replace("languages: [javascript]", "languages: [SECRET_LANGUAGE]"),
            "SECRET_LANGUAGE",
        ),
        (
            external_catalog(&[external_rule(
                "secret-field",
                r#"{ kind: literal, pattern: "needle" }"#,
            )])
            .replace(
                "policy_class: blocking",
                "SECRET_FIELD: value\n    policy_class: blocking",
            ),
            "SECRET_FIELD",
        ),
        ("SECRET_YAML: [unterminated".to_string(), "SECRET_YAML"),
        (
            external_catalog(&[
                external_rule(
                    "SECRET_DUPLICATE_ID",
                    r#"{ kind: literal, pattern: "one" }"#,
                ),
                external_rule(
                    "SECRET_DUPLICATE_ID",
                    r#"{ kind: literal, pattern: "two" }"#,
                ),
            ]),
            "SECRET_DUPLICATE_ID",
        ),
        (
            external_catalog(&[external_rule(
                "secret-uri",
                r#"{ kind: literal, pattern: "needle" }"#,
            )])
            .replace(GENERIC_HELP, "SECRET_INVALID_URI"),
            "SECRET_INVALID_URI",
        ),
    ];
    for (source, secret) in cases {
        let error = RuleCatalog::parse_yaml(&source, CatalogOrigin::External)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(secret), "diagnostic reflected `{secret}`");
    }

    let malformed = RuleOverride::from_str("remote-download=SECRET_OVERRIDE")
        .unwrap_err()
        .to_string();
    assert!(!malformed.contains("SECRET_OVERRIDE"));
    let unknown = RuleOverride::from_str("SECRET_UNKNOWN=off").unwrap();
    let error = EffectiveRuleSet::build(builtin_catalog().unwrap(), [unknown])
        .unwrap_err()
        .to_string();
    assert!(!error.contains("SECRET_UNKNOWN"));
}

#[test]
fn typed_builtin_parameter_defaults_are_closed_and_bounded() {
    let catalog = builtin_catalog().unwrap();
    let typo = match &catalog.get("typosquatting").unwrap().matcher {
        RuleMatcher::Builtin { parameters, .. } => parameters.typosquat().unwrap(),
        _ => panic!("expected builtin"),
    };
    assert_eq!(typo.max_edit_distance(), 1);
    assert_eq!(typo.min_length_for_distance_two(), 8);
    assert!(typo.edit_distance_enabled() && typo.keyboard_enabled());
    assert_eq!(typo.keyboard_layout().as_str(), "qwerty-us-v1");
    assert!(typo.unicode_confusables_enabled());
    assert_eq!(typo.confusables_profile().as_str(), "uts39-v1");
    let defaults = EffectiveRuleSet::build(catalog, []).unwrap();
    let shape = defaults
        .rule("version-shape-anomaly")
        .unwrap()
        .parameters()
        .npm_version_shape()
        .unwrap();
    assert_eq!(
        (
            shape.minimum_predecessors(),
            shape.baseline_transitions(),
            shape.minimum_history_days(),
            shape.maximum_jump_delay_hours(),
            shape.major_jump_threshold(),
            shape.minor_jump_threshold(),
        ),
        (6, 5, 30, 72, 2, 10)
    );
    let rapid = defaults
        .rule("rapid-publish-window")
        .unwrap()
        .parameters()
        .npm_rapid_publish()
        .unwrap();
    assert_eq!((rapid.window_hours(), rapid.package_threshold()), (24, 5));
}

#[test]
fn behavioral_parameter_overrides_are_typed_audited_and_order_independent() {
    let catalog = builtin_catalog().unwrap();
    let values = [
        "version-shape-anomaly=param:minimum_predecessors=8",
        "version-shape-anomaly=param:baseline_transitions=7",
        "rapid-publish-window=param:window_hours=48",
        "typosquatting=param:max_edit_distance=2",
    ];
    let build = |order: &[usize]| {
        EffectiveRuleSet::build(
            catalog,
            order
                .iter()
                .map(|index| RuleOverride::from_str(values[*index]).unwrap()),
        )
        .unwrap()
    };
    let first = build(&[0, 1, 2, 3]);
    assert_eq!(first.digest(), build(&[3, 2, 1, 0]).digest());
    assert_ne!(
        first.digest(),
        EffectiveRuleSet::build(catalog, []).unwrap().digest()
    );
    assert_eq!(first.applied_overrides().len(), 4);
    let shape = first
        .rule("version-shape-anomaly")
        .unwrap()
        .parameters()
        .npm_version_shape()
        .unwrap();
    assert_eq!(
        (shape.minimum_predecessors(), shape.baseline_transitions()),
        (8, 7)
    );
}

#[test]
fn parameter_overrides_reject_duplicates_wrong_targets_ranges_and_caps() {
    let catalog = builtin_catalog().unwrap();
    let parse = |value| RuleOverride::from_str(value).unwrap();
    assert!(EffectiveRuleSet::build(
        catalog,
        [
            parse("rapid-publish-window=param:window_hours=24"),
            parse("rapid-publish-window=param:window_hours=25"),
        ],
    )
    .is_err());
    for value in [
        "remote-download=param:window_hours=24",
        "version-shape-anomaly=param:minimum_predecessors=0",
        "version-shape-anomaly=param:minimum_predecessors=10001",
        "version-shape-anomaly=param:baseline_transitions=0",
        "version-shape-anomaly=param:baseline_transitions=10001",
        "version-shape-anomaly=param:minimum_history_days=0",
        "version-shape-anomaly=param:minimum_history_days=36501",
        "version-shape-anomaly=param:maximum_jump_delay_hours=0",
        "version-shape-anomaly=param:maximum_jump_delay_hours=8761",
        "version-shape-anomaly=param:major_jump_threshold=0",
        "version-shape-anomaly=param:major_jump_threshold=10001",
        "version-shape-anomaly=param:minor_jump_threshold=0",
        "version-shape-anomaly=param:minor_jump_threshold=10001",
        "rapid-publish-window=param:window_hours=0",
        "rapid-publish-window=param:window_hours=721",
        "rapid-publish-window=param:package_threshold=0",
        "rapid-publish-window=param:package_threshold=251",
        "typosquatting=param:max_edit_distance=3",
    ] {
        assert!(
            EffectiveRuleSet::build(catalog, [parse(value)]).is_err(),
            "{value}"
        );
    }
    assert!(EffectiveRuleSet::build(
        catalog,
        [
            parse("version-shape-anomaly=param:minimum_predecessors=5"),
            parse("version-shape-anomaly=param:baseline_transitions=5"),
        ],
    )
    .is_err());
    for value in [
        "typosquatting=param:keyboard_layout=qwerty-us-v1",
        "rapid-publish-window=param:maximum_search_objects=100",
        "version-shape-anomaly=param:cache_ttl_minutes=1",
        "version-shape-anomaly=param:policy_class=blocking",
        "rapid-publish-window=param:not_a_field=1",
        "rapid-publish-window=param:window_hours=-1",
    ] {
        assert!(RuleOverride::from_str(value).is_err(), "{value}");
    }
    for value in [
        "version-shape-anomaly=param:minimum_predecessors=10000",
        "version-shape-anomaly=param:baseline_transitions=1",
        "version-shape-anomaly=param:minimum_history_days=36500",
        "version-shape-anomaly=param:maximum_jump_delay_hours=8760",
        "version-shape-anomaly=param:major_jump_threshold=10000",
        "version-shape-anomaly=param:minor_jump_threshold=10000",
        "rapid-publish-window=param:window_hours=720",
        "rapid-publish-window=param:package_threshold=250",
        "typosquatting=param:max_edit_distance=2",
    ] {
        assert!(
            EffectiveRuleSet::build(catalog, [parse(value)]).is_ok(),
            "{value}"
        );
    }
}
