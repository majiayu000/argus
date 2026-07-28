use super::*;

fn session(records: &[String], overrides: &[String]) -> RuleSession {
    let temp = TempDir::new().unwrap();
    write_catalog(temp.path(), "rules.yaml", records);
    RuleSession::load(Some(temp.path()), overrides).unwrap()
}

#[test]
fn executable_language_extensions_and_case_variants_are_centralized() {
    let rules = [
        rule(
            "bash-marker",
            "bash",
            r#"{ kind: literal, pattern: "BASH_MARKER" }"#,
            "low",
            "blocking",
        ),
        rule(
            "python-marker",
            "python",
            r#"{ kind: literal, pattern: "PYTHON_MARKER" }"#,
            "low",
            "blocking",
        ),
        rule(
            "javascript-marker",
            "javascript",
            r#"{ kind: literal, pattern: "JAVASCRIPT_MARKER" }"#,
            "low",
            "blocking",
        ),
        rule(
            "typescript-marker",
            "typescript",
            r#"{ kind: literal, pattern: "TYPESCRIPT_MARKER" }"#,
            "low",
            "blocking",
        ),
    ];
    let session = session(&rules, &[]);
    let cases = [
        ("script.sh", "BASH_MARKER", "bash-marker"),
        ("script.BASH", "BASH_MARKER", "bash-marker"),
        ("script.ZsH", "BASH_MARKER", "bash-marker"),
        ("module.py", "PYTHON_MARKER", "python-marker"),
        ("module.PYI", "PYTHON_MARKER", "python-marker"),
        ("index.js", "JAVASCRIPT_MARKER", "javascript-marker"),
        ("index.CJS", "JAVASCRIPT_MARKER", "javascript-marker"),
        ("index.MjS", "JAVASCRIPT_MARKER", "javascript-marker"),
        ("view.JsX", "JAVASCRIPT_MARKER", "javascript-marker"),
        ("index.ts", "TYPESCRIPT_MARKER", "typescript-marker"),
        ("index.CTS", "TYPESCRIPT_MARKER", "typescript-marker"),
        ("index.MtS", "TYPESCRIPT_MARKER", "typescript-marker"),
        ("view.TsX", "TYPESCRIPT_MARKER", "typescript-marker"),
        (
            "package.json:scripts/postinstall.sh",
            "BASH_MARKER",
            "bash-marker",
        ),
    ];
    for (path, marker, expected_rule) in cases {
        let mut findings = Vec::new();
        session
            .scan_bytes(path, marker.as_bytes(), &mut findings)
            .unwrap();
        assert_eq!(findings.len(), 1, "{path}: {findings:?}");
        assert_eq!(findings[0].rule_id, expected_rule, "{path}");
    }

    for (path, marker) in [
        ("wrong.js", "PYTHON_MARKER"),
        ("unsupported.bin", "BASH_MARKER"),
    ] {
        let mut findings = Vec::new();
        session
            .scan_bytes(path, marker.as_bytes(), &mut findings)
            .unwrap();
        assert!(findings.is_empty(), "{path}: {findings:?}");
    }
}

#[test]
fn literal_and_unicode_regex_matching_are_bounded_and_one_per_file() {
    let rules = [
        rule(
            "case-literal",
            "text",
            r#"{ kind: literal, pattern: "Needle" }"#,
            "low",
            "blocking",
        ),
        rule(
            "unicode-regex",
            "text",
            r#"{ kind: regex, pattern: "[α-ω]+" }"#,
            "low",
            "blocking",
        ),
    ];
    let session = session(&rules, &[]);
    let mut findings = Vec::new();
    session
        .scan_bytes("case.txt", b"needle only", &mut findings)
        .unwrap();
    assert!(findings.is_empty());

    session
        .scan_bytes(
            "matches.txt",
            "Needle Needle\nαβγ and α".as_bytes(),
            &mut findings,
        )
        .unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].rule_id, "case-literal");
    assert_eq!(findings[1].rule_id, "unicode-regex");
    assert_eq!(findings[0].evidence.as_deref().unwrap(), ["matches.txt:1"]);
    assert_eq!(findings[1].evidence.as_deref().unwrap(), ["matches.txt:2"]);
    assert!(!format!("{:?}", findings).contains("αβγ"));
}

#[test]
fn eligible_input_byte_limit_accepts_equality_and_rejects_plus_one() {
    let session = session(
        &[rule(
            "bounded-input",
            "text",
            r#"{ kind: literal, pattern: "x" }"#,
            "low",
            "blocking",
        )],
        &[],
    );
    let mut findings = Vec::new();
    session
        .scan_bytes(
            "exact.txt",
            &vec![b'x'; MAX_EXTERNAL_INPUT_BYTES],
            &mut findings,
        )
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert!(session
        .scan_bytes(
            "overflow.txt",
            &vec![b'x'; MAX_EXTERNAL_INPUT_BYTES + 1],
            &mut Vec::new(),
        )
        .is_err());
}

#[test]
fn disabled_rules_short_circuit_before_input_decoding() {
    let id = "disabled-rule";
    let session = session(
        &[rule(
            id,
            "text",
            r#"{ kind: regex, pattern: "expensive.*matcher" }"#,
            "high",
            "blocking",
        )],
        &[format!("{id}=off")],
    );
    session
        .scan_bytes("invalid.txt", &[0xff], &mut Vec::new())
        .unwrap();
}
