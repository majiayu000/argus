use anyhow::Result;
use serde_json::json;
use std::path::Path;
use std::process::{Command, Output};

fn run_case(
    corpus_root: &Path,
    id: &str,
    kind: &str,
    case_path: &str,
    surface: Option<&str>,
) -> Result<Output> {
    let index = json!({
        "surface": surface,
        "cases": [{
            "id": id,
            "kind": kind,
            "path": case_path,
            "expectedDecision": "allow",
            "rules": []
        }]
    });
    std::fs::write(
        corpus_root.join("index.json"),
        serde_json::to_vec_pretty(&index)?,
    )?;

    Ok(Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(["corpus", "test", "--corpus"])
        .arg(corpus_root)
        .output()?)
}

fn assert_failed_with(output: Output, diagnostic: &str) -> Result<()> {
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!(
        output.status.code(),
        Some(1),
        "corpus unexpectedly passed:\n{stdout}"
    );
    assert!(
        stdout.contains(diagnostic),
        "missing diagnostic `{diagnostic}`:\n{stdout}"
    );
    Ok(())
}

#[test]
fn missing_corpus_case_paths_fail_closed() -> Result<()> {
    for (id, kind, surface) in [
        ("missing-agent", "fixture", Some("agent-skill")),
        ("missing-package", "fixture", None),
        ("missing-lockfile", "lockfile", None),
    ] {
        let corpus = tempfile::tempdir()?;
        let output = run_case(corpus.path(), id, kind, "fixtures/missing", surface)?;
        let stdout = String::from_utf8(output.stdout)?;

        assert_eq!(
            output.status.code(),
            Some(1),
            "missing case `{id}` did not fail closed:\n{stdout}"
        );
        assert!(
            stdout.contains("case path unavailable"),
            "missing case `{id}` lacked a clear diagnostic:\n{stdout}"
        );
    }

    Ok(())
}

#[test]
fn absolute_case_path_is_rejected() -> Result<()> {
    let corpus = tempfile::tempdir()?;
    let fixture = corpus.path().join("fixture");
    std::fs::create_dir_all(&fixture)?;
    let declared = fixture.to_string_lossy().into_owned();

    let output = run_case(
        corpus.path(),
        "absolute",
        "fixture",
        &declared,
        Some("agent-skill"),
    )?;
    assert_failed_with(output, "case path must be relative")
}

#[test]
fn parent_escape_case_path_is_rejected() -> Result<()> {
    let sandbox = tempfile::tempdir()?;
    let corpus = sandbox.path().join("corpus");
    let outside = sandbox.path().join("outside");
    std::fs::create_dir_all(&corpus)?;
    std::fs::create_dir_all(&outside)?;

    let output = run_case(
        &corpus,
        "parent-escape",
        "fixture",
        "../outside",
        Some("agent-skill"),
    )?;
    assert_failed_with(output, "case path escapes index root")
}

#[cfg(unix)]
#[test]
fn symlink_escape_case_path_is_rejected() -> Result<()> {
    use std::os::unix::fs::symlink;

    let sandbox = tempfile::tempdir()?;
    let corpus = sandbox.path().join("corpus");
    let outside = sandbox.path().join("outside");
    std::fs::create_dir_all(&corpus)?;
    std::fs::create_dir_all(&outside)?;
    symlink(&outside, corpus.join("linked"))?;

    let output = run_case(
        &corpus,
        "symlink-escape",
        "fixture",
        "linked",
        Some("agent-skill"),
    )?;
    assert_failed_with(output, "case path escapes index root")
}

#[test]
fn fixture_case_path_must_be_directory() -> Result<()> {
    let corpus = tempfile::tempdir()?;
    std::fs::write(corpus.path().join("SKILL.md"), "# benign")?;

    let output = run_case(
        corpus.path(),
        "fixture-file",
        "fixture",
        "SKILL.md",
        Some("agent-skill"),
    )?;
    assert_failed_with(output, "fixture path must be a directory")
}

#[test]
fn lockfile_case_path_must_be_regular_file() -> Result<()> {
    let corpus = tempfile::tempdir()?;
    std::fs::create_dir_all(corpus.path().join("lockfile-dir"))?;

    let output = run_case(
        corpus.path(),
        "lockfile-dir",
        "lockfile",
        "lockfile-dir",
        None,
    )?;
    assert_failed_with(output, "lockfile path must be a regular file")
}

#[test]
fn agent_fixture_eval_reports_scoped_confusion_matrix() -> Result<()> {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/agent");
    let output = Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(["corpus", "eval", "--corpus"])
        .arg(&corpus)
        .args(["--format", "json"])
        .output()?;
    assert!(
        output.status.success(),
        "eval failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["dataset_type"], "synthetic-fixtures");
    assert_eq!(report["sample_count"], 39);
    assert_eq!(report["true_positives"], 31);
    assert_eq!(report["false_positives"], 0);
    assert_eq!(report["false_negatives"], 0);
    assert_eq!(report["true_negatives"], 8);
    assert_eq!(report["precision"], 1.0);
    assert_eq!(report["recall"], 1.0);
    Ok(())
}

#[test]
fn checkout_ref_state_products_report_operational_errors() -> Result<()> {
    let operand = "github.event.action && github.event.number";
    let regions = format!(
        "refs/pull/{}/head",
        "${{ github.event.action && github.event.number }}".repeat(30)
    );
    let arguments = std::iter::repeat_n(operand, 30)
        .collect::<Vec<_>>()
        .join(", ");
    let formatted = format!("${{{{ format('refs/pull/{{0}}/head', {arguments}) }}}}");
    for revision in [regions, formatted] {
        let root = tempfile::tempdir()?;
        let workflows = root.path().join(".github/workflows");
        std::fs::create_dir_all(&workflows)?;
        std::fs::write(
            workflows.join("test.yml"),
            format!(
                "name: State boundary\non: workflow_run\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: {revision}\n"
            ),
        )?;
        let output = Command::new(env!("CARGO_BIN_EXE_argus"))
            .args(["agent", "scan"])
            .arg(root.path())
            .args(["--format", "json"])
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)?
            .contains("checkout ref exceeds 1024 symbolic alternatives"));
    }
    Ok(())
}

#[test]
fn checkout_ref_symbolic_bytes_and_yaml_trim() -> Result<()> {
    let regions = "${{ github.event.action && github.event.number }}".repeat(10);
    let arguments = std::iter::repeat_n("github.event.action && github.event.number", 10)
        .collect::<Vec<_>>()
        .join(", ");
    let mut cases = Vec::new();
    let separators = "github.event.action == 'a' && 'a' || github.event.action == 'b' && 'b' || github.event.action == 'c' && 'c' || 'd'";
    for delta in [-1isize, 0, 1] {
        let source = "x".repeat((262144isize + delta) as usize);
        let array_source = "x".repeat((262143isize + delta) as usize);
        let array_separators = ['a', 'b', 'c', 'd']
            .into_iter()
            .enumerate()
            .map(|(index, character)| {
                let value = format!(
                    "'{}'",
                    character.to_string().repeat((131072isize + delta) as usize)
                );
                if index == 3 {
                    value
                } else {
                    format!("github.event.action == '{index}' && {value}")
                }
            })
            .collect::<Vec<_>>()
            .join(" || ");
        for revision in [
            format!("${{{{ join('{source}', {separators}) }}}}"),
            format!("${{{{ join(fromJSON('[\"{array_source}\",\"\"]'), {separators}) }}}}"),
            format!("${{{{ join(fromJSON('[\"\",\"\",\"\"]'), {array_separators}) }}}}"),
            format!(
                "${{{{ join(github.event.action && '{source}' || '{}', github.event.action && 'a' || 'b') }}}}",
                "y".repeat((262144isize + delta) as usize)
            ),
        ] {
            cases.push((revision, false, delta > 0));
        }
    }
    for size in [919, 920, 8192] {
        let literal = "x".repeat(size);
        for revision in [
            format!("{literal}{regions}"),
            format!("{regions}{literal}"),
            format!("${{{{ format('{literal}', {arguments}) }}}}"),
        ] {
            cases.push((revision, false, size != 919));
        }
    }
    for (escape, tainted) in [
        ("\\N", false),
        ("\\x1c", false),
        ("\\x1d", false),
        ("\\x1e", false),
        ("\\x1f", false),
        (" ", true),
        ("\\t", true),
        ("\\r", true),
        ("\\n", true),
        ("\\uFEFF", true),
        ("\\u00A0", true),
        ("\\u2028", true),
        ("\\u2029", true),
    ] {
        cases.push((
            format!("\"{escape}refs/pull/${{{{ github.event.number }}}}/head\""),
            tainted,
            false,
        ));
        cases.push((
            format!("\"refs/pull/${{{{ github.event.number }}}}/head{escape}\""),
            tainted,
            false,
        ));
    }
    for (revision, tainted, oversized) in cases {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            let root = tempfile::tempdir()?;
            let workflows = root.path().join(".github/workflows");
            std::fs::create_dir_all(&workflows)?;
            std::fs::write(
                workflows.join("test.yml"),
                format!(
                    "name: Byte and trim boundary\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: {revision}\n"
                ),
            )?;
            let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                .args(["agent", "scan"])
                .arg(root.path())
                .args(["--format", "json"])
                .output()?;
            if oversized && trigger != "pull_request" {
                assert_eq!(output.status.code(), Some(2), "{trigger}: {revision}");
                assert!(output.stdout.is_empty());
                assert!(String::from_utf8(output.stderr)?
                    .contains("checkout ref exceeds 1048576 bytes of symbolic output"));
            } else {
                let blocked = tainted && trigger != "pull_request";
                assert_eq!(output.status.code(), Some(i32::from(blocked)));
                assert!(output.stderr.is_empty());
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(report["decision"], if blocked { "block" } else { "allow" });
                assert_eq!(
                    report["findings"]
                        .as_array()
                        .expect("findings")
                        .iter()
                        .any(
                            |finding| finding["rule_id"] == "AGT-06-workflow-untrusted-checkout"
                                && finding["severity"] == "critical"
                        ),
                    blocked
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_format_length_overflow_reports_an_operational_error() -> Result<()> {
    let revision = "${{ format(format('refs/pull/{{0}}/head{0}', format('{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}', '{1}{1}{1}{1}{1}{1}{1}{1}{1}{1}')), github.event.number, '') }}";
    for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
        let root = tempfile::tempdir()?;
        let workflows = root.path().join(".github/workflows");
        std::fs::create_dir_all(&workflows)?;
        std::fs::write(
            workflows.join("test.yml"),
            format!(
                "name: Format length boundary\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: {revision}\n"
            ),
        )?;
        let output = Command::new(env!("CARGO_BIN_EXE_argus"))
            .args(["agent", "scan"])
            .arg(root.path())
            .args(["--format", "json"])
            .output()?;
        if trigger == "pull_request" {
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(report["decision"], "allow");
        } else {
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8(output.stderr)?.contains("checkout ref format exceeds"));
        }
    }
    Ok(())
}

#[test]
fn parsed_checkout_numbers_preserve_taint() -> Result<()> {
    for (revision, tainted) in [
        (
            "refs/pull/${{ join(github.event.*.number, '') }}/head",
            true,
        ),
        (
            "refs/pull/${{ join(fromJSON(toJSON(github.event.*)).*.number, '') }}/head",
            true,
        ),
        (
            "refs/pull/${{ join(github.event.*.number[0], '') }}/head",
            false,
        ),
        (
            "refs/pull/${{ join(github.event['*'].number, '') }}/head",
            false,
        ),
        (
            "refs/pull/${{ toJSON(join(github.event.*.number, '')) }}/head",
            false,
        ),
        (
            "refs/pull/${{ fromJSON(format('{0}.0', github.event.number)) }}/head",
            true,
        ),
        (
            "refs/pull/${{ fromJSON(format('[{0}]', github.event.number))[0.5] }}/head",
            true,
        ),
        (
            "refs/pull/${{ fromJSON(format('\"{0}.0\"', github.event.number)) }}/head",
            false,
        ),
        (
            "refs/pull/${{ fromJSON(format('[42,{0}]', github.event.number))[0.5] }}/head",
            false,
        ),
        (
            "refs/pull/${{ join(fromJSON(format('{{\"n\":{0}}}', github.event.number)).*, '') }}/head",
            true,
        ),
        (
            "refs/pull/${{ join(fromJSON(format('[{0}]', github.event.number)).*, '') }}/head",
            true,
        ),
        (
            "refs/pull/${{ fromJSON(format('[42,{0}]', github.event.number)).*[0] }}/head",
            false,
        ),
        (
            "refs/pull/${{ fromJSON(format('{0}0e-1', github.event.number)) }}/head",
            true,
        ),
        (
            "refs/pull/${{ fromJSON(format('{0}0e-2', github.event.number)) }}/head",
            false,
        ),
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            let fixture = tempfile::tempdir()?;
            let workflows = fixture.path().join(".github/workflows");
            std::fs::create_dir_all(&workflows)?;
            std::fs::write(
                workflows.join("triage.yml"),
                format!(
                    "name: Numeric checkout\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: {revision}\n"
                ),
            )?;
            let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                .args(["agent", "scan"])
                .arg(fixture.path())
                .args(["--format", "json"])
                .output()?;
            let blocks = tainted && trigger != "pull_request";
            assert_eq!(output.status.code(), Some(i32::from(blocks)));
            assert!(output.stderr.is_empty());
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(report["decision"], if blocks { "block" } else { "allow" });
            assert_eq!(
                report["findings"]
                    .as_array()
                    .expect("scan findings")
                    .iter()
                    .filter(|finding| {
                        finding["rule_id"] == "AGT-06-workflow-untrusted-checkout"
                            && finding["severity"] == "critical"
                    })
                    .count(),
                usize::from(blocks)
            );
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_root_projection_hex_and_nesting() -> Result<()> {
    let mut cases = vec![
        (
            "refs/pull/${{ join(github.*.*.number, '') }}/head".to_string(),
            true,
            false,
        ),
        (
            "refs/pull/${{ join(GitHub.*.*[format('num{0}', 'ber')], '') }}/merge".to_string(),
            true,
            false,
        ),
        (
            "refs/pull/${{ join(github.*.*.missing, '') }}/head".to_string(),
            false,
            false,
        ),
        (
            "refs/pull/${{ join(github['*'].*.number, '') }}/head".to_string(),
            false,
            false,
        ),
        (
            "refs/pull/${{ join(github.*['*'].number, '') }}/head".to_string(),
            false,
            false,
        ),
        (
            "refs/pull/${{ toJSON(join(github.*.*.number, '')) }}/head".to_string(),
            false,
            false,
        ),
        (
            "refs/pull/${{ join(github.*.*.number[0], '') }}/head".to_string(),
            false,
            false,
        ),
        (
            "refs/pull/${{ join(github.*.number, '') }}/head".to_string(),
            true,
            false,
        ),
        (
            "refs/pull/${{ join(fromJSON(toJSON(github.*)).*.number, '') }}/head".to_string(),
            true,
            false,
        ),
        (
            "refs/pull/${{ join(github.*.missing, '') }}/head".to_string(),
            false,
            false,
        ),
        (
            "refs/pull/${{ join(github['*'].number, '') }}/head".to_string(),
            false,
            false,
        ),
        (
            "refs/pull/${{ toJSON(join(github.*.number, '')) }}/head".to_string(),
            false,
            false,
        ),
        (
            "refs/pull/${{ 0x0 && github.event.number }}/head".to_string(),
            false,
            false,
        ),
        (
            "refs/pull/${{ 0X00 && github.event.number }}/head".to_string(),
            false,
            false,
        ),
        (
            "refs/pull/${{ 0xff && github.event.number }}/head".to_string(),
            true,
            false,
        ),
        (
            "refs/pull/${{ !0x0 && github.event.number }}/head".to_string(),
            true,
            false,
        ),
        (
            "refs/pull/${{ '0x0' && github.event.number }}/head".to_string(),
            true,
            false,
        ),
    ];
    for depth in [256, 257, 2048] {
        cases.push((
            format!(
                "refs/pull/${{{{ {}github.event.number || github.event.number{} }}}}/head",
                "(".repeat(depth),
                ")".repeat(depth)
            ),
            true,
            depth > 256,
        ));
    }
    for (revision, tainted, oversized) in cases {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            let root = tempfile::tempdir()?;
            let workflows = root.path().join(".github/workflows");
            std::fs::create_dir_all(&workflows)?;
            std::fs::write(workflows.join("test.yml"), format!("name: Root and literal boundary\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: {revision}\n"))?;
            let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                .args(["agent", "scan"])
                .arg(root.path())
                .args(["--format", "json"])
                .output()?;
            if oversized && trigger != "pull_request" {
                assert_eq!(output.status.code(), Some(2));
                assert!(output.stdout.is_empty());
                assert!(String::from_utf8(output.stderr)?
                    .contains("checkout ref exceeds 256 levels of expression nesting"));
            } else {
                let blocked = tainted && trigger != "pull_request";
                assert_eq!(
                    output.status.code(),
                    Some(i32::from(blocked)),
                    "{trigger}: {revision}"
                );
                assert!(output.stderr.is_empty());
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(report["decision"], if blocked { "block" } else { "allow" });
                assert_eq!(
                    report["findings"]
                        .as_array()
                        .expect("findings")
                        .iter()
                        .any(
                            |finding| finding["rule_id"] == "AGT-06-workflow-untrusted-checkout"
                                && finding["severity"] == "critical"
                        ),
                    blocked
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_named_projection_and_unary_depth() -> Result<()> {
    let mut cases = vec![
        ("refs/pull/${{ join(github.*.pull_request.number, '') }}/head".to_string(), true, false),
        ("refs/pull/${{ join(GitHub.*[format('pull_{0}', 'request')].number, '') }}/merge".to_string(), true, false),
        ("refs/pull/${{ join(github.*.pull_request[format('num{0}', 'ber')], '') }}/head".to_string(), true, false),
        ("refs/pull/${{ false || join(github.*.pull_request.number, '') }}/head".to_string(), true, false),
        ("refs/pull/${{ join(github.*.missing.number, '') }}/head".to_string(), false, false),
        ("refs/pull/${{ join(github.*.pull_request.missing, '') }}/head".to_string(), false, false),
        ("refs/pull/${{ join(github.*.pull_requests.number, '') }}/head".to_string(), false, false),
        ("refs/pull/${{ join(github['*'].pull_request.number, '') }}/head".to_string(), false, false),
        ("refs/pull/${{ join(github.*['*'].number, '') }}/head".to_string(), false, false),
        ("refs/pull/${{ toJSON(join(github.*.pull_request.number, '')) }}/head".to_string(), false, false),
        ("refs/pull/${{ join('github.*.pull_request.number', '') }}/head".to_string(), false, false),
        ("refs/pull/${{ join(fromJSON('[{}]').*.pull_request.number, '') }}/head".to_string(), false, false),
        ("refs/pull/${{ join(fromJSON('[{\"pull_request\":{}}]').*.pull_request.number, '') }}/head".to_string(), false, false),
        ("refs/pull/${{ true && '42' || join(github.*.pull_request.number, '') }}/head".to_string(), false, false),
        ("${{ github.ref }}".to_string(), false, false),
    ];
    for depth in [255, 256, 257] {
        for expression in [
            format!("{}true", "!".repeat(depth)),
            format!("{}true", "! ".repeat(depth)),
            format!("!{}true{}", "(".repeat(depth - 1), ")".repeat(depth - 1)),
            format!(
                "{}{}true{}",
                "!(".repeat(depth / 2),
                if depth % 2 == 0 { "" } else { "!" },
                ")".repeat(depth / 2)
            ),
        ] {
            cases.push((
                format!("refs/pull/${{{{ {expression} }}}}/head"),
                false,
                depth > 256,
            ));
        }
        let inner = if depth % 2 == 0 { "true" } else { "false" };
        cases.push((
            format!(
                "refs/pull/${{{{ {}{inner} && github.event.number }}}}/head",
                "!".repeat(depth)
            ),
            true,
            depth > 256,
        ));
    }
    for expression in [
        format!("'{}'", "!".repeat(1024)),
        format!("'{}''{}'", "!".repeat(256), "!".repeat(256)),
        format!("{}true || {}true", "!".repeat(256), "!".repeat(256)),
        format!(
            "format('{{0}}{{1}}', {}true, {}true)",
            "!".repeat(255),
            "!".repeat(255)
        ),
        "!0xff && github.event.number".to_string(),
        "github.event.action != 'opened' && '42'".to_string(),
    ] {
        cases.push((
            format!("refs/pull/${{{{ {expression} }}}}/head"),
            false,
            false,
        ));
    }
    for (revision, tainted, oversized) in cases {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            let root = tempfile::tempdir()?;
            let workflows = root.path().join(".github/workflows");
            std::fs::create_dir_all(&workflows)?;
            std::fs::write(workflows.join("test.yml"), format!("name: Named and unary boundary\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: {revision}\n"))?;
            let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                .args(["agent", "scan"])
                .arg(root.path())
                .args(["--format", "json"])
                .output()?;
            if oversized && trigger != "pull_request" {
                assert_eq!(output.status.code(), Some(2));
                assert!(output.stdout.is_empty());
                assert!(String::from_utf8(output.stderr)?
                    .contains("checkout ref exceeds 256 levels of expression nesting"));
            } else {
                let blocked = tainted && trigger != "pull_request";
                assert_eq!(
                    output.status.code(),
                    Some(i32::from(blocked)),
                    "{trigger}: {revision}"
                );
                assert!(output.stderr.is_empty());
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(report["decision"], if blocked { "block" } else { "allow" });
                assert_eq!(
                    report["findings"]
                        .as_array()
                        .expect("findings")
                        .iter()
                        .any(
                            |finding| finding["rule_id"] == "AGT-06-workflow-untrusted-checkout"
                                && finding["severity"] == "critical"
                        ),
                    blocked
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_access_chain_depth() -> Result<()> {
    let mut cases = Vec::new();
    for depth in [255, 256, 257] {
        for expression in [
            format!("github{}", ".a".repeat(depth)),
            format!("github{}", ".*".repeat(depth)),
            format!("github{}", "['a']".repeat(depth)),
            format!("{}github{}", "!".repeat(128), ".a".repeat(depth - 128)),
            format!(
                "{}github{}{}",
                "(".repeat(128),
                ".a".repeat(depth - 128),
                ")".repeat(128)
            ),
            format!("(github{}){}", ".a".repeat(128), ".a".repeat(depth - 129)),
            format!("fromJSON(toJSON(github)){}", ".a".repeat(depth - 2)),
            format!(
                "github{}[github{}]",
                ".a".repeat(128),
                ".a".repeat(depth - 129)
            ),
            format!("(github{} || true).a", ".a".repeat(depth - 2)),
        ] {
            cases.push((
                format!("refs/pull/${{{{ {expression} }}}}/head"),
                false,
                depth > 256,
            ));
        }
    }
    for expression in [
        format!("'{}'", ".![]()".repeat(1024)),
        format!("'{}''{}'", ".a".repeat(256), ".a".repeat(256)),
        format!("{}0.5", "!".repeat(256)),
        format!("{}0xff", "!".repeat(256)),
        format!("{}1.25e-3{}", "(".repeat(256), ")".repeat(256)),
        format!("github{} || github{}", ".a".repeat(256), ".b".repeat(256)),
        format!(
            "format('{{0}}{{1}}', github{}, github{})",
            ".a".repeat(255),
            ".b".repeat(255)
        ),
    ] {
        cases.push((
            format!("refs/pull/${{{{ {expression} }}}}/head"),
            false,
            false,
        ));
    }
    for expression in [
        format!("{}github.event.number{}", "(".repeat(256), ")".repeat(256)),
        format!("github{} || github.event.number", ".a".repeat(256)),
        format!("{}false || github.event.number", "!".repeat(256)),
    ] {
        cases.push((
            format!("refs/pull/${{{{ {expression} }}}}/head"),
            true,
            false,
        ));
    }
    for (revision, tainted, oversized) in cases {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            let root = tempfile::tempdir()?;
            let workflows = root.path().join(".github/workflows");
            std::fs::create_dir_all(&workflows)?;
            std::fs::write(workflows.join("test.yml"), format!("name: Named and unary boundary\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: {revision}\n"))?;
            let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                .args(["agent", "scan"])
                .arg(root.path())
                .args(["--format", "json"])
                .output()?;
            if oversized && trigger != "pull_request" {
                assert_eq!(output.status.code(), Some(2));
                assert!(output.stdout.is_empty());
                assert!(String::from_utf8(output.stderr)?
                    .contains("checkout ref exceeds 256 levels of expression nesting"));
            } else {
                let blocked = tainted && trigger != "pull_request";
                assert_eq!(
                    output.status.code(),
                    Some(i32::from(blocked)),
                    "{trigger}: {revision}"
                );
                assert!(output.stderr.is_empty());
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(report["decision"], if blocked { "block" } else { "allow" });
                assert_eq!(
                    report["findings"]
                        .as_array()
                        .expect("findings")
                        .iter()
                        .any(
                            |finding| finding["rule_id"] == "AGT-06-workflow-untrusted-checkout"
                                && finding["severity"] == "critical"
                        ),
                    blocked
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_workflow_run_wildcard_and_json_bytes() -> Result<()> {
    let mut cases = Vec::new();
    for expression in [
        "join(github.event.*.pull_requests.*.number, '')",
        "join(github.*.*.pull_requests.*.number, '')",
        "join(github.event.*['pull_requests'].*['number'], '')",
        "join(fromJSON(toJSON(github.event)).*.pull_requests.*.number, '')",
        "join(github.event.*.pull_requests.*.number, '-')",
    ] {
        for suffix in ["head", "merge"] {
            cases.push((expression.to_string(), suffix, true, false));
        }
    }
    for expression in [
        "join(github.event.*.pull_requests.*.missing, '')",
        "join(github.event.*.wrong.*.number, '')",
        "join(github.event.*.pull_requests.*.numbered, '')",
        "join(github.event.*.pull_requests.*.title, '')",
        "join(fromJSON('[{\"number\":42}]').*.number, '')",
        "'github.event.*.pull_requests.*.number'",
    ] {
        cases.push((expression.to_string(), "head", false, false));
    }
    for levels in [3, 4, 5] {
        cases.push((
            format!(
                "{}'{}'{} && github.event.number",
                "toJSON(".repeat(levels),
                "\\".repeat(64 * 1024),
                ")".repeat(levels)
            ),
            "head",
            true,
            levels > 3,
        ));
    }
    for extra in [0, 1, 2] {
        let value = format!(
            "{}{}",
            "\\".repeat((1048576 - 4) / 2),
            "a".repeat(extra + 1)
        );
        cases.push((
            format!("toJSON('{value}') && github.event.number"),
            "head",
            true,
            extra == 2,
        ));
    }
    let first = "\\".repeat((1048576 - 4) / 4);
    for suffix in ["a", "ab", "abc"] {
        let second = format!("{}{suffix}", &first[..first.len() - 1]);
        cases.push((
            format!("toJSON(inputs.x && '{first}' || '{second}') && github.event.number"),
            "head",
            true,
            suffix.len() == 3,
        ));
    }
    for (expression, suffix, tainted, oversized) in cases {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            let root = tempfile::tempdir()?;
            let workflows = root.path().join(".github/workflows");
            std::fs::create_dir_all(&workflows)?;
            std::fs::write(workflows.join("test.yml"), format!("name: Workflow JSON\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: refs/pull/${{{{ {expression} }}}}/{suffix}\n"))?;
            let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                .args(["agent", "scan"])
                .arg(root.path())
                .args(["--format", "json"])
                .output()?;
            if oversized && trigger != "pull_request" {
                assert_eq!(output.status.code(), Some(2));
                assert!(output.stdout.is_empty());
                assert!(String::from_utf8(output.stderr)?
                    .contains("checkout ref exceeds 1048576 bytes of symbolic output"));
            } else {
                let blocked = tainted && trigger != "pull_request";
                assert_eq!(
                    output.status.code(),
                    Some(i32::from(blocked)),
                    "{trigger}: expression length {}",
                    expression.len()
                );
                assert!(output.stderr.is_empty());
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(report["decision"], if blocked { "block" } else { "allow" });
                assert_eq!(
                    report["findings"]
                        .as_array()
                        .expect("findings")
                        .iter()
                        .any(
                            |finding| finding["rule_id"] == "AGT-06-workflow-untrusted-checkout"
                                && finding["severity"] == "critical"
                        ),
                    blocked
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_missing_parsed_properties_preserve_truthiness() -> Result<()> {
    let mut cases = Vec::new();
    for missing in [
        "fromJSON('{}').missing",
        "fromJSON('{\"present\":1}').MISSING",
        "fromJSON('{}')['missing']",
        "fromJSON('{}')[format('mis{0}', 'sing')]",
        "fromJSON('[]')[0]",
        "fromJSON('[42]')[1]",
        "fromJSON('[42]')['missing']",
        "fromJSON('[42]')[-1]",
        "fromJSON('{\"child\":{}}').child.missing",
        "fromJSON('[{}]')[0].missing",
        "fromJSON('{}').missing.more",
        "fromJSON('[[]]')[0][0]",
        "fromJSON('[null]')[0]",
        "fromJSON('{\"value\":null}').value",
        "fromJSON('{\"value\":false}').value",
        "fromJSON('{\"value\":0}').value",
        "fromJSON('{\"value\":\"\"}').value",
    ] {
        cases.push((format!("{missing} && github.event.number"), false));
        cases.push((format!("{missing} || github.event.number"), true));
        cases.push((format!("{missing} || '42'"), false));
    }
    for (expression, blocked) in [
        ("fromJSON('[{}]').*.missing && github.event.number", true),
        ("fromJSON('[{}]').*.missing || github.event.number", false),
        ("join(fromJSON('[{}]').*.missing, '') && github.event.number", false),
        ("join(fromJSON('[{}]').*.missing, '') || github.event.number", true),
        ("fromJSON('{}').* && github.event.number", true),
        ("fromJSON('{}').* || github.event.number", false),
        ("!fromJSON('{}').missing && github.event.number", true),
        ("fromJSON(format('{{\"number\":{0}}}', github.event.number)).number", true),
        ("fromJSON(format('[{0}]', github.event.number))[0]", true),
        ("fromJSON(format('{{\"child\":{{\"number\":{0}}}}}', github.event.number)).child.number", true),
        ("join(fromJSON(format('[{{\"number\":{0}}}]', github.event.number)).*.number, '')", true),
        ("inputs.unknown.missing && github.event.number", true),
        ("fromJSON('[42]')[inputs.index] && github.event.number", true),
        ("fromJSON('{\"present\":true}')[inputs.key] && github.event.number", true),
        ("fromJSON('{\"present\":true}')[inputs.key] || github.event.number", true),
        ("fromJSON(inputs.json).missing && github.event.number", true),
    ] {
        cases.push((expression.to_string(), blocked));
    }
    for (expression, tainted) in cases {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            for suffix in ["head", "merge"] {
                let root = tempfile::tempdir()?;
                let workflows = root.path().join(".github/workflows");
                std::fs::create_dir_all(&workflows)?;
                std::fs::write(workflows.join("test.yml"), format!("name: Missing parsed property\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: refs/pull/${{{{ {expression} }}}}/{suffix}\n"))?;
                let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                    .args(["agent", "scan"])
                    .arg(root.path())
                    .args(["--format", "json"])
                    .output()?;
                let blocked = tainted && trigger != "pull_request";
                assert_eq!(
                    output.status.code(),
                    Some(i32::from(blocked)),
                    "{trigger}: {expression}"
                );
                assert!(output.stderr.is_empty());
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(report["decision"], if blocked { "block" } else { "allow" });
                assert_eq!(
                    report["findings"]
                        .as_array()
                        .expect("findings")
                        .iter()
                        .any(
                            |finding| finding["rule_id"] == "AGT-06-workflow-untrusted-checkout"
                                && finding["severity"] == "critical"
                        ),
                    blocked
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_json_templates_preserve_bracket_literals() -> Result<()> {
    for (expression, tainted) in [
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', github.event.number)).selected", true),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', github['event']['number']))['selected']", true),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"text\":\"don''t\",\"selected\":{0}}}', github.event.number)).selected", true),
        ("fromJSON(format('{{\"padding\":[[\"number\"]],\"selected\":{{\"numbers\":[{0}]}}}}', github.event.number)).selected.numbers[0]", true),
        ("join(fromJSON(format('[{{\"padding\":[\"number\"],\"selected\":{0}}}]', github.event.number)).*.selected, '')", true),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', github.event.workflow_run.pull_requests[0].number)).selected", true),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', github.event.number))['selected']", true),
        ("fromJSON('[\"number\"]')[0] && github['event']['number']", true),
        ("fromJSON('[\"number\"]')[0] || github.event.number", false),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":false}}', github.event.number)).selected && github.event.number", false),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', 42, github.event.number)).selected", false),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":\"github.event.number\"}}', github.event.number)).selected", false),
        ("'github[''event''][''number'']'", false),
        ("'don''t [\"number\"]' || github.event.number", false),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":null}}', github.event.number)).selected && github.event.number", false),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', github.event.number)).missing && github.event.number", false),
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            for suffix in ["head", "merge"] {
                let root = tempfile::tempdir()?;
                let workflows = root.path().join(".github/workflows");
                std::fs::create_dir_all(&workflows)?;
                std::fs::write(workflows.join("test.yml"), format!("name: Quoted JSON template\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: refs/pull/${{{{ {expression} }}}}/{suffix}\n"))?;
                let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                    .args(["agent", "scan"])
                    .arg(root.path())
                    .args(["--format", "json"])
                    .output()?;
                let blocked = tainted && trigger != "pull_request";
                assert_eq!(output.status.code(), Some(i32::from(blocked)), "{trigger}: {expression}");
                assert!(output.stderr.is_empty());
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(report["decision"], if blocked { "block" } else { "allow" });
                assert_eq!(report["findings"].as_array().expect("findings").iter().any(|finding|
                    finding["rule_id"] == "AGT-06-workflow-untrusted-checkout" && finding["severity"] == "critical"
                ), blocked);
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_serialized_context_format_retains_identity() -> Result<()> {
    for (expression, tainted) in [
        ("fromJSON(format('{0}', toJSON(github))).event.number", true),
        ("fromJSON(format('{0}', toJSON(github.event))).number", true),
        ("fromJSON(format('{0}', toJSON(github.event.pull_request))).number", true),
        ("fromJSON(format('{0}', toJSON(github.event.workflow_run))).pull_requests[0].number", true),
        ("fromJSON(format('{0}', toJSON(GitHub['Event'])))['pull_request']['number']", true),
        ("fromJSON(format('{0}', toJSON(github))).event[format('num{0}', 'ber')]", true),
        ("fromJSON(format('{{\"selected\":{0}}}', toJSON(github))).selected.event.number", true),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', toJSON(github.event))).selected.number", true),
        ("join(fromJSON(format('{0}', toJSON(github.event.*), 'unused padding for the existing format bound')).*.number, '')", true),
        ("join(fromJSON(format('{0}', toJSON(github.*))).*.pull_request.number, '')", true),
        ("join(fromJSON(format('{0}', toJSON(github.event.*))).*.pull_requests.*.number, '')", true),
        ("fromJSON(fromJSON(format('{0}', toJSON(toJSON(github))))).event.number", true),
        ("fromJSON(format('{0}', join(toJSON(github), ''))).event.number", true),
        ("fromJSON(format('{0}', toJSON(fromJSON('{\"event\":{\"number\":42}}')))).event.number", false),
        ("fromJSON(format('{0}', toJSON('github.event.number')))", false),
        ("fromJSON(format('{0}', toJSON(github.event))).workflow_run.number", false),
        ("join(fromJSON(format('{0}', toJSON(github.event.*))).*.numbered, '')", false),
        ("fromJSON(format('{{\"selected\":42}}', toJSON(github.event))).selected", false),
        ("fromJSON(format('{{\"selected\":\"github.event.number\"}}', toJSON(github.event))).selected", false),
        ("fromJSON(format('{0}', toJSON(github))) && '42'", false),
        ("fromJSON(format('{0}', toJSON(github))) || github.event.number", false),
        ("fromJSON(format('{{\"text\":\"don''t [\\\"number\\\"]\",\"number\":42}}', toJSON(github.event))).number", false),
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            for suffix in ["head", "merge"] {
                let root = tempfile::tempdir()?;
                let workflows = root.path().join(".github/workflows");
                std::fs::create_dir_all(&workflows)?;
                std::fs::write(workflows.join("test.yml"), format!("name: Serialized context\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: refs/pull/${{{{ {expression} }}}}/{suffix}\n"))?;
                let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                    .args(["agent", "scan"]).arg(root.path()).args(["--format", "json"]).output()?;
                let blocked = tainted && trigger != "pull_request";
                assert_eq!(output.status.code(), Some(i32::from(blocked)), "{trigger}: {expression}");
                assert!(output.stderr.is_empty());
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(report["decision"], if blocked { "block" } else { "allow" });
                assert_eq!(report["findings"].as_array().expect("findings").iter().any(|finding|
                    finding["rule_id"] == "AGT-06-workflow-untrusted-checkout" && finding["severity"] == "critical"
                ), blocked);
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_access_path_bytes_fail_before_discarding() -> Result<()> {
    let sources = (0..64)
        .map(|index| format!("github.a{index:02}"))
        .collect::<Vec<_>>()
        .join(" || ");
    for delta in [-1isize, 0, 1] {
        let property = "x".repeat((16372isize + delta) as usize);
        let access = format!("({sources}).{property}");
        for expression in [
            access.clone(),
            format!("!({access})"),
            format!("!({access}) && github.event.number"),
            format!("({sources})[format('{{0}}', '{property}')]"),
            format!("!(({sources})[format('{{0}}', '{property}')])"),
        ] {
            for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
                let root = tempfile::tempdir()?;
                let workflows = root.path().join(".github/workflows");
                std::fs::create_dir_all(&workflows)?;
                std::fs::write(workflows.join("test.yml"), format!("name: Access byte boundary\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: ${{{{ {expression} }}}}\n"))?;
                let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                    .args(["agent", "scan"])
                    .arg(root.path())
                    .args(["--format", "json"])
                    .output()?;
                if delta > 0 && trigger != "pull_request" {
                    assert_eq!(output.status.code(), Some(2), "oversized access: {trigger}");
                    assert!(output.stdout.is_empty());
                    assert!(String::from_utf8(output.stderr)?
                        .contains("checkout ref exceeds 1048576 bytes of symbolic output"));
                } else {
                    assert_eq!(output.status.code(), Some(0));
                    assert!(output.stderr.is_empty());
                    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                    assert_eq!(report["decision"], "allow");
                }
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_serialized_context_keeps_existing_length_error() -> Result<()> {
    for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
        for suffix in ["head", "merge"] {
            let root = tempfile::tempdir()?;
            let workflows = root.path().join(".github/workflows");
            std::fs::create_dir_all(&workflows)?;
            std::fs::write(workflows.join("test.yml"), format!("name: Existing format bound\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: refs/pull/${{{{ join(fromJSON(format('{{0}}', toJSON(github.event.*))).*.number, '') }}}}/{suffix}\n"))?;
            let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                .args(["agent", "scan"])
                .arg(root.path())
                .args(["--format", "json"])
                .output()?;
            if trigger == "pull_request" {
                assert_eq!(output.status.code(), Some(0));
                assert!(output.stderr.is_empty());
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(report["decision"], "allow");
            } else {
                assert_eq!(output.status.code(), Some(2));
                assert!(output.stdout.is_empty());
                assert!(String::from_utf8(output.stderr)?.contains("checkout ref format exceeds"));
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_bracket_wildcard_selectors_match_dot_projections() -> Result<()> {
    for (expression, tainted) in [
        ("join(github.event[*].number, '')", true),
        ("join(GitHub[ * ].number, '')", true),
        ("join(github[*][*].number, '')", true),
        (
            "join(github.event.workflow_run.pull_requests[*].number, '')",
            true,
        ),
        ("join(github.event[*].pull_requests[*].number, '')", true),
        ("join(fromJSON(toJSON(github.event))[*].number, '')", true),
        (
            "join(fromJSON(format('[{{\"n\":{0}}}]', github.event.number))[*].n, '')",
            true,
        ),
        ("join(github.event['*'].number, '')", false),
        ("join(github.event[format('{0}', '*')].number, '')", false),
        ("join(github.event[*].missing, '')", false),
        (
            "join(github.event.workflow_run.pull_requests['*'].number, '')",
            false,
        ),
        ("join(fromJSON('[{\"number\":42}]')[*].number, '')", false),
        (
            "join(fromJSON('{\"*\":{\"number\":42}}')['*'].number, '')",
            false,
        ),
        ("'github.event[*].number'", false),
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            for suffix in ["head", "merge"] {
                let root = tempfile::tempdir()?;
                let workflows = root.path().join(".github/workflows");
                std::fs::create_dir_all(&workflows)?;
                std::fs::write(workflows.join("test.yml"), format!("name: Bracket wildcard\non: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: refs/pull/${{{{ {expression} }}}}/{suffix}\n"))?;
                let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                    .args(["agent", "scan"])
                    .arg(root.path())
                    .args(["--format", "json"])
                    .output()?;
                let blocked = tainted && trigger != "pull_request";
                assert_eq!(
                    output.status.code(),
                    Some(i32::from(blocked)),
                    "{trigger}: {expression}"
                );
                assert!(output.stderr.is_empty());
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                assert_eq!(report["decision"], if blocked { "block" } else { "allow" });
                assert_eq!(
                    report["findings"]
                        .as_array()
                        .expect("findings")
                        .iter()
                        .any(
                            |finding| finding["rule_id"] == "AGT-06-workflow-untrusted-checkout"
                                && finding["severity"] == "critical"
                        ),
                    blocked
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_concrete_access_bytes_fail_before_discarding() -> Result<()> {
    let keys = (0..64)
        .map(|bits| {
            let key = (0..6)
                .map(|bit| if bits & (1 << bit) == 0 { 'x' } else { 'X' })
                .collect::<String>();
            format!("'{key}'")
        })
        .collect::<Vec<_>>();
    let keys = keys[..63]
        .iter()
        .rev()
        .enumerate()
        .fold(keys[63].clone(), |rest, (index, key)| {
            format!("github.condition{index} && {key} || ({rest})")
        });
    for delta in [-1isize, 0, 1] {
        let value = "v".repeat((16384isize + delta) as usize);
        let access = format!("fromJSON('{{\"xxxxxx\":\"{value}\"}}')[{keys}]");
        for expression in [access.clone(), format!("!({access})")] {
            for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
                let root = tempfile::tempdir()?;
                let workflows = root.path().join(".github/workflows");
                std::fs::create_dir_all(&workflows)?;
                std::fs::write(workflows.join("test.yml"), format!("on: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: ${{{{ {expression} }}}}\n"))?;
                let output = Command::new(env!("CARGO_BIN_EXE_argus"))
                    .args(["agent", "scan"])
                    .arg(root.path())
                    .args(["--format", "json"])
                    .output()?;
                if delta > 0 && trigger != "pull_request" {
                    assert_eq!(output.status.code(), Some(2));
                    assert!(output.stdout.is_empty());
                    assert!(String::from_utf8(output.stderr)?
                        .contains("checkout ref exceeds 1048576 bytes of symbolic output"));
                } else {
                    assert_eq!(output.status.code(), Some(0));
                    assert!(output.stderr.is_empty());
                    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                    assert_eq!(report["decision"], "allow");
                }
            }
        }
    }
    Ok(())
}

#[test]
fn checkout_ref_many_empty_format_arguments_remain_allowed() -> Result<()> {
    let arguments = std::iter::repeat_n("''", 32768)
        .collect::<Vec<_>>()
        .join(",");
    let root = tempfile::tempdir()?;
    let workflows = root.path().join(".github/workflows");
    std::fs::create_dir_all(&workflows)?;
    std::fs::write(workflows.join("test.yml"), format!("on: pull_request_target\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          ref: ${{{{ format({arguments}) }}}}\n"))?;
    let output = Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(["agent", "scan"])
        .arg(root.path())
        .args(["--format", "json"])
        .output()?;
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["decision"], "allow");
    Ok(())
}
