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
    assert_eq!(report["sample_count"], 38);
    assert_eq!(report["true_positives"], 30);
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
