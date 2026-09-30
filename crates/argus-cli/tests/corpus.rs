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
fn parsed_checkout_numbers_preserve_taint() -> Result<()> {
    for (revision, tainted) in [
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
