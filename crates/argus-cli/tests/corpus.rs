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
