use anyhow::Result;
use serde_json::json;
use std::process::Command;

#[test]
fn missing_corpus_case_paths_fail_closed() -> Result<()> {
    for (id, kind, surface) in [
        ("missing-agent", "fixture", Some("agent-skill")),
        ("missing-package", "fixture", None),
        ("missing-lockfile", "lockfile", None),
    ] {
        let corpus = tempfile::tempdir()?;
        let index = json!({
            "surface": surface,
            "cases": [{
                "id": id,
                "kind": kind,
                "path": "fixtures/missing",
                "expectedDecision": "allow",
                "rules": []
            }]
        });
        std::fs::write(
            corpus.path().join("index.json"),
            serde_json::to_vec_pretty(&index)?,
        )?;

        let output = Command::new(env!("CARGO_BIN_EXE_argus"))
            .args(["corpus", "test", "--corpus"])
            .arg(corpus.path())
            .output()?;
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
