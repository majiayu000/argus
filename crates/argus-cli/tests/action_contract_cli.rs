use std::process::Command;

#[test]
fn version_is_exact_for_action_self_check() {
    let output = Command::new(env!("CARGO_BIN_EXE_argus"))
        .arg("--version")
        .output()
        .expect("run argus --version");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"argus 0.1.0\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn operational_error_is_stderr_only_with_exit_two() {
    let output = Command::new(env!("CARGO_BIN_EXE_argus"))
        .args([
            "scan",
            "/definitely/missing/argus-action-fixture",
            "--format",
            "json",
        ])
        .output()
        .expect("run missing-path scan");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}
