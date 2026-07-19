use std::process::{Command, Output};

fn argus(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .output()
        .expect("run argus CLI")
}

#[test]
fn npm_anomaly_cli_help_documents_opt_in_and_cache() {
    let output = argus(&["fetch", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--metadata-anomaly"), "{help}");
    assert!(help.contains("--metadata-cache-dir"), "{help}");
    assert!(help.contains("Disabled by default"), "{help}");
}

#[test]
fn npm_anomaly_cli_rejects_silent_cache_configuration() {
    for format in ["text", "json", "sarif"] {
        let output = argus(&[
            "fetch",
            "demo",
            "--metadata-cache-dir",
            "/tmp/argus-unused-metadata-cache",
            "--format",
            format,
        ]);
        assert_eq!(output.status.code(), Some(2), "format={format}");
        assert!(output.stdout.is_empty(), "format={format}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("--metadata-cache-dir requires --metadata-anomaly"),
            "format={format}: {error}"
        );
    }
}

#[test]
fn npm_anomaly_cli_operational_error_never_emits_a_report() {
    for format in ["text", "json", "sarif"] {
        let output = argus(&[
            "fetch",
            "demo",
            "--metadata-anomaly",
            "--registry",
            "not-a-url",
            "--format",
            format,
        ]);
        assert_eq!(output.status.code(), Some(2), "format={format}");
        assert!(output.stdout.is_empty(), "format={format}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("registry URL"), "format={format}: {error}");
    }
}
