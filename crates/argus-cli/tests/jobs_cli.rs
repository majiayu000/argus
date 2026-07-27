use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_argus"))
        .args(args)
        .output()
        .unwrap()
}

fn assert_jobs_preflight(mut prefix: Vec<&str>) {
    for invalid in ["0", "65", "-1", "1.5", "many"] {
        let added = if invalid == "-1" {
            prefix.push("--jobs=-1");
            1
        } else {
            prefix.extend(["--jobs", invalid]);
            2
        };
        let output = run(&prefix);
        assert_eq!(output.status.code(), Some(2), "{prefix:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("jobs"), "{prefix:?}: {stderr}");
        prefix.truncate(prefix.len() - added);
    }
}

#[test]
fn invalid_jobs_fail_before_every_scan_or_network_route() {
    for args in [
        vec!["scan", "/definitely/missing"],
        vec!["fetch", "demo", "--registry", "http://127.0.0.1:9"],
        vec!["pypi-fetch", "demo", "--registry", "http://127.0.0.1:9"],
        vec!["crates-fetch", "demo", "--registry", "http://127.0.0.1:9"],
        vec!["go-fetch", "demo", "--registry", "http://127.0.0.1:9"],
        vec!["nuget-fetch", "demo", "--registry", "http://127.0.0.1:9"],
        vec!["maven-fetch", "a:b", "--registry", "http://127.0.0.1:9"],
        vec!["gems-fetch", "demo", "--registry", "http://127.0.0.1:9"],
        vec!["composer-fetch", "a/b", "--registry", "http://127.0.0.1:9"],
        vec!["agent", "scan", "/definitely/missing"],
        vec![
            "vulns",
            "package",
            "--ecosystem",
            "npm",
            "--name",
            "demo",
            "--version",
            "1.0.0",
            "--cache-dir",
            "/definitely/missing",
        ],
        vec![
            "vulns",
            "lockfile",
            "/definitely/missing/package-lock.json",
            "--cache-dir",
            "/definitely/missing",
        ],
        vec!["corpus", "test", "--corpus", "/definitely/missing"],
        vec!["corpus", "eval", "--corpus", "/definitely/missing"],
    ] {
        assert_jobs_preflight(args);
    }
}

#[test]
fn valid_boundaries_are_accepted_by_clap() {
    for jobs in ["1", "2", "64"] {
        let output = run(&["scan", "/definitely/missing", "--jobs", jobs]);
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("invalid value"), "{stderr}");
        assert!(stderr.contains("path is neither"), "{stderr}");
    }
}

#[test]
fn unrelated_intel_commands_do_not_accept_jobs() {
    let output = run(&["intel", "--jobs", "2"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
}
