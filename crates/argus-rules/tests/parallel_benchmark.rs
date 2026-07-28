use argus_core::{ExecutionContext, ScanConcurrency, ScanReport};
use argus_rules::{
    scan_package_dir_with_rules_and_context, scan_text_files_with_context, RuleSession,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

const FILE_COUNT: usize = 2_048;
const EXTERNAL_RULE_COUNT: usize = 16;
const SAMPLE_COUNT: usize = 5;

struct Fixture {
    name: &'static str,
    root: PathBuf,
    rules_root: Option<PathBuf>,
    rules: RuleSession,
    digest: String,
}

struct TimingRow {
    jobs: usize,
    median_ms: f64,
    minimum_ms: f64,
    maximum_ms: f64,
    rss_kib: Option<u64>,
    output_digest: String,
}

struct BenchmarkResult {
    fixture_digest: String,
    output_digest: String,
    rows: Vec<TimingRow>,
    base: Option<TimingRow>,
}

fn sha256_hex(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        let bytes = part.as_ref();
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    hex::encode(digest.finalize())
}

fn cpu_source(index: usize) -> String {
    let mut body = String::new();
    for line in 0..64 {
        body.push_str(&format!(
            "const value_{index}_{line} = ({index} + {line}) * 3;\n"
        ));
    }
    body.push_str(&format!(
        "export function compute_{index}(input) {{ return input + value_{index}_63; }}\n"
    ));
    body
}

fn external_source(index: usize) -> String {
    format!(
        "// ARGUS_BUCKET_{:02}\nexport const benchmark_{index} = {index};\n",
        index % EXTERNAL_RULE_COUNT
    )
}

fn rule_catalog() -> String {
    let mut raw = "schema_version: 1\nrules:\n".to_string();
    for index in 0..EXTERNAL_RULE_COUNT {
        raw.push_str(&format!(
            "  - {{ id: \"bench-{index:02}\", description: \"benchmark marker\", \
             policy_class: blocking, default_severity: high, \
             help_uri: \"https://example.test/bench-{index:02}\", \
             languages: [javascript], matcher: {{ kind: literal, \
             pattern: \"ARGUS_BUCKET_{index:02}\" }} }}\n"
        ));
    }
    raw
}

fn build_fixture(
    base: &Path,
    name: &'static str,
    source: fn(usize) -> String,
    external: bool,
) -> Fixture {
    let root = base.join(name).join("package");
    fs::create_dir_all(&root).unwrap();
    let package = format!(r#"{{"name":"{name}-benchmark","version":"1.0.0"}}"#);
    fs::write(root.join("package.json"), &package).unwrap();
    let mut fixture_parts = vec![package.into_bytes()];
    for index in 0..FILE_COUNT {
        let rel = format!("src/{:02}/source-{index:04}.js", index % 32);
        let body = source(index);
        let path = root.join(&rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &body).unwrap();
        fixture_parts.push(rel.into_bytes());
        fixture_parts.push(body.into_bytes());
    }
    let (rules_root, rules) = if external {
        let rules_root = base.join(name).join("rules");
        fs::create_dir_all(&rules_root).unwrap();
        let catalog = rule_catalog();
        fs::write(rules_root.join("benchmark.yaml"), &catalog).unwrap();
        fixture_parts.push(catalog.into_bytes());
        (
            Some(rules_root.clone()),
            RuleSession::load(Some(&rules_root), &[]).unwrap(),
        )
    } else {
        (None, RuleSession::builtin().unwrap())
    };
    Fixture {
        name,
        root,
        rules_root,
        rules,
        digest: sha256_hex(fixture_parts),
    }
}

fn normalized_report_digest(mut report: ScanReport) -> String {
    report.path = PathBuf::from("<fixture>");
    sha256_hex([serde_json::to_vec(&report).unwrap()])
}

fn scan_sample(fixture: &Fixture, jobs: usize) -> (Duration, String) {
    let execution = ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap();
    let started = Instant::now();
    let report =
        scan_package_dir_with_rules_and_context(&fixture.root, &fixture.rules, &execution).unwrap();
    (started.elapsed(), normalized_report_digest(report))
}

fn base_sample(binary: &Path, fixture: &Fixture) -> (Duration, String) {
    let mut command = Command::new(binary);
    command.args(["scan", fixture.root.to_str().unwrap(), "--format", "json"]);
    if let Some(rules_root) = &fixture.rules_root {
        command.args(["--rules-dir", rules_root.to_str().unwrap()]);
    }
    let started = Instant::now();
    let output = command.output().unwrap();
    let elapsed = started.elapsed();
    assert!(
        matches!(output.status.code(), Some(0 | 1)),
        "base scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut report: ScanReport = serde_json::from_slice(&output.stdout).unwrap();
    report.path = PathBuf::from("<fixture>");
    (elapsed, normalized_report_digest(report))
}

fn timing_row(jobs: usize, mut samples: Vec<Duration>, output_digest: String) -> TimingRow {
    samples.sort();
    TimingRow {
        jobs,
        median_ms: milliseconds(samples[SAMPLE_COUNT / 2]),
        minimum_ms: milliseconds(samples[0]),
        maximum_ms: milliseconds(samples[SAMPLE_COUNT - 1]),
        rss_kib: current_rss_kib(),
        output_digest,
    }
}

fn benchmark_fixture(fixture: &Fixture, base_binary: Option<&Path>) -> BenchmarkResult {
    let mut baseline_digest = None;
    let mut rows = Vec::new();
    for jobs in [1, 2, 4, 8] {
        let _warmup = scan_sample(fixture, jobs);
        let mut samples = Vec::new();
        let mut digest = String::new();
        for _ in 0..SAMPLE_COUNT {
            let (elapsed, actual_digest) = scan_sample(fixture, jobs);
            samples.push(elapsed);
            digest = actual_digest;
        }
        if let Some(expected) = &baseline_digest {
            assert_eq!(&digest, expected, "{} jobs={jobs}", fixture.name);
        } else {
            baseline_digest = Some(digest.clone());
        }
        rows.push(timing_row(jobs, samples, digest));
    }
    let base = base_binary.map(|binary| {
        let _warmup = base_sample(binary, fixture);
        let mut samples = Vec::new();
        let mut digest = String::new();
        for _ in 0..SAMPLE_COUNT {
            let (elapsed, actual_digest) = base_sample(binary, fixture);
            samples.push(elapsed);
            digest = actual_digest;
        }
        timing_row(1, samples, digest)
    });
    BenchmarkResult {
        fixture_digest: fixture.digest.clone(),
        output_digest: baseline_digest.unwrap(),
        rows,
        base,
    }
}

fn scanner_worker_evidence(root: &Path) -> (usize, usize) {
    let jobs = 8;
    let execution = ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap();
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let arrivals = AtomicUsize::new(0);
    let names = Mutex::new(BTreeSet::new());
    let barrier = Arc::new(Barrier::new(jobs));
    scan_text_files_with_context(root, 1024 * 1024, &execution, |_file| {
        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(current, Ordering::SeqCst);
        names.lock().unwrap().insert(
            std::thread::current()
                .name()
                .expect("named invocation worker")
                .to_string(),
        );
        if arrivals.fetch_add(1, Ordering::SeqCst) < jobs {
            barrier.wait();
        }
        active.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    })
    .unwrap();
    let name_count = names.lock().unwrap().len();
    (peak.load(Ordering::SeqCst), name_count)
}

fn capture(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn git_identity() -> (String, bool, String, String, String) {
    let head = capture("git", &["rev-parse", "HEAD"]);
    let status = capture("git", &["status", "--porcelain"]);
    let root = PathBuf::from(capture("git", &["rev-parse", "--show-toplevel"]));
    let diff = Command::new("git")
        .args(["diff", "--no-ext-diff", "--binary", "HEAD"])
        .output()
        .map(|output| output.stdout)
        .unwrap_or_default();
    let report_path = std::env::var_os("ARGUS_BENCH_REPORT")
        .and_then(|path| PathBuf::from(path).canonicalize().ok());
    let mut patch_parts = vec![diff.clone()];
    let untracked = Command::new("git")
        .current_dir(&root)
        .args(["ls-files", "--others", "--exclude-standard"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default();
    for relative in untracked.lines() {
        let path = root.join(relative);
        if path.canonicalize().ok() == report_path {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            patch_parts.push(relative.as_bytes().to_vec());
            patch_parts.push(bytes);
        }
    }
    (
        head,
        status != "unavailable" && !status.is_empty(),
        sha256_hex([status.as_bytes()]),
        sha256_hex([diff]),
        sha256_hex(patch_parts),
    )
}

fn cpu_model() -> String {
    let model = capture("sysctl", &["-n", "machdep.cpu.brand_string"]);
    if model != "unavailable" {
        return model;
    }
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|raw| {
            raw.lines()
                .find_map(|line| line.strip_prefix("model name\t: "))
                .map(str::to_string)
        })
        .unwrap_or(model)
}

fn current_rss_kib() -> Option<u64> {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        if let Some(value) = status
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .and_then(|line| line.split_whitespace().next())
            .and_then(|value| value.parse().ok())
        {
            return Some(value);
        }
    }
    capture("ps", &["-o", "rss=", "-p", &std::process::id().to_string()])
        .parse()
        .ok()
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn append_fixture_report(report: &mut String, fixture: &Fixture, result: &BenchmarkResult) {
    report.push_str(&format!(
        "## {} fixture\n\n\
         - files: {FILE_COUNT}\n\
         - fixture SHA-256: `{}`\n\
         - current output SHA-256: `{}`\n",
        fixture.name, result.fixture_digest, result.output_digest
    ));
    if let Some(base) = &result.base {
        let regression = (result.rows[0].median_ms - base.median_ms) / base.median_ms * 100.0;
        report.push_str(&format!(
            "- serial base output SHA-256: `{}`\n\
             - serial base median/range: {:.3} ms / {:.3}–{:.3} ms\n\
             - current jobs=1 vs serial base: {regression:+.2}%\n\
             - base/current output identity: `{}`\n",
            base.output_digest,
            base.median_ms,
            base.minimum_ms,
            base.maximum_ms,
            base.output_digest == result.output_digest
        ));
    } else {
        report.push_str(
            "- serial base: not measured (set `ARGUS_BENCH_BASE_BINARY` to an \
             `001056f`-equivalent release binary)\n",
        );
    }
    report.push_str(
        "\n| jobs | median ms | range ms | RSS KiB after samples |\n\
         |---:|---:|---:|---:|\n",
    );
    for row in &result.rows {
        assert_eq!(row.output_digest, result.output_digest);
        report.push_str(&format!(
            "| {} | {:.3} | {:.3}–{:.3} | {} |\n",
            row.jobs,
            row.median_ms,
            row.minimum_ms,
            row.maximum_ms,
            row.rss_kib
                .map_or_else(|| "unavailable".to_string(), |value| value.to_string())
        ));
    }
    report.push('\n');
}

#[test]
#[ignore = "manual reproducible benchmark; timing is advisory, never a CI threshold"]
fn parallel_scanner_benchmark_report() {
    let fixture_root = tempfile::tempdir().unwrap();
    let cpu = build_fixture(fixture_root.path(), "cpu-only", cpu_source, false);
    let external = build_fixture(fixture_root.path(), "external-heavy", external_source, true);
    let (worker_peak, worker_ids) = scanner_worker_evidence(&cpu.root);
    assert_eq!(worker_peak, 8);
    assert_eq!(worker_ids, 8);

    let base_binary = std::env::var_os("ARGUS_BENCH_BASE_BINARY").map(PathBuf::from);
    let cpu_result = benchmark_fixture(&cpu, base_binary.as_deref());
    let external_result = benchmark_fixture(&external, base_binary.as_deref());
    let (head, dirty, status_digest, diff_digest, patch_digest) = git_identity();
    let base_identity =
        std::env::var("ARGUS_BENCH_BASE_IDENTITY").unwrap_or_else(|_| "not supplied".to_string());
    let mut report = format!(
        "# GH-143 parallel scanner benchmark\n\n\
         Generated by `cargo test --release -p argus-rules --test \
         parallel_benchmark -- --ignored --nocapture`.\n\n\
         Timing is advisory and is not a CI threshold. Output digests and worker \
         bounds are hard assertions.\n\n\
         - head: `{head}`\n\
         - worktree dirty: `{dirty}`\n\
         - porcelain status SHA-256: `{status_digest}`\n\
         - HEAD diff SHA-256: `{diff_digest}`\n\
         - full worktree patch SHA-256 (excluding this report): `{patch_digest}`\n\
         - serial base identity: `{base_identity}`\n\
         - CPU: {}\n\
         - OS: `{}`\n\
         - rustc: `{}`\n\
         - scanner worker evidence at jobs=8: peak={worker_peak}, \
         unique worker IDs={worker_ids}\n\
         - protocol: one warmup plus {SAMPLE_COUNT} measured samples per jobs value\n\n",
        cpu_model(),
        capture("uname", &["-a"]),
        capture("rustc", &["--version"]),
    );
    append_fixture_report(&mut report, &cpu, &cpu_result);
    append_fixture_report(&mut report, &external, &external_result);
    println!("{report}");
    if let Ok(path) = std::env::var("ARGUS_BENCH_REPORT") {
        fs::write(path, report).unwrap();
    }
}
