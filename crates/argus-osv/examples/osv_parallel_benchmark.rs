use anyhow::{bail, Context, Result};
use argus_core::{Ecosystem, ExecutionContext, PackageCoordinate, ScanConcurrency};
use argus_osv::client::{
    OsvClient, OsvTransport, ResponseLimits, TransportResponse, MAX_BATCH_QUERIES,
};
use argus_osv::{CoordinateQuery, CoordinateSet, OsvError};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;
use std::time::{Duration, Instant};

const QUERY_COUNT: usize = 4 * MAX_BATCH_QUERIES;
const DETAIL_COUNT: usize = 32;
const SERVICE_DELAY: Duration = Duration::from_millis(15);
const MEASURED_RUNS: usize = 5;
const MODIFIED: &str = "2026-07-27T00:00:00Z";

struct BenchmarkTransport {
    active: AtomicUsize,
    peak: AtomicUsize,
    query_barrier: Barrier,
    query_window: usize,
    detail_barrier: Barrier,
    detail_window: usize,
}

impl BenchmarkTransport {
    fn new(jobs: usize) -> Self {
        let query_window = jobs.min(4);
        let detail_window = jobs.min(8);
        Self {
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            query_barrier: Barrier::new(query_window),
            query_window,
            detail_barrier: Barrier::new(detail_window),
            detail_window,
        }
    }

    fn enter(&self) -> ActiveGuard<'_> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        ActiveGuard { transport: self }
    }

    fn response(value: Value) -> TransportResponse {
        TransportResponse {
            status: 200,
            content_type: Some("application/json".to_string()),
            body: serde_json::to_vec(&value).expect("benchmark JSON serialization"),
        }
    }
}

struct ActiveGuard<'a> {
    transport: &'a BenchmarkTransport,
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.transport.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl OsvTransport for BenchmarkTransport {
    fn post_query_batch(
        &self,
        body: &[u8],
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        let request: Value = serde_json::from_slice(body)
            .map_err(|error| OsvError::new(argus_osv::OsvErrorKind::Internal, error.to_string()))?;
        let queries = request["queries"].as_array().ok_or_else(|| {
            OsvError::new(
                argus_osv::OsvErrorKind::Internal,
                "benchmark request omitted queries",
            )
        })?;
        let first_name = queries
            .first()
            .and_then(|query| query["package"]["name"].as_str())
            .ok_or_else(|| {
                OsvError::new(
                    argus_osv::OsvErrorKind::Internal,
                    "benchmark request omitted first package name",
                )
            })?;
        let first_index = first_name
            .strip_prefix("package-")
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                OsvError::new(
                    argus_osv::OsvErrorKind::Internal,
                    "benchmark package index is malformed",
                )
            })?;
        let chunk_index = first_index / MAX_BATCH_QUERIES;

        let _active = self.enter();
        if chunk_index < self.query_window {
            self.query_barrier.wait();
        }
        std::thread::sleep(SERVICE_DELAY);

        let results = queries
            .iter()
            .map(|query| {
                let name = query["package"]["name"].as_str().unwrap_or_default();
                let vulns = if name == "package-0000" {
                    (0..DETAIL_COUNT)
                        .map(|index| {
                            json!({
                                "id": format!("GHSA-BENCH-{index:02}"),
                                "modified": MODIFIED
                            })
                        })
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                json!({"vulns":vulns})
            })
            .collect::<Vec<_>>();
        Ok(Self::response(json!({"results":results})))
    }

    fn get_advisory(
        &self,
        id: &str,
        _limits: ResponseLimits,
    ) -> Result<TransportResponse, OsvError> {
        let detail_index = id
            .strip_prefix("GHSA-BENCH-")
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                OsvError::new(
                    argus_osv::OsvErrorKind::Internal,
                    "benchmark detail ID is malformed",
                )
            })?;
        let _active = self.enter();
        if detail_index < self.detail_window {
            self.detail_barrier.wait();
        }
        std::thread::sleep(SERVICE_DELAY);
        Ok(Self::response(json!({
            "schema_version":"1.8.0",
            "id":id,
            "modified":MODIFIED,
            "affected":[{
                "package":{"ecosystem":"npm","name":"package-0000"},
                "versions":["1.0.0"]
            }]
        })))
    }
}

#[derive(Serialize)]
struct BenchmarkReport {
    environment: Environment,
    fixture: Fixture,
    output_sha256: String,
    results: Vec<JobResult>,
    note: &'static str,
}

#[derive(Serialize)]
struct Environment {
    os: &'static str,
    arch: &'static str,
    cpu_count: usize,
    rustc: String,
    commit: String,
    peak_rss_bytes: Option<u64>,
}

#[derive(Serialize)]
struct Fixture {
    query_count: usize,
    querybatch_chunks: usize,
    detail_count: usize,
    service_delay_ms: u128,
    sha256: String,
}

#[derive(Serialize)]
struct JobResult {
    jobs: usize,
    expected_peak: usize,
    observed_peak: usize,
    warmup_ms: f64,
    measured_ms: Vec<f64>,
    median_ms: f64,
    minimum_ms: f64,
    maximum_ms: f64,
    speedup_vs_jobs_1: f64,
}

struct Run {
    elapsed_ms: f64,
    peak: usize,
    output_sha256: String,
}

fn main() -> Result<()> {
    let coordinates = fixture()?;
    let fixture_bytes =
        serde_json_canonicalizer::to_vec(&coordinates).context("canonicalize fixture")?;
    let fixture_sha256 = sha256(&fixture_bytes);
    let mut results = Vec::new();
    let mut common_output = None::<String>;

    for jobs in [1, 2, 4, 8] {
        let warmup = run_once(&coordinates, jobs)?;
        verify_run(jobs, &warmup, &mut common_output)?;
        let mut measured = Vec::with_capacity(MEASURED_RUNS);
        let mut observed_peak = warmup.peak;
        for _ in 0..MEASURED_RUNS {
            let run = run_once(&coordinates, jobs)?;
            verify_run(jobs, &run, &mut common_output)?;
            observed_peak = observed_peak.max(run.peak);
            measured.push(run.elapsed_ms);
        }
        measured.sort_by(f64::total_cmp);
        results.push(JobResult {
            jobs,
            expected_peak: jobs.min(8),
            observed_peak,
            warmup_ms: warmup.elapsed_ms,
            median_ms: measured[MEASURED_RUNS / 2],
            minimum_ms: measured[0],
            maximum_ms: measured[MEASURED_RUNS - 1],
            measured_ms: measured,
            speedup_vs_jobs_1: 0.0,
        });
    }

    let baseline = results[0].median_ms;
    for result in &mut results {
        result.speedup_vs_jobs_1 = baseline / result.median_ms;
    }
    let report = BenchmarkReport {
        environment: Environment {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            cpu_count: std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1),
            rustc: command_output("rustc", &["--version"]),
            commit: command_output("git", &["rev-parse", "HEAD"]),
            peak_rss_bytes: None,
        },
        fixture: Fixture {
            query_count: QUERY_COUNT,
            querybatch_chunks: QUERY_COUNT.div_ceil(MAX_BATCH_QUERIES),
            detail_count: DETAIL_COUNT,
            service_delay_ms: SERVICE_DELAY.as_millis(),
            sha256: fixture_sha256,
        },
        output_sha256: common_output.context("benchmark produced no output digest")?,
        results,
        note: "Wall-clock speed is advisory; peak concurrency and output digest equality are hard assertions.",
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn fixture() -> Result<CoordinateSet> {
    CoordinateSet::new(
        (0..QUERY_COUNT)
            .map(|index| {
                CoordinateQuery::new(
                    PackageCoordinate::new(Ecosystem::Npm, format!("package-{index:04}"), "1.0.0")?,
                    [format!("fixture:{index:04}")],
                )
                .map_err(anyhow::Error::from)
            })
            .collect::<Result<Vec<_>>>()?,
        0,
    )
    .map_err(anyhow::Error::from)
}

fn run_once(coordinates: &CoordinateSet, jobs: usize) -> Result<Run> {
    let transport = BenchmarkTransport::new(jobs);
    let execution = ExecutionContext::new(ScanConcurrency::new(jobs)?)?;
    let started = Instant::now();
    let snapshot = OsvClient::new(&transport).query_with_context(coordinates, &execution)?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let output = serde_json_canonicalizer::to_vec(&snapshot)?;
    Ok(Run {
        elapsed_ms,
        peak: transport.peak.load(Ordering::SeqCst),
        output_sha256: sha256(&output),
    })
}

fn verify_run(jobs: usize, run: &Run, common_output: &mut Option<String>) -> Result<()> {
    let expected_peak = jobs.min(8);
    if run.peak != expected_peak {
        bail!(
            "jobs={jobs} observed peak {}, expected {expected_peak}",
            run.peak
        );
    }
    match common_output {
        Some(expected) if expected != &run.output_sha256 => {
            bail!("jobs={jobs} output digest changed")
        }
        Some(_) => {}
        None => *common_output = Some(run.output_sha256.clone()),
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn command_output(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_string())
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "unavailable".to_string())
}
