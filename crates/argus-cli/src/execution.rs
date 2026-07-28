//! CLI parsing for invocation-local scan concurrency.

use anyhow::Result;
use argus_core::{ExecutionContext, ScanConcurrency};

#[derive(clap::Args, Debug)]
pub(crate) struct ExecutionArgs {
    /// Number of bounded scan workers (1..=64).
    #[arg(long, value_name = "N", value_parser = parse_jobs)]
    jobs: Option<ScanConcurrency>,
}

impl ExecutionArgs {
    pub(crate) fn resolve(&self) -> Result<ExecutionContext> {
        Ok(ExecutionContext::new(
            self.jobs.unwrap_or_else(ScanConcurrency::automatic),
        )?)
    }
}

fn parse_jobs(raw: &str) -> Result<ScanConcurrency, String> {
    let jobs = raw
        .parse::<usize>()
        .map_err(|_| format!("jobs must be an integer in 1..=64, got `{raw}`"))?;
    ScanConcurrency::new(jobs).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_jobs;

    #[test]
    fn jobs_boundaries_are_typed() {
        assert_eq!(parse_jobs("1").unwrap().get(), 1);
        assert_eq!(parse_jobs("64").unwrap().get(), 64);
        for invalid in ["0", "65", "-1", "1.5", "many"] {
            assert!(parse_jobs(invalid).is_err(), "{invalid}");
        }
    }
}
