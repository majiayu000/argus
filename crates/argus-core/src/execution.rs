//! Bounded, invocation-local execution for deterministic scan work.

use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuildError};
use std::error::Error;
use std::fmt;
use std::num::NonZeroUsize;

/// Validated scan worker count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanConcurrency(NonZeroUsize);

impl ScanConcurrency {
    /// Largest explicit worker count accepted by public and CLI APIs.
    pub const MAX_EXPLICIT: usize = 64;
    /// Automatic worker counts are capped to avoid surprising oversubscription.
    pub const MAX_AUTOMATIC: usize = 16;

    /// Validate an explicit worker count.
    pub fn new(jobs: usize) -> Result<Self, ScanConcurrencyError> {
        if !(1..=Self::MAX_EXPLICIT).contains(&jobs) {
            return Err(ScanConcurrencyError { jobs });
        }
        Ok(Self(NonZeroUsize::new(jobs).expect("validated as nonzero")))
    }

    /// Resolve the worker count from this process' available parallelism.
    pub fn automatic() -> Self {
        Self::automatic_from(
            std::thread::available_parallelism()
                .ok()
                .map(NonZeroUsize::get),
        )
    }

    /// Deterministic automatic-resolution seam for callers and tests.
    pub fn automatic_from(available: Option<usize>) -> Self {
        let jobs = available.unwrap_or(1).clamp(1, Self::MAX_AUTOMATIC);
        Self(NonZeroUsize::new(jobs).expect("automatic jobs are clamped to nonzero"))
    }

    pub fn get(self) -> usize {
        self.0.get()
    }
}

impl Default for ScanConcurrency {
    fn default() -> Self {
        Self::automatic()
    }
}

/// Error returned for an explicit worker count outside `1..=64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanConcurrencyError {
    jobs: usize,
}

impl ScanConcurrencyError {
    pub fn jobs(self) -> usize {
        self.jobs
    }
}

impl fmt::Display for ScanConcurrencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "scan concurrency must be in 1..={}, got {}",
            ScanConcurrency::MAX_EXPLICIT,
            self.jobs
        )
    }
}

impl Error for ScanConcurrencyError {}

/// Error constructing an invocation-local execution pool.
#[derive(Debug)]
pub struct ExecutionContextError(ThreadPoolBuildError);

impl fmt::Display for ExecutionContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "failed to build scan worker pool: {}", self.0)
    }
}

impl Error for ExecutionContextError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

/// A single private Rayon pool owned by one scan invocation.
///
/// Inputs passed to [`execute_ordered`](Self::execute_ordered) must already be
/// in their canonical stable order. Work is dispatched in bounded windows,
/// joined, and then committed in input order. This makes error selection and
/// global-budget accounting independent of worker completion order.
pub struct ExecutionContext {
    concurrency: ScanConcurrency,
    pool: ThreadPool,
}

impl fmt::Debug for ExecutionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionContext")
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}

impl ExecutionContext {
    pub fn new(concurrency: ScanConcurrency) -> Result<Self, ExecutionContextError> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(concurrency.get())
            .thread_name(|index| format!("argus-scan-{index}"))
            .build()
            .map_err(ExecutionContextError)?;
        Ok(Self { concurrency, pool })
    }

    /// Construct the deterministic compatibility context used by legacy APIs.
    pub fn serial() -> Result<Self, ExecutionContextError> {
        Self::new(ScanConcurrency::new(1).expect("one is valid"))
    }

    pub fn concurrency(&self) -> ScanConcurrency {
        self.concurrency
    }

    /// Execute owned per-input work in parallel and reduce it in stable order.
    ///
    /// `subsystem_cap` may lower concurrency for a subsystem such as OSV, but
    /// never raises it above the invocation's validated worker count.
    pub fn execute_ordered<I, O, E, Work, Commit>(
        &self,
        inputs: &[I],
        subsystem_cap: Option<usize>,
        work: Work,
        mut commit: Commit,
    ) -> Result<(), E>
    where
        I: Sync,
        O: Send,
        E: Send,
        Work: Fn(usize, &I) -> Result<O, E> + Sync,
        Commit: FnMut(usize, O) -> Result<(), E>,
    {
        let window_size = subsystem_cap
            .unwrap_or(self.concurrency.get())
            .clamp(1, self.concurrency.get());

        if window_size == 1 {
            for (index, input) in inputs.iter().enumerate() {
                commit(index, work(index, input)?)?;
            }
            return Ok(());
        }

        for (window_index, window) in inputs.chunks(window_size).enumerate() {
            let start = window_index
                .checked_mul(window_size)
                .expect("input slice index cannot overflow usize");
            let results: Vec<Result<O, E>> = self.pool.install(|| {
                window
                    .par_iter()
                    .enumerate()
                    .map(|(offset, input)| work(start + offset, input))
                    .collect()
            });

            for (offset, result) in results.into_iter().enumerate() {
                commit(start + offset, result?)?;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn worker_threads(&self) -> usize {
        self.pool.current_num_threads()
    }
}

#[cfg(test)]
mod tests;
