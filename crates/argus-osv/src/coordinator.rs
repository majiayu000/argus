use crate::client::MAX_OSV_IN_FLIGHT;
use crate::model::{OsvError, OsvErrorKind};
use argus_core::ExecutionContext;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub(crate) struct OsvCoordinator<'a> {
    execution: &'a ExecutionContext,
}

impl<'a> OsvCoordinator<'a> {
    pub(crate) fn new(execution: &'a ExecutionContext) -> Self {
        Self { execution }
    }

    pub(crate) fn window_size(&self) -> usize {
        self.execution.concurrency().get().min(MAX_OSV_IN_FLIGHT)
    }

    /// Execute one already bounded ascending window in the invocation pool.
    ///
    /// The caller reserves the complete window's request budget before this
    /// method dispatches any work. Results are joined and returned in input
    /// order, so the caller observes the lowest stable error.
    pub(crate) fn execute_window<I, O>(
        &self,
        inputs: &[I],
        work: impl Fn(usize, &I) -> Result<O, OsvError> + Sync,
    ) -> Result<Vec<O>, OsvError>
    where
        I: Sync,
        O: Send,
    {
        debug_assert!(inputs.len() <= self.window_size());
        let mut outputs = Vec::with_capacity(inputs.len());
        self.execution.execute_ordered(
            inputs,
            Some(MAX_OSV_IN_FLIGHT),
            |index, input| {
                catch_unwind(AssertUnwindSafe(|| work(index, input))).unwrap_or_else(|_| {
                    Err(OsvError::new(
                        OsvErrorKind::Internal,
                        "OSV transport worker panicked",
                    ))
                })
            },
            |_, output| {
                outputs.push(output);
                Ok(())
            },
        )?;
        Ok(outputs)
    }
}
