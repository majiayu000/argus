use super::{ExecutionContext, ScanConcurrency};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

#[test]
fn explicit_concurrency_accepts_only_contract_range() {
    assert_eq!(ScanConcurrency::new(1).unwrap().get(), 1);
    assert_eq!(ScanConcurrency::new(64).unwrap().get(), 64);
    assert_eq!(ScanConcurrency::new(0).unwrap_err().jobs(), 0);
    assert_eq!(ScanConcurrency::new(65).unwrap_err().jobs(), 65);
}

#[test]
fn automatic_concurrency_has_floor_and_cap() {
    for (available, expected) in [
        (None, 1),
        (Some(0), 1),
        (Some(1), 1),
        (Some(16), 16),
        (Some(128), 16),
    ] {
        assert_eq!(ScanConcurrency::automatic_from(available).get(), expected);
    }
}

#[test]
fn context_owns_exact_private_worker_count() {
    let context = ExecutionContext::new(ScanConcurrency::new(2).unwrap()).unwrap();
    assert_eq!(context.worker_threads(), 2);
}

#[test]
fn ordered_execution_uses_multiple_bounded_workers() {
    let context = ExecutionContext::new(ScanConcurrency::new(2).unwrap()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let threads = Mutex::new(HashSet::new());
    let inputs = [0, 1];
    let mut committed = Vec::new();

    context
        .execute_ordered(
            &inputs,
            None,
            |index, _| {
                threads.lock().unwrap().insert(std::thread::current().id());
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                barrier.wait();
                active.fetch_sub(1, Ordering::SeqCst);
                Ok::<_, &'static str>(index)
            },
            |index, output| {
                committed.push((index, output));
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(threads.lock().unwrap().len(), 2);
    assert_eq!(committed, vec![(0, 0), (1, 1)]);
}

#[test]
fn lowest_input_error_wins_independent_of_completion() {
    let context = ExecutionContext::new(ScanConcurrency::new(4).unwrap()).unwrap();
    let inputs = [0, 1, 2, 3];
    let error = context
        .execute_ordered(
            &inputs,
            None,
            |index, _| match index {
                1 => Err("lowest"),
                3 => Err("later"),
                _ => Ok(index),
            },
            |_, _| Ok(()),
        )
        .unwrap_err();
    assert_eq!(error, "lowest");
}

#[test]
fn subsystem_cap_bounds_each_window() {
    let context = ExecutionContext::new(ScanConcurrency::new(4).unwrap()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let inputs = [0, 1];

    context
        .execute_ordered(
            &inputs,
            Some(2),
            |_, _| {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                barrier.wait();
                active.fetch_sub(1, Ordering::SeqCst);
                Ok::<_, ()>(())
            },
            |_, _| Ok(()),
        )
        .unwrap();

    assert_eq!(peak.load(Ordering::SeqCst), 2);
}
