use argus_core::{ExecutionContext, ScanConcurrency};
use argus_rules::scan_text_files_with_context;
use std::collections::BTreeSet;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

#[test]
fn actual_file_workers_use_multiple_bounded_invocation_threads() {
    for jobs in [1, 2, 4, 8] {
        let fixture = tempfile::tempdir().unwrap();
        for index in 0..jobs {
            fs::write(
                fixture.path().join(format!("{index:02}.js")),
                format!("const value{index} = {index};"),
            )
            .unwrap();
        }
        let execution = ExecutionContext::new(ScanConcurrency::new(jobs).unwrap()).unwrap();
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let worker_names = Mutex::new(BTreeSet::new());
        let barrier = Arc::new(Barrier::new(jobs));

        let (outputs, skipped) =
            scan_text_files_with_context(fixture.path(), 1024, &execution, |file| {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                worker_names.lock().unwrap().insert(
                    std::thread::current()
                        .name()
                        .expect("invocation pool worker name")
                        .to_string(),
                );
                barrier.wait();
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(file.rel.clone())
            })
            .unwrap();

        assert!(skipped.binary.is_empty());
        assert!(skipped.oversized.is_empty());
        assert!(skipped.unreadable.is_empty());
        assert_eq!(outputs.len(), jobs);
        assert_eq!(peak.load(Ordering::SeqCst), jobs);
        assert_eq!(worker_names.lock().unwrap().len(), jobs);
        assert!(peak.load(Ordering::SeqCst) <= execution.concurrency().get());
        if jobs > 1 {
            assert!(worker_names.lock().unwrap().len() > 1);
        }
    }
}
