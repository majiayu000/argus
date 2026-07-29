# Tasks — GH-99 stable command-judge fixtures

- [x] `SP99-T1` Replace dynamically created executable scripts with a stable checked-in runner and isolated scenario files. Covers: B-001, B-003, B-004. Owner: CLI tests. Dependencies: none. Done when: the helper creates no executable inode and production code is unchanged. Verify: `git diff -- crates/argus-cli/src/agent.rs crates/argus-cli/tests/fixtures/judge-runner.sh`.
- [x] `SP99-T2` Preserve all command-judge scenarios and run them repeatedly with default test parallelism. Covers: B-002, B-004. Owner: CLI tests. Dependencies: SP99-T1. Done when: repeated targeted runs pass without retries inside code. Verify: `for run in 1 2 3 4 5; do cargo test -p argus-cli --bin argus command_judge; done`.
- [x] `SP99-T3` Run SpecRail, formatting, lint, full workspace tests, and corpus gates. Covers: B-001, B-002, B-003, B-004. Owner: coordinator. Dependencies: SP99-T1, SP99-T2. Done when: all repository gates pass. Verify: `python3 checks/check_workflow.py --repo . --all-specs`; `cargo test --workspace --all-targets`; `cargo run --quiet -p argus-cli -- corpus test --corpus corpus`.

## Invariant Coverage

Product IDs: B-001, B-002, B-003, B-004.

Task coverage union: B-001, B-002, B-003, B-004.
