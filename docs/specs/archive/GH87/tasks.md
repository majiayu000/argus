# Tasks — GH-87 syntax-aware capability extraction

- [x] `SP87-T1` Add MSRV-compatible Tree-sitter core and shell/Python/JS/TS grammars. Covers: B-001, B-005. Owner: agent parser. Dependencies: none. Done when: all grammars initialize under the workspace MSRV contract. Verify: `cargo check -p argus-agent`.
- [x] `SP87-T2` Emit typed executable facts with alias and bounded constant resolution. Covers: B-001, B-002, B-003, B-004. Owner: syntax analyzer. Dependencies: SP87-T1. Done when: each supported language has executable and benign-negative tests. Verify: `cargo test -p argus-agent capability::syntax`.
- [x] `SP87-T3` Rewire capability classification to facts and fail closed on incomplete parses. Covers: B-004, B-005, B-006. Owner: capability layer. Dependencies: SP87-T2. Done when: raw line scanning is removed and errors reach the scan caller. Verify: `cargo test -p argus-agent capability`.
- [x] `SP87-T4` Add adversarial alias/concat and comment-only integration fixtures. Covers: B-002, B-003, B-006. Owner: agent integration. Dependencies: SP87-T3. Done when: bypass fixture blocks and benign-negative fixture allows. Verify: `cargo test -p argus-agent --test integration`.
- [x] `SP87-T5` Reconcile GH-59 status and run repository gates. Covers: B-001, B-002, B-003, B-004, B-005, B-006. Owner: coordinator. Dependencies: SP87-T1..T4. Done when: specs describe shipped behavior and full gates pass. Verify: `python3 checks/check_workflow.py --repo . --all-specs`; `cargo test --workspace --all-targets`; `cargo run --quiet -p argus-cli -- corpus test --corpus corpus`.

## Invariant Coverage

Product IDs: B-001, B-002, B-003, B-004, B-005, B-006.

Task coverage union: B-001, B-002, B-003, B-004, B-005, B-006.
