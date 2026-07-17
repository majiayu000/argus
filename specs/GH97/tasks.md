# Tasks — GH-97 multi-commit review patch parsing

- [x] `SP97-T1` Track declared old/new hunk counts and exit only after full consumption. Covers: B-001, B-003, B-004, B-005. Owner: review parser. Dependencies: none. Done when: complete hunks transition deterministically and incomplete hunks fail closed. Verify: `pytest -q tests/test_review_json_gate.py`.
- [x] `SP97-T2` Add multi-commit envelope and malformed/truncated hunk regressions. Covers: B-002, B-003, B-004, B-005. Owner: tests. Dependencies: SP97-T1. Done when: both commit indexes are retained and invalid hunk bodies remain blocked. Verify: `pytest -q tests/test_review_json_gate.py`.
- [x] `SP97-T3` Run SpecRail and Python test gates. Covers: B-001, B-002, B-003, B-004, B-005. Owner: coordinator. Dependencies: SP97-T1, SP97-T2. Done when: workflow checks and full pytest pass. Verify: `python3 checks/check_workflow.py --repo . --all-specs`; `pytest -q`.

## Invariant Coverage

Product IDs: B-001, B-002, B-003, B-004, B-005.

Task coverage union: B-001, B-002, B-003, B-004, B-005.
