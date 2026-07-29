# Product Spec

## Linked Issue

GH-99

complexity: low

## Problem

The command-judge tests create executable shell scripts during the test process and immediately
execute them. GitHub-hosted Linux runners repeatedly return `ETXTBSY` even after the script is
written to a temporary name and renamed, making unrelated pull requests fail CI nondeterministically.

## Behavioral Invariants

1. B-001 Command-judge tests must not execute an inode created for writing during the test process.
2. B-002 Success, delayed exit, timeout, output overflow, and non-zero exit coverage must remain intact.
3. B-003 Production command execution and error propagation behavior must not change.
4. B-004 Each test scenario must remain isolated and safe under parallel test execution.

## Acceptance Criteria

- [x] Command-judge tests pass repeatedly with the default parallel test runner.
- [x] The full workspace test suite passes without retry logic or weakened assertions.
- [x] No production command behavior changes.

## Non-goals

- Do not retry `ETXTBSY` in production.
- Do not serialize the workspace test suite in CI.
- Do not change the public judge command interface.
