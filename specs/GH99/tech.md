# Tech Spec

## Linked Issue

GH-99

## Design

Add one executable shell runner under the existing CLI test fixtures. The runner is present before
the test process starts. Each test creates only a private, non-executable scenario body and a symlink
to the stable runner. The runner resolves the symlink directory and sources the closed scenario file.
The kernel therefore executes a stable checkout inode while every scenario retains its own temporary
directory and existing shell behavior.

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":99,"complete":true,"paths":["crates/argus-cli/src/agent.rs","crates/argus-cli/tests/fixtures/judge-runner.sh","specs/GH99/product.md","specs/GH99/tasks.md","specs/GH99/tech.md"],"spec_refs":["specs/GH99/product.md","specs/GH99/tech.md","specs/GH99/tasks.md"]}
-->

## Product-to-Test Mapping

| Invariant | Implementation | Verification |
| --- | --- | --- |
| B-001, B-003 | stable checked-in runner; no production changes | diff review and targeted command-judge tests |
| B-002 | existing scenario bodies and assertions | targeted command-judge tests |
| B-004 | one temporary scenario directory per test | repeated default-parallel targeted tests |

## Rollback

Revert the fixture runner and test helper change; no persisted data or public API changes.
