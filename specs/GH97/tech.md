# Tech Spec

## Linked Issue

GH-97

## Design

Extend `HUNK_RE` to capture optional old/new counts (default one), then track remaining line
counts while parsing. Context consumes both sides, removal consumes old, and addition consumes new.
The parser leaves hunk state only when both counts reach zero. A new hunk/file boundary or EOF with
remaining counts is an error. Content outside a hunk, including mail-patch envelopes, remains ignored.

This uses unified-diff grammar rather than recognizing mutable Git email prose, and therefore does
not turn malformed hunk content into an accepted separator.

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":97,"complete":true,"paths":["checks/review_json_gate.py","specrail-manifest.json","specs/GH97/product.md","specs/GH97/tasks.md","specs/GH97/tech.md","tests/test_review_json_gate.py"],"spec_refs":["specs/GH97/product.md","specs/GH97/tech.md","specs/GH97/tasks.md"]}
-->

## Product-to-Test Mapping

| Invariant | Implementation | Verification |
| --- | --- | --- |
| B-001, B-002 | hunk counters and completed-state transition | multi-commit mail patch test |
| B-003 | existing side indexes with counted transitions | assertions for both commit paths |
| B-004 | unsupported line while counts remain | bare in-hunk line test |
| B-005 | boundary/EOF completeness check | truncated hunk tests |

## Rollback

Revert the counter tracking and regression tests; no persisted data or public API changes.
