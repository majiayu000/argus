# Product Spec

## Linked Issue

GH-97

complexity: low

## Problem

Independent review evidence uses `gh pr diff --patch`. Multi-commit pull requests include
mail-patch envelopes between unified diffs. The current parser remains in hunk state after a
completed hunk and rejects an envelope blank line as malformed diff content, blocking valid PRs.

## Behavioral Invariants

1. B-001 A completed unified-diff hunk must exit hunk state using its declared old/new line counts.
2. B-002 Mail-patch headers, signatures, and separators outside hunks must not affect path/line indexes.
3. B-003 Added, removed, and context lines from every commit must remain indexed on the correct side.
4. B-004 Bare or unsupported content before a hunk has consumed its declared counts must fail closed.
5. B-005 A truncated hunk at a new file boundary or end of input must fail closed.

## Acceptance Criteria

- [x] Multi-commit `gh pr diff --patch` evidence parses successfully.
- [x] Comments can bind to changed lines from both the first and later commits.
- [x] Malformed and truncated in-hunk content remains rejected.

## Non-goals

- Do not relax review artifact schemas or merge authorization.
- Do not implement a general email parser.
- Do not change GitHub evidence collection commands.
