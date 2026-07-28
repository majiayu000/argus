# Product Spec

## Linked Issue

GH-87

complexity: high

## Problem

GH-59 declares syntax-aware shell, Python, JavaScript, and TypeScript capability extraction as
complete, but the shipped implementation scans every script line with regular expressions. It
cannot distinguish comments and documentation strings from executable structures, misses aliases
and constant concatenation, and can silently allow incomplete parses.

## Behavioral Invariants

1. B-001 Shell, Python, JavaScript, and TypeScript capability inputs come from parsed executable
   command, call, assignment, redirect, and access structures rather than raw source lines.
2. B-002 Comments, documentation-only strings, and inert string assignments do not create
   executable capability findings.
3. B-003 Import aliases, command aliases, and simple literal/constant concatenation resolve before
   capability and host classification.
4. B-004 Dynamic network targets produce explicit `unresolved_host` evidence.
5. B-005 A supported-language parse containing error or missing nodes fails the scan explicitly;
   an unsupported script language produces an explicit incomplete-analysis manifest finding.
6. B-006 Existing capability manifest fields and deterministic intent/misfit decisions remain
   compatible, including every frozen GH-58 fixture.

## Acceptance Criteria

- [x] Comment-only and documentation-only mentions are clean.
- [x] Shell, Python, JavaScript, and TypeScript executable structures are detected.
- [x] Aliased calls and simple constant concatenation resolve deterministically.
- [x] Dynamic targets and unsupported Ruby scripts cannot silently produce `allow`.
- [x] Malformed supported scripts return an operational error.
- [x] Existing agent integration and corpus decisions remain unchanged.
- [x] GH-59 product, tech, and task status accurately describe the implementation.

## Non-goals

- Do not execute scanned code or invoke a package manager/interpreter.
- Do not implement whole-program data flow, user-defined function summaries, or cross-file symbols.
- Do not add syntax support beyond shell, Python, JavaScript, and TypeScript in this issue.
- Do not move the optional LLM judge into the deterministic capability layer.
