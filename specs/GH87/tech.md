# Tech Spec

## Linked Issue

GH-87

## Design

Use Tree-sitter with a Rust-1.75-compatible core (`0.24.7`) and maintained shell/Python/JS/TS
grammars. A new syntax module parses each supported script and emits typed facts containing source
location, canonical callee, arguments, resolved constant values, redirects, and unresolved-value
state. The capability layer classifies only those facts; raw comments and inert strings never enter
the classifier.

The analyzer performs bounded local resolution in source order: import aliases (including named
JS/TS and CommonJS destructuring), shell aliases, direct assignments, string literals, and
`+`/shell concatenation. Dynamic reassignments invalidate stale constants, and nested scopes use
isolated binding environments. Unknown identifiers remain unresolved. Remote-shell escalation
requires a network source and shell sink in the same parsed pipeline rather than unrelated facts in
one file. Parse trees with error or missing nodes return an error through `scan_agent_surface`.
Ruby remains classified as a script for compatibility but emits a Medium `analysis_incomplete`
manifest finding rather than an empty allow.

Sensitive values passed directly to network calls retain syntax-node provenance. Shell expansion
nodes and Python/JS/TS identifier, member-access, and `getenv` nodes are eligible credential reads;
ordinary string fragments, single-quoted shell dollars, and escaped shell dollars are not.

## Planned Changes Manifest

<!-- specrail-planned-changes
{"version":1,"issue":87,"complete":true,"paths":["Cargo.lock","Cargo.toml","crates/argus-agent/Cargo.toml","crates/argus-agent/src/capability.rs","crates/argus-agent/src/capability/classify.rs","crates/argus-agent/src/capability/syntax.rs","crates/argus-agent/src/capability/syntax/receiver.rs","crates/argus-agent/src/capability/syntax/reference.rs","crates/argus-agent/src/capability/syntax/tests.rs","crates/argus-agent/src/lib.rs","crates/argus-agent/tests/fixtures/agt06-alias-concat/SKILL.md","crates/argus-agent/tests/fixtures/agt06-alias-concat/collect.py","crates/argus-agent/tests/fixtures/agt06-comment-only/SKILL.md","crates/argus-agent/tests/fixtures/agt06-comment-only/examples.ts","crates/argus-agent/tests/gh87_capability.rs","crates/argus-agent/tests/integration.rs","specs/GH59/product.md","specs/GH59/tasks.md","specs/GH59/tech.md","specs/GH87/product.md","specs/GH87/tasks.md","specs/GH87/tech.md"],"spec_refs":["specs/GH87/product.md","specs/GH87/tech.md","specs/GH87/tasks.md"]}
-->

## Product-to-Test Mapping

| Invariant | Implementation | Verification |
| --- | --- | --- |
| B-001, B-002 | grammar selection and typed AST fact extraction | per-language executable and inert-text unit tests |
| B-003 | alias table and bounded constant evaluator | alias/concatenation unit and integration fixture |
| B-004 | unresolved value on network facts | dynamic host unit tests |
| B-005 | parse completeness check and unsupported-language fact | malformed/unsupported tests |
| B-006 | unchanged manifest emission and misfit layer | agent integration tests and corpus 18/18 |

## Error Boundary

Parser initialization and parse incompleteness return `anyhow::Error` with the relative file path
and language. Unsupported languages do not claim a clean analysis: they emit explicit Medium
manifest evidence. No parser error is converted to an empty fact list.

## Rollback

Revert the parser dependencies and syntax module, restore lexical extraction, and restore GH-59
status text. There are no persistence or public API migrations.
