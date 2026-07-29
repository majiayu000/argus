# Argus Repository Instructions

## Layout

- Rust workspace code lives in `crates/`; the CLI entry point is
  `crates/argus-cli`.
- Regression fixtures and their indexes live in `corpus/`.
- The repository-root GitHub Action lives in `action/`.
- Release tooling and its native Python tests live in `scripts/` and
  `scripts/tests/`.
- Current design, security, and release documentation lives in `docs/`.
- `docs/specs/archive/` preserves closed-issue packets as historical context
  only. It is not current workflow, gate, or task state and must not route work
  through SpecRail.

## Security Boundaries

- Argus inspects packages statically. Never execute untrusted packages,
  archives, fixtures, lifecycle scripts, build hooks, or install hooks while
  developing or testing it.
- Follow the synthetic-fixture and `.example.invalid` rules in
  `CONTRIBUTING.md`; do not add real malicious archives.
- Detection, parsing, integrity, or inventory failures must remain explicit
  operational errors. Never silently convert an incomplete scan into a clean
  or allow result.

## Development Workflow

Read `CONTRIBUTING.md` before changing code or fixtures. Search for an existing
implementation, test, or document before creating a new one.

Run the native Rust checks from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo run -q -p argus-cli -- corpus test --corpus corpus
```

Changes to release tooling or the root Action also require the native release
contract tests and Action checks:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_release_*.py'
npm ci --prefix action
npm test --prefix action
npm run package --prefix action
git diff --exit-code -- action/dist/index.js
```
