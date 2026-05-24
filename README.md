# safepm

NPM/JavaScript supply-chain install guard. Blocks lifecycle script execution until packages have been statically scanned and approved.

This is Milestone 0 per `../docs/todo/safepm-install-guard-spec-2026-05-13.md`: tarball/directory scanning with deterministic static rules.

## Usage

```bash
# Scan one package directory
cargo run -p safepm-cli -- scan ../safepm-test-corpus/fixtures/lifecycle-curl-sh

# Run the full regression corpus
cargo run -p safepm-cli -- corpus test --corpus ../safepm-test-corpus
```

## Layout

- `crates/safepm-core` — data types (`Decision`, `Finding`, `ScanReport`)
- `crates/safepm-rules` — static detection rules
- `crates/safepm-cli` — `safepm` binary
