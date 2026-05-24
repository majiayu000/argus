# argus

> "100-eyed guardian." Static install-time scanner for npm / JavaScript supply-chain attacks.

`argus` is a Rust CLI that decides whether a package directory or npm lockfile is safe to install, before any lifecycle script runs. It implements the deterministic-rule layer of the design at `../docs/todo/safepm-install-guard-spec-2026-05-13.md` (Milestone 0).

## Decisions

- **block** — at least one high-risk rule fired.
- **allow-with-approval** — only a known native-build pattern fired; require explicit approval.
- **allow** — no rule fired.

## Usage

```bash
# Scan one package directory
cargo run -p argus-cli -- scan ../safepm-test-corpus/fixtures/lifecycle-curl-sh

# Run the full regression corpus (10 fixtures + 1 lockfile)
cargo run -p argus-cli -- corpus test --corpus ../safepm-test-corpus

# Machine-readable output
cargo run -p argus-cli -- scan path/to/pkg --format json
```

The compiled binary is named `argus` and exits non-zero on `block`.

## Rule coverage (Milestone 0)

| Family   | Rules |
|----------|-------|
| lifecycle | `lifecycle-script`, `pre-scan-execution-marker` |
| content   | `remote-download`, `shell-pipe-execution`, `credential-access`, `network-exfiltration`, `binary-execution`, `runtime-hook`, `wallet-interception`, `token-harvest`, `github-write-api`, `npm-publish` |
| binary    | `binary-file` |
| name      | `typosquatting`, `low-reputation`, `dependency-confusion`, `public-registry-internal-name`, `known-native-build-pattern` |
| lockfile  | `lockfile-http-resolved`, `untrusted-registry-host` |

## Layout

- `crates/argus-core` — data types (`Decision`, `Finding`, `ScanReport`).
- `crates/argus-rules` — static detection rules.
- `crates/argus-cli` — the `argus` binary.

## Status

Milestone 0 only — no tarball fetch, no registry intelligence, no install-wrapper. See the SPEC for the milestone roadmap.
