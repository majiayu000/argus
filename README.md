# argus

[![CI](https://github.com/majiayu000/argus/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/majiayu000/argus/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> "100-eyed guardian." Static install-time scanner for npm, PyPI, and crates.io supply-chain attacks, with opt-in Sigstore signature verification.

`argus` is a Rust CLI that decides whether a package (npm, PyPI sdist/wheel, or `.crate` archive) or an npm lockfile is safe to install, before any lifecycle script, `setup.py`, or `build.rs` ever runs. It implements the deterministic-rule layer plus optional cryptographic provenance verification — see the "Status" section below for the current capability snapshot.

## Decisions

- **block** — at least one high-risk rule fired.
- **allow-with-approval** — only a known native-build pattern fired; require explicit approval.
- **allow** — no rule fired.

## Usage

```bash
# Scan one local package directory
cargo run -p argus-cli -- scan corpus/fixtures/lifecycle-curl-sh

# Fetch a real npm package: packument -> tarball -> SHA-512 verify -> safe
# extract -> scan. No lifecycle script ever runs.
cargo run -p argus-cli -- fetch chalk@5.3.0
cargo run -p argus-cli -- fetch '@types/node@20.10.0' --format json

# Fetch a real PyPI package: JSON API -> sdist/wheel -> SHA-256 verify -> safe
# extract -> scan. setup.py never runs.
cargo run -p argus-cli -- pypi-fetch requests@2.31.0 --prefer wheel
cargo run -p argus-cli -- pypi-fetch django@5.0.0 --prefer both --format json

# Fetch a real crates.io crate: JSON API -> .crate -> SHA-256 verify -> safe
# extract -> scan. build.rs never runs.
cargo run -p argus-cli -- crates-fetch serde@1.0.228
cargo run -p argus-cli -- crates-fetch tokio --format json

# Custom registry that serves tarballs from a separate CDN/host:
cargo run -p argus-cli -- fetch internal-tool@1.2.3 \
  --registry https://npm.corp.example \
  --allow-tarball-host cdn.corp.example \
  --allow-tarball-host objects.corp.example

# Run the full regression corpus (10 fixtures + 1 lockfile)
cargo run -p argus-cli -- corpus test

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
| provenance | `missing-provenance` (info), `provenance-verified-subject` (info), `provenance-subject-mismatch` (block), `provenance-fetch-blocked` / `provenance-fetch-failed` / `provenance-parse-failed` (operational errors) |
| ai-context | `ai-context-poisoning` — writes to `.cursorrules`, `CLAUDE.md`, `.claude/*`, `AGENTS.md`, `.aider.conf.yml`, `.continuerules`, `.codexrules`, `.windsurfrules`. Pioneered at scale by the TrapDoor campaign (Socket.dev 2026-05-24). |

## PyPI rule coverage (Milestone 1)

| Family | Rules |
|--------|-------|
| sdist install-time | `setup-py-execution`, `setup-subprocess`, `setup-remote-download`, `setup-eval` |
| wheel + sdist | `import-time-hook` (rewriting `sys.modules` / `__builtins__` at module load) |
| structural | `pypi-sdist-no-manifest` (info) |
| ported from npm rules (file-content scan) | `credential-access`, `ai-context-poisoning`, `runtime-hook`, `wallet-interception` |
| name | `typosquatting` against 60+ Python package names |

## crates.io rule coverage (Milestone 1)

| Family | Rules |
|--------|-------|
| build.rs compile-time | `build-rs-subprocess` (shells / curl / wget / scripting interpreters only — plain `Command::new("rustc")` is allow-listed), `build-rs-network`, `build-rs-include-bytes` (binary blob + XOR loop), `xor-decryption-loop` |
| structural | `build-rs-execution` (info), `proc-macro-crate` (info), `embedded-binary-blob` (info) |
| ported from npm rules (file-content scan) | `credential-access`, `ai-context-poisoning`, `runtime-hook` |
| name | `typosquatting` against 70+ crate names |

## Layout

- `crates/argus-core` — data types (`Decision`, `Finding`, `ScanReport`).
- `crates/argus-rules` — static detection rules.
- `crates/argus-fetch` — npm registry client.
- `crates/argus-pypi` — PyPI registry client (sdist + wheel).
- `crates/argus-crates` — crates.io registry client (.crate + build.rs).
- `crates/argus-cli` — the `argus` binary.

## Development

Enable the git hooks once per clone so `cargo fmt` drift can't reach CI:

```sh
uv tool install pre-commit        # or: pipx install pre-commit
pre-commit install                # pre-commit stage: cargo fmt + file hygiene
pre-commit install -t pre-push    # pre-push stage: cargo clippy -D warnings
```

CI is the authoritative gate (`cargo fmt --check`, clippy, `cargo test`,
`argus corpus test`); the hooks just give faster local feedback. Run the full
local set anytime with `pre-commit run --all-files`.

## Status

**Pre-release.** Argus is not yet cut as a tagged release or published to any
package registry. Build it from source against `main`; we treat `main` as the
shipping branch and the [`CHANGELOG`](CHANGELOG.md) `[Unreleased]` section as
the current ship-list.

Capability snapshot (as of 2026-05-29):

- **M0** — rule engine + regression corpus + CI ([#4](https://github.com/majiayu000/argus/pull/4), [#5](https://github.com/majiayu000/argus/pull/5)).
- **M1** — npm tarball fetch + safe extraction + scan ([#6](https://github.com/majiayu000/argus/pull/6)), plus PyPI sdist/wheel ([#23](https://github.com/majiayu000/argus/pull/23)) and crates.io `.crate` + `build.rs` analysis ([#24](https://github.com/majiayu000/argus/pull/24)).
- **M2** — Sigstore signature verification (DSSE + Fulcio chain + Rekor inclusion + OIDC identity allowlist), opt-in behind the `sigstore` Cargo feature. Closes [#14](https://github.com/majiayu000/argus/issues/14); honest threat-disclosure of what M2 still does NOT prevent lives in [`docs/design/sigstore-verification.md`](docs/design/sigstore-verification.md) §10.

Long-tail ecosystem coverage (Maven / NuGet / Go modules / RubyGems / Packagist)
is tracked under [#22](https://github.com/majiayu000/argus/issues/22); launch-readiness polish under [#42](https://github.com/majiayu000/argus/issues/42).

Detection coverage is intentionally **not** claimed in headline numbers without
benchmark evidence — see [`corpus/`](corpus/) for the regression set the
project gates on and [`docs/supply-chain-attacks.md`](docs/supply-chain-attacks.md)
for the attack catalog argus is designed against.
