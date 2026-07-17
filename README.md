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

# SARIF 2.1.0 for code-scanning integrations
cargo run -p argus-cli -- scan path/to/pkg --format sarif > argus.sarif

# Scan agent surfaces: MCP configs, skills, hooks, AGENTS.md / CLAUDE.md.
# Detects injection/override language (AGT-01), dangerous script
# capabilities like curl|sh or secret-read + network-egress (AGT-03),
# and high-risk config flags such as alwaysLoad: true (AGT-05).
cargo run -p argus-cli -- agent scan ~/.claude
cargo run -p argus-cli -- agent scan path/to/skill .mcp.json --format json

# Recompute the explicitly synthetic GH-58 fixture metrics.
cargo run -p argus-cli -- corpus eval --corpus corpus/agent --format json
```

The compiled binary is named `argus` and exits non-zero on `block`.

### SARIF and GitHub Code Scanning

`--format sarif` is available on package/lockfile scans, every ecosystem fetch
command, and `agent scan`. The output preserves Argus rule IDs, severity,
file/line evidence when present, package coordinates, and stable partial
fingerprints. A finding without a line uses an artifact-level location; Argus
does not invent line 1.

Generic SARIF consumers can read the generated file directly. A GitHub Actions
job can upload it with the official action (currently `v4`):

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - run: argus scan path/to/pkg --format sarif > argus.sarif
  - uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: argus.sarif
```

Argus writes SARIF only after a complete scan report exists. Invalid input,
parser failures, network failures, and other operational errors still write an
error to stderr, exit `2`, and leave stdout empty instead of emitting a clean
SARIF run. A successful SARIF report retains the normal decision exit codes:
`allow` = 0, `block` = 1, and `allow-with-approval` = 2.

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

## Agent-surface rule coverage (GH-57)

`argus agent scan` statically scans agent supply-chain surfaces — MCP
configs, skill definitions, hook scripts, and instruction files — without
executing anything.

| Rule | Severity | Detects |
|------|----------|---------|
| `AGT-01-injection-language` | critical → block | authority-claim / instruction-override / concealment language (English + Chinese) in `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, `.claude/**/*.md`, and MCP tool `description` fields |
| `capability-manifest` | medium → approval | declarative capability entries in JSON (`capability`, `evidence`, optional `resolved_host`) for network egress, unresolved hosts, sensitive reads, agent config writes, exec/eval, obfuscation, and persistence |
| `AGT-03-remote-exec` | high → block | remote download piped to a shell (`curl … \| sh`, `iwr … \| iex`) in hook/skill scripts |
| `AGT-03-secret-exfil` | high → block | high-sensitivity credential access combined with network egress in the same script |
| `capability-misfit` | high → block | declared skill intent does not justify high-risk capability combinations such as credential exfiltration or agent config/hook writes |
| `agent-config-write` | medium → approval or high → block | script writes `.claude/settings*.json` or hook paths; matching agent-config intent is declarative, mismatched intent blocks |
| `hook-persistence` | high → block | script persists or auto-approves an agent hook |
| `credential-access` / `network-exfiltration` | high → block | manifest-backed evidence for credential reads and off-box network exfiltration |
| `AGT-05-mcp-always-load` | medium → approval | `mcpServers.<name>.alwaysLoad: true` (permanent full trust) |
| `AGT-05-enable-all-project-mcp` | medium → approval | `enableAllProjectMcpServers: true` |
| `AGT-05-enabled-mcpjson-servers` | medium → approval | non-empty `enabledMcpjsonServers` allowlist |
| `AGT-05-posttooluse-output-rewrite` | medium → approval | `PostToolUse` hook rewriting `updatedToolOutput` for non-MCP tools |
| `AGT-05-config-unparseable` | info | agent config file is not valid JSON |
| `AGT-02` | medium → approval | an **already-approved** MCP/skill description drifted from its recorded baseline hash (rug-pull detection; see below) |
| `AGT-02-baseline-entry-missing` | info | a baselined description is no longer present on the scanned surface |
| `AGT-02-baseline-unreadable` | info | `--baseline` file could not be read/parsed (scan continues; not treated as "no drift") |

AGT-04 (install-time high-context file diff) remains follow-up work — see issue #57.

### Optional external semantic judge

The deterministic scanner remains the default and never starts a process or
uses the network. To add an explicitly configured semantic layer, pass both
`--llm-judge` and the path to an executable bridge:

```bash
argus agent scan path/to/skill \
  --llm-judge \
  --llm-judge-command ./my-llm-judge-bridge \
  --format json
```

Argus starts that exact executable without a shell or interpolated arguments,
writes a versioned JSON request to stdin, and requires a strict JSON response
containing `schema_version`, `decision`, and a non-empty `rationale`. The bridge
can recommend `allow`, `allow-with-approval`, or `block`; its result becomes an
additional `llm-intent-judge` finding, so it can escalate but never erase or
downgrade deterministic findings.

The opt-in process is fail-closed: 30-second timeout, 4 MiB request limit,
1 MiB limits for stdout and stderr, and a 4096-byte rationale limit. Timeouts,
non-zero exits, output overflow, invalid UTF-8/JSON, unknown response fields,
or unsupported decisions make the scan return an operational error. The
bridge owns any network/API configuration; Argus contains no provider URL or
credential handling.

## AGT-02 description-drift baseline (GH-64)

AGT-01/03/05 catch malicious agent surfaces at first sight, but they cannot
catch a **rug-pull**: an MCP tool/server `description` or `SKILL.md`
frontmatter that a human already approved and that is later silently mutated.
AGT-02 closes that gap with an explicit, file-based baseline.

```bash
# 1. Approve the current descriptions — writes the baseline file.
cargo run -p argus-cli -- agent scan --update-baseline agt02.baseline.json ~/.claude
#    → prints "baseline written: N entries" to stderr, exits 0.

# 2. Later scans compare against the approved baseline.
cargo run -p argus-cli -- agent scan --baseline agt02.baseline.json ~/.claude
#    → any drifted description emits an AGT-02 finding (medium → allow-with-approval).
```

What is baselined: every MCP `mcpServers.<name>.description` and
`tools[].description` field, plus `SKILL.md` frontmatter `name` / `description`.
Each entry is keyed by `"<relative-path>#<locator>"` and stored as a SHA-256
hex hash of the description's UTF-8 bytes. Findings show only the first 12 hex
chars of the old/new hashes — never the description plaintext, which may itself
carry injection language. `--baseline` and `--update-baseline` are mutually
exclusive.

Behavior: a changed hash → AGT-02 `medium` (re-approval, not a hard block —
legitimate edits and rug-pulls are lexically indistinguishable; if the new text
also trips AGT-01, the existing critical → block derivation still escalates). A
baselined entry that disappeared → `info`. A brand-new description not in the
baseline → no AGT-02 finding (AGT-01/03/05 cover first-time surface). With no
`--baseline`/`--update-baseline`, AGT-02 is inert and behavior is identical to
GH-57 (no baseline = no drift check, stated explicitly rather than faked).

### Trust boundary

`--update-baseline` **is the approval action**: whoever runs it declares the
current descriptions trusted. argus does not custody that trust — it only
records and compares hashes. Treat the baseline file as a security artifact:
commit it to your own version control and review its diffs, exactly as you
would review the descriptions themselves. AGT-02 answers only "did an approved
description change?"; whether the new content is *malicious* is still AGT-01's
(lexical) and GH-59's (intent-misfit) job.

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

---

## The Agent Infra Stack

This project is one layer of an open-source stack for running coding agents (Claude Code, Codex) as serious infrastructure. Every piece works standalone; together they close the loop:

`argus` is the **Trust** layer at install time — scan what you pull from package registries before it ever runs. Its runtime counterpart is `vibeguard`.

| Layer | Project | What it does |
|---|---|---|
| Extend | [claude-skill-registry](https://github.com/majiayu000/claude-skill-registry) | Discover and search community Claude Code skills |
| Extend | [spellbook](https://github.com/majiayu000/spellbook) | Cross-runtime skills for Claude Code, Codex, and multi-agent workflows |
| Trust | [argus](https://github.com/majiayu000/argus) **◀ you are here** | Static install-time scanner for supply-chain attacks (npm / PyPI / crates.io) |
| Trust | [vibeguard](https://github.com/majiayu000/vibeguard) | Rules, hooks, and guards against hallucinated or unverified agent changes |
| Remember | [remem](https://github.com/majiayu000/remem) | Local-first persistent memory for Claude Code and Codex sessions |
| Orchestrate | [harness](https://github.com/majiayu000/harness) | Rust agent orchestration platform — rules, skills, GC, observability |
| Route | [litellm-rs](https://github.com/majiayu000/litellm-rs) | High-performance Rust AI gateway — 100+ LLM APIs via OpenAI format |
| Keep | [keepline](https://github.com/majiayu000/keepline) | Session command center — monitor, recover, never lose agent work |
