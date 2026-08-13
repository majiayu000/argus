# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Reduce agent-rule false positives by limiting `override system` matches to
  agent-authority targets such as instructions, prompts, messages, and policy,
  including narrowly formatted or safety-qualified authority targets.
- Freeze the completed GH-145 single-AI review as 1,438 package-level samples:
  719 packages preserving all 849 original detector findings and 719
  deterministically sampled non-block predictions from the same pinned source
  snapshot. The single-review tooling verifies source and detector revisions,
  shard hashes, predictions, package identities, immutable reviewer evidence,
  explicit reviewer/model provenance, rationales, and complete coverage.
  The review contains 24 `block` and 1,414 `non-block` labels with no unresolved
  rows. CI reproduces the frozen outputs and statically rescans the pinned source
  with the current Argus binary, failing on any operational error or regression
  below precision 0.073171 / recall 0.625. The immutable frozen review report
  remains the historical detector-baseline result.
- Agent-surface scans report bundled ELF, Mach-O, and PE/DOS executables as an
  explicit approval finding instead of treating them as unreadable text or
  silently skipping their uninspected binary semantics.
- Crates.io proc-macro source discovery now follows a bounded module graph of
  at most 1,024 unique source files and fails closed with explicit operational
  errors for oversized, binary, invalid, crate-root-escaping, or
  symlink/reparse-backed reachable sources, instead of allowing an incomplete
  traversal to appear clean (GH-194).
- Crates.io proc-macro module traversal now parses Rust items structurally,
  preserves rustc-style module directory ownership for `#[path]` and inline
  modules, visits block, macro-invocation, and attribute inputs, fails closed
  when a macro definition emits an external module whose invocation context is
  unknown, recursively handles `cfg`/`cfg_attr(path)` conservatively, and caps
  parsing and resolution work before filesystem probes (GH-200).
- `known-native-build-pattern` now also recognizes addons compiled locally
  from bundled sources (`node-gyp`, `cmake-js`, `prebuildify`, `neon`), not
  only prebuilt platform `optionalDependencies`. Ordinary node-gyp packages
  previously blocked on their lone `lifecycle-script` finding with no
  downgrade path. Scripts that also fetch a remote payload — including
  `prebuild-install`/`node-pre-gyp`, which reach the network on the common
  path — are excluded (GH-185).
- `credential-access` no longer fires on prose documentation. A README that
  quotes `~/.npmrc` or `~/.aws/credentials` is not a package reading them, and
  that shape dominated the false positives the skill census measured. Agent
  instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.claude/**`)
  stay in scope, because there a credential path is a payload the user's agent
  reads (GH-184).
- Add benign corpus fixtures covering the false-positive shapes the skill
  census measured: documented `curl | sh` installers, runtime HTTPS clients,
  base64-decoded embedded data, and lint rules that match dynamic-execution
  text. Benign coverage goes from 2 cases to 6 (GH-145).
- Add opt-in weighted risk scoring (`--risk-scoring`, `--risk-decides`,
  `--risk-approval-threshold`, `--risk-block-threshold`). Weights derive from
  the severity detectors already assign, so `Low` and `Critical` stop being
  interchangeable and independent risks accumulate. Reports carry the score and
  per-rule contributions in text, JSON, and SARIF. The completed GH-145
  benchmark publishes per-rule support and Wilson intervals, but cannot
  distinguish 15 AGT-01 block labels from 229 non-block labels by rule id and
  has only one or two observations for six other ids. The severity profile
  therefore remains the non-overfit default rather than inventing per-rule
  probabilities from sparse policy outcomes.
- Add `argus lockfile-scan`, which fetches and statically scans every
  dependency a lockfile resolves and aggregates them into one decision and
  exit code. Dependencies that were skipped or could not be assessed are
  reported explicitly, and an unassessed dependency escalates the aggregate
  decision to `block` rather than contributing nothing. `--base` restricts the
  sweep to added/changed dependencies; SARIF emits one run per package.
- Add the approval-only `encoded-dynamic-execution` rule for direct JavaScript
  `eval`/`Function(atob(...))` and Python
  `exec`/`eval(base64.b64decode(...))` chains. Statistical obfuscation
  heuristics remain out of scope.
- Add the approval-only `obfuscated-source` rule for structural obfuscation
  signatures build tooling does not produce: systematic `_0x`-hex identifier
  mangling and nested decoder chains. Shannon entropy, minified shape, and
  maximum line length are attached as evidence on a finding that already
  fired; they never raise one on their own, because legitimate bundles share
  that shape. The completed labeled benchmark contains no
  `obfuscated-source` observations, so it cannot support standalone
  entropy/minified thresholds; the structural signatures remain the trigger.

## [0.1.0] - 2026-07-23

First tagged release. Graduates the pre-launch history below into a versioned
section.

### Added

- Binary release automation and a repository-root GitHub Action contract.
  `v0.1.0` publishes verified prebuilt binaries with checksums and Sigstore
  attestations, gated by the documented administrator and release controls
  ([#92](https://github.com/majiayu000/argus/issues/92)).

- `argus agent scan` — static scanner for agent supply-chain surfaces:
  MCP configs, skills, hooks, and `AGENTS.md`/`CLAUDE.md`. Rules AGT-01
  (injection/override language, EN+ZH), AGT-03 (remote-exec pipe,
  secret-read + network-egress combos), AGT-05 (high-risk config flags:
  `alwaysLoad`, `enableAllProjectMcpServers`, `enabledMcpjsonServers`,
  `PostToolUse` output rewriting)
  ([#57](https://github.com/majiayu000/argus/issues/57)).

- `argus` CLI — scan a single package and run the regression corpus
  ([#6](https://github.com/majiayu000/argus/pull/6),
  [#4](https://github.com/majiayu000/argus/pull/4),
  [#5](https://github.com/majiayu000/argus/pull/5)).
- npm tarball fetch + safe extraction + rule scan
  ([#6](https://github.com/majiayu000/argus/pull/6)).
- PyPI ecosystem support — sdist + wheel fetch and scan
  ([#23](https://github.com/majiayu000/argus/pull/23)).
- crates.io ecosystem support — `.crate` fetch + `build.rs` analysis
  ([#24](https://github.com/majiayu000/argus/pull/24),
  [#40](https://github.com/majiayu000/argus/pull/40) extends `build.rs` detection
  to packages that declare a custom build script in `Cargo.toml`).
- M1 provenance — npm subject-digest cross-check against the published DSSE
  attestation bundle ([#15](https://github.com/majiayu000/argus/pull/15)).
- **M2 Sigstore signature verification** behind a `sigstore` feature flag
  ([#29](https://github.com/majiayu000/argus/pull/29) DSSE primitive,
  [#35](https://github.com/majiayu000/argus/pull/35) bundle wrapper + vendored
  trust root, [#36](https://github.com/majiayu000/argus/pull/36) wires
  `argus-fetch` to use it, [#27](https://github.com/majiayu000/argus/pull/27)
  design doc, [#30](https://github.com/majiayu000/argus/pull/30) Day 2 spike
  findings). Resolves [#14](https://github.com/majiayu000/argus/issues/14).
- Detection rules: AI-context poisoning (TrapDoor-class)
  ([#18](https://github.com/majiayu000/argus/pull/18)) and crypto/web3
  typosquat dictionary plus the `crypto-key-stealer` fixture
  ([#17](https://github.com/majiayu000/argus/pull/17)).
- Tarball-host allowlist for custom registries and CDN delegation
  ([#13](https://github.com/majiayu000/argus/pull/13)).
- Pre-commit hook framework so `cargo fmt` drift cannot reach CI
  ([#28](https://github.com/majiayu000/argus/pull/28)).
- Documentation: TrapDoor (2026-05-24) supply-chain attack catalog entry
  ([#19](https://github.com/majiayu000/argus/pull/19)); M2 Sigstore design
  ([#27](https://github.com/majiayu000/argus/pull/27)).
- Apache-2.0 LICENSE and CI / license badges
  ([#16](https://github.com/majiayu000/argus/pull/16)).

### Changed

- Updated the CI checkout action to the current major version.
- Hoisted shared `host_of` / `validate_artifact_url` / `verify_sha256_hex` /
  `ArtifactScan` / `MockTransport` helpers into `argus-core` and a new
  `argus-test-support` dev crate; removes ~315 duplicated lines and
  unblocks long-tail ecosystem work
  ([#26](https://github.com/majiayu000/argus/pull/26)).

### Fixed

- Constant-time digest comparison (`subtle::ConstantTimeEq`) for tarball
  integrity ([#11](https://github.com/majiayu000/argus/pull/11)).
- Reject HTTPS → HTTP downgrade during redirect follow
  ([#12](https://github.com/majiayu000/argus/pull/12),
  [#39](https://github.com/majiayu000/argus/pull/39) hardens the check to
  happen before the follow rather than after).
- Reject unsafe artifact filenames from PyPI metadata (path-traversal guard)
  ([#38](https://github.com/majiayu000/argus/pull/38)).
- Treat malformed attestation payloads as a hard failure rather than a
  silent skip ([#41](https://github.com/majiayu000/argus/pull/41)).
- Preserve high-severity Sigstore decisions even when info-level findings
  are present ([#37](https://github.com/majiayu000/argus/pull/37)).
- Keep Sigstore info findings non-blocking when the higher layers succeeded.

### Security

- Sigstore signature verification provides cryptographic evidence about
  *who signed* a package, but does NOT prove publisher intent. Honest
  threat-disclosure of attack classes M2 does not close (OIDC compromise,
  builder-workflow tampering, trust-root rotation) lives in
  [`docs/design/sigstore-verification.md`](docs/design/sigstore-verification.md)
  §10.
- See [`docs/supply-chain-attacks.md`](docs/supply-chain-attacks.md) for the
  attack-catalog argus is designed against.

[Unreleased]: https://github.com/majiayu000/argus/compare/v0.1.0...main
[0.1.0]: https://github.com/majiayu000/argus/releases/tag/v0.1.0
