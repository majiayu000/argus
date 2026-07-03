# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This is the pre-launch history. The first tagged release will graduate the
items below into a versioned section.

### Added

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

[Unreleased]: https://github.com/majiayu000/argus/commits/main
