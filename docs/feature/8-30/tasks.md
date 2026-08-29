# Implementation and roadmap

## P0 — implemented in this feature

- [x] Preserve both sides of `LockfileScanTargetChange` in the CLI plan.
- [x] Scan base and current artifacts for changed coordinates.
- [x] Apply the pinned malicious-package snapshot to whole-lockfile current
  reports.
- [x] Emit deterministic introduced and resolved finding sets.
- [x] Block the aggregate decision when a required base comparison fails.
- [x] Cover delta identity, rendering, CLI help, empty delta, added dependency,
  and unavailable base behavior with synthetic tests.
- [x] Run all repository-native verification gates.

## P1 — next 30–60 days

- Build synthetic event replay packets around clean/malicious version pairs,
  starting with install-hook injection, `binding.gyp` execution, setup/build
  subprocess plus download, and agent hook/baseline drift.
- Maintain separate benign-popular, benign-dangerous, malware, paired-delta,
  and agent-baseline evaluation sets. New default-block behavior requires zero
  benign-popular false blocks and no regression in supported event replay.
- Add explicit executable-file inventory to version comparisons where existing
  findings do not represent newly introduced native or opaque payloads.
- Define an approval ledger only after the delta identity is stable. Bind each
  approval to the exact coordinate, digest, capability, reason, and expiry.
- Ship a narrow GitHub Action v1 contract around lockfile delta, integrity,
  malicious intelligence, current findings, and SARIF.

## P2 — next 60–90 days

- Add a small export contract for artifacts requiring isolated dynamic
  observation. Do not embed a sandbox into Argus.
- Export suggested CI egress/secret restrictions to sibling controls; do not
  implement an EDR or network firewall in this repository.
- Extend paired artifact comparisons to additional ecosystems only after npm,
  PyPI, and crates.io meet the same precision and replay gates.
- Consolidate the public UX around project admission, single-package
  inspection, and agent-baseline inspection after the underlying contracts are
  proven. Avoid command aliases or compatibility layers during that redesign.

## Paused directions

- New package ecosystems and broad platform coverage.
- Default LLM judgment or semantic risk scores in the block path.
- Treating Sigstore or SLSA success as proof of safety.
- A hosted dashboard, multi-tenant policy service, SIEM, EDR, or home-grown
  dynamic sandbox.
- More lexical agent prompt-injection block rules before the baseline and
  capability paths meet the precision gate.

## Completion evidence

Fresh verification on 2026-08-30:

```text
cargo fmt --all -- --check                                      PASS
cargo clippy --workspace --all-targets -- -D warnings          PASS
cargo test --workspace --all-targets                           PASS
cargo run -q -p argus-cli -- corpus test --corpus corpus       PASS (32/32)
```

Focused contracts also passed: 12 `lockfile_scan` unit tests, 9
`lockfile_scan_cli` tests, and the 36-test intelligence CLI suite inside the
full workspace run. All package artifacts used by the new tests are synthetic;
the implementation does not execute package code.
