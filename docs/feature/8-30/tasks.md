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

## P1 — implemented

- [x] Add the first synthetic npm clean-to-malicious replay. It builds real
  tarballs and SHA-512 integrity values, serves them through a real TCP
  registry, invokes the production binary, and proves that a newly added
  `preinstall` remote-download pipeline is introduced and blocks without being
  executed.
- [x] Extend paired replay coverage to `binding.gyp` execution, PyPI
  setup/build subprocess plus download, crates.io `build.rs`, and agent
  hook/baseline drift.
- [x] Maintain separate benign-popular, benign-dangerous, malware, paired-delta,
  and agent-baseline evaluation sets. New default-block behavior requires zero
  benign-popular false blocks and no regression in supported event replay.
- [x] Reuse the stable `binary-file`, `agent-native-executable`, ecosystem build
  findings, and semantic finding delta as the executable inventory; do not add
  a second inventory that can disagree with detector output.
- [x] Define an approval ledger after the delta identity is stable. Bind each
  approval to the exact coordinate, digest, capability, reason, and expiry.
- [x] Ship a narrow GitHub Action contract around lockfile delta, integrity,
  malicious intelligence, current findings, and SARIF.

## P2 — implemented boundary

- [x] Add a small export contract for artifacts requiring isolated dynamic
  observation. Do not embed a sandbox into Argus.
- [x] Export suggested CI egress/secret restrictions to sibling controls; do not
  implement an EDR or network firewall in this repository.
- [x] Keep additional ecosystems paused until each has lockfile-byte binding and
  the same real-registry precision/replay evidence as npm, PyPI, and crates.io.
- [x] Consolidate the public UX around project admission, single-package
  inspection, and agent-baseline inspection after the underlying contracts are
  proven. The existing commands are the three surfaces; no aliases or
  compatibility layers were added.

## P3 — capability correlation

- [x] Attach machine-readable capability and evidence fields to npm/PyPI
  package findings without adding a parallel fact/report model.
- [x] Correlate same-location credential-exfiltration and
  download-to-execution chains into explicit blocking findings.
- [x] Preserve standalone credential/network policy so ecosystems without full
  correlation are not weakened.
- [x] Add inert malicious and benign npm/PyPI corpus coverage and production
  CLI/TCP-registry E2E proving unknown-coordinate detection without execution.
- [x] Update the public rule contract and run every repository-native gate.

## P4 — user delivery

- [x] Freeze the source and Action binary contract at `v0.2.2` without
  claiming that the candidate is already published.
- [x] Put the verified GitHub Action and immutable local-binary path before the
  developer-oriented Cargo examples.
- [x] Run the no-mutation five-target release candidate workflow from the
  final release-prep commit ([run](https://github.com/majiayu000/argus/actions/runs/33309818650)).
- [x] After explicit release authorization, publish the immutable `v0.2.2`
  assets ([release run](https://github.com/majiayu000/argus/actions/runs/33313613384))
  and pass Action dogfood on Linux, macOS, and Windows
  ([dogfood run](https://github.com/majiayu000/argus/actions/runs/33314633370)).
- [x] Keep the protected `v1` branch on `v0.2.1` until the product reaches its
  explicitly approved `v1.0` stability boundary.

## P5 — GitHub Actions admission

- [x] Reuse `agent scan`, the root Action, report formats, SARIF, and decision
  semantics instead of adding a fourth command or compatibility layer.
- [x] Discover immediate `.github/workflows/*.{yml,yaml}` files and parse YAML
  structurally; malformed or duplicate-key workflows are operational errors.
- [x] Require review for mutable remote Action/reusable-workflow references and
  block direct attacker-controlled context interpolation in `run` scripts.
- [x] Block privileged `pull_request_target` / `workflow_run` flows that
  explicitly check out attacker-controlled refs.
- [x] Add process-level hostile/benign/malformed E2E and three inert synthetic
  corpus cases without executing workflow code.
- [x] Add a CI precision gate that downloads five popular public workflows
  from immutable commits, verifies their SHA-256 digests, runs the production
  CLI, and requires zero false blocks.

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
cargo run -q -p argus-cli -- corpus test --corpus corpus       PASS (36/36)
cargo test -p argus-cli --test admission_e2e                  PASS (local TCP registry)
cargo test -p argus-cli --test public_registry_e2e -- --ignored PASS (npm/PyPI/crates)
cargo test -p argus-cli --test public_workflow_e2e -- --ignored PASS (5/5 public workflows, zero false blocks)
python3 -m unittest discover -s scripts/tests -p 'test_release_*.py' PASS (12/12)
npm test --prefix action                                       PASS (16/16)
npm run package --prefix action                                PASS
```

The primary acceptance tests are process-level E2E tests, not mocks: one uses
real TCP sockets and the production binary to replay paired npm, PyPI,
crates.io, and agent surfaces; the other uses public npm, PyPI, and crates.io
over real DNS/TLS with immutable benign-popular versions. Synthetic hostile
artifacts are inert archive bytes and are never executed.
