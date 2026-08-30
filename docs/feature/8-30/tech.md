# Admission technical specification

## Existing components to reuse

The implementation stays within the existing lockfile scan path:

- `argus_lockfile::diff_scan_targets` already returns added, removed, and
  changed targets with both base and current coordinates.
- `EcosystemFetcher` already performs fetch, integrity verification, safe
  extraction, and static scanning.
- `ScanReport` already carries the exact coordinate, findings, and decision.
- `intel::apply_malicious_snapshot` already verifies and applies a local
  malicious-package snapshot.
- `LockfileScanOutcome` already owns aggregate decision and fail-closed fetch
  or scan failures.

No new cross-crate trait, baseline database, policy language, or execution mode
is required.

The completed P1/P2 implementation adds two CLI-local boundary modules:
`approvals` parses and assesses exact approval bindings, while `observation`
writes the isolated-observation manifest atomically. Fetchers receive the
lockfile-retained digest through the existing pipeline options; no second
fetch path or execution runtime was introduced.

## Command contract

`lockfile-scan` gains the existing shared option:

```text
--malicious-db <PATH>
--approval-ledger <PATH>
--export-observation <PATH>
```

Without `--base`, all current targets are scanned and the malicious snapshot is
applied to every successfully scanned current report.

With `--base`:

- `added` current targets are scanned;
- `changed.current` targets are scanned and remain the only package reports
  contributing findings to JSON, text, SARIF, and the normal policy fold;
- `changed.base` targets are scanned only to construct version comparison
  evidence;
- removed targets are not fetched because they cannot execute after the
  current lockfile is applied.

The malicious snapshot is applied to current reports only. Historical base
matching is not needed to decide whether the current coordinate is known
malicious, and a historical intelligence match must not create a current SARIF
alert.

For npm SRI, uv/PyPI artifact hashes, and Cargo checksums, the selected
downloaded bytes must match at least one lockfile-retained SHA-1/256/384/512
digest. Registry-advertised integrity is still verified separately. Unsupported,
malformed, or mismatching lockfile evidence leaves the package unassessed and
blocks the aggregate decision.

Approval records use strict JSON schema version 1 and bind purl, algorithm,
digest, capability, reason, and `expiresAt`. Duplicate, empty, malformed, or
expired records fail operationally. Only a complete set of approval-scoped
capabilities can change aggregate `allow-with-approval` to `allow`; package
reports preserve their original findings and decision as audit evidence.

## Finding identity and delta

Finding comparison uses a stable semantic identity:

```text
(rule_id, severity, location, capability, resolved_host)
```

`detail` and `evidence` are report explanation, not identity. Line-number or
wording changes must not turn the same capability at the same location into a
new finding. Duplicate identities are compared as sets.

For each successfully assessed changed target, JSON records:

```json
{
  "base": { "purl": "pkg:npm/demo@1.0.0", "decision": "allow" },
  "current": { "purl": "pkg:npm/demo@2.0.0", "decision": "block" },
  "introduced": [/* current Finding values */],
  "resolved": [/* base Finding values */]
}
```

Text output names the base-to-current coordinate transition and prints the
introduced and resolved rule IDs. Clean changes are retained with empty arrays
so the report proves that both sides were assessed.

## Failure contract

- A current fetch or scan failure retains the existing `failed` entry and
  blocks the aggregate decision.
- If a current changed target succeeds but its required base target does not
  produce a report, `comparison_failed` records the base locator and cause and
  blocks the aggregate decision.
- A configured malicious snapshot that is missing, corrupt, incompatible, or
  future-dated returns an operational error before rendering. It is never
  converted into a no-match.
- Local or unsupported current targets retain the existing explicit `skipped`
  behavior. This feature does not claim to compare artifacts the ecosystem
  pipeline cannot fetch.
- A successful comparison cannot downgrade the current report decision.

## Determinism and output

- Current report ordering follows current lockfile target ordering.
- Version comparison ordering follows `diff_scan_targets` changed ordering.
- Introduced findings follow current report order; resolved findings follow
  base report order.
- JSON adds `version_changes` and `comparison_failed` arrays.
- Text states comparison coverage before package findings.
- SARIF continues to render current reports only. Aggregate exit status still
  reflects comparison failures even when SARIF has no result for the failed
  base artifact.

## Security invariants

1. No untrusted artifact content is executed.
2. Both comparison sides use the same rule session and static scan pipeline.
3. The base artifact never replaces the current artifact in the active report.
4. Current malicious intelligence participates in the final decision before
   version deltas are finalized.
5. Missing comparison evidence cannot yield `allow`.
6. A finding present in both versions remains in the current report even though
   it is absent from `introduced`.

## Capability correlation contract

Package findings use the existing `Finding.capability`, `evidence`, and
`resolved_host` fields as the single machine-readable fact carrier. No second
report model or risk score is introduced. The first correlated capability set
is deliberately small:

```text
install_trigger, sensitive_reference, sensitive_read, net_egress, remote_download,
process_spawn, exec_eval
```

Detectors still emit the individual observations. A deterministic correlation
pass then adds one blocking attack-chain finding when the required facts share
one executable location:

- `credential-exfiltration-chain`: `sensitive_read` plus `net_egress` or
  `remote_download`;
- `download-execution-chain`: `remote_download` plus `process_spawn` or
  `exec_eval`.

Standalone `credential-access` and `network-exfiltration` observations preserve
their existing blocking policy. Correlation adds stronger intent-bearing
evidence without weakening package ecosystems that do not yet emit the full
capability set. It never combines unrelated locations, treats provenance as
safety, or executes the package to fill missing facts.

A sensitive path mentioned in executable source remains visible as
`sensitive_reference`, but it cannot enter a blocking chain. Only a supported
syntax fact proving a file-reading call or command becomes `sensitive_read`.

For npm, supported JavaScript and TypeScript sources and lifecycle scripts
retain AST-backed evidence. For PyPI, `setup.py` supplies install-time network,
process, and dynamic-execution facts, while the shared Python content scan
supplies sensitive-read evidence. Syntax failure remains an operational error.

The process-level acceptance test must serve inert npm and PyPI archives from a
local TCP registry, invoke the production CLI, and prove both sides:

- a previously unknown coordinate with a same-file credential-exfiltration
  chain blocks without a malicious-database match;
- standalone or split network and sensitive-read capabilities remain visible,
  preserve their existing decision, and do not become a fabricated chain.

## Verification

Focused:

```sh
cargo test -p argus-cli lockfile_scan
cargo test -p argus-cli --test lockfile_scan_cli
```

Repository gates:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo run -q -p argus-cli -- corpus test --corpus corpus
```
