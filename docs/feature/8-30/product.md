# Product and threat model

## User and moment of value

The primary user is a developer or CI owner reviewing a dependency or agent
surface before it is installed, loaded, or merged. The moment of value is the
admission decision, not a later dashboard.

The first product workflow is the existing lockfile scan:

```sh
argus lockfile-scan package-lock.json \
  --base package-lock.main.json \
  --malicious-db malicious-packages.json \
  --approval-ledger approvals.json \
  --export-observation observation.json
```

Single-package inspection and agent-baseline inspection remain important, but
the product stays intentionally small: project admission is `lockfile-scan`,
single-package inspection uses the ecosystem fetch commands, and agent or
repository-workflow admission uses `agent scan`. No aliases, hosted approval
service, or compatibility layer is introduced.

## Trust boundaries

Argus trusts only inputs it has validated at their boundary:

- the supported lockfile parser establishes package coordinates;
- the registry transport and ecosystem fetcher establish the retrieved bytes;
- integrity verification establishes equality with the registry-selected
  digest and, for npm/PyPI/crates lockfile admission, independently with at
  least one digest retained by the lockfile;
- the local malicious-package database establishes only that an exact
  coordinate is or is not present in one pinned snapshot;
- the base lockfile establishes the comparison coordinate, not an assertion
  that the base package is benign.

Valid provenance, a known maintainer, a familiar repository, or a no-match in
the malicious snapshot never upgrades a decision to allow.

## Threat scenarios and control ownership

| Scenario | Argus core | Remaining control |
|---|---|---|
| Known malicious exact version | Pinned intelligence match blocks | Feed production and incident response |
| Registry bytes differ from expected digest | Integrity failure is explicit | Registry remediation |
| Legitimate publisher adds an install/build hook | Base/current finding delta exposes the new surface; current policy decides | Human approval or rejection |
| OIDC publishing workflow is exposed | Artifact change is still inspected despite valid identity | Workflow permissions and environment protection |
| Cache poisoning changes consumed bytes | Verified artifact boundary rejects mismatch where a digest exists | Read-only and isolated CI caches |
| Runtime downloader or dynamic C2 activates | Static rules can expose the loader but cannot prove runtime behavior | Isolated detonation and egress denial |
| Native binary hides behavior | Inventory/static evidence only | Signature policy and sandbox analysis |
| Agent hook or MCP capability drifts | Existing agent baseline path | Runtime least privilege and secret isolation |
| Workflow uses a mutable Action tag | AGT-06 requires explicit approval | Pin the reviewed full commit SHA and review upstream ownership |
| Privileged workflow evaluates untrusted PR data as code | AGT-06 blocks direct script interpolation and untrusted checkout | GitHub environment protection, least-privilege token, and secret isolation |
| Scan, fetch, intelligence, or comparison fails | No clean result; operational error or block | Repair evidence source and rerun |

## Decision and approval semantics

The current package report remains authoritative for policy. Version comparison
adds provenance about *when* a finding appeared; it must not erase a current
finding merely because it also existed in the base artifact.

- `allow`: every current package decision allows and all required assessment
  completed.
- `allow-with-approval`: at least one current package requires explicit review
  and nothing blocks or failed.
- `block`: a current package blocks, a fetch/scan failed, or a required base
  comparison could not be completed.

An approval binds the exact purl, one verified lockfile digest, capability,
reason, and future expiry. It is evaluated only for `allow-with-approval`
reports in npm, PyPI, and crates.io, where Argus has verified lockfile bytes.
It never changes a `block`, fetch failure, scan failure, or comparison failure.

Artifacts that still require runtime evidence can be exported to an observation
manifest. The manifest contains the coordinate, lockfile integrity, findings,
and suggested CI restrictions. Running a sandbox, firewall, or EDR remains the
responsibility of a separate control.

## Product constraints

- No package, fixture, lifecycle script, hook, or build script is executed.
- No score is treated as truth and no LLM is added to the admission path.
- No provenance signal downgrades malicious or high-risk content evidence.
- No skipped, failed, or unavailable comparison is summarized as clean.
- No new ecosystem is added in this feature.
- Local HTTP is accepted only for an exact same-origin loopback registry used
  by isolated E2E; public artifact transport remains HTTPS-only.
- JSON and text expose the delta. SARIF remains current-findings-only so base
  findings are not presented as newly active alerts.

## Success measures

P0 is successful when:

- an unchanged lockfile performs no package fetches with `--base`;
- an added dependency is scanned exactly as before;
- a changed dependency scans base and current artifacts without executing
  either;
- introduced and resolved findings are deterministic and visible;
- an unavailable base artifact blocks rather than producing an empty delta;
- `--malicious-db` works on whole-lockfile current reports and corrupt or
  missing snapshots fail before any clean report is emitted;
- all existing native checks and the synthetic corpus pass.
- the pinned public-workflow benchmark completes with zero false blocks.

Precision work is a release gate, not a marketing target. Default-block rules
must prove zero false blocks on a maintained benign-popular set and replay all
supported incident fixtures before promotion. The existing agent case-control
benchmark remains a regression signal, not an estimate of production
prevalence.
