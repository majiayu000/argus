# Argus security admission direction — 2026-08-30

## Decision

Argus should be the fail-closed admission gate that answers one narrow
question before a dependency or agent configuration is applied:

> May this exact artifact and this exact change enter this machine or CI run?

Argus remains static and pre-execution. It verifies the resolved artifact,
scans it without running package or workflow code, consumes pinned
malicious-package intelligence, compares upgrades with their base artifacts,
inspects repository workflow trust boundaries, and emits an auditable `allow`,
`allow-with-approval`, or `block` decision.

Argus is not a general SCA platform, EDR, dynamic malware sandbox, SIEM, or a
hosted multi-tenant security product. Provenance proves how bytes were built;
it does not prove that the bytes are benign. Dynamic detonation, CI egress and
secret controls, and incident response remain sibling integrations.

## Why this direction

Recent incidents invalidate a trust model based only on package identity,
maintainer identity, or valid provenance:

- ChainDrop used compromised legitimate release paths, included packages with
  valid SLSA provenance, and moved command-and-control discovery into Ethereum.
- `@7nohe/openapi-react-query-codegen` was published through an exposed GitHub
  OIDC workflow after an external actor reached a publishing path. The
  malicious releases added install-time execution surfaces.
- Registry and CI platforms are adding publish-time malware scanning, staged
  publishing, read-only caches, and network controls. Argus should complement
  those controls at the consumer's admission boundary, not duplicate them.

The product implication is that an upgrade must be reviewed as a change in
capability, even when the publisher and provenance are valid. The useful
question is not only “does the current package contain a risky construct?” but
also “did this upgrade introduce that construct?”

## Core defense loop

1. Resolve the exact package coordinate from the lockfile.
2. Fetch through the ecosystem pipeline and verify registry integrity.
3. Safely extract and statically scan; never execute package code.
4. Match the exact coordinate against a pinned, verified malicious-package
   snapshot when the operator supplies one.
5. For a changed coordinate, scan both base and current artifacts and report
   introduced and resolved findings.
6. Derive the current decision from the complete current evidence. If either
   side required for the comparison cannot be assessed, block the aggregate
   result rather than presenting an incomplete comparison as clean.
7. Send remaining uncertainty to sibling controls: isolated detonation for
   runtime behavior and CI egress/secret enforcement for execution-time harm.
8. Before repository workflow changes merge, scan the repository root for
   mutable Action dependencies, direct untrusted-context script injection, and
   privileged workflows that check out attacker-controlled code.

## What the report must answer

1. Which exact dependency coordinates were added or changed?
2. Which findings are new in each upgraded artifact, and which disappeared?
3. Did integrity verification and malicious-package matching complete?
4. Why is the aggregate decision allow, approval, or block?
5. Which artifacts or comparison sides were not assessed, and therefore must
   not be interpreted as safe?

## Research inputs

- Zscaler ThreatLabz, “Tracking Shai-Hulud Inside the ChainDrop npm Worm”:
  <https://www.zscaler.com/blogs/security-research/tracking-shai-hulud-inside-chaindrop-npm-worm>
- StepSecurity, “@7nohe/openapi-react-query-codegen Compromised Through an
  Exposed npm Publishing Workflow”:
  <https://www.stepsecurity.io/blog/7nohe-openapi-react-query-codegen-compromised-npm-publishing-workflow>
- OpenSSF malicious-packages data set:
  <https://github.com/ossf/malicious-packages>
- npm lifecycle script configuration:
  <https://docs.npmjs.com/cli/v11/using-npm/config/#ignore-scripts>
- GitHub Actions security hardening:
  <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- OpenSSF Scorecard workflow checks:
  <https://github.com/ossf/scorecard/blob/main/docs/checks.md>

These incident reports are evidence for the threat model, not malware fixtures.
Argus tests continue to use synthetic packages and `.example.invalid` only.

## Documents

- [Product and threat model](product.md)
- [P0 technical specification](tech.md)
- [Implementation and roadmap](tasks.md)
