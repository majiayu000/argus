# Quarantine

This directory is for local, uncommitted real malicious package samples.

Rules:

- Do not commit real malicious tarballs.
- Do not run `npm install`, `bun install`, `pnpm install`, or `yarn install` on these samples.
- Only download, hash, unpack into an isolated temp directory, and static scan.
- Keep the machine free of real tokens while inspecting quarantine samples.
- Prefer disposable containers or VMs.

Suggested metadata-only entry format:

```yaml
- id: ua-parser-js-2021
  advisory: GHSA-pjwm-rvh2-c87w
  package: ua-parser-js
  version: 0.7.29
  sha512: TBD
  mode: real-static-only
  expectedDecision: block
  expectedRules:
    - lifecycle-script
    - binary-downloader
```
