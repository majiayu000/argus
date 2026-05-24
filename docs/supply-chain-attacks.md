# Supply-chain attack catalog (2018 – May 2026)

Curated reference of real npm / PyPI / GitHub Actions / OS-level supply-chain incidents, organized for argus rule design and corpus expansion. Each entry distinguishes **fact** (citable from the linked source), **inference** (reasoning over the facts), and **argus coverage** (which existing rule fires, what is a gap).

> Compiled 2026-05-24 by reading vendor blogs, CVE advisories, and CISA alerts. URLs are at the bottom. Anything not citable is marked as inference.

## Contents

- [Threat-class taxonomy](#threat-class-taxonomy)
- [Incident timeline (newest first)](#incident-timeline-newest-first)
  - [2026](#2026)
  - [2025](#2025)
  - [2024](#2024)
  - [Pre-2024 (seminal)](#pre-2024-seminal)
- [Cross-cutting patterns](#cross-cutting-patterns)
- [argus rule coverage matrix](#argus-rule-coverage-matrix)
- [Detection gaps and next steps](#detection-gaps-and-next-steps)
- [Sources](#sources)

---

## Threat-class taxonomy

| Class | Vector | Recent example |
|-------|--------|----------------|
| **Maintainer phishing** | Look-alike npm/PyPI login domain harvests token | eslint-config-prettier (Jul 2025, `npnjs.com`) |
| **Token theft + targeted republish** | Stolen token used to push a malicious version | event-stream (2018), Bitwarden CLI (Apr 2026) |
| **Self-replicating worm** | Postinstall script harvests local creds, then republishes every package the victim can publish | Shai-Hulud (Sep 2025), Mini Shai-Hulud (Apr–May 2026) |
| **Typosquatting** | New package name 1–2 chars from a popular one | `raydium-bs58` vs `bs58` (Mar 2026) |
| **Dependency confusion** | Internal-looking unscoped name published on public registry | well-documented since Birsan 2021 |
| **CI compromise / pwn-request** | Pull-request workflows run on attacker-controlled fork code | TanStack (May 2026) |
| **Cache poisoning** | Cross fork-base GitHub Actions cache trust boundary | TanStack (May 2026) |
| **Reusable-action hijack** | Mutable tag in a popular GitHub Action repointed to malicious code | tj-actions/changed-files (Mar 2025) |
| **Long-game maintainer trust** | Attacker spends 18+ months becoming a maintainer | xz-utils (CVE-2024-3094) |
| **Crypto-wallet rewriter** | Runtime hook on `globalThis.fetch` or wallet RPC rewrites destination addresses | @solana/web3.js (Dec 2024), chalk/debug (Sep 2025) |
| **Lockfile poisoning** | `resolved` URL points at a non-allowlisted host or plain HTTP | hypothetical — covered by argus today |
| **Build-script smuggling** | Backdoor lives in generated `.m4`/binary not the source | xz-utils (CVE-2024-3094) |

---

## Incident timeline (newest first)

### 2026

#### Mini Shai-Hulud wave 5 — atool maintainer compromise (2026-05-19)

**Facts** [source: Unit 42 npm threat landscape update 2026-05-21]
- 639 malicious package versions across 323 unique packages published in roughly one hour after the `atool` maintainer account was taken over.
- Largest single-hour package count of any Shai-Hulud wave to date.
- Attributed to TeamPCP.

**argus coverage**: `lifecycle-script`, `token-harvest`, `github-write-api`, `npm-publish` — all fire on the published artifacts. The "TanStack pwn-request" precondition (compromising the CI account) is upstream of argus.

**Gap**: argus cannot tell a freshly compromised account from a legitimate one. The 1-hour window between compromise and detection is the dangerous one.

---

#### Microsoft `durabletask` PyPI compromise (2026-05-19)

**Facts** [source: StepSecurity, Datadog Security Labs]
- Three malicious versions of Microsoft's official Python SDK `durabletask` published to PyPI.
- 28 KB obfuscated payload silently downloads + executes.
- Steals credentials from AWS, Azure, GCP, Kubernetes, password managers, "over 90 developer tool configurations".
- Lateral-moves through cloud infrastructure.

**argus coverage**: PyPI not yet supported — out of scope for M1.

**Gap**: argus is npm-only. PyPI parity is M2+ work.

---

#### node-ipc compromise (2026-05-14)

**Facts** [source: StepSecurity blog "Active Supply Chain Attack: Malicious node-ipc..."]
- Versions 9.1.6, 9.2.3, 12.0.1 of `node-ipc` published simultaneously to npm.
- ~10 M weekly downloads on the base package.
- 80 KB obfuscated credential-stealing payload injected into the package's CommonJS bundle (runtime, not install).

**argus coverage**: `runtime-hook` would fire on the bundle's global rewrites; `credential-access` if the payload reads `.npmrc`/`.env` literally; `network-exfiltration` on the POST to the C2.

**Gap**: an 80 KB obfuscated single-file bundle is exactly the case where argus's lexical rules are weakest. AST or semantic analysis would help — tracked nowhere in argus today.

---

#### TanStack — pwn-request + CI cache poisoning (2026-05-11)

**Facts** [source: TanStack postmortem, InfoQ, Wiz, Snyk]
- 84 malicious package artifacts across 42 `@tanstack/*` packages, published between 19:20 and 19:26 UTC.
- Attack chain combined three primitives:
  1. **`pull_request_target` "Pwn Request" pattern** — the workflow ran with secrets on attacker-controlled PR code.
  2. **Cache poisoning** across the fork↔base trust boundary.
  3. **Runtime memory extraction** of an OIDC token from the GitHub Actions runner process.
- The maliciously published packages **passed provenance attestation** because they were signed by the same legitimate CI flow.

**argus coverage**: `lifecycle-script` + content rules fire on the artifacts themselves; argus's recent provenance subject-digest check (#15) would *not* catch this because the subject digest matches the bytes — the attestation is genuine, just for malicious content.

**Gap**: argus's signature verification path (#14) won't help either. This is the canonical "trusted CI compromised at the source" attack — provenance is the wrong layer to stop it. Stops require human review of unusually large simultaneous publish windows + builder-identity scoping.

---

#### Bitwarden CLI brief poisoning (2026-04-22)

**Facts** [source: Unit 42 npm threat landscape update]
- `@bitwarden/cli@2026.4.0` distributed via npm between 17:57 and 19:30 EST on 2026-04-22.
- Multi-stage payload on install steals credentials from cloud providers, CI/CD, dev workstations.
- Self-propagates by backdooring every npm package the victim can publish ("Shai-Hulud: The Third Coming").

**argus coverage**: `lifecycle-script`, `token-harvest`, `github-write-api`, `npm-publish` all fire.

**Gap**: 1-hour 33-min exposure window means rapid-publish detection matters more than after-the-fact rule firing.

---

#### Axios RAT compromise (2026-03-31)

**Facts** [source: InfoQ, Arctic Wolf]
- `axios@1.14.1` and `axios@0.30.4` published with a fully-functional Remote Access Trojan.
- Axios ships 100 M+ weekly downloads — top-50 npm dependency.
- Published via hijacked maintainer account.

**argus coverage**: depends on the RAT delivery mechanism (install-time vs runtime). If install-time: `lifecycle-script` + `binary-execution` or `remote-download`. If runtime: `runtime-hook` + `network-exfiltration`.

**Gap**: argus does not currently flag "unusually large version-number gap" (axios was at 1.7.x; a 1.14.x jump is suspicious). A "version-shape anomaly" rule would help.

---

#### Multi-platform supply chain campaign (2026-04-21 to 2026-04-23)

**Facts** [source: GitGuardian "No Off Season"]
- Three coordinated supply chain attacks in 48 hours across npm, PyPI, and Docker Hub.
- All three targeted secrets: API keys, cloud creds, SSH keys, CI tokens.

**argus coverage**: npm payloads covered by existing rules. PyPI/Docker out of scope.

---

#### SAP-related npm packages compromise (2026-04)

**Facts** [source: The Hacker News]
- `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`, `mbt@1.2.48` compromised.
- Credential-stealing payload, attributed to TeamPCP Mini Shai-Hulud variants.

**argus coverage**: Same rule set as other Shai-Hulud-family events.

---

#### PyTorch Lightning supply chain attack (2026-04-30)

**Facts** [source: Penligent.ai]
- `pytorch-lightning` 2.6.2 and 2.6.3 included a hidden `_runtime` directory and an obfuscated **JavaScript** payload that executes when the Python module is imported.
- Mixed-ecosystem attack — Python package shipping JS as part of the payload.

**argus coverage**: Out of scope (PyPI).

**Gap (note)**: When argus eventually does PyPI, the rule that catches "Python package ships a `.js` payload that runs at import" is interesting — it parallels the npm `binary-file` rule.

---

#### LiteLLM PyPI compromise (2026-03-24)

**Facts** [source: Truesec, Datadog, Trend Micro, official LiteLLM advisory]
- `litellm` 1.82.7 and 1.82.8 on PyPI carried malicious code.
- Datadog attributes it to TeamPCP / Shai-Hulud-family campaign.
- LiteLLM is an AI-gateway widely embedded in agent stacks — high blast radius into LLM credential pools.

**argus coverage**: Out of scope (PyPI).

---

#### npm crypto-wallet typosquats (2026-03-24)

**Facts** [source: Socket via gbhackers.com]
- Five packages by `galedonovan`: `raydium-bs58`, `base-x-64`, `base_xd`, `bs58-basic`, `ethersproject-wallet`.
- Each typosquats a legitimate Solana/Ethereum crypto library.
- Hooks the exact function where developers pass private keys (e.g. `Base58.decode()`), exfiltrates the key to a Telegram bot, returns the expected value.

**argus coverage**: `typosquatting` + `low-reputation` would fire on names. `network-exfiltration` on the Telegram POST. `credential-access` is debatable since secrets come from runtime arguments, not files.

**Gap**: argus's typosquat dictionary today includes `react`/`react-dom`/`lodash` but NOT crypto names like `bs58`, `ethersproject-*`, `@solana/web3.js`. The popular-packages list needs ecosystem extension. Catalogued in the corpus next-fixture queue.

---

#### Trivy scanner npm compromise (2026-03)

**Facts** [source: TeamPCP attributed by Tenable, Wiz]
- Aqua Security's Trivy npm package compromised.
- Same TeamPCP toolset as the larger Mini Shai-Hulud campaign.

---

### 2025

#### Shai-Hulud 2.0 — second wave (2025-11)

**Facts** [source: Unit 42, Datadog "Shai-Hulud 2.0", Elastic, RL]
- Renewed npm-focused compromise targeting packages already on the original Shai-Hulud playbook.
- Improved wiper functionality and credential harvesting vs the September 2025 original.
- Sometimes called SHA1-Hulud.

**argus coverage**: same family as the OG worm — `lifecycle-script` + `token-harvest` + `github-write-api` + `npm-publish` all fire.

---

#### Shai-Hulud OG — npm worm (2025-09-15)

**Facts** [source: Unit 42, CISA AA-25-266A, Sysdig, Trellix, Picus]
- 500+ npm packages compromised including `@ctrl/tinycolor`.
- Postinstall script `bundle.js`:
  - Steals npm tokens, GitHub PATs, AWS/GCP/Azure keys.
  - Creates a public GitHub repo named "Shai-Hulud" under the victim's account and commits stolen secrets there (counter-intuitive — exposes the secrets but also creates a tracking artifact).
  - Enumerates other packages the victim maintains.
  - Injects itself + publishes new compromised versions.
- Initial vector: credential-harvesting phishing campaign spoofing npm ("update your MFA settings"), running parallel to the s1ngularity (Nx) campaign.

**argus coverage**: every signature rule fires — `lifecycle-script`, `token-harvest`, `github-write-api` (PUT to api.github.com), `npm-publish`. The corpus fixture `worm-behavior/` is modeled directly on this incident.

---

#### chalk/debug 16-minute compromise (2025-09-08)

**Facts** [source: Sygnia, ccn.com]
- Phishing of the `chalk` maintainer escalated within ~16 minutes to malicious code in 18 trusted JS packages.
- Aggregate weekly download volume: 2 B+ (yes, two billion).
- Payload was a crypto-wallet rewriter: hook destination addresses in transactions before signing, swap to attacker-controlled addresses with visually-similar "lookalike" rendering.

**argus coverage**: `runtime-hook` + `wallet-interception` would fire. The `runtime-wallet-hook` corpus fixture is modeled on this class.

**Gap**: 16-minute exposure window is the real story here. Detection is fine but pre-publish gating is what would have stopped harm.

---

#### s1ngularity / Nx campaign (2025-08)

**Facts** [source: Trellix, Unit 42 background notes for Shai-Hulud]
- Targeted attack against `nx` monorepo tooling packages.
- Harvested 2,349 developer credentials from 1,079 systems.
- Set the stage for Shai-Hulud by populating the credential pool.

**argus coverage**: `lifecycle-script` + `credential-access` for the harvesting payload itself.

---

#### eslint-config-prettier hijack (2025-07-18) — CVE-2025-54313

**Facts** [source: StepSecurity, JFrog, Snyk advisory SNYK-JS-ESLINTCONFIGPRETTIER-10873299, ZeroPath]
- Phishing email on 2025-07-17 from `npnjs.com` (look-alike of `npmjs.com`) impersonated npm support, sent maintainer `JounQin` to enter creds.
- Attacker pushed malicious versions: `eslint-config-prettier` 8.10.1, 9.1.1, 10.1.7 (10.1.6 was safe — only `package.json` modified, no payload).
- Also poisoned: `eslint-plugin-prettier`, `synckit`, `@pkgr/core`, `napi-postinstall`. Combined ~78 M weekly downloads.
- Payload: postinstall script invokes `rundll32` on Windows against a bundled `node-gyp.dll` containing the Scavenger RAT.

**argus coverage**: `lifecycle-script` + `binary-file` + `binary-execution` all fire. The `binary-dropper` corpus fixture is modeled on this class.

**Gap**: The look-alike domain `npnjs.com` is the upstream root cause. argus is a scanner, not a phishing filter — but a "registry-hosted vs typosquat domain" rule on the user's git history could be a future skill.

---

#### tj-actions/changed-files (2025-03-14 to 2025-03-15) — CVE-2025-30066

**Facts** [source: Wiz, CISA, Unit 42, GitHub advisory GHSA-mrrh-fwg8-r2c3]
- All version tags of `tj-actions/changed-files` repointed to malicious code by an attacker who compromised a PAT used by a bot with access to the repo.
- 23,000+ public repos consumed this action.
- Payload: Python script extracted secrets from the Runner Worker process memory and printed them to GitHub Actions logs — public for any public repo.
- Likely upstream cause: compromise of `reviewdog/action-setup@v1` (CVE-2025-30154).
- Patched in v46.0.1.

**argus coverage**: argus does not scan GitHub Actions workflows. **Full gap.**

**Detection idea**: a "mutable-tag action" rule on consumer projects — `uses: tj-actions/changed-files@v46` (mutable) is high-risk; `@<commit-sha>` is fine. Out of scope for argus npm scanner but worth a sibling tool.

---

### 2024

#### xz-utils CVE-2024-3094 (2024-03-29 disclosure)

**Facts** [source: Wikipedia entry, Hunted Labs, Checkmarx, Yarsalabs]
- Backdoor in `xz-utils` 5.6.0 (2024-02-24) and 5.6.1 (2024-03-09) discovered by Andres Freund on 2024-03-29 while investigating sshd CPU anomalies.
- Attack staged from 2021: attacker identity "Jia Tan" created GitHub account 2021-01-26, accreted contributor reputation, became maintainer late 2022, planted backdoor infrastructure (ifunc changes) mid-2023, deployed payload Feb 2024.
- Backdoor lived in `build-to-host.m4` macros plus obfuscated binary in test files (`tests/files/bad-3-corrupt_lzma2.xz`, `tests/files/good-large_compressed.lzma`) — invisible if you read the source tarball, only triggered through the build script.
- CVSS 10.0. Affected Linux distros (Debian, Gentoo, Arch, Fedora, openSUSE, Alpine sid/testing).
- Patched in 5.6.2 on 2024-05-29.

**argus coverage**: argus is npm/PyPI-only. **Full gap.**

**Inference [confidence: high]**: even a hypothetical argus-for-tarballs would have missed this — the backdoor was in compiled binary "test fixtures" and a single-purpose `.m4` macro that only ran via autotools. `binary-file` would have flagged the test artifacts as suspicious, but the project has many legitimate binary test fixtures.

**Lesson**: long-game social-engineering attacks against maintainer accounts are not addressable by static rules. argus's threat model explicitly says so (SPEC §1).

---

#### @solana/web3.js compromise (2024-12)

**Facts** [source: ReversingLabs, PortSwigger Daily Swig]
- Versions 1.95.6 and 1.95.7 of `@solana/web3.js` contained credential-stealing functions.
- Mitigation: downgrade to 1.95.5 or upgrade to 1.95.8.
- Rotate ALL secrets/keys from any system that installed the malicious versions.

**argus coverage**: depends on payload location. If install-time: `lifecycle-script` + `credential-access`. If runtime: `runtime-hook` + `wallet-interception`.

---

### Pre-2024 (seminal)

#### ua-parser-js / coa / rc — DanaBot waves (2021-10)

**Facts** [source: FOSSA blog, Bleeping Computer]
- `ua-parser-js` (millions weekly), `coa` (~9 M weekly), `rc` (~14 M weekly) all compromised in October 2021.
- Identical mechanism across the three: `"preinstall": "start /B node compile.js & node compile.js"`.
- Payload: DanaBot family trojan — credential scraping, screenshots, file capture, cryptominer.
- The `compile.js` postinstall pattern is the original "shape" for several later attacks.

**argus coverage**: `lifecycle-script` + `remote-download` + `binary-execution`. The `lifecycle-curl-sh` corpus fixture generalizes this pattern.

---

#### event-stream / flatmap-stream (2018-10)

**Facts** [source: Dominic Tarr's "statement on event-stream compromise" gist, The Register]
- Dominic Tarr, original maintainer of `event-stream`, handed publish access to `right9control` (later identified as Hans Jürgen Schönig sock puppet) who had emailed asking to take over.
- `right9control` added `flatmap-stream` as a dep, then on 2018-10-05 pushed `flatmap-stream@0.1.1` with obfuscated code targeting Copay (Bitcoin wallet) build chain.
- The malicious code unpacked only when the parent project was Copay — narrow targeting kept it undetected for months.

**argus coverage**: `lifecycle-script` would fire on the install hook used by Copay's build. The Copay-specific unpack check is exactly the kind of dependency confusion that's hard to model statically.

**Lesson**: social engineering of an exhausted maintainer is older than the cloud, and argus does not solve it.

---

## Cross-cutting patterns

1. **Phishing of maintainers is the #1 entry point.** Look-alike domains (`npnjs.com`, similar Google-search-ad campaigns), "MFA update required" pretexts, GitHub Actions PATs leaked through workflow logs. Of the 2025–2026 incidents catalogued above, at least six trace back to a single phished maintainer.

2. **Worms collapse the incident-response window.** Pre-Shai-Hulud, a stolen maintainer token led to a hand-crafted poisoned version. Post-Shai-Hulud, the same stolen token automatically poisons every package the victim can publish, within minutes. The 16-minute chalk window is now baseline.

3. **Provenance attestation is not a panacea.** TanStack proved that an attacker who pivots through legitimate CI infrastructure gets a real Sigstore signature on malicious bytes. argus's #14 follow-up (full signature verification) is still worth doing, but it does not stop the strongest current attack class.

4. **The lifecycle-script monoculture is intact.** Nearly every 2025–2026 incident uses `preinstall` or `postinstall`. Bun's `trustedDependencies` and pnpm's `approve-builds` are the strongest registry-side mitigations; argus's default `--ignore-scripts` posture lands in the same spot. PR #6 confirms argus never runs lifecycle scripts during scan.

5. **Crypto-wallet attacks have moved from install-time to runtime hooks.** `runtime-hook` + `wallet-interception` are the rules that fire on the chalk/debug pattern. `@solana/web3.js` ran the same playbook months earlier.

6. **Cross-ecosystem attacks are now routine.** TeamPCP publishes the same payload to npm and PyPI in the same hour. PyTorch Lightning shipped JS-in-Python. argus's PyPI-parity story is real M2 work.

---

## argus rule coverage matrix

Mapping every incident above to argus's current detection rules. ⛔ = full gap, ⚠️ = partial / rule fires but easily bypassed, ✅ = a rule directly catches the attack pattern.

| Incident (Year) | Initial vector | Payload class | argus rule(s) | Verdict |
|---|---|---|---|---|
| Mini Shai-Hulud wave 5 atool (2026-05) | maintainer compromise | worm | lifecycle-script + token-harvest + github-write-api + npm-publish | ✅ catches post-install |
| Microsoft durabletask (2026-05) | maintainer compromise | cred stealer | — (PyPI) | ⛔ ecosystem gap |
| node-ipc (2026-05) | maintainer compromise | runtime cred stealer | runtime-hook + network-exfiltration | ⚠️ heavy obfuscation in single bundle |
| TanStack (2026-05) | CI pwn-request + cache poisoning | worm-class but **with valid provenance** | lifecycle-script + content rules | ⚠️ provenance check (#15) does not help |
| Bitwarden CLI (2026-04) | maintainer compromise | multi-stage cred stealer + worm | lifecycle-script + token-harvest + github-write-api | ✅ |
| Axios RAT (2026-03) | maintainer compromise | RAT | depends on install vs runtime | ⚠️ |
| SAP `@cap-js/*` (2026-04) | TeamPCP worm | cred stealer | lifecycle-script + token-harvest | ✅ |
| PyTorch Lightning (2026-04) | maintainer compromise | JS-in-Python loader | — | ⛔ ecosystem gap |
| LiteLLM PyPI (2026-03) | TeamPCP worm | cred stealer | — | ⛔ ecosystem gap |
| galedonovan crypto typosquats (2026-03) | typosquat | runtime key theft | typosquatting + low-reputation + network-exfiltration | ⚠️ dictionary needs crypto names |
| Shai-Hulud OG (2025-09) | maintainer phishing | worm | full set | ✅ corpus fixture `worm-behavior` |
| chalk/debug (2025-09) | maintainer phishing | wallet rewriter | runtime-hook + wallet-interception | ✅ corpus fixture `runtime-wallet-hook` |
| s1ngularity / Nx (2025-08) | maintainer phishing | cred harvest | lifecycle-script + credential-access | ✅ |
| eslint-config-prettier (2025-07) | phishing via npnjs.com | RAT via rundll32 | lifecycle-script + binary-file + binary-execution | ✅ corpus fixture `binary-dropper` |
| tj-actions (2025-03) | PAT compromise | GA secret exfil | — | ⛔ GitHub Actions out of scope |
| xz-utils (2024-03) | long-game maintainer | build-script smuggling | — | ⛔ ecosystem out of scope; long-game social engineering not detectable statically |
| @solana/web3.js (2024-12) | maintainer compromise | wallet hook | runtime-hook + wallet-interception | ✅ |
| ua-parser/coa/rc (2021-10) | maintainer compromise | DanaBot | lifecycle-script + remote-download + binary-execution | ✅ corpus fixture `lifecycle-curl-sh` |
| event-stream (2018-10) | social engineering of exhausted maintainer | targeted bitcoin theft | lifecycle-script | ⚠️ Copay-specific unpack hard to model |

**Summary** (2025–2026 incidents only):
- ✅ Direct catch: 7 / 16 incidents
- ⚠️ Partial / bypassable: 4 / 16 incidents
- ⛔ Ecosystem/architecture gap: 5 / 16 incidents (4 PyPI, 1 GitHub Actions)

---

## Detection gaps and next steps

Each gap below is a real candidate for an argus follow-up issue or a sibling tool.

### Gaps argus can close in M1.x

1. **Typosquat dictionary needs crypto names.** Add `bs58`, `ethers`, `web3.js`, `@solana/web3.js`, `viem`, `wagmi`, `@flashbots/*`, `hardhat`, `truffle` to `name::POPULAR_PACKAGES`. Cheap. Caught 1 attack in this catalog.

2. **Version-shape anomaly rule.** When a package's version jumps multiple minors or a major in a single hour, that is suspicious — Bitwarden CLI, Axios, chalk all had this signature. Implementable as a rule over the packument's `time` field. New rule `version-shape-anomaly` (info or block depending on severity).

3. **Rapid-publish-window rule.** Multiple packages from the same maintainer published in a < 1 hour window is the Shai-Hulud / atool signature. Requires querying the npm user's recent publish history — needs additional registry endpoint.

4. **Builder-identity allowlist.** argus's #14 follow-up (full Sigstore verify) is the prerequisite. Once signatures are verified, refuse `provenance-verified-subject` unless the cert OIDC identity matches `https://github.com/<allowed-orgs>/...`.

### Gaps argus cannot close in M1.x

5. **PyPI parity.** TeamPCP runs the same playbook against PyPI. Either argus grows a PyPI mode or a sibling tool ships. M2.

6. **GitHub Actions consumer-side scanning.** tj-actions-style attacks require scanning workflow YAML for mutable tags and unsafe `pull_request_target` patterns. Different surface; out of scope for npm scanner.

7. **CI provenance pwn-request defense.** TanStack proves provenance attestation alone is insufficient. Mitigation lives in maintainer-side workflow design, not consumer-side scanning.

8. **Long-game maintainer trust attacks.** xz-utils-class incidents need social-graph / commit-pattern anomaly detection. Open research problem; not for argus.

### New corpus fixtures worth adding (M1.x)

- `crypto-key-stealer/` — typosquats a crypto library, hooks `Base58.decode`, POST key to Telegram. Maps to galedonovan.
- `obfuscated-runtime-bundle/` — large minified single-file bundle with hidden `globalThis.fetch` rewrite. Maps to node-ipc.
- `version-shape-anomaly/` (synthetic) — a packument fixture that suddenly jumps from 1.7.x to 1.14.x. Once the rule exists.
- `slsa-signed-malicious/` — synthesizes a tarball + valid attestation for malicious content. Tests that argus's provenance check correctly does NOT clear it just because the digest matches. Maps to TanStack.

---

## Sources

### Vendor + research blogs

- Unit 42 (Palo Alto Networks): [The npm Threat Landscape (Updated May 21, 2026)](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)
- Unit 42: [Shai-Hulud Worm Compromises npm Ecosystem](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- Unit 42: [GitHub Actions Supply Chain Attack: tj-actions/changed-files](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/)
- Wiz: [GitHub Action tj-actions/changed-files supply chain attack](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)
- Wiz: [Mini Shai-Hulud Strikes Again: TanStack + more npm Packages Compromised](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- Datadog Security Labs: [Shai-Hulud 2.0 npm worm: analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- Datadog Security Labs: [LiteLLM and Telnyx compromised on PyPI: TeamPCP](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)
- Sysdig: [Shai-Hulud: the self-replicating worm](https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages)
- ReversingLabs: [Shai-Hulud npm supply chain attack](https://www.reversinglabs.com/blog/shai-hulud-worm-npm)
- ReversingLabs: [Atomic and Exodus crypto wallets targeted](https://www.reversinglabs.com/blog/atomic-and-exodus-crypto-wallets-targeted-in-malicious-npm-campaign)
- ReversingLabs: [Malware found in Solana npm library](https://www.reversinglabs.com/blog/malware-found-in-solana-npm-library-with-50m-downloads)
- StepSecurity: [Active Supply Chain Attack: node-ipc](https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack)
- StepSecurity: [Microsoft durabletask PyPI Package Compromised](https://www.stepsecurity.io/blog/microsofts-durabletask-pypi-package-compromised-in-supply-chain-attack)
- StepSecurity: [eslint-config-prettier compromise](https://www.stepsecurity.io/blog/supply-chain-security-alert-eslint-config-prettier-package-shows-signs-of-compromise)
- TanStack: [Postmortem: TanStack npm supply-chain compromise](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- Sygnia: [16 Minutes to Impact (chalk)](https://www.sygnia.co/threat-reports-and-advisories/npm-supply-chain-attack-september-2025/)
- Snyk: [Maintainers of ESLint Prettier Plugin Attacked via npm](https://snyk.io/blog/maintainers-of-eslint-prettier-plugin-attacked-via-npm-supply-chain-malware/)
- Snyk advisory: [SNYK-JS-ESLINTCONFIGPRETTIER-10873299 (CVE-2025-54313)](https://security.snyk.io/vuln/SNYK-JS-ESLINTCONFIGPRETTIER-10873299)
- JFrog: [eslint-config-prettier Hijack — 10.1.6 is safe](https://research.jfrog.com/post/eslint-config-prettier-hijack-10-1-6-safe/)
- Socket: [Malicious npm Packages Impersonate Flashbots SDKs](https://socket.dev/blog/malicious-npm-packages-impersonate-flashbots-sdks-targeting-ethereum-wallet-credentials)
- GitGuardian: [No Off Season — three campaigns in 48 hours](https://blog.gitguardian.com/three-supply-chain-campaigns-hit-npm-pypi-and-docker-hub-in-48-hours/)
- Tenable: [Mini Shai-Hulud Supply Chain Attack CVE-2026-45321 FAQ](https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions)
- Trend Micro: [Inside the LiteLLM Supply Chain Compromise](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html)
- Trend Micro: [What We Know About the NPM Supply Chain Attack](https://www.trendmicro.com/en_us/research/25/i/npm-supply-chain-attack.html)
- Arctic Wolf: [Supply Chain Attack Impacts Widely Used Axios npm Package](https://arcticwolf.com/resources/blog/supply-chain-attack-impacts-widely-used-axios-npm-package/)
- InfoQ: [TanStack Details Sophisticated npm Supply Chain Attack](https://www.infoq.com/news/2026/05/tanstack-supply-chain-attack/)
- InfoQ: [Axios npm Package Compromised in Supply Chain Attack](https://www.infoq.com/news/2026/04/axios-supply-chain/)
- The Hacker News: [SAP-Related npm Packages Compromised](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)
- The Hacker News: [GitHub Action Compromise Puts CI/CD Secrets at Risk in 23K+ Repositories](https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html)
- The Hacker News: [Mini Shai-Hulud Worm Compromises TanStack, Mistral AI, Guardrails AI & More](https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html)
- Trellix: [npm Account Hijacking and the Rise of Supply Chain Attacks](https://www.trellix.com/blogs/research/npm-account-hijacking-and-the-rise-of-supply-chain-attacks/)
- ZeroPath: [CVE-2025-54313 deep technical dive](https://zeropath.com/blog/cve-2025-54313-eslint-config-prettier-supply-chain-malware)
- Cycode: [GitHub Action tj-actions/changed-files complete guide](https://cycode.com/blog/github-action-tj-actions-changed-files-supply-chain-attack-the-complete-guide/)
- FOSSA: [Embedded Malware in NPM: Coa, Rc, Ua-parser](https://fossa.com/blog/embedded-malware-npm-coa-rc-ua-parser/)
- OPSWAT: [ESLint Hack: Major Software Supply Chain Attack](https://www.opswat.com/blog/recent-eslint-hack-raises-software-supply-chain-concerns-to-the-next-level)
- SafeDep: [eslint-config-prettier compromised — 30 M weekly downloads](https://safedep.io/eslint-config-prettier-major-npm-supply-chain-hack/)
- Mend: [NPM Supply Chain Attack Hits Popular Packages with Crypto Drainer](https://www.mend.io/blog/npm-supply-chain-attack-infiltrates-popular-packages/)
- Hunted Labs: [Jia Tan's GitHub History and the XZ Utils Breach](https://www.huntedlabs.com/blog/where-the-wild-things-are-a-complete-analysis-of-jia-tans-github-history-and-the-xz-utils-software-supply-chain-breach)

### Government + clearing houses

- CISA: [Widespread Supply Chain Compromise Impacting npm Ecosystem (AA-25-266A)](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- CISA: [Supply Chain Compromise of tj-actions/changed-files (CVE-2025-30066) and reviewdog/action-setup@v1 (CVE-2025-30154)](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)

### Reference

- Wikipedia: [XZ Utils backdoor](https://en.wikipedia.org/wiki/XZ_Utils_backdoor)
- Dominic Tarr: [statement on event-stream compromise](https://gist.github.com/dominictarr/9fd9c1024c94592bc7268d36b8d83b3a)
- GitHub Advisory Database: [GHSA-mrrh-fwg8-r2c3 (tj-actions/changed-files)](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3)
