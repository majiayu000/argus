# Sigstore Signature Verification — Design (M2, Issue #14)

> Status: implemented · Authored: 2026-05-26 · Completed: 2026-05-28 · Tracks: [#14](https://github.com/majiayu000/argus/issues/14)
>
> Owner: @majiayu000
>
> Implementation: shipped behind the optional `sigstore` Cargo feature in [#29](https://github.com/majiayu000/argus/pull/29), [#35](https://github.com/majiayu000/argus/pull/35), and [#36](https://github.com/majiayu000/argus/pull/36), with the npm v0.2 compatibility path hardened in [#151](https://github.com/majiayu000/argus/pull/151) and [#165](https://github.com/majiayu000/argus/pull/165).

---

## 1. Threat Model — what M1 closed, what M2 closes

### M1 already in place (PR #15, merged)

Subject-digest cross-check against the npm-published `attestations.url` DSSE bundle.

- Detects: tampered packument or rogue mirror that swaps in a different tarball after the attestation was published.
- Cannot detect: a fully-forged DSSE bundle whose subject digest matches a tarball signed with an attacker key, or a bundle signed by a Fulcio cert whose OIDC identity does not belong to the legitimate publisher.

### M2 adds

| Layer | What it asserts |
|---|---|
| DSSE signature | The attestation envelope was actually signed by the leaf certificate's private key. |
| Fulcio chain | The leaf certificate chains to the official Sigstore Fulcio root, valid at the time of signing. |
| Rekor inclusion | The attestation was actually logged in the public Rekor transparency log, with a valid signed entry timestamp. |
| OIDC identity | The certificate's OIDC `san` and `issuer` extensions match an allowlisted builder (see §3). |

After M2, a forged attestation requires either compromising a real OIDC-published builder run, or compromising the Sigstore trust roots themselves. That is a meaningfully different adversary class than "tamper with the packument".

### Out of scope for M2 (explicit)

- Verifying publisher *intent* (the OIDC identity may legitimately match a builder you did not personally vet — see §3 trust-policy section).
- Detecting attestations that are valid but unrelated to the tarball you fetched (M1 already covers that via subject-digest).
- TUF-protected refresh of the Sigstore trust roots — we ship a snapshot and rely on `sigstore` crate defaults for staleness handling.

---

## 2. Crate boundary

Decision: new `argus-verify` crate (decision recorded 2026-05-26 with project owner).

```
crates/
  argus-verify/
    Cargo.toml          # standalone DSSE + full Sigstore verifier dependencies
    src/
      lib.rs            # public API for both verification layers
      dsse.rs           # standalone DSSE envelope verification
      sigstore.rs       # Fulcio/Rekor/SCT/artifact/identity verification
      trust/
        trusted_root.json # vendored, digest-pinned Sigstore trust root
```

### Why a separate crate

- Adds ~30 transitive deps. Keeping them out of `argus-core` / `argus-fetch` means the default `argus` binary footprint stays roughly where M1 left it.
- `argus-fetch` declares `argus-verify` as an **optional dependency** behind a `sigstore` feature flag (not enabled by default). Operators who want Sigstore set `argus-cli` to build with `--features sigstore`.
- The `--verify-sigstore` CLI flag is parsed unconditionally; if the binary was built without the feature, the flag exits with a clear error rather than silently skipping verification.

### What does NOT change

- `argus-core::url` and `argus-core::scan` (just landed in #25 / PR #26): re-used as-is.
- `argus-fetch::provenance` (M1): the `check_subject_digest` path stays exactly as it is. M2 layers on top, not in place of.
- The `Transport` trait stays the same and fetches only the npm attestations document. Full verification is offline against the bundle's inclusion material and the vendored, digest-pinned Sigstore trust root.

---

## 3. Trust roots & policy

Decision: require the operator to supply the accepted OIDC identity regular
expressions; the GitHub Actions issuer remains the CLI default.

### OIDC identity policy

`--verify-sigstore` requires at least one `--sigstore-identity <REGEX>`. The leaf
certificate's `subjectAlternativeName` URI must match one supplied expression,
and its OIDC issuer must match `--sigstore-issuer` (which defaults to):

```
https://token.actions.githubusercontent.com
```

### Why this scope

- Trust remains an operator decision rather than a built-in list of acceptable
  repositories or workflows.
- Missing identity expressions are rejected before network access. Malformed
  expressions and policy mismatches cannot produce a verified result.

### What policy is not bundled

- Argus does not ship built-in trust decisions for GitLab CI, self-hosted CI,
  custom GitHub workflows, or other publishers. Operators must supply the exact
  issuer and identity expressions they accept.
- Bundles that provide only a public-key hint, including the current npm-keyring
  shape, remain unsupported because they do not carry a Fulcio certificate
  chain for this verifier.

Supported Fulcio-backed identities verify only when the operator explicitly
supplies matching issuer and identity policy. A mismatch produces
`provenance-signature-invalid` at Critical severity and blocks.

---

## 4. Default mode & CLI surface

Decision: opt-in via `--verify-sigstore` (decision recorded 2026-05-26).

```
argus fetch chalk --verify-sigstore \
  --sigstore-identity '^https://github\.com/example/project/.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
```

### Why opt-in for M2

- The default fetch path stays offline-friendly. No Rekor / Fulcio round-trip on the hot path.
- Reduces blast radius if a Sigstore outage happens (Rekor has had multi-hour incidents historically).
- Mirrors `cosign verify` ergonomics: explicit verification, not implicit.

### Promotion path to default-on (M3 or later)

- Track the rate of `provenance-signature-verified` findings vs total fetches across the corpus.
- Once stable for ≥30 days against the top-100 OIDC-publishing packages, flip the default and add `--no-verify-sigstore` as the opt-out.
- This is M3 work, **not committed** in M2.

---

## 5. Findings (rule IDs)

| Rule ID | Severity | When | Decision impact |
|---|---|---|---|
| `provenance-signature-verified` | Info | All required DSSE, Fulcio, SCT, Rekor, artifact, and OIDC identity-policy checks pass. | none (positive signal only) |
| `provenance-signature-invalid` | Critical | Any required cryptographic, transparency, artifact-binding, or identity-policy check fails. | `block` |
| `provenance-signature-untrusted-issuer` | Info | Legacy structured verdict retained for API compatibility; the full verifier no longer emits it for policy mismatches. | none |
| `provenance-signature-unverified` | High | Verification was requested but no attestation completed full verification, or the verifier could not evaluate the supplied material. | `block` |

### Why no `medium` severity in this set

Each finding answers a binary question: either we have signature evidence or we do not. A graded severity ("signature is sort of valid") would be honest threat disclosure noise rather than signal.

---

## 6. Test corpus

The shipped tests are deterministic and offline. A captured
`sigstore@2.3.1` tarball and npm v0.2 SLSA bundle live under
`crates/argus-verify/src/testdata/`; no test contacts npm, Fulcio, Rekor, or a
package registry.

- `crates/argus-verify/tests/sigstore_real_fixture.rs` exercises the complete
  cryptographic chain and rejects corrupted artifacts, DSSE signatures, SETs,
  inclusion proofs, Rekor bodies, Fulcio chains, SCT keys, validation times,
  issuers, and identities.
- `crates/argus-fetch/tests/sigstore_integration.rs` carries the same evidence
  through the fetch pipeline with `MockTransport`, including verified,
  unsupported, corrupt, downgraded, artifact-mismatch, and identity-mismatch
  outcomes.
- `crates/argus-fetch/tests/sigstore_feature_off.rs` proves that requesting
  verification from a build without the optional feature fails explicitly.

The npm-keyring public-key-hint bundle remains an explicit `Unsupported`
outcome; it never becomes verified or silently clean.

---

## 7. Historical estimate

The implementation is complete. The estimate below is retained as design
history rather than current work.

- Day 1: `argus-verify` crate skeleton, integrate `sigstore` crate, DSSE verification path against synthetic fixtures.
- Day 2: Fulcio chain + Rekor inclusion proof, wire into `argus-fetch::provenance`, finding plumbing.
- Day 3: OIDC identity allowlist, fixtures, corpus updates, `--verify-sigstore` CLI flag, docs.

Total: ~3 days of focused work. This is the **honest** estimate; the "tracer bullet" (one verification end-to-end on a real package) is achievable in ~1 day but the boundary work to make it production-quality dominates.

---

## 8. Open questions (status after Day 1 + Day 2 research spike)

### Resolved by Day 1 (PR #29, merged 2026-05-28) and the Day 2 spike

- **Crate library choice**: switched from the official `sigstore` crate to the modular `sigstore-verify` + `sigstore-trust-root` + `sigstore-types` family (0.11.0, from prefix-dev/sigstore-rust). The modular crates are **synchronous**, verification-only, and offline-capable with a pre-loaded `TrustedRoot`. An audited path patch carries the npm v0.2 compatibility changes described in §10.
- **Bundle version compatibility** (highest pre-Day-2 risk): a compile-spike using the real `sigstore@2.3.1` npm attestations fixture confirmed that `sigstore_types::Bundle::from_json` parses the npm `mediaType=application/vnd.dev.sigstore.bundle+json;version=0.2` bundle without modification, even though the fork's README emphasises v0.3. v0.2 → v0.3 is additive enough that the parser accepts both.
- **DSSE signature-verification primitive**: implemented in argus-verify Day 1 *without* the sigstore crate at all (pure RustCrypto). The Day 2 sigstore-verify integration covers the higher layers (Fulcio chain + Rekor + identity policy) and the existing DSSE primitive remains as a backstop / duplicate check.

### Resolved in the shipped implementation

- **Trust-root snapshot**: the repository vendors
  `crates/argus-verify/src/trust/trusted_root.json`; verification is
  deterministic and offline.
- **Verifier dependency boundary**: the optional `sigstore` feature keeps the
  default build free of the verifier dependency path. Requesting verification
  from a build without that feature is a hard error.
- **Artifact binding**: focused fixtures prove that the downloaded artifact
  bytes are bound to the in-toto subject and that tampering blocks.
- **Identity policy**: caller-supplied identity expressions are validated as
  regular expressions and issuer or identity mismatches block.
- **Rekor behavior**: the verifier consumes embedded transparency-log material;
  an online Rekor re-check remains outside M2.
- **Fetch API**: signature verification is a sibling layer after the existing
  subject-digest check, so M1 behavior remains intact when the feature is off.

---

## 9. Acceptance (completed)

- [x] `argus-verify` is a workspace member and compiles in the workspace.
- [x] `argus-fetch` builds with and without the optional `sigstore` feature;
  requesting verification without the feature fails explicitly.
- [x] Offline positive and negative fixtures cover DSSE, Fulcio, SCT, Rekor,
  artifact binding, issuer, and identity validation.
- [x] A captured real `sigstore@2.3.1` npm bundle reaches
  `provenance-signature-verified`; corrupt or policy-mismatched variants block.
- [x] Disabling `--verify-sigstore` preserves the existing M1 path without
  signature-layer findings.
- [x] The repository corpus remains part of the normal workspace gate.
- [x] [#36](https://github.com/majiayu000/argus/pull/36) closed
  [#14](https://github.com/majiayu000/argus/issues/14); later hardening is
  recorded in §10.

---

## 10. Honest threat disclosure

What M2 still does NOT prevent, even with full Sigstore verification:

- **TrapDoor-class OIDC compromise**: an attacker who gains write access to a real GitHub repository in the allowlist (e.g. by stealing maintainer credentials) can publish a malicious package whose attestation passes every M2 layer. Sigstore signature verification proves *who signed*, not *what they signed is safe*.
- **Builder-workflow compromise**: a malicious change to a reusable workflow in the allowlist would produce attestations that pass M2 but ship attacker code. This is the case M3 builder-workflow pinning would address.
- **Trust-root rotation**: if the Sigstore Fulcio root is rotated and we have not pulled an updated trust bundle, valid signatures will fail M2 with `provenance-signature-invalid` until we ship an update.

### npm v0.2 compatibility patch

The crates.io `sigstore-verify` 0.11.0 release still has three narrow incompatibilities with npm's captured `sigstore@2.3.1` SLSA bundle: it excludes `intoto/0.0.2` + SET from candidate integrated-time sources, binds in-toto subjects only with SHA-256, and requires the write-only Rekor envelope payload even though committed entries retain only `payloadHash`.

Argus path-patches an exact, checksum-verified 0.11.0 source copy. The patch:

- admits a positive `intoto/0.0.2` integrated time only when an inclusion promise is present; the original verifier must still validate the SET, inclusion proof/checkpoint, future-time bound, and certificate validity before success;
- computes SHA-512 only from caller-supplied artifact bytes and matches it against in-toto subjects, while retaining SHA-256 support;
- validates committed Rekor entries against payload type/hash plus the exact DSSE signature and Fulcio certificate. The non-canonical original envelope JSON hash cannot be reproduced from a bundle, but its declared value remains bound by the verified SET and inclusion proof.

No error string or bundle shape is downgraded. Fulcio chain/EKU/time, SCT, issuer, identity, DSSE PAE signature, artifact binding, Rekor consistency, checkpoint/proof, and SET checks all remain mandatory. The real fixture reaches `Verified`; corrupt signatures, artifacts, SETs, proofs, Rekor bodies, chains, SCT keys, times, and identity policies remain invalid and block. The npm-keyring public-key-hint path remains `Unsupported`.

The vendored crate README records the upstream tag, commit, crates.io checksum, license, patch scope, and removal condition. Remove the path patch only after an upstream release passes the same positive and negative fixture matrix.
