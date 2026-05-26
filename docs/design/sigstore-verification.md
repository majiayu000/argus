# Sigstore Signature Verification — Design (M2, Issue #14)

> Status: draft · Authored: 2026-05-26 · Tracks: [#14](https://github.com/majiayu000/argus/issues/14)
>
> Owner: @majiayu000
>
> Implementation: deferred to a follow-on session. This document fixes scope, trust roots, crate boundary, public API, error taxonomy, and corpus before any code lands.

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
    Cargo.toml          # [dependencies] sigstore, x509-parser, p256/p384, ...
    src/
      lib.rs            # public API
      trust.rs          # OIDC identity allowlist
      dsse.rs           # DSSE envelope verification
      rekor.rs          # transparency-log inclusion proof
```

### Why a separate crate

- Adds ~30 transitive deps. Keeping them out of `argus-core` / `argus-fetch` means the default `argus` binary footprint stays roughly where M1 left it.
- `argus-fetch` declares `argus-verify` as an **optional dependency** behind a `sigstore` feature flag (not enabled by default). Operators who want Sigstore set `argus-cli` to build with `--features sigstore`.
- The `--verify-sigstore` CLI flag is parsed unconditionally; if the binary was built without the feature, the flag exits with a clear error rather than silently skipping verification.

### What does NOT change

- `argus-core::url` and `argus-core::scan` (just landed in #25 / PR #26): re-used as-is.
- `argus-fetch::provenance` (M1): the `check_subject_digest` path stays exactly as it is. M2 layers on top, not in place of.
- The `Transport` trait stays the same — Rekor and Fulcio fetches go through the same trait so they remain mockable in tests.

---

## 3. Trust roots & policy

Decision: GitHub Actions official reusable workflows only (decision recorded 2026-05-26).

### Allowlisted OIDC identities (initial set)

The leaf cert's `subjectAlternativeName` URI must match one of:

```
https://github.com/actions/.+/.github/workflows/.+@refs/tags/.+
https://github.com/slsa-framework/.+/.github/workflows/.+@refs/tags/.+
```

…with the certificate's OIDC issuer extension equal to:

```
https://token.actions.githubusercontent.com
```

### Why this scope

- `actions/*` and `slsa-framework/*` cover the canonical SLSA generator reusable workflows that the npm registry currently accepts for `--provenance` publishing.
- A custom-workflow publisher (`https://github.com/your-org/.../workflows/...`) **falls back to M1 subject-digest verification only** — we emit an `info`-level finding documenting that signature verification was skipped because the OIDC identity is not in the trust allowlist.
- Operators can extend the allowlist later via a config file. This is **not** part of M2 — keeping config-driven trust roots out of the initial milestone avoids a surface where a typo in a config file silently disables the most important guard.

### What this explicitly does NOT cover

- GitLab CI OIDC publishing.
- Self-hosted CI tokens.
- Manually-signed npm attestations (signed by `cosign sign` outside CI).

For all three, M2 produces `provenance-signature-untrusted-issuer` at `info` severity. That makes the gap visible in the report without blocking ingest.

---

## 4. Default mode & CLI surface

Decision: opt-in via `--verify-sigstore` (decision recorded 2026-05-26).

```
argus fetch chalk --verify-sigstore
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
| `provenance-signature-verified` | Info | All four layers pass (DSSE, Fulcio chain, Rekor inclusion, OIDC identity in allowlist). | none (positive signal only) |
| `provenance-signature-invalid` | High | DSSE signature does not validate against leaf cert, OR Fulcio chain is broken, OR Rekor inclusion proof is invalid. | `block` |
| `provenance-signature-untrusted-issuer` | Info | DSSE/Fulcio/Rekor all pass but OIDC identity is not in the allowlist (e.g. custom workflow). | none (transparency only — M1 subject-digest remains the gate) |
| `provenance-signature-unverified` | Info | Network failure fetching Rekor or Fulcio trust roots; signature could not be evaluated. | none (soft-fail) |

### Why no `medium` severity in this set

Each finding answers a binary question: either we have signature evidence or we do not. A graded severity ("signature is sort of valid") would be honest threat disclosure noise rather than signal.

---

## 6. Test corpus

### Real packages (live fetch, gated behind `--features sigstore-online-tests`)

| Package | Why |
|---|---|
| `sigstore@2.3.1` | Canonical OIDC-published example via slsa-framework. |
| `@actions/core@1.10.x` | GitHub Actions reusable-workflow publish. |
| `chalk@5.4.x` | npm-published with provenance but via a custom workflow → exercises the `untrusted-issuer` path. |

These tests are excluded from default CI (the `sigstore-online-tests` feature is off) so a Rekor outage cannot flap the build.

### Synthetic fixtures (offline, default CI)

- **Forged-bundle, valid subject digest, bogus leaf cert** — must produce `provenance-signature-invalid`.
- **Forged-bundle, leaf cert from real Fulcio but OIDC SAN points to `github.com/attacker/...`** — must produce `provenance-signature-invalid` (chain valid but SAN not in allowlist).
- **Valid bundle, MockTransport returns 503 for Rekor** — must produce `provenance-signature-unverified` and decision must remain unchanged from M1.
- **No attestation at all** — must produce existing M1 `missing-provenance` finding (no regression).

Synthetic fixtures live under `crates/argus-verify/tests/fixtures/`. The forged-bundle generator is a small helper binary at `crates/argus-verify/tests/forge/` so the fixtures can be regenerated when Sigstore trust roots rotate.

---

## 7. Estimate

- Day 1: `argus-verify` crate skeleton, integrate `sigstore` crate, DSSE verification path against synthetic fixtures.
- Day 2: Fulcio chain + Rekor inclusion proof, wire into `argus-fetch::provenance`, finding plumbing.
- Day 3: OIDC identity allowlist, fixtures, corpus updates, `--verify-sigstore` CLI flag, docs.

Total: ~3 days of focused work. This is the **honest** estimate; the "tracer bullet" (one verification end-to-end on a real package) is achievable in ~1 day but the boundary work to make it production-quality dominates.

---

## 8. Open questions (resolve before implementation)

1. **Trust-root snapshot**: do we vendor the Sigstore trust root TUF metadata into the repo, or rely on the `sigstore` crate's built-in default? Vendoring gives reproducible builds but adds rotation maintenance. **Recommendation**: use the crate default for M2; revisit if we hit a trust-root rotation incident.
2. **Async vs sync**: `sigstore` crate is async-first. `argus-fetch` is currently sync. **Recommendation**: spawn a tokio current-thread runtime inside the verify call, isolating async to the verify boundary. Do not async-ify the rest of argus-fetch.
3. **Caching of Rekor responses**: do we cache transparency-log lookups on disk? **Recommendation**: no caching in M2 — opt-in flag implies the user is OK paying the network cost per call. Caching is M3.
4. **Existing `argus-fetch::provenance` API**: should `check_subject_digest`'s return type extend to carry signature-verification results, or should we add a sibling `verify_signature` function? **Recommendation**: sibling function, keep M1 surface untouched.

---

## 9. Acceptance (for the future PR)

- [ ] `argus-verify` crate compiles with `cargo check` and is workspace member.
- [ ] `argus-fetch` builds with **and without** the `sigstore` feature; default build does not pull in any Sigstore dep.
- [ ] Synthetic offline fixtures: all four scenarios in §6 pass.
- [ ] Live-fetch corpus (gated): `sigstore@2.3.1` and `@actions/core` produce `provenance-signature-verified`; `chalk@5.4.x` produces `provenance-signature-untrusted-issuer` without blocking.
- [ ] `argus fetch chalk` (without `--verify-sigstore`) is **bit-identical** to today's M1 output. No latency change, no new dep loaded.
- [ ] `cargo run -p argus-cli -- corpus test` still 12/12.
- [ ] PR closes #14.

---

## 10. Honest threat disclosure

What M2 still does NOT prevent, even with full Sigstore verification:

- **TrapDoor-class OIDC compromise**: an attacker who gains write access to a real GitHub repository in the allowlist (e.g. by stealing maintainer credentials) can publish a malicious package whose attestation passes every M2 layer. Sigstore signature verification proves *who signed*, not *what they signed is safe*.
- **Builder-workflow compromise**: a malicious change to a reusable workflow in the allowlist would produce attestations that pass M2 but ship attacker code. This is the case M3 builder-workflow pinning would address.
- **Trust-root rotation**: if the Sigstore Fulcio root is rotated and we have not pulled an updated trust bundle, valid signatures will fail M2 with `provenance-signature-invalid` until we ship an update.

Documenting these gaps in the M2 PR description is mandatory (per project honest-threat-disclosure preference).
