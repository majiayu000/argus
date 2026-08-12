# argus agent-skill corpus (seed)

Material for hardening `argus agent scan` beyond the lexical layer. Built from a
full census of `claude-skill-registry-data` (202,660 skills). See
`../registry-census.md` for the census itself.

## What's here

- `fixtures/` + `index.json` — 7 **synthetic** agent-skill fixtures in argus
  corpus schema. All hosts point at `.example.invalid` (non-resolvable); no
  fixture downloads, executes, or sends anything real. Drop into `argus/corpus`.
- `labeling-manifest.json` + `labeling-worklists/` — a pinned, sharded
  two-cohort AI-reviewed benchmark: 719 unique census-hit packages preserving all
  849 detector findings, plus 719 detector non-block packages.

## The 7 fixtures — and why the negatives matter most

| id | expected | shape |
|----|----------|-------|
| skill-config-backdoor | block | formatter skill whose setup.sh writes `~/.claude/settings` + registers auto-approve hook (capability-misfit) |
| skill-cred-exfil | block | stats skill that reads keys/.env and POSTs off-box (sensitive_read + net_egress) |
| skill-obfuscated-dropper | block | `curl \| base64 -d \| bash` remote stage-2 |
| skill-injection-md | block | hidden HTML comment claiming absolute authority + concealment (pure text attack, no scripts) |
| **skill-benign-installer** | **allow** | SKILL.md documents `curl astral.sh/uv/install.sh \| sh` — official installer, no scripts |
| **skill-benign-net-tool** | **allow-with-approval** | weather skill reads API key + calls its own API (capabilities match intent) |
| **skill-benign-system-override** | **allow** | theme/gesture/game/branding docs use generic `override system` prose without agent-authority targets |

The three negatives encode recurring false-positive traps in the lexical layer:
**benign installers, legitimate API tools, and generic `override system` prose
that does not target agent authority**. Any new detector must keep all three
green, or it is not an improvement — it just relabels noise.

## Labeling worklist

The manifest binds every shard to the exact source commit/tree, row count, and
SHA-256. Each JSONL row contains its path, detector evidence, context, and empty
label/note fields.

| legacy finding batch | count | purpose |
|-------|-------|---------|
| script-capability | 245 | real scripts with extracted capabilities (15 flagged high — misfit/obfuscation combos) |
| override_lang | 210 | SKILL.md injection-language hits (mixed TP/FP) |
| concealment | 244 | SKILL.md concealment-language hits (mixed) |
| *-fp-sample | 150 | 50 each of exfil/curl_pipe/autorun — near-100% FP, to quantify the noise floor |
| detector-non-block-v1 | 719 packages | deterministic non-block cohort for finding false negatives and true negatives |

The 849 legacy hit rows are detector findings, not independent package labels.
They are aggregated into 719 package samples so packages with several findings
do not receive extra statistical weight; every finding and context remains in
the package row.

The declared AI reviewer labels ground truth as `block` / `non-block` /
`needs-context`; the evaluation pipeline derives TP/FP/FN/TN from that label
and a live scan by the current Argus binary. See
`../../eval/labeling/README.md` for the single-review workflow.

All 1,438 samples now have definitive evidence-backed labels: 24 `block` and
1,414 `non-block`, with no unresolved rows. The initial current-scanner result
is 15 TP, 232 FP, 9 FN, and 1,182 TN (precision 0.060729, recall 0.625). The
balanced case-control design does not estimate source-population prevalence.

## Census headline (why this exists)

- **99.9%** of skills are pure text (SKILL.md only) — the attack surface is the
  **LLM instruction**, not script execution.
- Only **1,263** script files exist corpus-wide; 245 carry any capability.
- Current lexical patterns: exfil_instruction **3,509 hits ≈ all FP**
  (`POST /token`, `postgresql://user:password`), curl_pipe_sh **1,571 ≈ FP**
  (official installers). Shipping a trust badge on this layer would be
  actively misleading.

## Current implementation status

`argus corpus test --corpus corpus/agent` asserts all 7 synthetic fixtures,
including all three negatives. `argus agent scan --format json` now emits manifest
fields on capability-backed findings:

```json
{
  "capability": "net_egress",
  "evidence": ["scripts/fetch.sh:8"],
  "resolved_host": "api.weather.example.invalid"
}
```

`index.json` also carries a frozen evaluation contract for these seven
maintainer-reviewed synthetic fixtures. Recompute it with:

```bash
argus corpus eval --corpus corpus/agent --format json
```

The result is explicitly a **synthetic fixture metric**, not a real-world
quality claim. At the implementation head it reports 4 TP, 0 FP, 0 FN, 3 TN,
precision 1.0, and recall 1.0. These seven synthetic fixture metrics remain
separate from the pinned 1,438-row AI-reviewed benchmark.
