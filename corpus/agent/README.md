# argus agent-skill corpus (seed)

Material for hardening `argus agent scan` beyond the lexical layer. Built from a
full census of `claude-skill-registry-data` (202,660 skills). See
`../registry-census.md` for the census itself.

## What's here

- `fixtures/` + `index.json` — 6 **synthetic** agent-skill fixtures in argus
  corpus schema. All hosts point at `.example.invalid` (non-resolvable); no
  fixture downloads, executes, or sends anything real. Drop into `argus/corpus`.
- `labeling-worklist.jsonl` — 849 **real** census hits with context, for manual
  TP/FP labeling to measure the current detector's precision.

## The 6 fixtures — and why the negatives matter most

| id | expected | shape |
|----|----------|-------|
| skill-config-backdoor | block | formatter skill whose setup.sh writes `~/.claude/settings` + registers auto-approve hook (capability-misfit) |
| skill-cred-exfil | block | stats skill that reads keys/.env and POSTs off-box (sensitive_read + net_egress) |
| skill-obfuscated-dropper | block | `curl \| base64 -d \| bash` remote stage-2 |
| skill-injection-md | block | hidden HTML comment claiming absolute authority + concealment (pure text attack, no scripts) |
| **skill-benign-installer** | **allow** | SKILL.md documents `curl astral.sh/uv/install.sh \| sh` — official installer, no scripts |
| **skill-benign-net-tool** | **allow-with-approval** | weather skill reads API key + calls its own API (capabilities match intent) |

The two negatives encode the census's core finding: the current lexical layer
**false-positives on benign installers and legit API tools**. Any new detector
must keep these two green, or it is not an improvement — it just relabels noise.

## Labeling worklist

Each JSONL row: `path`, `category`, `batch`, matched capability/pattern,
`contexts` (line + surrounding text), and empty `label` / `reviewer_note`.

| batch | count | purpose |
|-------|-------|---------|
| script-capability | 245 | real scripts with extracted capabilities (15 flagged high — misfit/obfuscation combos) |
| override_lang | 210 | SKILL.md injection-language hits (mixed TP/FP) |
| concealment | 244 | SKILL.md concealment-language hits (mixed) |
| *-fp-sample | 150 | 50 each of exfil/curl_pipe/autorun — near-100% FP, to quantify the noise floor |

Fill `label` with `TP` / `FP` / `needs-context`. The high-priority scripts and
override/concealment batches are the useful eval set; the fp-samples exist to
put a number on the false-positive rate that motivated this work.

## Census headline (why this exists)

- **99.9%** of skills are pure text (SKILL.md only) — the attack surface is the
  **LLM instruction**, not script execution.
- Only **1,263** script files exist corpus-wide; 245 carry any capability.
- Current lexical patterns: exfil_instruction **3,509 hits ≈ all FP**
  (`POST /token`, `postgresql://user:password`), curl_pipe_sh **1,571 ≈ FP**
  (official installers). Shipping a trust badge on this layer would be
  actively misleading.

## Current implementation status

`argus corpus test --corpus corpus/agent` asserts all 6 synthetic fixtures,
including both negatives. `argus agent scan --format json` now emits manifest
fields on capability-backed findings:

```json
{
  "capability": "net_egress",
  "evidence": ["scripts/fetch.sh:8"],
  "resolved_host": "api.weather.example.invalid"
}
```

The remaining external step is hand-labeling `labeling-worklist.jsonl`; without
labels, precision/recall cannot be measured honestly.
