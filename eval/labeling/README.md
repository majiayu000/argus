# AI review workflow for the agent benchmark (#145)

This directory exports and finalizes a pinned two-cohort benchmark for one AI
reviewer. Scripts may select and move samples, verify integrity, and calculate
statistics. They must never assign or suggest a label.

The source snapshot and every worklist shard are frozen in
`corpus/agent/labeling-manifest.json`. The snapshot is
`majiayu000/claude-skill-registry-data` commit
`0cd5e5daa71a0fd8e5de723904e5f33fb6e5eed3`, tree
`d936718ef2277eb14eb5fb59f04ed914f290500c`.

## Benchmark composition

| cohort | rows | frozen prediction | purpose |
|---|---:|---|---|
| `detector-hit` | 719 | 247 `block`, 401 `allow`, 71 `allow-with-approval` | review unique packages while preserving all 849 #88 detector findings |
| `detector-non-block` | 719 | row-level `allow` / `allow-with-approval` | expose false negatives and supply a recall denominator |

The 1,438-row balanced set is a package-level case-control benchmark. Its
precision and recall describe this frozen benchmark; they do not estimate
malicious-sample prevalence in the 202,660-skill source population.

## Workflow

```text
verify + export → one declared AI reviews every sample → frozen final labels
```

### 1. Export one reviewer assignment

From the repository root:

```bash
python3 eval/labeling/export_assignments.py \
  --reviewer-id codex \
  --reviewer-model gpt-5
```

This verifies the manifest SHA-256 and row count for all six shards before
writing `eval/labeling/assignments/reviewer.csv`.

The file contains 1,438 samples in deterministic order. Every row includes the
declared reviewer ID/model, cohort, frozen prediction, package root, source
commit, and a link pinned to that commit. Aggregated hit rows retain every
original detector finding and its source context. `label` and `notes` are
empty.

### 2. Review every sample

The AI reviewer fills `label` and an evidence-based rationale in `notes` for
every row. If the exported context is insufficient, inspect the package at the
pinned source commit; do not guess.

| label | ground-truth meaning |
|---|---|
| `block` | the package should be blocked |
| `non-block` | the package should not be blocked |
| `needs-context` | the available pinned evidence is insufficient; the row remains unresolved |

These are ground-truth labels, not `TP` / `FP` labels. The evaluation script
combines them with `prediction_decision` to derive TP, FP, FN, and TN. This
keeps the same label contract valid for both hit and non-block cohorts.

### 3. Validate and freeze the review

```bash
python3 eval/labeling/finalize_review.py \
  --review eval/labeling/assignments/reviewer.csv \
  --out-dir eval/labeling/out
```

Outputs:

- `review_report.json`: reviewer provenance, completion state, label
  distribution, and (only when complete) the confusion matrix.
- `unresolved.csv`: `needs-context` and missing labels with their frozen
  evidence.
- `final_labels.jsonl`: definitive `block` and `non-block` labels with reviewer
  provenance and rationale.

The command reloads the frozen manifest and all declared worklist shards, then
rejects any reviewer file whose sample set or immutable source, prediction, or
evidence fields differ from the export. Mixed reviewer/model provenance is
also rejected.

By default, any unresolved row makes the command fail and benchmark metrics
remain absent. During review, an explicit intermediate snapshot can be written
without metrics:

```bash
python3 eval/labeling/finalize_review.py \
  --review eval/labeling/assignments/reviewer.csv \
  --out-dir eval/labeling/out \
  --allow-incomplete
```

The benchmark is ready to commit only when all 1,438 rows have definitive
evidence-backed labels and the strict command succeeds.

## Rebuild the non-block cohort

Build Argus in a separate detached worktree at the detector baseline recorded
in the manifest. Run the builder from the implementation checkout, and check
out the pinned source snapshot without executing any source content:

```bash
git clone https://github.com/majiayu000/claude-skill-registry-data \
  /path/to/claude-skill-registry-data
git -C /path/to/claude-skill-registry-data checkout \
  0cd5e5daa71a0fd8e5de723904e5f33fb6e5eed3
git worktree add --detach /path/to/argus-detector-baseline \
  7bcd1afbb1a64c90adaf5e1b60a8ca4f0a8b0fba
cargo build \
  --manifest-path /path/to/argus-detector-baseline/Cargo.toml \
  -p argus-cli
python3 eval/labeling/build_non_hit_worklist.py \
  --source-repo /path/to/claude-skill-registry-data \
  --argus-repo /path/to/argus-detector-baseline \
  --argus /path/to/argus-detector-baseline/target/debug/argus
```

The builder verifies both commits and trees. It first rescans the 719 unique
skill roots represented by the 849 preserved #88 findings, aggregates every
finding into its package sample, and verifies or restores its source context.
When the canonical aggregate shards are used as input, it first expands their
`detectorFindings`, so rebuilding from the current checkout is byte-stable.
It then excludes those roots, SHA-256-ranks the remaining roots with the
manifest seed, and statically scans the first 950 candidates. It writes both
719-row cohorts into three shards each, with per-row source blob/content hashes
and actual pinned-baseline predictions. It disables executable lookup and
outbound proxies; it never runs source scripts.

## Tests

```bash
python3 -m unittest discover -s eval/labeling/tests -p 'test_*.py'
python3 eval/labeling/tests/run_fixture_test.py
```
