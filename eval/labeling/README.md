# Human labeling workflow for the agent benchmark (#145)

This directory exports, reconciles, and evaluates a pinned two-cohort
benchmark. Scripts may select and move samples, verify integrity, and calculate
statistics. They must never assign or suggest a human label.

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
verify + export → two humans label independently → agreement/disputes
                → human arbitration → frozen final labels
```

### 1. Export both reviewer assignments

From the repository root:

```bash
python3 eval/labeling/export_assignments.py
```

This verifies the manifest SHA-256 and row count for all six shards before
writing:

- `eval/labeling/assignments/reviewer_A.csv`
- `eval/labeling/assignments/reviewer_B.csv`

Each file contains 1,438 samples in the same deterministic order. The files
differ only in the `reviewer` column. Every row includes its cohort, frozen
prediction, package root, source commit, and a link pinned to that commit.
Aggregated hit rows retain every original detector finding and its source
context. `label` and `notes` are empty.

### 2. Two humans label independently

Reviewers A and B must not see each other's assignment while labeling. Every
labeled row requires a reviewer rationale in `notes`.

| label | ground-truth meaning |
|---|---|
| `block` | the package should be blocked |
| `non-block` | the package should not be blocked |
| `needs-context` | the reviewer cannot decide; human arbitration is required |

These are ground-truth labels, not `TP` / `FP` labels. The evaluation script
combines them with `prediction_decision` to derive TP, FP, FN, and TN. This
keeps the same label contract valid for both hit and non-block cohorts.

### 3. Calculate agreement and disputes

```bash
python3 eval/labeling/compute_agreement.py \
  --a eval/labeling/assignments/reviewer_A.csv \
  --b eval/labeling/assignments/reviewer_B.csv \
  --out-dir eval/labeling/out
```

Outputs:

- `agreement_report.json`: agreement, Cohen's kappa, label distribution, and
  the confusion matrix over finalized rows.
- `disputes.csv`: disagreements, `needs-context`, and missing labels, with
  empty `final_label` / `final_notes`.
- `final_labels.jsonl`: rows independently agreed as `block` or `non-block`.

The command rejects reviewer files that differ in immutable source,
prediction, or evidence fields.

### 4. Human arbitration and final merge

A third human, or both reviewers together, fills `final_label` and
`final_notes` in a copy of `disputes.csv`. Then run:

```bash
python3 eval/labeling/compute_agreement.py \
  --a eval/labeling/assignments/reviewer_A.csv \
  --b eval/labeling/assignments/reviewer_B.csv \
  --out-dir eval/labeling/out \
  --arbitration eval/labeling/out/disputes_resolved.csv
```

Unresolved rows never enter `final_labels.jsonl`. A frozen benchmark is ready
to commit only when all 1,438 rows have human final labels.

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
