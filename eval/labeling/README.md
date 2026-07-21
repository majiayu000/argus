# Human labeling workflow for the agent-scan precision/recall baseline (#88)

Tooling to dual-label `corpus/agent/labeling-worklist.jsonl` (849 real census
hits) with human TP/FP judgments.

**Labels must be human-provided.** AI labeling is explicitly forbidden for
issue #88 — these scripts only move data around, compute agreement statistics,
and merge already-human decisions. No script in this directory assigns or
suggests a label.

## Workflow

```
export → two humans label independently → agreement/dispute report
       → human arbitration of disputes → merged final labels
```

### 1. Export reviewer assignments

```
python3 eval/labeling/export_assignments.py
```

Writes `eval/labeling/assignments/reviewer_A.csv` and `reviewer_B.csv`
(849 rows each, identical content). Each row carries the sample id, batch,
category, priority, source path, detector summary (matched pattern or
extracted capabilities), and the matched context snippets, plus empty
`label` and `notes` columns.

### 2. Two humans label independently

Reviewer A fills `reviewer_A.csv`; reviewer B fills `reviewer_B.csv`.
The reviewers must not see each other's file while labeling.

Allowed values for `label`:

| label | meaning |
|-------|---------|
| `TP` | the detector hit is a real finding |
| `FP` | the detector hit is noise |
| `needs-context` | the reviewer cannot decide from the snippet (goes to arbitration) |

Use `notes` for the reviewer rationale (issue #88 requires reviewer notes).

### 3. Agreement / dispute report

```
python3 eval/labeling/compute_agreement.py \
  --a eval/labeling/assignments/reviewer_A.csv \
  --b eval/labeling/assignments/reviewer_B.csv \
  --out-dir eval/labeling/out
```

Outputs in `eval/labeling/out/`:

- `agreement_report.json` — percent agreement and Cohen's kappa over
  dual-labeled rows, plus counts.
- `disputes.csv` — every row where A and B disagree, where either marked
  `needs-context`, or where a label is missing. Has empty `final_label` /
  `final_notes` columns.
- `final_labels.jsonl` — at this stage, only the rows where A and B agree
  on TP or FP.

### 4. Human arbitration

A third human (or both reviewers together) fills `final_label` (TP or FP)
and `final_notes` in a copy of `disputes.csv`, e.g.
`eval/labeling/out/disputes_resolved.csv`.

### 5. Merge final labels

```
python3 eval/labeling/compute_agreement.py \
  --a eval/labeling/assignments/reviewer_A.csv \
  --b eval/labeling/assignments/reviewer_B.csv \
  --out-dir eval/labeling/out \
  --arbitration eval/labeling/out/disputes_resolved.csv
```

`final_labels.jsonl` now contains agreed rows (`"source": "agreed"`) plus
arbitrated rows (`"source": "arbitrated"`), each with both reviewers' notes
for provenance. Arbitrated rows also keep `dispute_reason`
(`disagreement` / `uncertain` / `unlabeled`), so a label resolved from a real
reviewer disagreement stays distinguishable from one resolved for a row that
no reviewer labeled; `agreement_report.json` reports the same breakdown under
`arbitrated_by_reason`. Rows still unresolved stay in `disputes.csv` and never
enter the final labels.

## Tests

A tiny synthetic fixture (not real labels) proves the agreement pipeline
end-to-end:

```
python3 eval/labeling/tests/run_fixture_test.py
```
