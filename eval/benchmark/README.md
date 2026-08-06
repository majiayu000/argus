# Synthetic benchmark contract

This directory contains a versioned, strict, fail-closed evaluator for
synthetic Argus fixtures. It is a contract and test harness, not a quality
claim. The evaluator accepts only `dataset_type: synthetic-fixtures`, requires
two named human reviewers plus an arbitrator, validates every artifact's
SHA-256, and emits deterministic JSON with sample sizes, TP/FP/FN/TN counts,
precision, recall, and extensible per-group metrics.

```sh
python3 eval/benchmark/evaluator.py path/to/manifest.json --root path/to/root
python3 eval/benchmark/tests/run_fixture_test.py
```

`needs-context` (or any other unresolved label) is rejected and never enters
metrics. Duplicate or missing sample IDs, unknown keys/types, hash drift,
missing hit/non-hit coverage, undefined precision/recall denominators, and
threshold failures all fail closed. Optional `min_precision` and `min_recall`
thresholds are only exercised by the checked-in synthetic fixture test; they
are not production gates. Equality at a threshold passes and values below it
fail.

The 849 hit-only worklist in `eval/labeling/` still requires two independent
真人 reviewers and human arbitration. It cannot establish recall because it
contains no non-hit population. Until a real frozen dataset is created and
reviewed, this tool provides no precision/recall or other quality statement.
Every source dataset and final-labels artifact is bound by an explicit path
and SHA-256 and is verified under `--root`; per-sample decisions retain both
reviewer evidence and, when needed, arbitration evidence.

Manifest shape (schema version 1):

```json
{
  "schema_version": 1,
  "dataset_type": "synthetic-fixtures",
  "dataset_id": "example-v1",
  "source": {
    "corpus_revision": "...",
    "scanner_revision": "...",
    "dataset_artifact": {"path": "dataset.json", "sha256": "64 lowercase hex characters"},
    "final_labels_artifact": {"path": "final-labels.jsonl", "sha256": "64 lowercase hex characters"},
    "provenance": "..."
  },
  "reviewer_provenance": {
    "method": "human-dual-review",
    "reviewers": ["human-a", "human-b"],
    "arbitrator": "human-arbitrator"
  },
  "samples": [{
    "id": "sample-1",
    "kind": "hit",
    "group": "group-1",
    "coordinate": "stable-observation-coordinate",
    "artifact": {"path": "fixture.txt", "sha256": "..."},
    "ground_truth": {
      "status": "positive",
      "findings": [{"rule_id": "R-1", "finding_id": "f-1"}],
      "resolution": {
        "source": "agreed",
        "reviewer_a": {"status": "positive", "evidence": "..."},
        "reviewer_b": {"status": "positive", "evidence": "..."},
        "arbitration": null
      }
    },
    "prediction": {"status": "positive", "findings": [{"rule_id": "R-1", "finding_id": "f-1"}]}
  }]
}
```

Observation identity is the immutable `artifact.sha256`, independent of the
display `id`, group, or coordinate; duplicate digests are rejected to prevent
contradictory rows from being counted twice. Group, coordinate, path, and
prediction are derived from (and strictly cross-validated against) the frozen
dataset artifact, so a manifest cannot use a free coordinate to bypass
identity. Positive statuses require at least one finding and negative statuses
require an empty finding list. The final-labels artifact is non-empty, parsed,
and the sole ground-truth source after exact per-sample cross-validation.
