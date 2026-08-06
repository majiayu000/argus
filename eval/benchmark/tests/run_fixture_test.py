#!/usr/bin/env python3
"""Synthetic-only contract/evaluator matrix and fail-closed tests."""

import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from evaluator import ValidationError, evaluate  # noqa: E402


def manifest(root: Path):
    artifact = root / "fixture.txt"
    artifact.write_text("synthetic benchmark fixture\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

    def sample(sid, kind, truth, prediction):
        findings = ([{"rule_id": "SYN-01", "finding_id": sid + "-finding"}] if prediction == "positive" else [])
        truth_findings = ([{"rule_id": "SYN-01", "finding_id": sid + "-truth"}] if truth == "positive" else [])
        return {
            "id": sid,
            "kind": kind,
            "group": "synthetic",
            "artifact": {"path": "fixture.txt", "sha256": digest},
            "ground_truth": {"status": truth, "findings": truth_findings},
            "prediction": {"status": prediction, "findings": findings},
        }

    return {
        "schema_version": 1,
        "dataset_type": "synthetic-fixtures",
        "dataset_id": "fixture-matrix-v1",
        "source": {"corpus_revision": "synthetic-corpus-r1", "scanner_revision": "synthetic-scanner-r1", "corpus_sha256": "a" * 64, "provenance": "checked-in synthetic fixture"},
        "reviewer_provenance": {"method": "human-dual-review", "reviewers": ["reviewer-A", "reviewer-B"], "arbitrator": "reviewer-arbitrator"},
        "samples": [
            sample("hit-tp", "hit", "positive", "positive"),
            sample("hit-fp", "hit", "negative", "positive"),
            sample("non-hit-fn", "non-hit", "positive", "negative"),
            sample("non-hit-tn", "non-hit", "negative", "negative"),
        ],
    }


def expect_reject(base, root, mutate, label):
    item = copy.deepcopy(base)
    mutate(item)
    try:
        evaluate(item, root)
    except ValidationError:
        return
    raise AssertionError(f"{label}: malformed manifest was accepted")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        base = manifest(root)
        report = evaluate(base, root)
        assert report["metrics"]["counts"] == {"TP": 1, "FP": 1, "FN": 1, "TN": 1}
        assert report["metrics"]["precision"] == 0.5
        assert report["metrics"]["recall"] == 0.5
        assert report["sample_sizes"] == {"total": 4, "eligible": 4, "hit": 2, "non_hit": 2}
        assert list(report["groups"]) == ["synthetic"]
        assert json.dumps(report, sort_keys=True) == json.dumps(evaluate(base, root), sort_keys=True)

        # Unknown keys/types, identity, provenance, and integrity all reject.
        expect_reject(base, root, lambda x: x.update(extra=True), "unknown top-level key")
        expect_reject(base, root, lambda x: x["source"].update(extra=True), "unknown nested key")
        expect_reject(base, root, lambda x: x.update(schema_version="1"), "wrong type")
        expect_reject(base, root, lambda x: x["samples"].append(copy.deepcopy(x["samples"][0])), "duplicate sample ID")
        expect_reject(base, root, lambda x: x["samples"].__setitem__(3, {**x["samples"][3], "artifact": {**x["samples"][3]["artifact"], "sha256": "b" * 64}}), "hash drift")
        expect_reject(base, root, lambda x: x["reviewer_provenance"].update(reviewers=["one"]), "reviewer provenance")
        expect_reject(base, root, lambda x: x["samples"].__setitem__(0, {**x["samples"][0], "ground_truth": {"status": "needs-context", "findings": []}}), "unresolved label")
        expect_reject(base, root, lambda x: x["samples"].__setitem__(0, {**x["samples"][0], "kind": "hit", "prediction": {"status": "negative", "findings": []}}), "hit prediction contract")
        expect_reject(base, root, lambda x: x.update(samples=[x["samples"][0], x["samples"][1]]), "missing non-hit")

        # Precision and recall denominators fail closed.
        expect_reject(base, root, lambda x: x.update(samples=[x["samples"][2], x["samples"][3]]), "empty precision denominator")
        expect_reject(base, root, lambda x: x.update(samples=[x["samples"][1], x["samples"][3]]), "empty recall denominator")

        # Equality at a configured boundary passes; just above it fails.
        equal = copy.deepcopy(base)
        equal["thresholds"] = {"min_precision": 0.5, "min_recall": 0.5}
        assert evaluate(equal, root)["threshold_result"]["passed"] is True
        expect_reject(base, root, lambda x: x.update(thresholds={"min_precision": 0.500001, "min_recall": 0.5}), "precision threshold")
        expect_reject(base, root, lambda x: x.update(thresholds={"min_precision": 0.5, "min_recall": 0.500001}), "recall threshold")

    print("PASS: benchmark contract synthetic matrix and fail-closed cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
