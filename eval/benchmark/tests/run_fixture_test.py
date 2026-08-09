#!/usr/bin/env python3
"""Synthetic-only contract/evaluator matrix and fail-closed tests."""

import copy
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from evaluator import ValidationError, evaluate, load_json  # noqa: E402


def _write(root: Path, name: str, content: str) -> str:
    path = root / name
    path.write_text(content, encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(root: Path):
    def sample(sid, kind, truth, prediction):
        filename = sid + ".txt"
        digest = _write(root, filename, f"independent synthetic fixture {sid}\n")
        findings = ([{"rule_id": "SYN-01", "finding_id": sid + "-prediction"}] if prediction == "positive" else [])
        truth_findings = ([{"rule_id": "SYN-01", "finding_id": sid + "-truth"}] if truth == "positive" else [])
        resolution = {
            "source": "single-ai-review",
            "reviewer": {
                "status": truth,
                "evidence": f"AI review evidence for {sid}",
            },
        }
        return {
            "id": sid,
            "kind": kind,
            "group": "synthetic",
            "coordinate": sid,
            "artifact": {"path": filename, "sha256": digest},
            "ground_truth": {"status": truth, "findings": truth_findings, "resolution": resolution},
            "prediction": {"status": prediction, "findings": findings},
        }

    samples = [
        sample("hit-tp", "hit", "positive", "positive"),
        sample("hit-fp", "hit", "negative", "positive"),
        sample("non-hit-fn", "non-hit", "positive", "negative"),
        sample("non-hit-tn", "non-hit", "negative", "negative"),
    ]
    dataset = {"schema_version": 1, "samples": [{
        "id": s["id"], "kind": s["kind"], "path": s["artifact"]["path"], "sha256": s["artifact"]["sha256"],
        "group": s["group"], "coordinate": s["coordinate"], "prediction": s["prediction"]
    } for s in samples]}
    labels = "\n".join(json.dumps({"sample_id": s["id"], **s["ground_truth"]}, sort_keys=True) for s in samples) + "\n"
    dataset_digest = _write(root, "dataset.json", json.dumps(dataset, sort_keys=True) + "\n")
    labels_digest = _write(root, "final-labels.jsonl", labels)
    return {
        "schema_version": 1,
        "dataset_type": "synthetic-fixtures",
        "dataset_id": "fixture-matrix-v1",
        "source": {
            "corpus_revision": "synthetic-corpus-r1",
            "scanner_revision": "synthetic-scanner-r1",
            "dataset_artifact": {"path": "dataset.json", "sha256": dataset_digest},
            "final_labels_artifact": {"path": "final-labels.jsonl", "sha256": labels_digest},
            "provenance": "checked-in synthetic fixture bound to its dataset and final-label artifacts",
        },
        "reviewer_provenance": {
            "method": "single-ai-review",
            "reviewer": "codex",
            "model": "gpt-5",
        },
        "samples": samples,
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
        assert report["reviewer_provenance"] == base["reviewer_provenance"]
        assert report["source"] == base["source"]
        assert list(report["groups"]) == ["synthetic"]
        assert json.dumps(report, sort_keys=True) == json.dumps(evaluate(base, root), sort_keys=True)

        # Unknown keys/types, identity, provenance, and integrity all reject.
        expect_reject(base, root, lambda x: x.update(extra=True), "unknown top-level key")
        expect_reject(base, root, lambda x: x["source"].update(extra=True), "unknown nested key")
        expect_reject(base, root, lambda x: x.update(schema_version=True), "bool schema version")
        expect_reject(base, root, lambda x: x.update(schema_version="1"), "wrong schema version type")
        expect_reject(base, root, lambda x: x["reviewer_provenance"].update(reviewer="  "), "empty reviewer identity")
        expect_reject(base, root, lambda x: x["samples"][0].update(group="other-group"), "group bypass")
        expect_reject(base, root, lambda x: x["samples"][0].update(coordinate="free-coordinate"), "free coordinate bypass")
        expect_reject(base, root, lambda x: x["samples"].append({**copy.deepcopy(x["samples"][0]), "id": "different-id"}), "duplicate observation identity")
        expect_reject(base, root, lambda x: x["samples"].__setitem__(3, {**x["samples"][3], "artifact": {**x["samples"][3]["artifact"], "sha256": "b" * 64}}), "hash drift")
        expect_reject(base, root, lambda x: x["reviewer_provenance"].update(model=""), "reviewer model provenance")
        expect_reject(base, root, lambda x: x["samples"].__setitem__(0, {**x["samples"][0], "ground_truth": {**x["samples"][0]["ground_truth"], "status": "needs-context"}}), "unresolved label")
        expect_reject(base, root, lambda x: x["samples"].__setitem__(0, {**x["samples"][0], "ground_truth": {**x["samples"][0]["ground_truth"], "findings": []}}), "positive finding contract")
        expect_reject(base, root, lambda x: x["samples"].__setitem__(1, {**x["samples"][1], "ground_truth": {**x["samples"][1]["ground_truth"], "status": "positive", "findings": [{"rule_id": "SYN-01", "finding_id": "fp-truth"}]}}), "negative/positive finding identity contract")
        expect_reject(base, root, lambda x: x["samples"].__setitem__(0, {**x["samples"][0], "kind": "hit", "prediction": {"status": "negative", "findings": []}}), "hit prediction contract")
        expect_reject(base, root, lambda x: x.update(samples=[x["samples"][0], x["samples"][1]]), "missing non-hit")

        # Correct hashes do not make empty frozen artifacts valid.
        def empty_dataset(x):
            digest = _write(root, "dataset.json", "")
            x["source"]["dataset_artifact"]["sha256"] = digest
        expect_reject(base, root, empty_dataset, "empty dataset artifact")

        def empty_labels(x):
            digest = _write(root, "final-labels.jsonl", "")
            x["source"]["final_labels_artifact"]["sha256"] = digest
        expect_reject(base, root, empty_labels, "empty final-labels artifact")
        base = manifest(root)

        # Review evidence cannot disagree with the frozen ground truth.
        def flip_review(x):
            resolution = x["samples"][0]["ground_truth"]["resolution"]
            resolution["reviewer"]["status"] = "negative"
        expect_reject(base, root, flip_review, "review evidence mismatch")

        # Root containment and regular-file checks reject symlink escape.
        outside = Path(tmp).parent / (Path(tmp).name + "-outside")
        outside.write_text("outside\n", encoding="utf-8")
        try:
            os.symlink(outside, root / "escape.txt")
            escaped = copy.deepcopy(base)
            escaped["samples"][0]["artifact"] = {"path": "escape.txt", "sha256": hashlib.sha256(outside.read_bytes()).hexdigest()}
            expect_reject(escaped, root, lambda x: None, "root-outside symlink")
        finally:
            outside.unlink()

        # Precision and recall denominators fail closed.
        expect_reject(base, root, lambda x: x.update(samples=[x["samples"][2], x["samples"][3]]), "empty precision denominator")
        expect_reject(base, root, lambda x: x.update(samples=[x["samples"][1], x["samples"][3]]), "empty recall denominator")

        # Equality at a configured boundary passes; just above it fails.
        equal = copy.deepcopy(base)
        equal["thresholds"] = {"min_precision": 0.5, "min_recall": 0.5}
        assert evaluate(equal, root)["threshold_result"]["passed"] is True
        expect_reject(base, root, lambda x: x.update(thresholds={"min_precision": 0.500001, "min_recall": 0.5}), "precision threshold")
        expect_reject(base, root, lambda x: x.update(thresholds={"min_precision": 0.5, "min_recall": 0.500001}), "recall threshold")

        # Duplicate JSON keys are rejected before schema validation.
        duplicate = root / "duplicate.json"
        duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        try:
            load_json(duplicate)
        except ValidationError:
            pass
        else:
            raise AssertionError("duplicate JSON key was accepted")

    print("PASS: benchmark contract synthetic matrix and fail-closed cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
