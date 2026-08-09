import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
LABELING = ROOT / "eval" / "labeling"
sys.path.insert(0, str(LABELING))


def load_gate():
    path = LABELING / "evaluate_current.py"
    spec = importlib.util.spec_from_file_location("evaluate_current", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CurrentQualityGateTests(unittest.TestCase):
    def test_live_predictions_replace_frozen_predictions(self):
        gate = load_gate()
        rows = {
            "one": {"sample_id": "one", "skill_root": "root/one", "label": "block", "prediction_decision": "allow"},
            "two": {"sample_id": "two", "skill_root": "root/two", "label": "block", "prediction_decision": "block"},
            "three": {"sample_id": "three", "skill_root": "root/three", "label": "non-block", "prediction_decision": "allow"},
            "four": {"sample_id": "four", "skill_root": "root/four", "label": "non-block", "prediction_decision": "block"},
        }
        decisions = {
            "root/one": "block",
            "root/two": "allow",
            "root/three": "allow-with-approval",
            "root/four": "block",
        }
        rules = {"root/one": ["rule-a"], "root/four": ["rule-a"]}

        report = gate.evaluate_rows(
            rows,
            lambda root: {"decision": decisions[root], "rules": rules.get(root, [])},
            jobs=2,
        )

        self.assertEqual(
            report["benchmark"],
            {"tp": 1, "fp": 1, "fn": 1, "tn": 1, "precision": 0.5, "recall": 0.5},
        )
        self.assertEqual(
            report["decision_counts"],
            {"allow": 1, "allow-with-approval": 1, "block": 2},
        )
        self.assertEqual(
            report["rule_metrics"],
            {
                "rule-a": {
                    "support": 2,
                    "block_labels": 1,
                    "non_block_labels": 1,
                    "benchmark_block_fraction": 0.5,
                    "wilson_95_low": 0.094531,
                    "wilson_95_high": 0.905469,
                }
            },
        )

    def test_all_operational_errors_are_reported(self):
        gate = load_gate()
        rows = {
            "one": {"sample_id": "one", "skill_root": "root/one", "label": "block", "prediction_decision": "block"},
            "two": {"sample_id": "two", "skill_root": "root/two", "label": "non-block", "prediction_decision": "allow"},
        }

        def fail(root):
            raise RuntimeError(f"cannot scan {root}")

        with self.assertRaisesRegex(RuntimeError, "root/one.*root/two"):
            gate.evaluate_rows(rows, fail, jobs=2)

    def test_threshold_equality_passes_and_regression_fails(self):
        gate = load_gate()
        metrics = {"precision": 0.25, "recall": 0.5}
        gate.enforce_thresholds(metrics, min_precision=0.25, min_recall=0.5)
        with self.assertRaisesRegex(RuntimeError, "precision"):
            gate.enforce_thresholds(metrics, min_precision=0.26, min_recall=0.5)
        with self.assertRaisesRegex(RuntimeError, "recall"):
            gate.enforce_thresholds(metrics, min_precision=0.25, min_recall=0.51)

    def test_final_labels_must_exactly_match_validated_review(self):
        gate = load_gate()
        reviewer = {"id": "codex", "model": "gpt-test"}
        row = {
            "sample_id": "one",
            "cohort": "hit",
            "batch": "batch",
            "skill_root": "root/one",
            "path": "root/one/SKILL.md",
            "source_commit": "a" * 40,
            "source_url": "https://example.invalid/one",
            "prediction_decision": "block",
            "label": "non-block",
            "notes": "declared benign behavior",
        }
        record = gate.review_contract.final_record(row, reviewer)
        with tempfile.TemporaryDirectory() as directory:
            labels = Path(directory) / "labels.jsonl"
            labels.write_text(json.dumps(record) + "\n", encoding="utf-8")
            gate.validate_final_labels(labels, {"one": row}, reviewer)

            record["notes"] = "drifted"
            labels.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "disagree"):
                gate.validate_final_labels(labels, {"one": row}, reviewer)


if __name__ == "__main__":
    unittest.main()
