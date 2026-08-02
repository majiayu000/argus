#!/usr/bin/env python3
"""Unit tests for the pinned human-labeling task builders."""

import csv
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

LABELING_DIR = Path(__file__).resolve().parents[1]


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, LABELING_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load_module("build_non_hit_worklist", "build_non_hit_worklist.py")
exporter = load_module("export_assignments", "export_assignments.py")
agreement = load_module("compute_agreement", "compute_agreement.py")


class ExportAssignmentsTests(unittest.TestCase):
    def make_test_manifest(self, root):
        source = {
            "repository": "https://example.invalid/source",
            "commit": "a" * 40,
        }
        hit_rows = [
            {
                "batch": "detector-hit-v1",
                "category": "dev",
                "contexts": [{"context": "legacy evidence", "line": 4}],
                "detectorFindings": [
                    {
                        "batch": "legacy",
                        "contexts": [
                            {"context": "legacy evidence", "line": 4}
                        ],
                        "matched": "override",
                        "path": "dev/one/SKILL.md",
                    }
                ],
                "label": "",
                "path": "dev/one/SKILL.md",
                "priority": "high",
                "reviewerNote": "",
                "skillRoot": "dev/one",
            }
        ]
        non_block_rows = [
            {
                "batch": "detector-non-block-v1",
                "category": "ops",
                "cohort": "detector-non-block",
                "contexts": [{"context": "benign evidence", "line": 1}],
                "label": "",
                "path": "ops/two/SKILL.md",
                "prediction": {
                    "decision": "allow",
                    "positiveDecision": "block",
                    "rules": [],
                },
                "priority": "normal",
                "reviewerNote": "",
                "skillRoot": "ops/two",
            }
        ]
        cohorts = []
        for cohort_id, filename, rows in (
            ("detector-hit", "hit.jsonl", hit_rows),
            ("detector-non-block", "non-block.jsonl", non_block_rows),
        ):
            raw = b"".join(
                (
                    json.dumps(row, separators=(",", ":"), sort_keys=True)
                    + "\n"
                ).encode()
                for row in rows
            )
            path = root / filename
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            cohorts.append(
                {
                    "id": cohort_id,
                    "predictionDecision": (
                        "block" if cohort_id == "detector-hit" else "allow"
                    ),
                    "predictionCounts": {
                        (
                            "block"
                            if cohort_id == "detector-hit"
                            else "allow"
                        ): len(rows)
                    },
                    "rowCount": len(rows),
                    "combinedSha256": digest,
                    **(
                        {
                            "detectorFindingCount": 1,
                            "legacyInputCombinedSha256": "0" * 64,
                            "legacyInputRowCount": 1,
                            "legacyUniqueSkillRootCount": 1,
                        }
                        if cohort_id == "detector-hit"
                        else {}
                    ),
                    "shards": [
                        {
                            "path": filename,
                            "rowCount": len(rows),
                            "sha256": digest,
                        }
                    ],
                }
            )
        manifest = {
            "schemaVersion": 1,
            "sourceSnapshot": source,
            "detectorBaseline": {"positiveDecision": "block"},
            "cohorts": cohorts,
        }
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path

    def test_export_is_pinned_unlabeled_and_dual_reviewed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self.make_test_manifest(root)
            rows = exporter.load_manifest_worklists(
                manifest_path,
                repo_root=root,
            )
            records = exporter.build_records(rows)
            paths = exporter.write_assignments(root / "out", records)

            self.assertEqual(len(records), 2)
            self.assertEqual(
                {record["cohort"] for record in records},
                {"detector-hit", "detector-non-block"},
            )
            self.assertTrue(all(record["label"] == "" for record in records))
            self.assertEqual(
                {record["skill_root"] for record in records},
                {"dev/one", "ops/two"},
            )
            self.assertTrue(
                all(
                    record["source_commit"] == "a" * 40
                    and f"/blob/{'a' * 40}/" in record["source_url"]
                    and record["prediction_decision"] in {"block", "allow"}
                    for record in records
                )
            )

            exported = []
            for path in paths:
                with path.open(newline="", encoding="utf-8") as handle:
                    exported.append(list(csv.DictReader(handle)))
            reviewer_a, reviewer_b = exported
            self.assertEqual(
                [row["sample_id"] for row in reviewer_a],
                [row["sample_id"] for row in reviewer_b],
            )
            self.assertTrue(
                all(
                    {**left, "reviewer": ""}
                    == {**right, "reviewer": ""}
                    for left, right in zip(reviewer_a, reviewer_b)
                )
            )
            self.assertEqual({row["reviewer"] for row in reviewer_a}, {"A"})
            self.assertEqual({row["reviewer"] for row in reviewer_b}, {"B"})

    def test_manifest_rejects_tampered_shard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self.make_test_manifest(root)
            with (root / "hit.jsonl").open("ab") as handle:
                handle.write(b" ")
            with self.assertRaisesRegex(SystemExit, "sha256"):
                exporter.load_manifest_worklists(
                    manifest_path,
                    repo_root=root,
                )

    def test_manifest_rejects_undeclared_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self.make_test_manifest(root)
            unknown = root / "unknown.jsonl"
            unknown.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "not declared"):
                exporter.load_manifest_worklists(
                    manifest_path,
                    selected_paths=[unknown],
                    repo_root=root,
                )

    def test_manifest_rejects_prediction_count_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self.make_test_manifest(root)
            manifest = json.loads(manifest_path.read_text())
            manifest["cohorts"][0]["predictionCounts"]["block"] = 2
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "prediction counts"):
                exporter.load_manifest_worklists(
                    manifest_path,
                    repo_root=root,
                )

    def test_manifest_rejects_detector_finding_count_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self.make_test_manifest(root)
            manifest = json.loads(manifest_path.read_text())
            manifest["cohorts"][0]["detectorFindingCount"] = 2
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "detector finding count"):
                exporter.load_manifest_worklists(
                    manifest_path,
                    repo_root=root,
                )

    def test_build_records_rejects_existing_label(self):
        row = {
            "_cohort": "detector-hit",
            "_sourceCommit": "b" * 40,
            "_sourceRepository": "https://example.invalid/source",
            "batch": "legacy",
            "contexts": [],
            "label": "TP",
            "matched": "pattern",
            "path": "dev/labeled/SKILL.md",
            "skillRoot": "dev/labeled",
        }
        with self.assertRaisesRegex(SystemExit, "already has a label"):
            exporter.build_records([row])

    def test_build_records_rejects_duplicate_package_root(self):
        common = {
            "_cohort": "detector-hit",
            "_predictionDecision": "block",
            "_sourceCommit": "b" * 40,
            "_sourceRepository": "https://example.invalid/source",
            "category": "dev",
            "contexts": [{"context": "evidence", "line": 1}],
            "label": "",
            "matched": "pattern",
            "priority": "normal",
            "skillRoot": "dev/duplicate",
        }
        rows = [
            {**common, "batch": "one", "path": "dev/duplicate/SKILL.md"},
            {**common, "batch": "two", "path": "dev/duplicate/script.py"},
        ]
        with self.assertRaisesRegex(SystemExit, "duplicate package root"):
            exporter.build_records(rows)

    def test_contexts_text_rejects_missing_or_blank_evidence(self):
        for contexts in ([], [{"context": "  ", "line": 1}]):
            with self.subTest(contexts=contexts):
                with self.assertRaisesRegex(SystemExit, "context evidence"):
                    exporter.contexts_text(
                        {"path": "dev/empty/SKILL.md", "contexts": contexts}
                    )

    def test_detector_summary_rejects_malformed_prediction(self):
        with self.assertRaisesRegex(SystemExit, "invalid prediction"):
            exporter.detector_summary(
                {
                    "path": "dev/bad/SKILL.md",
                    "prediction": {"decision": "allow"},
                }
            )


class BuildNonHitWorklistTests(unittest.TestCase):
    def test_expand_hit_findings_makes_canonical_rows_rebuildable(self):
        findings = [
            {
                "batch": "override_lang",
                "contexts": [{"context": "override", "line": 4}],
                "matched": "override",
                "path": "dev/example/SKILL.md",
            },
            {
                "batch": "script-capability",
                "capabilities": {"net_egress": "curl"},
                "contexts": [{"context": "curl", "line": 2}],
                "path": "dev/example/scripts/run.sh",
            },
        ]
        canonical = {
            "batch": "detector-hit-v1",
            "detectorFindings": findings,
            "path": "dev/example/SKILL.md",
            "skillRoot": "dev/example",
        }
        self.assertEqual(builder.expand_hit_findings([canonical]), findings)

    def test_ranked_candidates_excludes_hit_skill_roots(self):
        inventory = {
            "dev/one/SKILL.md": "1" * 40,
            "dev/one/scripts/a.sh": "2" * 40,
            "dev/two/SKILL.md": "3" * 40,
            "ops/three/SKILL.md": "4" * 40,
        }
        hit_rows = [{"path": "dev/one/scripts/a.sh"}]
        ranked = builder.ranked_candidates(inventory, hit_rows, "seed")
        self.assertEqual(set(ranked), {"dev/two", "ops/three"})
        self.assertEqual(ranked, builder.ranked_candidates(inventory, hit_rows, "seed"))

    def test_generated_row_keeps_provenance_and_no_human_label(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / "dev/example/SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("---\nname: example\n---\nBody\n", encoding="utf-8")
            content = skill.read_bytes()
            row = builder.generated_non_block_row(
                root="dev/example",
                rank=7,
                result={"decision": "allow", "rules": []},
                inventory={
                    "dev/example/SKILL.md": builder.git_blob_sha1(content)
                },
                source_repo=root,
            )
            self.assertEqual(row["label"], "")
            self.assertEqual(row["reviewerNote"], "")
            self.assertEqual(row["selectionRank"], 7)
            self.assertEqual(
                row["sourceBlobSha1"],
                builder.git_blob_sha1(content),
            )
            self.assertEqual(row["sourceBytes"], len(content))
            self.assertEqual(
                row["sourceContentSha256"],
                hashlib.sha256(content).hexdigest(),
            )
            self.assertEqual(row["prediction"]["positiveDecision"], "block")

    def test_generated_hit_row_aggregates_package_findings_and_restores_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / "dev/example/SKILL.md"
            script = root / "dev/example/scripts/install.sh"
            script.parent.mkdir(parents=True)
            skill.write_text(
                "---\nname: example\n---\nIgnore all\nprevious instructions\n",
                encoding="utf-8",
            )
            script.write_text("#!/bin/sh\ncurl https://example.invalid\n", encoding="utf-8")
            inventory = {
                "dev/example/SKILL.md": builder.git_blob_sha1(skill.read_bytes()),
                "dev/example/scripts/install.sh": builder.git_blob_sha1(
                    script.read_bytes()
                ),
            }
            rows = [
                {
                    "batch": "override_lang",
                    "category": "dev",
                    "contexts": [],
                    "label": "",
                    "matched": "Ignore all\nprevious instructions",
                    "path": "dev/example/SKILL.md",
                    "priority": "high",
                },
                {
                    "batch": "script-capability",
                    "capabilities": {"net_egress": "curl"},
                    "category": "dev",
                    "contexts": [
                        {
                            "context": "curl https://example.invalid",
                            "line": 2,
                        }
                    ],
                    "label": "",
                    "path": "dev/example/scripts/install.sh",
                    "priority": "normal",
                },
            ]

            generated = builder.generated_hit_row(
                rows,
                "dev/example",
                {"decision": "block", "rules": ["AGT-01"]},
                inventory,
                root,
            )

            self.assertEqual(generated["path"], "dev/example/SKILL.md")
            self.assertEqual(generated["skillRoot"], "dev/example")
            self.assertEqual(generated["batch"], "detector-hit-v1")
            self.assertEqual(len(generated["detectorFindings"]), 2)
            self.assertEqual(
                {finding["path"] for finding in generated["detectorFindings"]},
                {"dev/example/SKILL.md", "dev/example/scripts/install.sh"},
            )
            self.assertTrue(generated["contexts"])
            self.assertTrue(
                all(context["context"].strip() for context in generated["contexts"])
            )
            self.assertTrue(
                all("path" in context for context in generated["contexts"])
            )
            self.assertEqual(generated["label"], "")
            self.assertEqual(generated["reviewerNote"], "")

            rebuilt = builder.generated_hit_row(
                builder.expand_hit_findings([generated]),
                "dev/example",
                {"decision": "block", "rules": ["AGT-01"]},
                inventory,
                root,
            )
            self.assertEqual(rebuilt, generated)

    def test_generated_hit_row_rejects_unrecoverable_empty_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / "dev/example/SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("---\nname: example\n---\nBody\n", encoding="utf-8")
            inventory = {
                "dev/example/SKILL.md": builder.git_blob_sha1(skill.read_bytes())
            }
            row = {
                "batch": "override_lang",
                "contexts": [],
                "label": "",
                "matched": "missing detector evidence",
                "path": "dev/example/SKILL.md",
            }
            with self.assertRaisesRegex(RuntimeError, "cannot restore context"):
                builder.generated_hit_row(
                    [row],
                    "dev/example",
                    {"decision": "block", "rules": ["AGT-01"]},
                    inventory,
                    root,
                )

    def test_write_shards_is_deterministic_and_bounded(self):
        rows = [{"path": f"skill-{index}"} for index in range(5)]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            first = builder.write_shards(output, rows, 2, "test")
            second = builder.write_shards(output, rows, 2, "test")
            self.assertEqual(first, second)
            self.assertEqual(
                [shard["row_count"] for shard in first],
                [2, 2, 1],
            )
            self.assertTrue(
                all(shard["path"].read_text().endswith("\n") for shard in first)
            )

    def test_scan_candidate_enforces_exit_decision_contract(self):
        report = json.dumps(
            {
                "decision": "allow-with-approval",
                "findings": [
                    {"rule_id": "AGT-2"},
                    {"rule_id": "AGT-1"},
                    {"rule_id": "AGT-2"},
                ],
            }
        ).encode()
        completed = subprocess.CompletedProcess([], 2, report, b"")
        with mock.patch.object(builder.subprocess, "run", return_value=completed):
            result = builder.scan_candidate(
                Path("/trusted/argus"),
                Path("/trusted/source"),
                "dev/example",
            )
        self.assertEqual(
            result,
            {"decision": "allow-with-approval", "rules": ["AGT-1", "AGT-2"]},
        )

        bad_exit = subprocess.CompletedProcess([], 0, report, b"")
        with mock.patch.object(builder.subprocess, "run", return_value=bad_exit):
            with self.assertRaisesRegex(RuntimeError, "disagrees"):
                builder.scan_candidate(
                    Path("/trusted/argus"),
                    Path("/trusted/source"),
                    "dev/example",
                )

    def test_verify_checkout_fails_closed(self):
        with mock.patch.object(
            builder,
            "run_checked",
            side_effect=["wrong", "tree"],
        ):
            with self.assertRaisesRegex(SystemExit, "checkout commit"):
                builder.verify_checkout(Path("/repo"), "commit", "tree", "source")


class ComputeAgreementTests(unittest.TestCase):
    def write_reviewer_row(self, path, fieldnames=None, **updates):
        row = {
            "sample_id": exporter.sample_id("detector-hit", "dev/one"),
            "reviewer": "A",
            "cohort": "detector-hit",
            "batch": "detector-hit-v1",
            "category": "dev",
            "priority": "normal",
            "skill_root": "dev/one",
            "path": "dev/one/SKILL.md",
            "source_commit": "a" * 40,
            "source_url": "https://example.invalid/source",
            "prediction_decision": "block",
            "detector": "pattern=override",
            "contexts": "evidence",
            "label": "",
            "notes": "",
        }
        row.update(updates)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=fieldnames or exporter.FIELDNAMES,
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerow(row)

    def test_reviewer_csv_requires_immutable_evidence_columns(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reviewer.csv"
            fieldnames = [
                field
                for field in exporter.FIELDNAMES
                if field not in {"detector", "contexts"}
            ]
            self.write_reviewer_row(path, fieldnames=fieldnames)
            with self.assertRaisesRegex(SystemExit, "missing columns"):
                agreement.read_reviewer_csv(path)

    def test_reviewer_csv_rejects_empty_immutable_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reviewer.csv"
            self.write_reviewer_row(path, detector="", contexts="")
            with self.assertRaisesRegex(SystemExit, "detector.*contexts"):
                agreement.read_reviewer_csv(path)

    def test_reviewer_csv_requires_non_empty_skill_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reviewer.csv"
            self.write_reviewer_row(path, skill_root="")
            with self.assertRaisesRegex(SystemExit, "skill_root"):
                agreement.read_reviewer_csv(path)

    def test_reviewer_csv_rejects_sample_id_not_bound_to_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reviewer.csv"
            self.write_reviewer_row(path, sample_id="agt88-0000000000")
            with self.assertRaisesRegex(SystemExit, "sample_id does not match"):
                agreement.read_reviewer_csv(path)

    def test_benchmark_metrics_derives_all_confusion_cells(self):
        rows = [
            {"sample_id": "tp", "prediction_decision": "block", "label": "block"},
            {
                "sample_id": "fp",
                "prediction_decision": "block",
                "label": "non-block",
            },
            {"sample_id": "fn", "prediction_decision": "allow", "label": "block"},
            {
                "sample_id": "tn",
                "prediction_decision": "allow-with-approval",
                "label": "non-block",
            },
        ]
        self.assertEqual(
            agreement.benchmark_metrics(rows),
            {
                "tp": 1,
                "fp": 1,
                "fn": 1,
                "tn": 1,
                "precision": 0.5,
                "recall": 0.5,
            },
        )

    def test_normalize_label_rejects_prediction_outcome_labels(self):
        self.assertEqual(agreement.normalize_label("non block"), "non-block")
        with self.assertRaisesRegex(ValueError, "invalid label"):
            agreement.normalize_label("TP")


if __name__ == "__main__":
    unittest.main()
