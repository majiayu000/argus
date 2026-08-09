#!/usr/bin/env python3
"""End-to-end fixture test for the single-AI-review labeling pipeline."""

import csv
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FINALIZER = HERE.parent / "finalize_review.py"
EXPORTER = HERE.parent / "export_assignments.py"
FIX_IDS = {
    "fix-01": "agt88-bbe74ad684",
    "fix-02": "agt88-986704c6c8",
    "fix-03": "agt88-0605a5a6b3",
    "fix-04": "agt88-9596bf2e4c",
    "fix-05": "agt88-c256763861",
    "fix-06": "agt88-ef6cb42983",
}
INITIAL_LABELS = {
    "fix-01": ("block", "direct instruction override"),
    "fix-02": ("non-block", "installer example in documentation"),
    "fix-03": ("block", "concealment instruction targets the operator"),
    "fix-04": ("needs-context", "snippet does not establish intent"),
    "fix-05": ("", ""),
    "fix-06": ("non-block", "API request documentation"),
}
FINAL_LABELS = {
    **INITIAL_LABELS,
    "fix-04": ("non-block", "pinned source shows a benign API client"),
    "fix-05": ("block", "pinned source overrides trusted instructions"),
}


def fixture_rows():
    specs = [
        ("fix-01", "detector-hit", "override_lang", "high", "skills/one", "SKILL.md", "absolute authority", 3),
        ("fix-02", "detector-hit", "curl_pipe_sh-fp-sample", "fp-check", "skills/two", "SKILL.md", "curl | sh", 9),
        ("fix-03", "detector-hit", "concealment", "normal", "skills/three", "SKILL.md", "do not mention", 5),
        ("fix-04", "detector-non-block", "script-capability", "high", "skills/four", "scripts/run.sh", "curl api endpoint", 12),
        ("fix-05", "detector-non-block", "override_lang", "normal", "skills/five", "SKILL.md", "override system", 7),
        ("fix-06", "detector-non-block", "exfil_instruction-fp-sample", "fp-check", "skills/six", "SKILL.md", "POST /token", 2),
    ]
    rows = []
    for fixture_id, cohort, batch, priority, root, suffix, matched, line in specs:
        path = f"{root}/{suffix}"
        context = {
            "context": f"fixture evidence for {fixture_id}",
            "line": line,
            "path": path,
        }
        prediction = {
            "decision": "block" if cohort == "detector-hit" else "allow",
            "positiveDecision": "block",
            "rules": [batch] if cohort == "detector-hit" else [],
        }
        row = {
            "batch": f"{cohort}-v1",
            "category": "dev",
            "cohort": cohort,
            "contexts": [context],
            "label": "",
            "path": path,
            "prediction": prediction,
            "priority": priority,
            "reviewerNote": "",
            "skillRoot": root,
        }
        if cohort == "detector-hit":
            row["detectorFindings"] = [
                {
                    "batch": batch,
                    "contexts": [context],
                    "matched": matched,
                    "path": path,
                }
            ]
        rows.append(row)
    return rows


def write_jsonl(path, rows):
    raw = b"".join(
        (json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n").encode()
        for row in rows
    )
    path.write_bytes(raw)
    return raw


def fill_review(path, labels):
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    labels_by_id = {FIX_IDS[key]: value for key, value in labels.items()}
    for row in rows:
        row["label"], row["notes"] = labels_by_id[row["sample_id"]]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_fixture(root):
    rows = fixture_rows()
    cohorts = []
    for cohort_id in ("detector-hit", "detector-non-block"):
        cohort_rows = [row for row in rows if row["cohort"] == cohort_id]
        shard = root / f"{cohort_id}.jsonl"
        raw = write_jsonl(shard, cohort_rows)
        cohort = {
            "id": cohort_id,
            "rowCount": len(cohort_rows),
            "combinedSha256": hashlib.sha256(raw).hexdigest(),
            "predictionCounts": {
                "block" if cohort_id == "detector-hit" else "allow": len(cohort_rows)
            },
            "shards": [
                {
                    "path": shard.name,
                    "rowCount": len(cohort_rows),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            ],
        }
        if cohort_id == "detector-hit":
            cohort.update(
                {
                    "detectorFindingCount": len(cohort_rows),
                    "legacyInputCombinedSha256": "0" * 64,
                    "legacyInputRowCount": len(cohort_rows),
                    "legacyUniqueSkillRootCount": len(cohort_rows),
                }
            )
        cohorts.append(cohort)
    manifest = {
        "schemaVersion": 1,
        "sourceSnapshot": {
            "repository": "https://example.invalid/source",
            "commit": "a" * 40,
        },
        "detectorBaseline": {"positiveDecision": "block"},
        "cohorts": cohorts,
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assignments = root / "assignments"
    subprocess.run(
        [
            sys.executable,
            str(EXPORTER),
            "--manifest",
            str(manifest_path),
            "--repo-root",
            str(root),
            "--out-dir",
            str(assignments),
            "--reviewer-id",
            "codex",
            "--reviewer-model",
            "gpt-5",
        ],
        check=True,
    )
    return manifest_path, assignments / "reviewer.csv"


def run(out_dir, manifest, review, *, allow_incomplete=False, check=True):
    command = [
        sys.executable,
        str(FINALIZER),
        "--review",
        str(review),
        "--out-dir",
        str(out_dir),
        "--manifest",
        str(manifest),
        "--repo-root",
        str(manifest.parent),
    ]
    if allow_incomplete:
        command.append("--allow-incomplete")
    completed = subprocess.run(command, check=check, capture_output=True, text=True)
    report_path = out_dir / "review_report.json"
    report = json.loads(report_path.read_text()) if report_path.exists() else None
    return completed, report


def main():
    failures = []

    def check(name, actual, expected):
        if actual != expected:
            failures.append(f"{name}: expected {expected!r}, got {actual!r}")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        manifest, review = build_fixture(root)
        fill_review(review, INITIAL_LABELS)

        strict, _ = run(root / "strict", manifest, review, check=False)
        check("strict incomplete exit", strict.returncode, 1)

        _, partial = run(
            root / "partial",
            manifest,
            review,
            allow_incomplete=True,
        )
        check("partial total", partial["total_samples"], 6)
        check("partial final", partial["final_labels"], 4)
        check("partial unresolved", partial["unresolved_samples"], 2)
        check(
            "partial reasons",
            partial["unresolved_by_reason"],
            {"needs-context": 1, "unlabeled": 1},
        )
        check("partial benchmark", partial["benchmark"], None)

        with (root / "partial/unresolved.csv").open(newline="", encoding="utf-8") as handle:
            unresolved = {row["sample_id"]: row for row in csv.DictReader(handle)}
        check(
            "unresolved ids",
            sorted(unresolved),
            sorted((FIX_IDS["fix-04"], FIX_IDS["fix-05"])),
        )

        fill_review(review, FINAL_LABELS)
        _, complete = run(root / "complete", manifest, review)
        check("complete unresolved", complete["unresolved_samples"], 0)
        check("complete final", complete["final_labels"], 6)
        check(
            "complete provenance",
            complete["reviewer"],
            {"id": "codex", "model": "gpt-5"},
        )
        check(
            "complete benchmark",
            complete["benchmark"],
            {
                "tp": 2,
                "fp": 1,
                "fn": 1,
                "tn": 2,
                "precision": 0.666667,
                "recall": 0.666667,
            },
        )

        with (root / "complete/final_labels.jsonl").open(encoding="utf-8") as handle:
            finals = {row["sample_id"]: row for row in map(json.loads, handle)}
        check("final source", finals[FIX_IDS["fix-01"]]["source"], "single-ai-review")
        check(
            "final reviewer",
            finals[FIX_IDS["fix-01"]]["reviewer"],
            {"id": "codex", "model": "gpt-5"},
        )
        check(
            "final notes",
            finals[FIX_IDS["fix-01"]]["notes"],
            "direct instruction override",
        )

    if failures:
        print("FAIL")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print("PASS: single AI review pipeline behaved as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
