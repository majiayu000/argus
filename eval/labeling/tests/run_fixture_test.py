#!/usr/bin/env python3
"""End-to-end fixture test for compute_agreement.py.

Builds a 6-row frozen manifest, exports both reviewer assignments through the
production exporter, fills synthetic human decisions, and verifies:

  fix-01  A=block  B=block             -> agreed
  fix-02  A=non-block  B=non-block     -> agreed
  fix-03  A=block  B=non-block         -> dispute, arbitrated block
  fix-04  A=needs-context B=block      -> dispute, arbitrated non-block
  fix-05  A=block  B=(empty)           -> dispute, stays unresolved
  fix-06  A=non-block  B=non-block     -> agreed

Stage 1 (no arbitration): 3 agreed, 3 disputes, kappa over 5 dual-labeled rows.
Stage 2 (with arbitration): 5 final labels, 1 unresolved dispute.
"""

import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "compute_agreement.py")
EXPORTER = os.path.join(HERE, "..", "export_assignments.py")
FIX_IDS = {
    "fix-01": "agt88-bbe74ad684",
    "fix-02": "agt88-986704c6c8",
    "fix-03": "agt88-0605a5a6b3",
    "fix-04": "agt88-9596bf2e4c",
    "fix-05": "agt88-c256763861",
    "fix-06": "agt88-ef6cb42983",
}

REVIEW_LABELS = {
    "A": {
        "fix-01": ("block", "clear injection language"),
        "fix-02": ("non-block", "official installer"),
        "fix-03": ("block", "looks like concealment"),
        "fix-04": ("needs-context", "cannot tell from snippet"),
        "fix-05": ("block", "likely injection"),
        "fix-06": ("non-block", "api documentation"),
    },
    "B": {
        "fix-01": ("block", "agree injection"),
        "fix-02": ("non-block", "benign installer"),
        "fix-03": ("non-block", "reads like changelog advice"),
        "fix-04": ("block", "exfil shape"),
        "fix-05": ("", ""),
        "fix-06": ("non-block", "doc snippet"),
    },
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
        context = {"context": f"fixture evidence for {fixture_id}", "line": line, "path": path}
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
        (
            json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode()
        for row in rows
    )
    path.write_bytes(raw)
    return raw


def fill_reviewer(path, reviewer):
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    labels_by_id = {
        FIX_IDS[key]: value for key, value in REVIEW_LABELS[reviewer].items()
    }
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
            EXPORTER,
            "--manifest",
            str(manifest_path),
            "--repo-root",
            str(root),
            "--out-dir",
            str(assignments),
        ],
        check=True,
    )
    reviewer_a = assignments / "reviewer_A.csv"
    reviewer_b = assignments / "reviewer_B.csv"
    fill_reviewer(reviewer_a, "A")
    fill_reviewer(reviewer_b, "B")
    return manifest_path, reviewer_a, reviewer_b


def run(out_dir, manifest, reviewer_a, reviewer_b, arbitration=None):
    cmd = [
        sys.executable,
        SCRIPT,
        "--a", str(reviewer_a),
        "--b", str(reviewer_b),
        "--out-dir", out_dir,
        "--manifest", str(manifest),
        "--repo-root", str(Path(manifest).parent),
    ]
    if arbitration:
        cmd += ["--arbitration", arbitration]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    with open(os.path.join(out_dir, "agreement_report.json")) as fh:
        return json.load(fh)


def resolve_disputes(source, destination):
    with source.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    resolutions = {
        FIX_IDS["fix-03"]: ("block", "human arbitration: malicious"),
        FIX_IDS["fix-04"]: ("non-block", "human arbitration: benign"),
    }
    for row in rows:
        resolution = resolutions.get(row["sample_id"])
        if resolution:
            row["final_label"], row["final_notes"] = resolution
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    failures = []

    def check(name, actual, expected):
        if actual != expected:
            failures.append(f"{name}: expected {expected!r}, got {actual!r}")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest, reviewer_a, reviewer_b = build_fixture(root)
        # Stage 1: no arbitration.
        out1 = os.path.join(tmp, "stage1")
        report = run(out1, manifest, reviewer_a, reviewer_b)
        check("total_samples", report["total_samples"], 6)
        check("dual_labeled", report["dual_labeled"], 5)
        check("unlabeled_by_either", report["unlabeled_by_either"], 1)
        check("agreed_final", report["agreed_final"], 3)
        check("disputes_total", report["disputes_total"], 3)
        check("disputes_unresolved", report["disputes_unresolved"], 3)
        check("final_labels", report["final_labels"], 3)
        # Five dual-labeled pairs have three agreements.
        # observed agreement = 3/5 = 0.6
        check("percent_agreement", report["percent_agreement"], 0.6)
        # Marginals preserve the original two-class fixture proportions.
        # expected agreement = (2/5*2/5) + (2/5*3/5) = 0.4
        # kappa = (0.6 - 0.4) / (1 - 0.4) = 0.3333
        check("cohens_kappa", report["cohens_kappa"], 0.3333)

        with open(os.path.join(out1, "disputes.csv")) as fh:
            disputes = {r["sample_id"]: r for r in csv.DictReader(fh)}
        check(
            "dispute ids",
            sorted(disputes),
            sorted(FIX_IDS[key] for key in ("fix-03", "fix-04", "fix-05")),
        )
        check(
            "fix-03 reason",
            disputes[FIX_IDS["fix-03"]]["dispute_reason"],
            "disagreement",
        )
        check(
            "fix-04 reason",
            disputes[FIX_IDS["fix-04"]]["dispute_reason"],
            "uncertain",
        )
        check(
            "fix-05 reason",
            disputes[FIX_IDS["fix-05"]]["dispute_reason"],
            "unlabeled",
        )

        # Stage 2: human arbitration resolves fix-03/fix-04.
        out2 = os.path.join(tmp, "stage2")
        arbitration = root / "disputes_resolved.csv"
        resolve_disputes(root / "stage1/disputes.csv", arbitration)
        report2 = run(
            out2,
            manifest,
            reviewer_a,
            reviewer_b,
            arbitration=str(arbitration),
        )
        check("stage2 disputes_arbitrated", report2["disputes_arbitrated"], 2)
        check("stage2 disputes_unresolved", report2["disputes_unresolved"], 1)
        check("stage2 final_labels", report2["final_labels"], 5)
        check(
            "stage2 label_distribution",
            report2["label_distribution_final"],
            {"block": 2, "non-block": 3},
        )
        check(
            "stage2 benchmark",
            report2["benchmark"],
            {
                "tp": 2,
                "fp": 1,
                "fn": 0,
                "tn": 2,
                "precision": 0.666667,
                "recall": 1.0,
            },
        )

        with open(os.path.join(out2, "final_labels.jsonl")) as fh:
            finals = {r["sample_id"]: r for r in map(json.loads, fh)}
        check(
            "stage2 final ids",
            sorted(finals),
            sorted(
                FIX_IDS[key]
                for key in ("fix-01", "fix-02", "fix-03", "fix-04", "fix-06")
            ),
        )
        check("fix-03 source", finals[FIX_IDS["fix-03"]]["source"], "arbitrated")
        check("fix-03 label", finals[FIX_IDS["fix-03"]]["label"], "block")
        check(
            "fix-03 skill root",
            finals[FIX_IDS["fix-03"]]["skill_root"],
            "skills/three",
        )
        check("fix-04 label", finals[FIX_IDS["fix-04"]]["label"], "non-block")
        check("fix-01 source", finals[FIX_IDS["fix-01"]]["source"], "agreed")
        # Arbitrated rows keep why they were disputed, so a label resolved from a
        # genuine disagreement is distinguishable from one resolved for a row no
        # reviewer labeled.
        check(
            "fix-03 dispute_reason",
            finals[FIX_IDS["fix-03"]]["dispute_reason"],
            "disagreement",
        )
        check(
            "fix-04 dispute_reason",
            finals[FIX_IDS["fix-04"]]["dispute_reason"],
            "uncertain",
        )
        check(
            "fix-01 has no dispute_reason",
            "dispute_reason" in finals[FIX_IDS["fix-01"]],
            False,
        )
        check(
            "stage2 arbitrated_by_reason",
            report2["arbitrated_by_reason"],
            {"disagreement": 1, "uncertain": 1},
        )

    if failures:
        print("FAIL")
        for f in failures:
            print(f"  {f}")
        return 1
    print("PASS: fixture agreement pipeline (stage 1 + stage 2) behaved as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
